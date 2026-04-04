/*
 * win_server.c
 *
 * A Windows TCP server that listens on a configurable port
 * (default: 10000).
 * For each incoming connection, it spawns a child process (specified via
 * command-line arguments) with stdin, stdout, and stderr redirected to
 * the connected socket. The child runs asynchronously; the main loop
 * immediately returns to accepting the next connection.
 *
 * Single-threaded design: no worker threads are created.
 *
 * Usage: win_server.exe [-p port] <program> [args...]
 * Example: win_server.exe -p 10001 cmd.exe /c dir /?
 *
 * Compile with MSVC:
 *   cl /O2 /MT win_server.c /Fewin_server.exe
 * Compile with MinGW:
 *   gcc win_server.c -o win_server.exe -lws2_32
 *
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#endif

#ifndef LISTEN_PORT
#define LISTEN_PORT     10000
#endif

#ifndef LISTEN_BACKLOG
#define LISTEN_BACKLOG  5
#endif
#define WIN_SERVER_VERSION "2.0.0"
#define MAX_CHILD_PROCESSES ((MAXIMUM_WAIT_OBJECTS - 2) / 2)

#define CLIENT_DISCONNECT_FORCE_EXIT_CODE ERROR_BROKEN_PIPE

typedef struct ChildProcess {
    HANDLE process_handle;
    HANDLE session_job_handle;
    SOCKET client_socket;
    WSAEVENT socket_event;
    DWORD process_id;
    BOOL client_disconnect_detected;
    BOOL force_termination_requested;
} ChildProcess;

typedef struct DetachedSession {
    HANDLE job_handle;
    DWORD child_process_id;
} DetachedSession;

typedef struct DetachedSessionList {
    DetachedSession *items;
    size_t count;
    size_t capacity;
} DetachedSessionList;

static HANDLE g_shutdown_event = NULL;

/* --------------------------------------------------------------------
 * Logging helper: prints a timestamped message.
 * Format: [YYYY-MM-DD HH:MM:SS][LEVEL] message
 * -------------------------------------------------------------------- */
static void log_msg(const char *level, const char *fmt, ...)
{
    /* Get current local time */
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_ptr;
    char time_str[20]; /* "YYYY-MM-DD HH:MM:SS" = 19 chars + null */
    /* Determine output stream: only ERROR goes to stderr. */
    FILE *out = stdout;
    va_list args;

    tm_ptr = localtime(&now);
    if (tm_ptr != NULL) {
        tm_buf = *tm_ptr;
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
    } else {
        strcpy(time_str, "1970-01-01 00:00:00");
    }

    if (strcmp(level, "ERROR") == 0) {
        out = stderr;
    }

    /* Print timestamp and level */
    fprintf(out, "[%s][%s] ", time_str, level);

    /* Print the user-supplied message */
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);

    fprintf(out, "\n");
    fflush(out);
}

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (g_shutdown_event != NULL) {
            SetEvent(g_shutdown_event);
        }
        return TRUE;
    default:
        return FALSE;
    }
}

static void print_version(void)
{
    fprintf(stdout, "win_server %s\n", WIN_SERVER_VERSION);
}

static void print_usage(const char *program_name)
{
    fprintf(stderr, "win_server %s\n", WIN_SERVER_VERSION);
    fprintf(stderr, "Usage: %s [-p port] <program> [args...]\n", program_name);
    fprintf(stderr, "       %s -v | --version\n", program_name);
    fprintf(stderr, "Example: %s -p 10001 cmd.exe /c dir /?\n", program_name);
    fprintf(stderr, "Port range: 1-65535 (default: %d)\n", LISTEN_PORT);
}

static BOOL parse_listen_port(const char *port_text, u_short *port_out)
{
    char *end_ptr;
    long parsed_port;

    if (port_text == NULL || port_out == NULL || port_text[0] == '\0') {
        return FALSE;
    }

    parsed_port = strtol(port_text, &end_ptr, 10);
    if (*end_ptr != '\0' || parsed_port < 1 || parsed_port > 65535) {
        return FALSE;
    }

    *port_out = (u_short)parsed_port;
    return TRUE;
}

/* --------------------------------------------------------------------
 * Build a single command-line string from argv[start] .. argv[argc-1].
 * CreateProcess expects one flat command-line string.
 * Returns a heap-allocated string; caller must free() it.
 * -------------------------------------------------------------------- */
static char *build_command_line(int argc, char *argv[], int start)
{
    size_t total_len = 0;
    int i;
    char *cmd;

    for (i = start; i < argc; i++) {
        total_len += strlen(argv[i]) + 1; /* +1 for space or null */
    }

    cmd = (char *)malloc(total_len + 1);
    if (!cmd) {
        log_msg("ERROR", "malloc failed for command line buffer");
        return NULL;
    }

    cmd[0] = '\0';
    for (i = start; i < argc; i++) {
        if (i > start) {
            strcat(cmd, " ");
        }
        strcat(cmd, argv[i]);
    }

    return cmd;
}

static void make_socket_blocking_for_child(SOCKET client_sock)
{
    u_long blocking_mode = 0;

    /*
     * The listening socket is switched to non-blocking mode once we attach
     * it to an event with WSAEventSelect(). Clear any inherited async state
     * on the accepted socket before giving it to the child.
     */
    if (WSAEventSelect(client_sock, NULL, 0) == SOCKET_ERROR) {
        log_msg("WARN", "WSAEventSelect(clear) failed for client socket: %d",
                WSAGetLastError());
    }

    if (ioctlsocket(client_sock, FIONBIO, &blocking_mode) == SOCKET_ERROR) {
        log_msg("WARN", "ioctlsocket(FIONBIO=0) failed for client socket: %d",
                WSAGetLastError());
    }
}

static void send_rejection_message(SOCKET client_sock, const char *message)
{
    size_t total_len = strlen(message);
    size_t total_sent = 0;

    while (total_sent < total_len) {
        WSABUF buffer;
        DWORD bytes_sent = 0;
        int send_result;

        buffer.buf = (CHAR *)(message + total_sent);
        buffer.len = (ULONG)(total_len - total_sent);

        send_result = WSASend(client_sock, &buffer, 1, &bytes_sent, 0, NULL, NULL);
        if (send_result == SOCKET_ERROR) {
            log_msg("WARN", "WSASend() failed while rejecting client: %d",
                    WSAGetLastError());
            return;
        }

        if (bytes_sent == 0) {
            log_msg("WARN", "WSASend() sent 0 bytes while rejecting client.");
            return;
        }

        total_sent += bytes_sent;
    }
}

static const char *exception_code_name(DWORD exit_code)
{
    switch (exit_code) {
    case 0x80131500u:
        return "COR_E_EXCEPTION";
    case 0x80131506u:
        return "COR_E_EXECUTIONENGINE";
    case 0x80131623u:
        return "COR_E_FAILFAST";
    case 0x80000002u:
        return "STATUS_DATATYPE_MISALIGNMENT";
    case 0x80000003u:
        return "STATUS_BREAKPOINT";
    case 0xC0000005u:
        return "STATUS_ACCESS_VIOLATION";
    case 0xC0000006u:
        return "STATUS_IN_PAGE_ERROR";
    case 0xC000001Du:
        return "STATUS_ILLEGAL_INSTRUCTION";
    case 0xC0000025u:
        return "STATUS_NONCONTINUABLE_EXCEPTION";
    case 0xC0000026u:
        return "STATUS_INVALID_DISPOSITION";
    case 0xC000008Cu:
        return "STATUS_ARRAY_BOUNDS_EXCEEDED";
    case 0xC000008Du:
        return "STATUS_FLOAT_DENORMAL_OPERAND";
    case 0xC000008Eu:
        return "STATUS_FLOAT_DIVIDE_BY_ZERO";
    case 0xC000008Fu:
        return "STATUS_FLOAT_INEXACT_RESULT";
    case 0xC0000090u:
        return "STATUS_FLOAT_INVALID_OPERATION";
    case 0xC0000091u:
        return "STATUS_FLOAT_OVERFLOW";
    case 0xC0000092u:
        return "STATUS_FLOAT_STACK_CHECK";
    case 0xC0000093u:
        return "STATUS_FLOAT_UNDERFLOW";
    case 0xC0000094u:
        return "STATUS_INTEGER_DIVIDE_BY_ZERO";
    case 0xC0000095u:
        return "STATUS_INTEGER_OVERFLOW";
    case 0xC0000096u:
        return "STATUS_PRIVILEGED_INSTRUCTION";
    case 0xC00000FDu:
        return "STATUS_STACK_OVERFLOW";
    case 0xC000013Au:
        return "STATUS_CONTROL_C_EXIT";
    case 0xC0000374u:
        return "STATUS_HEAP_CORRUPTION";
    case 0xC0000409u:
        return "STATUS_STACK_BUFFER_OVERRUN";
    case 0xE0434352u:
        return "CLR_EXCEPTION";
    default:
        return NULL;
    }
}

static BOOL is_probable_exception_code(DWORD exit_code)
{
    if (exception_code_name(exit_code) != NULL) {
        return exit_code != 0xC000013Au;
    }

    if ((exit_code & 0x80000000u) != 0 &&
        ((exit_code >> 16) & 0x1FFFu) == 0x13u) {
        return TRUE;
    }

    return (exit_code & 0xF0000000u) == 0xC0000000u ||
           (exit_code & 0xF0000000u) == 0xE0000000u;
}

static HANDLE create_kill_on_close_job(void)
{
    HANDLE job_handle = CreateJobObjectA(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;

    if (job_handle == NULL) {
        log_msg("WARN", "CreateJobObject failed: %lu", GetLastError());
        return NULL;
    }

    ZeroMemory(&job_info, sizeof(job_info));
    job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if (!SetInformationJobObject(job_handle,
                                 JobObjectExtendedLimitInformation,
                                 &job_info,
                                 sizeof(job_info))) {
        log_msg("WARN", "SetInformationJobObject failed: %lu", GetLastError());
        CloseHandle(job_handle);
        return NULL;
    }

    return job_handle;
}

static BOOL query_job_active_processes(HANDLE job_handle,
                                       DWORD *active_process_count)
{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION job_info;

    if (active_process_count == NULL) {
        return FALSE;
    }

    ZeroMemory(&job_info, sizeof(job_info));
    if (!QueryInformationJobObject(job_handle,
                                   JobObjectBasicAccountingInformation,
                                   &job_info,
                                   sizeof(job_info),
                                   NULL)) {
        return FALSE;
    }

    *active_process_count = job_info.ActiveProcesses;
    return TRUE;
}

static BOOL append_detached_session(DetachedSessionList *sessions,
                                    HANDLE job_handle,
                                    DWORD child_process_id)
{
    size_t new_capacity;
    DetachedSession *new_items;

    if (sessions == NULL || job_handle == NULL) {
        return FALSE;
    }

    if (sessions->count == sessions->capacity) {
        new_capacity = (sessions->capacity == 0) ? 4 : sessions->capacity * 2;
        new_items = (DetachedSession *)realloc(
            sessions->items,
            new_capacity * sizeof(*new_items));
        if (new_items == NULL) {
            return FALSE;
        }

        sessions->items = new_items;
        sessions->capacity = new_capacity;
    }

    sessions->items[sessions->count].job_handle = job_handle;
    sessions->items[sessions->count].child_process_id = child_process_id;
    sessions->count++;
    return TRUE;
}

static void remove_detached_session(DetachedSessionList *sessions, size_t index)
{
    if (sessions == NULL || index >= sessions->count) {
        return;
    }

    if (index != sessions->count - 1) {
        sessions->items[index] = sessions->items[sessions->count - 1];
    }

    sessions->count--;
}

static void prune_detached_sessions(DetachedSessionList *sessions)
{
    size_t index = 0;

    if (sessions == NULL) {
        return;
    }

    while (index < sessions->count) {
        DWORD active_process_count = 0;
        DetachedSession *session = &sessions->items[index];

        if (!query_job_active_processes(session->job_handle,
                                        &active_process_count)) {
            log_msg("WARN",
                    "QueryInformationJobObject failed for detached session "
                    "from PID %lu: %lu",
                    session->child_process_id, GetLastError());
            index++;
            continue;
        }

        if (active_process_count != 0) {
            index++;
            continue;
        }

        CloseHandle(session->job_handle);
        remove_detached_session(sessions, index);
    }
}

static void close_detached_sessions(DetachedSessionList *sessions)
{
    size_t index;

    if (sessions == NULL) {
        return;
    }

    for (index = 0; index < sessions->count; index++) {
        if (sessions->items[index].job_handle != NULL) {
            CloseHandle(sessions->items[index].job_handle);
        }
    }

    free(sessions->items);
    sessions->items = NULL;
    sessions->count = 0;
    sessions->capacity = 0;
}

static void log_child_exit_status(const ChildProcess *child)
{
    DWORD exit_code = STILL_ACTIVE;
    const char *exception_name = NULL;

    if (!GetExitCodeProcess(child->process_handle, &exit_code)) {
        log_msg("ERROR", "GetExitCodeProcess failed for PID %lu: %lu",
                child->process_id, GetLastError());
        return;
    }

    exception_name = exception_code_name(exit_code);

    if (child->force_termination_requested &&
        exit_code == CLIENT_DISCONNECT_FORCE_EXIT_CODE) {
        log_msg("WARN",
                "Child process terminated after client disconnect "
                "(PID: %lu, exit code: %lu)",
                child->process_id, exit_code);
        return;
    }

    if (exit_code == 0) {
        if (child->client_disconnect_detected) {
            log_msg("INFO", "Child process exited after client disconnected "
                    "(PID: %lu)", child->process_id);
        } else {
            log_msg("INFO", "Child process exited normally (PID: %lu)",
                    child->process_id);
        }
        return;
    }

    if (exit_code == 0xC000013Au) {
        log_msg("WARN",
                "Child process stopped by console control signal "
                "(PID: %lu, exit code: 0x%08lX)",
                child->process_id, exit_code);
        return;
    }

    if (exception_name != NULL) {
        log_msg("ERROR",
                "Child process crashed with %s "
                "(PID: %lu, exit code: 0x%08lX)",
                exception_name, child->process_id, exit_code);
        return;
    }

    if (is_probable_exception_code(exit_code)) {
        log_msg("ERROR",
                "Child process terminated abnormally "
                "(PID: %lu, NTSTATUS: 0x%08lX)",
                child->process_id, exit_code);
        return;
    }

    log_msg("WARN", "Child process exited with code %lu (PID: %lu)",
            exit_code, child->process_id);
}

static void close_child_session_socket(ChildProcess *child)
{
    if (child->socket_event != WSA_INVALID_EVENT) {
        WSACloseEvent(child->socket_event);
        child->socket_event = WSA_INVALID_EVENT;
    }
    if (child->client_socket != INVALID_SOCKET) {
        closesocket(child->client_socket);
        child->client_socket = INVALID_SOCKET;
    }
}

static void force_terminate_child(ChildProcess *child)
{
    BOOL terminated = FALSE;

    if (child->force_termination_requested) {
        return;
    }

    child->force_termination_requested = TRUE;

    if (child->session_job_handle != NULL) {
        terminated = TerminateJobObject(child->session_job_handle,
                                        CLIENT_DISCONNECT_FORCE_EXIT_CODE);
        if (!terminated) {
            log_msg("WARN",
                    "TerminateJobObject failed for PID %lu: %lu. "
                    "Falling back to TerminateProcess.",
                    child->process_id, GetLastError());
        }
    }

    if (!terminated) {
        if (!TerminateProcess(child->process_handle,
                              CLIENT_DISCONNECT_FORCE_EXIT_CODE)) {
            log_msg("ERROR", "TerminateProcess failed for PID %lu: %lu",
                    child->process_id, GetLastError());
            return;
        }
    }

}

static void release_child_session_job(ChildProcess *child,
                                      DetachedSessionList *detached_sessions)
{
    DWORD active_process_count = 0;

    if (child->session_job_handle == NULL) {
        return;
    }

    if (child->force_termination_requested) {
        CloseHandle(child->session_job_handle);
        child->session_job_handle = NULL;
        return;
    }

    if (!query_job_active_processes(child->session_job_handle,
                                    &active_process_count)) {
        log_msg("WARN",
                "QueryInformationJobObject failed for child PID %lu: %lu. "
                "Keeping descendants alive until server shutdown.",
                child->process_id, GetLastError());
        active_process_count = 1;
    }

    if (active_process_count == 0) {
        CloseHandle(child->session_job_handle);
        child->session_job_handle = NULL;
        return;
    }

    if (!append_detached_session(detached_sessions,
                                 child->session_job_handle,
                                 child->process_id)) {
        log_msg("ERROR",
                "Failed to retain session job for exited child PID %lu. "
                "Remaining descendants will be terminated now.",
                child->process_id);
        CloseHandle(child->session_job_handle);
        child->session_job_handle = NULL;
        return;
    }

    child->session_job_handle = NULL;
}

static void note_client_disconnect(ChildProcess *child)
{
    int shutdown_result;
    int shutdown_error;

    if (child->client_disconnect_detected) {
        return;
    }

    child->client_disconnect_detected = TRUE;

    log_msg("WARN",
            "Client disconnected. Terminating child process immediately "
            "(PID: %lu)",
            child->process_id);

    if (child->client_socket == INVALID_SOCKET) {
        force_terminate_child(child);
        return;
    }

    shutdown_result = shutdown(child->client_socket, SD_BOTH);
    if (shutdown_result == SOCKET_ERROR) {
        shutdown_error = WSAGetLastError();
        if (shutdown_error != WSAENOTCONN) {
            log_msg("WARN", "shutdown() failed for PID %lu: %d",
                    child->process_id, shutdown_error);
        }
    }

    close_child_session_socket(child);
    force_terminate_child(child);
}

static void reap_child_process(ChildProcess children[],
                               DWORD *child_count,
                               DWORD child_index,
                               DetachedSessionList *detached_sessions)
{
    if (child_index >= *child_count) {
        return;
    }

    log_child_exit_status(&children[child_index]);
    close_child_session_socket(&children[child_index]);

    release_child_session_job(&children[child_index], detached_sessions);

    CloseHandle(children[child_index].process_handle);

    if (child_index != (*child_count - 1)) {
        children[child_index] = children[*child_count - 1];
    }

    (*child_count)--;
}

/* --------------------------------------------------------------------
 * Spawn a child process whose stdin/stdout/stderr are all redirected
 * to the given client socket. The child runs asynchronously -- this
 * function does NOT wait for it to exit.
 *
 * After the child is created, the parent keeps its own client socket
 * handle so it can detect remote disconnects and force cleanup if the
 * child gets stuck. The child still inherits its own stdio handle.
 * -------------------------------------------------------------------- */
static BOOL spawn_child(SOCKET client_sock,
                        const char *command_line,
                        ChildProcess *child_out)
{
    /*
     * CreateProcess may modify the command-line buffer in place,
     * so we need a writable copy.
     */
    char *cmd_buf;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE session_job_handle;
    DWORD creation_flags = CREATE_SUSPENDED;
    BOOL success;
    WSAEVENT socket_event;

    cmd_buf = (char *)malloc(strlen(command_line) + 1);
    if (!cmd_buf) {
        log_msg("ERROR", "malloc failed");
        closesocket(client_sock);
        return FALSE;
    }
    strcpy(cmd_buf, command_line);

    if (!SetHandleInformation((HANDLE)client_sock,
                              HANDLE_FLAG_INHERIT,
                              HANDLE_FLAG_INHERIT))
    {
        log_msg("ERROR", "SetHandleInformation(client socket) failed: %lu",
                GetLastError());
        closesocket(client_sock);
        free(cmd_buf);
        return FALSE;
    }

    /* Redirect child's stdin / stdout / stderr to the duplicated handle */
    session_job_handle = create_kill_on_close_job();

    ZeroMemory(&si, sizeof(si));
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = (HANDLE)client_sock;
    si.hStdOutput = (HANDLE)client_sock;
    si.hStdError  = (HANDLE)client_sock;

    ZeroMemory(&pi, sizeof(pi));

    log_msg("INFO", "Spawning child process: %s", cmd_buf);

    success = CreateProcessA(
        NULL,           /* lpApplicationName: NULL, parse from cmd line */
        cmd_buf,        /* lpCommandLine (writable buffer) */
        NULL,           /* lpProcessAttributes */
        NULL,           /* lpThreadAttributes */
        TRUE,           /* bInheritHandles: must be TRUE for redirection */
        creation_flags, /* dwCreationFlags */
        NULL,           /* lpEnvironment: inherit parent's */
        NULL,           /* lpCurrentDirectory: inherit parent's */
        &si,
        &pi
    );

    if (!success) {
        log_msg("ERROR", "CreateProcess failed: %lu", GetLastError());
        closesocket(client_sock);
        if (session_job_handle != NULL) {
            CloseHandle(session_job_handle);
        }
        free(cmd_buf);
        return FALSE;
    }

    if (!SetHandleInformation((HANDLE)client_sock, HANDLE_FLAG_INHERIT, 0)) {
        log_msg("WARN", "SetHandleInformation(clear inherit) failed: %lu",
                GetLastError());
    }

    if (session_job_handle != NULL &&
        !AssignProcessToJobObject(session_job_handle, pi.hProcess)) {
        log_msg("WARN",
                "AssignProcessToJobObject failed for PID %lu: %lu. "
                "Falling back to direct process termination.",
                pi.dwProcessId, GetLastError());
        CloseHandle(session_job_handle);
        session_job_handle = NULL;
    }

    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        log_msg("ERROR", "ResumeThread failed for PID %lu: %lu",
                pi.dwProcessId, GetLastError());

        if (session_job_handle != NULL) {
            TerminateJobObject(session_job_handle,
                               CLIENT_DISCONNECT_FORCE_EXIT_CODE);
            CloseHandle(session_job_handle);
        } else {
            TerminateProcess(pi.hProcess, CLIENT_DISCONNECT_FORCE_EXIT_CODE);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        closesocket(client_sock);
        free(cmd_buf);
        return FALSE;
    }

    socket_event = WSACreateEvent();
    if (socket_event == WSA_INVALID_EVENT) {
        log_msg("ERROR", "WSACreateEvent() failed for client socket: %d",
                WSAGetLastError());

        if (session_job_handle != NULL) {
            TerminateJobObject(session_job_handle,
                               CLIENT_DISCONNECT_FORCE_EXIT_CODE);
            CloseHandle(session_job_handle);
        } else {
            TerminateProcess(pi.hProcess, CLIENT_DISCONNECT_FORCE_EXIT_CODE);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        closesocket(client_sock);
        free(cmd_buf);
        return FALSE;
    }

    if (WSAEventSelect(client_sock, socket_event, FD_CLOSE) == SOCKET_ERROR) {
        log_msg("ERROR", "WSAEventSelect() failed for client socket: %d",
                WSAGetLastError());
        WSACloseEvent(socket_event);

        if (session_job_handle != NULL) {
            TerminateJobObject(session_job_handle,
                               CLIENT_DISCONNECT_FORCE_EXIT_CODE);
            CloseHandle(session_job_handle);
        } else {
            TerminateProcess(pi.hProcess, CLIENT_DISCONNECT_FORCE_EXIT_CODE);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        closesocket(client_sock);
        free(cmd_buf);
        return FALSE;
    }

    child_out->process_handle = pi.hProcess;
    child_out->session_job_handle = session_job_handle;
    child_out->client_socket = client_sock;
    child_out->socket_event = socket_event;
    child_out->process_id = pi.dwProcessId;
    child_out->client_disconnect_detected = FALSE;
    child_out->force_termination_requested = FALSE;

    log_msg("INFO", "Child process started (PID: %lu)", pi.dwProcessId);

    /*
     * The parent keeps its own client socket handle to monitor remote
     * disconnects. We only close the thread handle here.
     */
    CloseHandle(pi.hThread);

    free(cmd_buf);
    return TRUE;
}

static void accept_pending_connections(SOCKET listen_sock,
                                       const char *command_line,
                                       ChildProcess children[],
                                       DWORD *child_count)
{
    while (1) {
        struct sockaddr_in client_addr;
        INT client_addr_len = sizeof(client_addr);
        SOCKET client_sock;
        char client_addr_str[64];
        DWORD addr_str_len = sizeof(client_addr_str);
        ChildProcess child;

        client_sock = WSAAccept(listen_sock,
                                (struct sockaddr *)&client_addr,
                                &client_addr_len,
                                NULL,
                                0);
        if (client_sock == INVALID_SOCKET) {
            int accept_error = WSAGetLastError();
            if (accept_error != WSAEWOULDBLOCK) {
                log_msg("WARN", "WSAAccept() failed: %d", accept_error);
            }
            return;
        }

        /* Log client info using WSAAddressToStringA instead of inet_ntop */
        if (WSAAddressToStringA((struct sockaddr *)&client_addr,
                                sizeof(client_addr),
                                NULL,
                                client_addr_str,
                                &addr_str_len) == 0) {
            log_msg("INFO", "Accepted connection from %s", client_addr_str);
        } else {
            /* Fallback: use WSANtohs to convert port */
            u_short client_port;
            WSANtohs(client_sock, client_addr.sin_port, &client_port);
            log_msg("INFO", "Accepted connection (port: %d)", client_port);
        }

        if (*child_count >= MAX_CHILD_PROCESSES) {
            log_msg("ERROR",
                    "Too many active child processes (%lu). Rejecting connection.",
                    *child_count);
            make_socket_blocking_for_child(client_sock);
            send_rejection_message(
                client_sock,
                "ERROR: too many active connections, please try again later.\r\n");
            closesocket(client_sock);
            continue;
        }

        make_socket_blocking_for_child(client_sock);

        if (spawn_child(client_sock, command_line, &child)) {
            children[*child_count] = child;
            (*child_count)++;
        }
    }
}

/* ====================================================================
 * main
 * ==================================================================== */
int main(int argc, char *argv[])
{
    int exit_code = 0;
    int command_start = 1;
    WSAEVENT listen_event = WSA_INVALID_EVENT;
    ChildProcess children[MAX_CHILD_PROCESSES];
    DetachedSessionList detached_sessions;
    DWORD child_count = 0;
    char *command_line;
    WSADATA wsa_data;
    int result;
    SOCKET listen_sock = INVALID_SOCKET;
    BOOL opt_val = TRUE;
    struct sockaddr_in server_addr;
    u_long host_addr = INADDR_ANY;
    u_short host_port = LISTEN_PORT;
    DWORD i;

    ZeroMemory(&detached_sessions, sizeof(detached_sessions));

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (argc == 2 &&
        (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0)) {
        print_version();
        return 0;
    }

    if (strcmp(argv[1], "-p") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            return 1;
        }

        if (!parse_listen_port(argv[2], &host_port)) {
            fprintf(stderr, "Invalid port: %s\n", argv[2]);
            print_usage(argv[0]);
            return 1;
        }

        command_start = 3;
    }

    if (command_start >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    /* Build the target command line from arguments */
    command_line = build_command_line(argc, argv, command_start);
    if (!command_line) {
        return 1;
    }

    log_msg("INFO", "win_server %s starting.", WIN_SERVER_VERSION);
    log_msg("INFO", "Target command line: %s", command_line);

    /* Initialize Winsock */
    result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        log_msg("ERROR", "WSAStartup failed: %d", result);
        free(command_line);
        return 1;
    }

    /* Create listening socket using WSASocket instead of socket() */
    listen_sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (listen_sock == INVALID_SOCKET) {
        log_msg("ERROR", "WSASocket() failed: %d", WSAGetLastError());
        WSACleanup();
        free(command_line);
        return 1;
    }

    if (!SetHandleInformation((HANDLE)listen_sock, HANDLE_FLAG_INHERIT, 0)) {
        log_msg("WARN", "SetHandleInformation(listen socket) failed: %lu",
                GetLastError());
    }

    /*
     * On Windows, SO_REUSEADDR allows another process to bind the same
     * listening port, which is not what we want for this server. Use
     * SO_EXCLUSIVEADDRUSE instead so the second bind fails reliably.
     */
    if (setsockopt(listen_sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   (const char *)&opt_val, sizeof(opt_val)) == SOCKET_ERROR) {
        log_msg("ERROR", "setsockopt(SO_EXCLUSIVEADDRUSE) failed: %d",
                WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        free(command_line);
        return 1;
    }

    /* Bind to 0.0.0.0:host_port using WSA byte order functions */
    ZeroMemory(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    /* Use WSAHtonl and WSAHtons for byte order conversion */
    WSAHtonl(listen_sock, host_addr, &server_addr.sin_addr.s_addr);
    WSAHtons(listen_sock, host_port, &server_addr.sin_port);

    if (bind(listen_sock, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) == SOCKET_ERROR)
    {
        log_msg("ERROR", "bind() failed: %d", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        free(command_line);
        return 1;
    }

    /* Start listening */
    if (listen(listen_sock, LISTEN_BACKLOG) == SOCKET_ERROR) {
        log_msg("ERROR", "listen() failed: %d", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        free(command_line);
        return 1;
    }

    log_msg("INFO", "Listening on 0.0.0.0:%d ...", host_port);
    log_msg("INFO", "Press Ctrl+C to stop.");
    log_msg("INFO",
            "Monitoring up to %d child processes in the main thread.",
            MAX_CHILD_PROCESSES);

    g_shutdown_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (g_shutdown_event == NULL) {
        log_msg("ERROR", "CreateEvent(shutdown) failed: %lu", GetLastError());
        exit_code = 1;
        goto cleanup;
    }

    if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        log_msg("ERROR", "SetConsoleCtrlHandler failed: %lu", GetLastError());
        exit_code = 1;
        goto cleanup;
    }

    listen_event = WSACreateEvent();
    if (listen_event == WSA_INVALID_EVENT) {
        log_msg("ERROR", "WSACreateEvent() failed: %d", WSAGetLastError());
        exit_code = 1;
        goto cleanup;
    }

    if (WSAEventSelect(listen_sock, listen_event, FD_ACCEPT) == SOCKET_ERROR) {
        log_msg("ERROR", "WSAEventSelect() failed: %d", WSAGetLastError());
        exit_code = 1;
        goto cleanup;
    }

    /* ----------------------------------------------------------------
     * Main event loop (single-threaded).
     * Wait on:
     *   1) shutdown event (Ctrl+C / console close)
     *   2) listening socket accept event
     *   3) child process handles
     *   4) client socket events (for disconnect detection)
     * ---------------------------------------------------------------- */
    while (1) {
        HANDLE wait_handles[MAXIMUM_WAIT_OBJECTS];
        DWORD wait_count = 0;
        DWORD wait_result;
        DWORD socket_events_start;
        DWORD socket_event_map[MAX_CHILD_PROCESSES];
        DWORD socket_event_count;

        prune_detached_sessions(&detached_sessions);

        wait_handles[wait_count++] = g_shutdown_event;
        wait_handles[wait_count++] = listen_event;

        for (i = 0; i < child_count; i++) {
            wait_handles[wait_count++] = children[i].process_handle;
        }

        socket_events_start = wait_count;
        socket_event_count = 0;
        for (i = 0; i < child_count; i++) {
            if (children[i].socket_event != WSA_INVALID_EVENT) {
                wait_handles[wait_count++] = children[i].socket_event;
                socket_event_map[socket_event_count++] = i;
            }
        }

        wait_result = WaitForMultipleObjects(wait_count,
                                             wait_handles,
                                             FALSE,
                                             INFINITE);
        if (wait_result == WAIT_FAILED) {
            log_msg("ERROR", "WaitForMultipleObjects failed: %lu",
                    GetLastError());
            exit_code = 1;
            break;
        }

        if (wait_result == WAIT_OBJECT_0) {
            log_msg("INFO", "Shutdown signal received. Stopping server.");
            break;
        }

        if (wait_result == WAIT_OBJECT_0 + 1) {
            WSANETWORKEVENTS network_events;

            if (WSAEnumNetworkEvents(listen_sock,
                                     listen_event,
                                     &network_events) == SOCKET_ERROR) {
                log_msg("WARN", "WSAEnumNetworkEvents() failed: %d",
                        WSAGetLastError());
                continue;
            }

            if ((network_events.lNetworkEvents & FD_ACCEPT) != 0) {
                if (network_events.iErrorCode[FD_ACCEPT_BIT] != 0) {
                    log_msg("WARN", "FD_ACCEPT reported error: %d",
                            network_events.iErrorCode[FD_ACCEPT_BIT]);
                } else {
                    accept_pending_connections(listen_sock,
                                               command_line,
                                               children,
                                               &child_count);
                }
            }
            continue;
        }

        if (wait_result >= WAIT_OBJECT_0 + 2 &&
            wait_result < WAIT_OBJECT_0 + socket_events_start) {
            DWORD child_index = wait_result - (WAIT_OBJECT_0 + 2);
            reap_child_process(children,
                               &child_count,
                               child_index,
                               &detached_sessions);
            continue;
        }

        if (wait_result >= WAIT_OBJECT_0 + socket_events_start &&
            wait_result < WAIT_OBJECT_0 + wait_count) {
            DWORD socket_event_index = wait_result - (WAIT_OBJECT_0 + socket_events_start);
            DWORD child_index = socket_event_map[socket_event_index];

            if (child_index < child_count) {
                WSANETWORKEVENTS network_events;
                if (WSAEnumNetworkEvents(children[child_index].client_socket,
                                         children[child_index].socket_event,
                                         &network_events) == SOCKET_ERROR) {
                    log_msg("WARN", "WSAEnumNetworkEvents() failed for client socket: %d",
                            WSAGetLastError());
                } else if ((network_events.lNetworkEvents & FD_CLOSE) != 0) {
                    note_client_disconnect(&children[child_index]);
                }
            }
            continue;
        }

        log_msg("WARN", "Unexpected wait result: %lu", wait_result);
    }

cleanup:
    for (i = 0; i < child_count; i++) {
        close_child_session_socket(&children[i]);

        if (children[i].session_job_handle != NULL) {
            CloseHandle(children[i].session_job_handle);
        }

        CloseHandle(children[i].process_handle);
    }

    close_detached_sessions(&detached_sessions);

    if (listen_event != WSA_INVALID_EVENT) {
        WSACloseEvent(listen_event);
    }

    if (listen_sock != INVALID_SOCKET) {
        closesocket(listen_sock);
    }

    if (g_shutdown_event != NULL) {
        CloseHandle(g_shutdown_event);
        g_shutdown_event = NULL;
    }

    SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
    WSACleanup();
    free(command_line);

    return exit_code;
}
