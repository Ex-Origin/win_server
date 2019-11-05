#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsock.h>
#include <io.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")
HANDLE global_heap;
SOCKET sockSrv;

#define MAGIC1 0x1A2A3A4A
#define MAGIC2 0x4A3A2A1A

struct Arguments
{
    DWORD magic1;
    DWORD padding1;
    struct sockaddr_in client;
    HANDLE stdout_read, stdin_write, stdout_write;
    char *execve_file;
    SOCKET conn;
    HANDLE process, self_handle;
    DWORD timeout;
    DWORD padding2;
    DWORD magic2;
};

DWORD WINAPI input_handle(LPVOID p)
{
    struct Arguments *local;
    char buf[0x1000];
    int nbytes;
    DWORD n, result;

    local = (struct Arguments *)p;
    while (1)
    {
        nbytes = recv(local->conn, buf, 0x1000, 0);
        if (nbytes <= 0)
        {
            TerminateProcess(local->process, 1234);
            return 0;
        }
        if (!WriteFile(local->stdin_write, buf, (DWORD)nbytes, &result, NULL))
        {
            memset(buf, 0, sizeof(buf));
            n = sprintf(buf, "WriteFile error. Error code: %d\n", GetLastError());
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, n, &result, NULL);
            ExitProcess(EXIT_FAILURE);
        }
    }
}

DWORD WINAPI output_handle(LPVOID p)
{
    struct Arguments *local;
    char buf[0x1000];
    int nbytes;

    local = (struct Arguments *)p;
    while (1)
    {
        ReadFile(local->stdout_read, buf, 0x1000, &nbytes, NULL);
        if (nbytes <= 0)
        {
            TerminateProcess(local->process, 1234);
            return 0;
        }
        nbytes = send(local->conn, buf, nbytes, 0);
        if (nbytes <= 0)
        {
            TerminateProcess(local->process, 1234);
            return 0;
        }
    }
}

BOOL WINAPI HandleCtrlCPress(DWORD dwCtrlType)
{
    if (dwCtrlType == CTRL_C_EVENT)
    {
        if (sockSrv)
        {
            closesocket(sockSrv);
        }
        ExitProcess(EXIT_SUCCESS);
    }
    else
    {
        return FALSE;
    }
}

DWORD WINAPI do_child_work(LPVOID p)
{
    struct Arguments *local;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE stdout_handle, thread_handle[2];
    DWORD result, nbytes, ExitCode, username_size;
    char buf[0x400], username[0x100];
    SYSTEMTIME sys_time;
    time_t local_time;
    HANDLE stdin_read, stdin_write, stdout_read, stdout_write, self_handle;
    SECURITY_ATTRIBUTES sa;

    local = (struct Arguments *)p;
    stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);

    sa.bInheritHandle = 1;
    sa.lpSecurityDescriptor = NULL;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    if (!CreatePipe(&stdin_read, &stdin_write, &sa, 0) || !CreatePipe(&stdout_read, &stdout_write, &sa, 0))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "CreatePipe error. Error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }
    GetStartupInfo(&si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = stdout_write;
    si.hStdError = stdout_write;
    si.hStdInput = stdin_read;

    if (!(local->magic1 == MAGIC1 && local->magic2 == MAGIC2))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "Magic error. Last error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    if (!CreateProcess(NULL, local->execve_file, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "CreateProcess error. Error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    local->stdout_read = stdout_read;
    local->stdin_write = stdin_write;
    local->stdout_write = stdout_write;
    local->process = pi.hProcess;

    thread_handle[0] = CreateThread(NULL, 0, input_handle, local, 0, NULL);
    thread_handle[1] = CreateThread(NULL, 0, output_handle, local, 0, NULL);

    memset(username, 0, sizeof(username));
    username_size = 0xf0;
    if (!GetUserName(username, &username_size))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "GetUserName error. Error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    memset(buf, 0, sizeof(buf));
    GetLocalTime(&sys_time);
    local_time = time(NULL);
    nbytes = sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d  START: %s  pid: %d  from: %s:%d\n",
                     sys_time.wYear, sys_time.wMonth, sys_time.wDay, sys_time.wHour, sys_time.wMinute, sys_time.wSecond,
                     username,
                     pi.dwProcessId,
                     inet_ntoa(local->client.sin_addr),
                     htons(local->client.sin_port));
    if (nbytes > sizeof(buf))
    {
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), "Stack overflow!\n", 16, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }
    WriteFile(stdout_handle, buf, nbytes, &result, NULL);

    if (WaitForSingleObject(pi.hProcess, local->timeout) == WAIT_TIMEOUT)
    {
        TerminateProcess(local->process, 5678);
    }
    GetExitCodeProcess(pi.hProcess, &ExitCode);

    memset(username, 0, sizeof(username));
    username_size = 0xf0;
    if (!GetUserName(username, &username_size))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "GetUserName error. Error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    if (!(local->magic1 == MAGIC1 && local->magic2 == MAGIC2))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "Magic error. Last error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    memset(buf, 0, sizeof(buf));
    GetLocalTime(&sys_time);
    nbytes = sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d  EXIT: %s  ExitCode: %d  pid: %d  from: %s:%d  duration: %d(sec)\n",
                     sys_time.wYear, sys_time.wMonth, sys_time.wDay, sys_time.wHour, sys_time.wMinute, sys_time.wSecond,
                     username,
                     ExitCode,
                     pi.dwProcessId,
                     inet_ntoa(local->client.sin_addr),
                     htons(local->client.sin_port),
                     time(NULL) - local_time);
    if (nbytes > sizeof(buf))
    {
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), "Stack overflow!\n", 16, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }
    WriteFile(stdout_handle, buf, nbytes, &result, NULL);

    if (closesocket(local->conn))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "closesocket error. Error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    if (!CloseHandle(stdin_write) || !CloseHandle(stdout_write) || !CloseHandle(stdin_read) || !CloseHandle(stdout_read))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "CloseHandle error. Error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    if (WaitForSingleObject(thread_handle[0], 100) == WAIT_TIMEOUT)
    {
        TerminateThread(thread_handle[0], 5678);
    }
    if (WaitForSingleObject(thread_handle[1], 100) == WAIT_TIMEOUT)
    {
        TerminateThread(thread_handle[0], 5678);
    }

    if (!CloseHandle(pi.hProcess) || !CloseHandle(pi.hThread) || !CloseHandle(thread_handle[0]) || !CloseHandle(thread_handle[1]))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "CloseHandle error. Error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    if (!(local->magic1 == MAGIC1 && local->magic2 == MAGIC2))
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "Magic error. Last error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    self_handle = local->self_handle;
    HeapFree(global_heap, HEAP_ZERO_MEMORY, local);
    if (self_handle)
    {
        if (!CloseHandle(self_handle))
        {
            memset(buf, 0, sizeof(buf));
            nbytes = sprintf(buf, "CloseHandle error. Error code: %d\n", GetLastError());
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
            ExitProcess(EXIT_FAILURE);
        }
    }
}

int main(int argc, char **args)
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err, len;
    SOCKET sockConn;
    SOCKADDR_IN addrSrv, addrClient;
    char *local_exeve_file, buf[0x100];
    DWORD nbytes, result, timeout;

    struct Arguments *child_work;

    if (argc < 3)
    {
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "Usage: server execve_file port [timeout(ms)]\n", 45, &result, NULL);
        return 0;
    }

    if (argc < 4)
    {
        timeout = INFINITE;
    }
    else
    {
        timeout = atoi(args[3]);
    }

    // set control + c handle
    SetConsoleCtrlHandler(HandleCtrlCPress, TRUE);
    local_exeve_file = args[1];

    global_heap = HeapCreate(0, 0, 0);
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        memset(buf, 0, sizeof(buf));
        nbytes = sprintf(buf, "WSAStartup error. Error code: %d\n", GetLastError());
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    sockSrv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    addrSrv.sin_family = AF_INET;
    addrSrv.sin_port = htons(atoi(args[2]));

    if (bind(sockSrv, (SOCKADDR *)&addrSrv, sizeof(SOCKADDR)) == SOCKET_ERROR)
    {
        memset(buf, 0, sizeof(buf));
        switch (GetLastError())
        {
        case 10048:
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), "The port is using by other program!\n", 36, &result, NULL);
            break;
        default:
            nbytes = sprintf(buf, "bind error. Error code: %d\n", GetLastError());
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, nbytes, &result, NULL);
            break;
        }
        ExitProcess(EXIT_FAILURE);
    }
    listen(sockSrv, 10);

    len = sizeof(SOCKADDR);

    while (1)
    {
        sockConn = accept(sockSrv, (SOCKADDR *)&addrClient, &len);

        child_work = HeapAlloc(global_heap, HEAP_ZERO_MEMORY, sizeof(struct Arguments));
        child_work->magic1 = MAGIC1;
        child_work->client = addrClient;
        child_work->execve_file = local_exeve_file;
        child_work->conn = sockConn;
        child_work->magic2 = MAGIC2;
        child_work->self_handle = 0;
        child_work->timeout = timeout;

        child_work->self_handle = CreateThread(NULL, 0, do_child_work, child_work, 0, NULL);
    }

    return 0;
}