# Win Server Detailed Design

## 1. Overview

`win_server` is a single-threaded Windows TCP server that turns each accepted
client connection into a child process session. The accepted socket is
redirected to the child process as `stdin`, `stdout`, and `stderr`, so the
remote client interacts with the child process as if it were attached to a
console-like stream.

The implementation lives in [win_server.c](./win_server.c) and is intentionally
small: it relies on Winsock events, `WaitForMultipleObjects`, and Windows job
objects instead of worker threads or an I/O completion framework.

In short, the process model is:

1. Start a listening TCP socket.
2. Accept a client connection.
3. Spawn one child process for that connection.
4. Monitor both the child process handle and the client disconnect event.
5. Tear down the process session immediately if the client goes away.
6. Keep orphaned descendants alive only when the original child exits on its
   own and background descendants still remain.

## 2. Design Goals

The current design optimizes for the following goals:

- Keep the implementation easy to inspect and debug.
- Avoid creating extra threads for per-connection management.
- Ensure child processes do not outlive the server accidentally.
- Detect client disconnects promptly and reclaim resources quickly.
- Preserve background descendants only in the narrow case where the child
  exits naturally and leaves additional processes behind.

## 3. Non-Goals

The current implementation deliberately does not try to provide:

- High connection fan-out beyond the `WaitForMultipleObjects` handle limit.
- Asynchronous overlapped I/O for client traffic.
- A shell-escaping layer for rebuilding Windows command lines.
- Authentication, encryption, or access control.
- A protocol above the raw redirected byte stream.

## 4. Runtime Architecture

The server is built around one main event loop. It waits on four classes of
objects:

1. A shutdown event set by the console control handler.
2. A listening socket event used for `FD_ACCEPT`.
3. One process handle per active child.
4. One socket event per active child used for `FD_CLOSE`.

This leads directly to the maximum concurrency limit:

- `MAXIMUM_WAIT_OBJECTS` is 64 on Windows.
- Two entries are reserved for shutdown and listen events.
- Each child consumes two wait slots: one process handle and one socket event.
- Therefore `MAX_CHILD_PROCESSES = (64 - 2) / 2 = 31`.

The design favors predictability over scale. Every active session is visible in
one array, every wait target is rebuilt on each loop iteration, and all state
transitions happen in the main thread.

## 5. Main Data Structures

### `ChildProcess`

`ChildProcess` is the primary in-memory session record for active clients.

- `process_handle`: handle used to wait for child exit.
- `session_job_handle`: per-session job object used for cleanup.
- `client_socket`: server-side socket handle retained after spawn.
- `socket_event`: Winsock event that signals `FD_CLOSE`.
- `process_id`: child PID for logs and diagnostics.
- `client_disconnect_detected`: remembers that the remote side went away.
- `force_termination_requested`: remembers that the server intentionally killed
  the session.

### `DetachedSession`

`DetachedSession` tracks a job object whose original child has already exited
but which still contains descendant processes.

- `job_handle`: handle kept open so descendants remain alive.
- `child_process_id`: PID of the original child, used for logging context.

### `DetachedSessionList`

This is a dynamic array that stores detached sessions until they become empty
or the server shuts down.

## 6. Startup Flow

Server startup follows this order:

1. Parse arguments and optional `-p` port.
2. Build the target command line string from the remaining arguments.
3. Initialize Winsock with `WSAStartup`.
4. Create a listening socket with `WSASocketA`.
5. Mark the listening socket as non-inheritable.
6. Enable `SO_EXCLUSIVEADDRUSE` so a second process cannot bind the same port.
7. Bind to `0.0.0.0:<port>`.
8. Start listening.
9. Create the manual-reset shutdown event.
10. Register `SetConsoleCtrlHandler`.
11. Create a Winsock event for the listening socket and subscribe to
    `FD_ACCEPT`.

### Why `SO_EXCLUSIVEADDRUSE`?

On Windows, `SO_REUSEADDR` does not behave like the Unix-style "quick restart"
flag many developers expect. This server instead uses `SO_EXCLUSIVEADDRUSE` so
that accidental double-starts fail reliably.

## 7. Event Loop Design

The event loop in `main()` is the center of the design.

At the beginning of each iteration, the server:

1. Calls `prune_detached_sessions()` to close job handles whose descendant
   count has already dropped to zero.
2. Rebuilds the wait handle array from current active state.
3. Rebuilds a `socket_event_map[]` array so socket-event indexes can be mapped
   back to `children[]` entries.
4. Calls `WaitForMultipleObjects()`.

The result is then dispatched into one of four handlers:

- Shutdown event: break the loop and begin global cleanup.
- Listen event: drain all pending accepts via `accept_pending_connections()`.
- Child process handle: reap one child via `reap_child_process()`.
- Client socket event: decode Winsock events and trigger disconnect handling.

### Why rebuild the wait arrays every time?

`children[]` is compacted when a child exits. Rebuilding the arrays on each
iteration keeps the indexing logic simple and avoids stale slots.

### Why use a dedicated socket event per child?

The accepted socket is handed to the child for I/O, but the parent still needs
its own view of connection liveness. The per-child `FD_CLOSE` event gives the
server a prompt signal when the remote peer disconnects, even if the child is
blocked on I/O or not handling errors itself.

## 8. Accept Path

The listen socket is associated with a Winsock event for `FD_ACCEPT`. When that
event is signaled, the server calls `accept_pending_connections()` and loops on
`WSAAccept()` until it reaches `WSAEWOULDBLOCK`.

This "drain until empty" pattern prevents the server from leaving queued
connections unaccepted after receiving only one readiness notification.

For each accepted socket, the server:

1. Logs the client address if possible.
2. Rejects the connection if `child_count` has reached 31.
3. Resets the accepted socket into blocking mode for child-side stdio use.
4. Spawns the child process.
5. Stores the session in `children[]`.

### Connection Rejection Path

When the server is full, it still tries to be polite:

1. Restore the accepted socket to blocking mode.
2. Send a short rejection message.
3. Close the socket.

This avoids silent drops and keeps the overload behavior explicit.

## 9. Child Spawn Pipeline

`spawn_child()` contains the most important lifecycle logic in the program.

The sequence is:

1. Duplicate the command line into a writable buffer because `CreateProcessA`
   may modify it in place.
2. Mark the accepted socket handle as inheritable.
3. Create a per-session job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
4. Prepare `STARTUPINFOA` so `stdin`, `stdout`, and `stderr` all point to the
   accepted socket handle.
5. Create the process in the suspended state with `CREATE_SUSPENDED`.
6. Clear the inherit flag on the parent's socket handle.
7. Assign the child process to the job object.
8. Resume the child thread.
9. Create a Winsock event for this client socket.
10. Subscribe the parent-side socket handle to `FD_CLOSE`.
11. Publish the populated `ChildProcess` record.

### Why create the process suspended first?

Creating the child suspended closes an important race. It allows the server to
assign the child to the session job object before user code starts running, so
the process cannot briefly escape job membership during startup.

### Why keep the parent socket handle open?

The child inherits its own standard-handle reference to the socket. The parent
retains another reference so it can detect `FD_CLOSE`, shut the socket down,
and force session cleanup when the client disappears.

## 10. Socket Mode Handling

The listening socket is switched into event-driven mode with `WSAEventSelect()`
for `FD_ACCEPT`, which implies non-blocking semantics. Accepted sockets inherit
state that is not suitable for child stdio usage, so the server explicitly
restores blocking mode in `make_socket_blocking_for_child()`.

That helper performs two actions:

1. Clears any event association with `WSAEventSelect(client_sock, NULL, 0)`.
2. Resets `FIONBIO` to blocking mode with `ioctlsocket()`.

Later, once the child is running, the parent associates the same socket handle
with a dedicated event again, but only for `FD_CLOSE` monitoring.

## 11. Disconnect Handling

Client disconnects are handled by `note_client_disconnect()`.

When a child's socket event reports `FD_CLOSE`, the server:

1. Marks `client_disconnect_detected = TRUE`.
2. Logs that the client disconnected.
3. Calls `shutdown(..., SD_BOTH)` when possible.
4. Closes the parent-side socket and socket event.
5. Forces termination of the child session.

The actual kill operation is performed by `force_terminate_child()`:

- First choice: `TerminateJobObject(session_job_handle, ERROR_BROKEN_PIPE)`.
- Fallback: `TerminateProcess(process_handle, ERROR_BROKEN_PIPE)`.

Using the job object first makes sure the entire process tree is terminated
instead of only the original child.

## 12. Child Reaping and Exit Classification

When a process handle becomes signaled, `reap_child_process()` performs the
post-exit workflow:

1. Log the exit status.
2. Close the session's parent-side socket and socket event.
3. Decide what to do with the session job object.
4. Close the process handle.
5. Compact the `children[]` array.

### Exit Status Logging

`log_child_exit_status()` classifies exits into several categories:

- Normal exit.
- Exit after client disconnect.
- Forced termination after disconnect.
- Console-control termination (`0xC000013A`).
- Known crash signatures such as access violations or stack overflows.
- Generic abnormal NTSTATUS values.
- Other non-zero exit codes.

This is mainly an observability feature, but it also encodes the server's
mental model of "expected" versus "suspicious" child termination.

## 13. Detached Session Retention

One subtle feature of the design is the detached-session mechanism.

If the original child exits on its own, the server does not immediately close
the session job handle. Instead, `release_child_session_job()` queries the job
object's active-process count.

The outcomes are:

- `force_termination_requested == TRUE`: close the job immediately, which kills
  anything still in it.
- Active process count is zero: close the job immediately.
- Active process count is non-zero: move the job handle into
  `DetachedSessionList` so descendants remain alive.

This supports scenarios where the launched child intentionally starts a helper
or worker process and then exits. Those descendants are still bounded by the
job object and will be cleaned up when:

- the descendants themselves eventually exit, or
- `win_server.exe` shuts down and closes all retained job handles.

### Why only preserve descendants after natural child exit?

The implementation draws a strict distinction between:

- child exited on its own: background descendants may be intentional;
- client disconnected or server forced teardown: the whole session should die
  immediately.

That policy reduces the chance of leaving behind stray background processes
after broken client sessions.

## 14. Shutdown Sequence

Shutdown is triggered by the console control handler setting
`g_shutdown_event`. The main loop then exits and enters the shared cleanup
block.

Cleanup order is:

1. Close each active child's socket event and client socket.
2. Close each active child's session job handle.
3. Close each active child's process handle.
4. Close all detached session job handles.
5. Close the listen event.
6. Close the listen socket.
7. Close the shutdown event.
8. Unregister the console control handler.
9. Call `WSACleanup()`.
10. Free the command line buffer.

Because session jobs use `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, closing those
handles is enough to kill remaining in-job descendants during shutdown.

## 15. Error Handling Strategy

The implementation uses a pragmatic error model:

- Fatal startup failures abort the program with a non-zero exit code.
- Per-connection failures are logged and isolated to the affected client.
- Cleanup paths prefer best-effort behavior over attempting deep recovery.
- Warnings are emitted when the preferred cleanup path fails and the server
  falls back to a weaker mechanism.

This is visible in several places:

- Failing to create or assign a job object does not block child startup; the
  server falls back to direct process termination.
- Failing to classify an address string still allows the connection.
- Failing to prune a detached session leaves it retained until a later pass.

## 16. Logging Design

Logging is intentionally simple:

- Timestamped local time.
- `INFO`, `WARN`, and `ERROR` levels.
- `ERROR` goes to `stderr`; other levels go to `stdout`.

The logger is synchronous and line-oriented, which matches the single-threaded
design and keeps log ordering easy to follow.

## 17. Known Tradeoffs and Limitations

The implementation is intentionally conservative, but a few tradeoffs are worth
calling out explicitly.

### Handle-limit scalability

The 31-session cap is a direct result of using one wait call over process and
socket event handles. Moving beyond that would require a different concurrency
model such as thread pools, multiple wait sets, or I/O completion ports.

### Command line reconstruction

`build_command_line()` simply joins arguments with spaces. It does not perform
full Windows quoting and escaping. In practice, callers should provide
arguments in a form that `CreateProcessA` will parse correctly.

### Process-centric cleanup

The server is excellent at lifecycle control, but it is not a shell protocol.
It treats the network connection as a raw byte stream and delegates all
higher-level semantics to the child process.

### Windows-only design

The implementation intentionally uses Windows-specific APIs such as Winsock
events, console control handlers, and job objects. Portability is not a goal.

## 18. Why This Design Works Well for This Project

For a small, inspectable Windows utility, this design hits a useful balance:

- small enough to understand in one source file,
- strict enough to avoid orphan process leaks,
- responsive enough to react quickly to disconnects,
- flexible enough to let intentional descendants survive until server shutdown.

That makes it a good fit for remote command execution, test harnesses, and
other controlled environments where operational predictability matters more
than very high connection counts.
