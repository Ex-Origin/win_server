# Win Server

A single-threaded Windows TCP server that spawns child processes for each incoming connection, with stdin/stdout/stderr redirected to the client socket.

Current version: `2.0.0`

## Features

- Listens on port `10000` by default, configurable via `-p`
- Spawns a child process for each connection
- Event-driven architecture using `WaitForMultipleObjects`
- Automatic client disconnect detection via `FD_CLOSE` events
- Job objects for reliable process cleanup
- Descendants can survive a child crash and still be cleaned up when `win_server.exe` exits
- Supports up to 31 concurrent connections

## Build

### MSVC
```bash
cl /O2 /MT win_server.c /Fewin_server.exe
```

### MinGW
```bash
gcc win_server.c -o win_server.exe -lws2_32
```

## Usage

```bash
win_server.exe [-p port] <program> [args...]
win_server.exe -v
win_server.exe --version
```

If `-p` is omitted, the server listens on port `10000`.

### Examples

```bash
# Show version
win_server.exe --version

# Run cmd.exe for each connection
win_server.exe cmd.exe

# Listen on port 12345
win_server.exe -p 12345 cmd.exe

# Run PowerShell
win_server.exe powershell.exe

# Run a custom script
win_server.exe python.exe script.py
```

## Architecture

### Event Loop

The server uses a single-threaded event loop that waits on:
1. Shutdown event (Ctrl+C)
2. Listen socket accept event
3. Child process handles (up to 31)
4. Client socket events (up to 31)

### Client Disconnect Handling

Each client socket has a dedicated `WSAEVENT` monitoring `FD_CLOSE`. When a client disconnects:
1. The event is signaled immediately
2. The child process is terminated via job object or `TerminateProcess`
3. Resources are cleaned up

Detached descendants are only retained when a child exits on its own. If the server tears down the session because the client disconnected, it still tries to terminate the whole session immediately.

### Limits

- Maximum concurrent connections: 31
- Reason: `WaitForMultipleObjects` supports up to 64 handles (2 fixed + 31 processes + 31 socket events)

## Implementation Details

- Uses WSA framework functions (`WSASocket`, `WSAAccept`, `WSAEventSelect`, etc.)
- Each connection gets a session job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
- If a child exits while descendants remain in its session job, the server keeps that job alive until server shutdown
- Non-blocking sockets for the server, blocking sockets inherited by children
- Graceful shutdown on console control signals

## Logging

The server outputs timestamped log messages in the format:
```
[YYYY-MM-DD HH:MM:SS][LEVEL] message
```

### Log Levels

- **INFO**: Normal operations (connection accepted, process started/exited)
- **WARN**: Non-fatal issues (client disconnect, API warnings)
- **ERROR**: Fatal errors (process crashes, system call failures)

### Process Exit Status

The server logs detailed exit status for child processes:

- **Normal exit (code 0)**: Process completed successfully
- **Client disconnect**: Process exited after client disconnected
- **Forced termination**: Process killed due to client disconnect (exit code `ERROR_BROKEN_PIPE`)
- **Console control signal**: Process stopped by Ctrl+C (exit code `0xC000013A`)
- **Detached session retention**: Descendants of an exited child can keep running until `win_server.exe` shuts down
- **Crash detection**: Recognizes common exception codes:
  - Access violations (`STATUS_ACCESS_VIOLATION`)
  - Stack overflow (`STATUS_STACK_OVERFLOW`)
  - Heap corruption (`STATUS_HEAP_CORRUPTION`)
  - Integer/float exceptions
  - CLR exceptions
  - And more (see `exception_code_name()` function)

### Example Log Output

```
[2026-04-01 02:10:15][INFO] Listening on 0.0.0.0:10000 ...
[2026-04-01 02:10:20][INFO] Accepted connection from 127.0.0.1:54321
[2026-04-01 02:10:20][INFO] Spawning child process: cmd.exe
[2026-04-01 02:10:20][INFO] Child process started (PID: 12345)
[2026-04-01 02:10:45][WARN] Client disconnected. Terminating child process immediately (PID: 12345)
[2026-04-01 02:10:45][WARN] Child process terminated after client disconnect (PID: 12345, exit code: 109)
```
