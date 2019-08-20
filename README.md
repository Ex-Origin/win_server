# Win Server

`Win Server` can be used to debug windows program with `pwntools`, it's just like `xinted` which redirects windows program to computer port.

## Usage

`win_server execve_file port`

For example: 
```bash
D:\>win_server babystack.exe 1000
```

## Principle

`Win server` runs the `execve file` as child process at first, then creates two pipe for `stdout` and `stdin`, finally creates three threads:

1. `input`: It recive buffer as `stdin` from remote socket with obstruction.
2. `output`: It send information which is from the stdout of program to remote socket with obstruction.
3. `end`: When the program is over or the socket is closed, the function will release resource. And it also will be obstructed.

Becase all funcions could be obstructed, so it is friendly to your `CPU`.

```
D:\>server.exe babystack.exe 1001
Connect 192.168.3.1
sockConn is 276
Process 328 is runing
Process 328 is end with code 1234
```

> The reason of exit code `1234` could be that the remote socket has closed connection.