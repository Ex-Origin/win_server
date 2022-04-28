# Win Server

`Win Server` can be used to debug windows program with `pwntools`, it's just like `xinetd` which redirects windows program to computer port.

## Usage

`win_server execve_file port [timeout(ms)]`

For example: 

```bash
D:\>win_server babystack.exe 10009
```

And you also can set timetout to 1 second.

```bash
D:\>win_server babystack.exe 10009 1000
```

## Principle

`Win server` runs the `do_child_work` as main thread at first, then creates two pipe for `stdout` and `stdin`, thirdly create child process, then creates two threads:

1. `input`: It recive buffer as `stdin` from remote socket with obstruction.
2. `output`: It send information which is from the stdout of program to remote socket with obstruction.

Finally, release resource.

Becase all funcions could be obstructed, so it is friendly to your `CPU`.

```
E:\test>win_server.exe LazyFragmentationHeap.exe 10009
2019-11-05 21:03:11  START: Ex  pid: 8400  from: 192.168.1.107:39098
2019-11-05 21:03:12  EXIT: Ex  ExitCode: 5678  pid: 8400  from: 192.168.1.107:39098  duration: 1(sec)
```

> The reason of exit code `1234` could be that the remote socket has closed connection, and `5678` could be timeout.

## Compile parameters

```bash
cl win_server.c /MT /GS /O2
```
