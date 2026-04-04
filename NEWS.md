# News

## 2.0.0 - 2026-04-04

- Rewrite the server around a single-threaded event loop built on `WaitForMultipleObjects`.
- Add configurable listen port support with `-p`, while keeping the default port at `10000`.
- Detect client disconnects via `FD_CLOSE` and terminate the related child process or job promptly.
- Use job objects for more reliable cleanup, while allowing detached descendants to remain alive until server shutdown when appropriate.
- Expand logging with timestamps, clearer exit-state reporting, and common Windows exception/crash names.
- Add explicit version metadata plus `-v` and `--version` output.
- Refresh the project documentation and usage examples.

## 2019-11-05

- Fix a possible use-after-free issue.
- Release resources that were previously leaked.
- Use Windows APIs more directly for better performance.
- Fix incorrect logging information.
