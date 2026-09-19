# Copilot instructions

- Keep the CLI implementation centered in `/home/runner/work/gorc/gorc/internal/gorc`.
- Prefer the standard library for CLI parsing, HTTP handling, config loading, and JSON processing.
- Treat `.http` files as the primary source of request definitions, using `###` as the request separator.
- Preserve support for request names, variable substitution, shared cookies, proxy configuration, and the documented authentication directives.
- Keep default CLI output quiet, and send optional diagnostic logging to stderr with leveled controls.
- Update `/home/runner/work/gorc/gorc/README.md` whenever user-facing CLI behavior changes.
