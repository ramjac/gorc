# Copilot instructions

- Keep the CLI implementation centered in `/home/runner/work/gorc/gorc/internal/app`.
- Prefer the standard library for CLI parsing, HTTP handling, config loading, and JSON processing.
- Treat `.http` files as the primary source of request definitions, using `###` as the request separator.
- Preserve support for request names, variable substitution, shared cookies, proxy configuration, and the documented authentication directives.
- Keep default CLI output quiet, and send optional diagnostic logging to stderr with leveled controls.
- Keep colorized response/log output enabled by default, with a documented config and flag to disable it.
- Follow Effective Go basics: use clear, descriptive names; prefer small focused helpers over repeated boilerplate; prefer standard library helpers over hand-rolled logic; keep package APIs narrow; avoid unnecessary abstraction; and refactor duplicated formatting or option logic into a single source of truth.
- Update `/home/runner/work/gorc/gorc/README.md` whenever user-facing CLI behavior changes.
