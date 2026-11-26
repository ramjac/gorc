# Copilot instructions

- Keep the CLI implementation centered in `internal/app`.
- Use the established `go.mod` dependencies rather than adding new ones: `spf13/cobra` for CLI parsing, `spf13/viper` with `go-viper/mapstructure/v2` for config loading, the standard library `net/http` for HTTP handling, and the standard library `encoding/json` for JSON processing.
- Treat `.http` files as the primary source of request definitions, using `###` as the request separator.
- Preserve support for request names, variable substitution, shared cookies, proxy configuration, and the documented authentication directives.
- Keep default CLI output quiet, and send optional diagnostic logging to stderr with leveled controls.
- Keep colorized response/log output enabled by default, with a documented config and flag to disable it.
- Follow Effective Go basics: use clear, descriptive names; prefer small focused helpers over repeated boilerplate; prefer standard library helpers over hand-rolled logic; keep package APIs narrow; avoid unnecessary abstraction; and refactor duplicated formatting or option logic into a single source of truth.
- Update `README.md` whenever user-facing CLI behavior changes.
