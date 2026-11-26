# AGENTS.md

## Overview

`gorc` is a Go CLI that executes REST requests defined in `.http` files (Insomnia/REST-client style: `###`-separated requests, `# @directive` metadata, `{{var}}` placeholders). It is a single Go module (`github.com/ramjac/gorc`, Go 1.24.0). Essentially all CLI code lives in one package, `internal/app`; `cmd/gorc/main.go` is a thin wrapper that just calls `app.Run`. `examples/todoapi` is a separate `package main` demo API (self-signed, CA-signed, and mTLS HTTPS listeners plus an NTLM route) used for manual/demo testing; it is not imported by the CLI.

## Commands

There is no Makefile, no linter config (no golangci-lint), and no `go generate` usage. CI (`.github/workflows/ci.yml`) is the whole gate:

```sh
go build ./...
go vet ./...
go test ./...
```

Versioned build (what the release workflow does, plus `CGO_ENABLED=0 -trimpath -ldflags "-s -w"`):

```sh
go build -ldflags "-X github.com/ramjac/gorc/internal/app.Version=vX.Y.Z" ./cmd/gorc
```

`internal/app.Version` defaults to `"dev"` and is injected only via ldflags.

Demo flow (see `examples/README.md`):

```sh
go run ./examples/todoapi   # first run generates certs into examples/todoapi/generated/ (gitignored)
GORC_DEMO_AZURE_TENANT=todo-demo-tenant go run ./cmd/gorc -c ./examples/gorc-demo.json ./examples/todo-demo.http --all
```

## Architecture

Control flow: `cmd/gorc/main.go` -> `app.Run(args, stdout, stderr) int` (`internal/app/cli.go`) -> cobra parse (`cliParser`) -> `run()` (parse `.http` file, load config/vars, select requests) -> `executeRequests([]executionPlan)` -> per-request `executeRequest` -> `resolveRequest` (variable resolution, path resolution, auth merging, precedence) -> `buildTransport` -> send -> `writeResponse` (text mode) or accumulation into `jsonDocument` (JSON mode, printed on exit).

File map of `internal/app`:

| File | Responsibility |
|---|---|
| `cli.go` | cobra command tree, `Run`/`runWithContext` (exit codes), `parseRunOptions` (pure flag parsing, used by tests), request selection (`--all`/`--index`/`--name`), interactive mode, implicit `.http` discovery in CWD (`discoverImplicitHTTPFile`) |
| `parser.go` | `.http` file parser: `###` splitting, preamble/headers/body state machine, `@directive` handling, `@var` assignments |
| `vars.go` | `{{var}}` resolution with selectors and pass cap |
| `config.go` | config discovery (viper), mapstructure unmarshal, `--vars-file` loading (flat JSON, values stringified) |
| `client.go` | the core (~1300 lines): request execution, cookie jar, output files, transport building (HTTP/1/2/3, proxies), auth (basic, bearer, digest, NTLM, mTLS), response rendering |
| `types.go` | `RequestSpec`, `AuthConfig`, `Config`, `RuntimeConfig`, `executionPlan` |
| `logger.go` | leveled stderr logger (`none` < `error` < `info` < `debug` < `trace`), colored level labels |
| `color.go` | colorization helpers; on by default |

Key types: `RequestSpec` (parsed single request), `Config` (loaded config file), `RuntimeConfig` (merged runtime view passed around), `executionPlan` (one parsed request + its resolved context, element of the slice handed to `executeRequests`).

## Conventions & invariants

These are deliberate behaviors; preserve them when changing nearby code.

- **Exit codes** (owned by `runWithContext` in `cli.go`): `0` ok, `1` generic error, `2` usage error, `130` cancellation (prints `cancelled` to stderr). `Run` uses `signal.NotifyContext`; don't scatter `os.Exit` elsewhere.
- **Relative paths resolve against the `.http` file's directory, not CWD**: `RuntimeConfig.RootDir` is set to `filepath.Dir(mustAbs(options.FilePath))` (`cli.go:283`). Relative `@body-file`, `@output`, and cert paths resolve against it. Tests must set `RootDir` explicitly (typically `t.TempDir()`).
- **Variable precedence** (in `vars.go`): CLI `--var` > request-local `@vars` > file-wide `@vars` (the first `###` section's vars become file-wide, later sections' vars are request-local — see `parser.go`) > `--vars-file` > config `vars` > environment (exact name first, then `UPPER_SNAKE`). Explicit selectors `$env`, `$cli`, `$config`, `$file`, `$request` bypass the chain. Unresolved `{{var}}` is a hard error; nested expansion is capped at 10 passes.
- **Config discovery order**: `--config` flag > `GORC_CONFIG` env var > `.gorc.json` > `gorc.json` > `~/.config/gorc/config.json`. The config struct unmarshals via mapstructure tags (viper `TagName = "mapstructure"`), and `Config.Vars` is always non-nil after load.
- **`InsecureSet` tri-state pattern** (`types.go:26-27`): `RequestSpec` has both `Insecure` and `InsecureSet` so a per-request `# @insecure false` directive can override an `insecure: true` config default. Follow this two-field pattern if you add similar tri-state settings.
- **Auth active ⇒ redirects suppressed**: whenever any auth scheme is active, `CheckRedirect` returns `http.ErrUseLastResponse` (`client.go:253-267`) so credentials are never forwarded to redirect targets (rationale: mTLS, digest, and NTLM credentials must not leak to another host). This is a security decision, not a bug — do not "fix" it.
- **Cookie jar is per-run** and built with the public-suffix list (`newCookieJar`, `client.go:401`) to prevent cross-host cookie leakage within one run. `executeRequests` shares the jar (and output-file state) across all plans from `plans[0]`, stops on the first error, and only prints a summary when there is more than one plan.
- **Output files: first write overwrites, subsequent writes to the same path in the same run append** (`outputFileState`, `client.go:409`).
- **Response body preview is capped at 1 MiB** (`maxResponsePreviewSize = 1 << 20`, `client.go:441`); the rest is drained. Binary bodies are omitted entirely (`body_omitted` in JSON output). In JSON format, `body` is a raw string and is never parsed as JSON.
- **Path/proxy precedence** (helpers `chooseResolvedValue`/`chooseResolvedPath` in `client.go`): proxy: request directive > CLI > config; self-signed cert: CLI > request > config; CA cert: request directive > auth-level > config.
- **HTTP version constraints**: `strict` HTTP/2 requires `https://` and accepts only `http://` proxies (via a hand-rolled CONNECT dialer, `http2ProxyDialer`); HTTP/3 (quic-go) rejects any proxy; `auto` uses the HTTP/1 transport with `ForceAttemptHTTP2` + `ProxyFromEnvironment` (unless an explicit proxy is set), and HTTP/1 blanks `TLSNextProto`.
- **mTLS client cert is attached only when the effective scheme is `mtls`**, not merely because a cert was configured.
- **Color is on by default**; `--no-color` flag or config `no_color` disables it; JSON-format output never contains ANSI.
- **`--interactive` conflicts with `--all`/`--index`/`--name`**; in JSON mode, prompts go to stderr and the single accumulated JSON document is emitted to stdout on quit.
- **Implicit file selection**: with no explicit file, a unique `.http` file in CWD is picked automatically (`discoverImplicitHTTPFile`, `cli.go:210`).

## Testing

- Standard library only, no network, no external fixtures. The dominant pattern (`client_test.go`, e.g. `TestExecuteRequestsUsesCookiesAndBasicAuth` at `client_test.go:27`): spin up `httptest.NewServer`, use `t.TempDir()`, construct `RuntimeConfig` and `[]executionPlan` directly (setting `RootDir`), call `executeRequests` with a `strings.Builder` as stdout, assert on the builder and returned results.
- Use `t.Setenv` for environment variables.
- For pure flag-parsing tests, use `parseRunOptions` (`cli.go:88`), which parses without executing (writers are `io.Discard`).
- `examples/todoapi` has its own tests (`server_test.go`, `certs_test.go`) covering the demo API including its NTLM route; they run as part of `go test ./...`.

## Gotchas

- **`.github/copilot-instructions.md` overlaps with this file.** It covers the same ground: keep CLI code in `internal/app`, treat `.http` with `###` separators as the primary input, and update `README.md` whenever user-facing CLI behavior changes (this last one is a real obligation). It also pins the dependency policy: `spf13/cobra` for CLI parsing, `spf13/viper` + `go-viper/mapstructure/v2` for config loading, standard library for HTTP and JSON — do not introduce new third-party dependencies for those concerns. If the two documents ever drift, treat `README.md` + the code as ground truth.
- **`jsthtlf/go-ntlm` in `go.mod` is not vestigial** — it is used only by the demo API (`examples/todoapi/server.go`, `server_test.go`). The CLI's NTLM *client* uses `Azure/go-ntlmssp`. Don't drop it from `go.mod`.
- `gopls` reports info-level hints (e.g. unused `(*outputFileState).write` in `client.go`, `newBody` in `client.go`, modernization hints in `parser.go`) but `go vet` and CI are clean; those hints are not part of the gate.
- Keep README in sync: it is the canonical user-facing reference (flags table, `.http` format, directives, auth schemes, variable resolution order, config discovery, JSON output contract). Documented behavior is a contract — changing it means updating the README in the same change.
