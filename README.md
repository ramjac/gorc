# gorc

A Go CLI for executing REST requests defined in `.http` files.

This project was a learning project using GPT-5.X coding assistants.

## Features

- Execute a single request from a `.http` file
- Execute selected requests or all requests from a multi-request `.http` file
- Use `###` to separate requests
- Support HTTP/1.1, HTTP/2, and HTTP/3
- Support HTTP and HTTPS
- Support Basic, Bearer, Digest, NTLM, mTLS, SSL CA certificates, and Azure AD client-credentials auth
- Load defaults from a JSON config file
- Resolve variables from the `.http` file, environment, config, JSON vars files, and CLI flags
- Reuse cookies across requests in the same run
- Support proxies
- Load request bodies from files
- Save response bodies to files
- Interactive request selection

## Build

```bash
go build ./...
```

## Test

```bash
go test ./...
```

## Examples

The repository includes a runnable demo in `examples/`.

- `examples/todoapi` contains a small in-memory Go todo API
- `examples/todo-demo.http` contains demo requests for the example API
- `examples/gorc-demo.json` contains matching `gorc` config defaults and variables

Start the demo API:

```bash
go run ./examples/todoapi
```

Then run the demo requests:

```bash
GORC_DEMO_AZURE_TENANT=todo-demo-tenant \
  go run ./cmd/gorc -c ./examples/gorc-demo.json ./examples/todo-demo.http --all
```

## Usage

```bash
gorc [flags] /absolute/or/relative/file.http
```

If no file is specified and the current directory contains exactly one `.http` file, `gorc` will use that file automatically.

### Common flags

- `--all`, `-a` execute every request in the file
- `--index`, `-x` execute specific 1-based request indexes, for example `-x 1,3`
- `--name`, `-n` execute requests by name
- `--interactive`, `-i` choose requests interactively
- `--config`, `-c` load config defaults
- `--vars-file`, `-e` load variables from JSON
- `--var`, `-v` set CLI variables
- `--body-file`, `-b` override the selected request body with a file
- `--output`, `-o` save selected response bodies, appending them in execution order when multiple requests run
- `--proxy`, `-p` use a proxy
- `--http-version`, `-H` select the HTTP version
- `--log-level`, `-l` control diagnostic logging on stderr
- `--no-color`, `-C` disable colored output
- `--self-signed-cert`, `-s` trust a specific self-signed server certificate
- `--insecure`, `-k` skip TLS verification

By default, `gorc` uses color for HTTP responses and diagnostic logging. Use `--no-color` or config `no_color: true` to disable it.

By default, `gorc` stays quiet and only prints HTTP request results to stdout. Diagnostic logging is opt-in and is written to stderr.

Each `gorc` invocation overwrites an existing output file on its first response, then appends later response bodies that target the same file.

If a request is interrupted with Ctrl+C or a similar termination signal, `gorc` cancels the in-flight work, prints `cancelled` to stderr, and exits with code `130`.

## `.http` format

### Single request

```http
@base = https://httpbin.org

GET {{base}}/get
Accept: application/json
```

### Multiple requests

```http
@base = https://httpbin.org

###
# @name login
POST {{base}}/anything/login
Content-Type: application/json

{"user":"demo","secret":"value"}

###
# @name me
GET {{base}}/anything/me
```

### Request directives

Directives are comments placed before a request:

```http
# @name create widget
# @auth bearer token={{api_token}}
# @body-file ./payload.json
# @output ./response.json
# @proxy http://127.0.0.1:8080
# @http-version 3
# @ca-cert ./certs/ca.pem
# @self-signed-cert ./certs/server.pem
# @insecure true
POST https://api.example.com/widgets
Content-Type: application/json
```

Use `# @insecure false` on an individual request to override an `insecure: true` config default.

Supported auth directives:

```http
# @auth basic {{user}} {{secret}}
# @auth bearer token={{token}}
# @auth digest {{user}} {{secret}}
# @auth ntlm {{domain_user}} {{secret}}
# @auth mtls cert=./certs/client.pem key=./certs/client-key.pem
# @auth mtls cert=./certs/client.pfx password={{certificate_password}}
# @auth azuread tenant_id={{tenant}} client_id={{client_id}} client_secret={{client_secret}} scope=https://management.azure.com/.default
# @auth none
```

The `mtls` authentication scheme accepts either a PEM certificate with a separate key, or a password-protected PKCS#12 `.pfx`/`.p12` certificate. Credentials can be supplied by the request directive or configuration. A configured client certificate is only ever sent when the effective auth scheme for a request is `mtls`; it is not attached to requests using any other scheme (including `none`).

For `basic`, `digest`, and `ntlm`, include both credentials after the scheme, with the username first. Values can use variables, for example `# @auth basic {{user}} {{secret}}`.

Use `# @auth none` on an individual request to disable an auth scheme configured at the CLI or config level, for example when a shared `.http` file mixes authenticated and public/unrelated endpoints.

When a request has an active auth scheme, gorc does not automatically follow redirect responses (3xx); the redirect response is returned as-is instead. This prevents credentials (Basic/digest/NTLM headers, bearer tokens, or an mTLS client certificate) from being forwarded to whatever server a redirect points at. Unauthenticated requests continue to follow redirects normally.

A custom `# @auth azuread` `token_url` must use `https://`; client_id/client_secret are posted in the request body and would otherwise be exposed in transit over plain HTTP.

Azure AD also supports:

- `resource=...` to use the legacy token endpoint
- `token_url=...` to override the token endpoint
- `token=...` to supply a bearer token directly, including values from `{{$env ...}}`

### Request body from file

You can either use `--body-file` or reference a body file in the request body:

```http
POST https://api.example.com/widgets
Content-Type: application/json

< ./payload.json
```

## Variables

Variables are resolved in this order:

1. CLI `--var`
2. request-local `.http` variables
3. shared `.http` file variables
4. `--vars-file` JSON values
5. config `vars`
6. environment variables

Examples:

```http
@base = {{$env API_BASE}}
@tenant = {{$config tenant}}
@token = {{$cli token}}

GET {{base}}/users/{{user_id}}
X-Tenant: {{tenant}}
```

Use `# @auth ...` directives when you want `gorc` to assemble authentication headers for you.

Explicit source selectors are also supported:

- `{{$env NAME}}`
- `{{$cli name}}`
- `{{$config name}}`
- `{{$file name}}`
- `{{$request name}}`

## Config file

`gorc` looks for config in this order:

1. `--config`
2. `GORC_CONFIG`
3. `.gorc.json`
4. `gorc.json`
5. `~/.config/gorc/config.json`

Example:

```json
{
  "http_version": "auto",
  "log_level": "debug",
  "no_color": false,
  "proxy": "http://127.0.0.1:8080",
  "self_signed_cert_file": "./certs/server.pem",
  "timeout": "30s",
  "vars": {
    "tenant": "example.onmicrosoft.com"
  },
  "auth": {
    "scheme": "bearer",
    "token": "{{api_token}}"
  }
}
```

## Notes

- `trace` logging includes low-level request lifecycle events such as connection acquisition, DNS lookup, connect/TLS milestones, and first-response-byte timing hooks exposed by Go's HTTP client.
- `debug` logging includes request selection, auth setup, transport choices, proxy usage, TLS material loading, and response-file writes.
- `info` logging includes request start and completion status lines.
- `error` logging includes transport and request failures.
- Response headings, status lines, headers, and log labels are colorized by default.
- HTTP/2 selection is strict in this CLI and currently requires an `https://` endpoint.
- A configured or directed self-signed certificate is added to the client trust store without disabling all TLS verification.
- HTTP/3 requires HTTPS and does not currently support proxies in this CLI.
- Cookies are shared only within a single CLI run.
