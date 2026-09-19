# gorc

A Go CLI for executing REST requests defined in `.http` files.

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

## Usage

```bash
gorc [flags] /absolute/or/relative/file.http
```

### Common flags

- `--all` execute every request in the file
- `--index 1,3` execute specific 1-based request indexes
- `--name "request name"` execute requests by name
- `--interactive` choose requests interactively
- `--config /path/to/gorc.json` load config defaults
- `--vars-file /path/to/vars.json` load variables from JSON
- `--var key=value` set CLI variables
- `--body-file /path/to/body.json` override the selected request body with a file
- `--output /path/to/response.out` save the selected response body
- `--proxy http://127.0.0.1:8080` use a proxy
- `--http-version auto|1|2|3` select the HTTP version
- `--insecure` skip TLS verification

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

{"username":"demo","password":"secret"}

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
# @insecure true
POST https://api.example.com/widgets
Content-Type: application/json
```

Supported auth directives:

```http
# @auth basic username={{user}} ******
# @auth bearer token={{token}}
# @auth digest username={{user}} ******
# @auth ntlm username={{domain_user}} ******
# @auth mtls cert=./certs/client.pem key=./certs/client-key.pem
# @auth azuread tenant_id={{tenant}} client_id={{client_id}} client_secret={{client_secret}} scope=https://management.azure.com/.default
```

For `basic`, `digest`, and `ntlm`, include both username and password values on the directive.

Azure AD also supports:

- `resource=...` to use the legacy token endpoint
- `token_url=...` to override the token endpoint
- `AZURE_ACCESS_TOKEN` to supply a bearer token directly

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
  "proxy": "http://127.0.0.1:8080",
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

- HTTP/2 uses Go's standard TLS negotiation.
- HTTP/3 requires HTTPS and does not currently support proxies in this CLI.
- Cookies are shared only within a single CLI run.
