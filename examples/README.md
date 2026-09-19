# Examples

This directory contains a small Go todo API and matching `gorc` request assets for demo purposes.

## Start the demo API

From the repository root:

```bash
go run ./examples/todoapi
```

The demo API starts three HTTPS listeners:

- `https://127.0.0.1:9443` - self-signed certificate
- `https://127.0.0.1:9444` - certificate signed by the demo CA
- `https://127.0.0.1:9445` - certificate signed by the demo CA and requiring an mTLS client certificate

On first run the server generates the demo certificates in `examples/todoapi/generated/`.

## Run the demo requests

From the repository root:

```bash
go run ./cmd/gorc -c ./examples/gorc-demo.json ./examples/todo-demo.http --all
```

You can also run just one request by name, for example:

```bash
go run ./cmd/gorc -c ./examples/gorc-demo.json ./examples/todo-demo.http --name ntlm todos
```

The demo request file exercises:

- self-signed server trust
- CA certificate trust
- basic auth
- bearer auth
- digest auth
- Azure AD-style client credentials
- mTLS client certificate auth
- request body and response output helpers

The example API source also includes an NTLM-protected route, but the bundled `.http` demo focuses on the flows that run end-to-end with the lightweight local server setup.
