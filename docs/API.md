# Gateway API

The
[published gateway API reference](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/gateway-api/)
is the canonical consumer-facing endpoint guide.

For implementation review, route registration is in
[`../internal/gateway/api.go`](../internal/gateway/api.go), with focused
handlers in adjacent `api_*.go`, `*_endpoint.go`, inspection, hook, and OTLP
files. The route registrations and handler tests are authoritative when an
endpoint changes.

This pointer replaces a hand-maintained endpoint table that had fallen behind
the registered API surface.
