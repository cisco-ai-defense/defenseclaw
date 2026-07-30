# Plan: allow private upstream IPs

**Status:** Completed.

The implementation delivered:

- explicit-IP configuration and environment inputs;
- validation that rejects CIDR, malformed, and non-exemptible addresses;
- shared preflight/dial enforcement with actual-peer observation;
- high-impact doctor reporting;
- Python registry-guard parity;
- startup and hot-reload replacement of allowlist state;
- egress audit evidence for an allowlisted peer; and
- Go/Python/schema/env-registry tests.

The verified design and source locations are in
[`design.md`](design.md), [`requirements.md`](requirements.md), and
[`tasks.md`](tasks.md). Operator syntax belongs in the published
[configuration](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/configuration/)
and
[environment-variable](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/env-vars/)
references.
