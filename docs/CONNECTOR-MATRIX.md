# Connector compatibility

Current operator-facing support is maintained in the published
[connector compatibility matrix](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/)
and
[capability matrix](https://cisco-ai-defense.github.io/defenseclaw/docs/capability-matrix/).
Those pages distinguish supported, preview, unsupported, and platform-specific
surfaces without duplicating the matrix here.

For implementation review, the connector registry and versioned hook contracts
live under [`../internal/gateway/connector/`](../internal/gateway/connector/).
The executable documentation parity check is
[`../internal/gateway/connector/docs_capability_matrix_test.go`](../internal/gateway/connector/docs_capability_matrix_test.go),
and the Python setup contract is in
[`../cli/defenseclaw/connector_contracts.py`](../cli/defenseclaw/connector_contracts.py).

Historical connector rollout records remain in
[`PR141-MATRIX-UPDATE.md`](PR141-MATRIX-UPDATE.md),
[`CONNECTOR-COMMIT-SUMMARY.md`](CONNECTOR-COMMIT-SUMMARY.md), and
[`CONNECTOR-REMAINING-FIXES.md`](CONNECTOR-REMAINING-FIXES.md). They are not
current support matrices.

## By-design / version limitation

OpenClaw remains a proxy connector (`STATUS_NOT_GATED`): there is no hook
contract gate on `openclaw --version`. Releases ≥2026.6.8 changed provider
transport, so setup and doctor emit a transport advisory and require the
plugin self-test rather than treating `:4000` liveness as agent-path
coverage. Provider `base_url` injection is intentionally not used; a
single-provider rewrite is bypassed by switching models.
