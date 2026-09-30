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

Older connector rollout records remain in git history. They are not
current support matrices.

## OpenClaw interception

OpenClaw is a proxy connector. For how DefenseClaw intercepts OpenClaw traffic and how to confirm coverage,
see the published [OpenClaw connector page](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/openclaw/).
