# Security and PII test suite

This is the contributor index for DefenseClaw's layered detection corpus. The
case schema, tier-specific fields, and corpus editing rules live with the data
in
[`internal/gateway/testdata/security_suite/README.md`](../internal/gateway/testdata/security_suite/README.md).

| Target | Scope |
| --- | --- |
| `make security-suite-test` | Deterministic regex/rule, stubbed-judge, and severity benchmark tests |
| `make security-suite-eval` | Opt-in live-model evaluation; requires `DEFENSECLAW_LLM_KEY` |
| `go test ./internal/gateway/ -run TestSecuritySuiteE2E -v` | In-process HTTP inspect and audit path; `DEFENSECLAW_GATEWAY_URL` selects an external gateway |

The implementation runner is
[`internal/gateway/security_suite_test.go`](../internal/gateway/security_suite_test.go).
The broad live benchmark, its labeled corpora, and its fixed result snapshots
are under
[`internal/gateway/testdata/security_suite/eval_corpus/`](../internal/gateway/testdata/security_suite/eval_corpus/).

Generated `eval-*` rows in `regex/corpus.jsonl` must not be edited by hand.
Regenerate them with the gated
`TestGenerateRegexImportFromEvalCorpus` path documented in the corpus README.
The deterministic suite is also covered by `make gateway-test` and therefore
by `make test`.
