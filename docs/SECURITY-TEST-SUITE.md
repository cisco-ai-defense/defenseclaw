# Security and PII test suite

This is the contributor index for DefenseClaw's layered detection corpus. The
case schema, tier-specific fields, and corpus editing rules live with the data
in
[`internal/gateway/testdata/security_suite/README.md`](../internal/gateway/testdata/security_suite/README.md).

| Target | Scope |
| --- | --- |
| `make security-suite-test` | Deterministic trusted-tool-call, regex/rule, stubbed-judge, and severity benchmark tests |
| `go test ./internal/gateway -run '^TestGuardrailProfilesCELActionFactsCorpusMatrix$' -v` | Every shipped profile's exact typed `f` CEL expressions against every authoritative, projectable CEL-targeted tool-call case |
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

The compact `toolcall/corpus.jsonl` is the TP/FP acceptance set for structured
tool actions. It contains inert payloads only and asserts canonical owner
routing without duplicating low-level parser grammar tests.

`TestGuardrailProfilesCELActionFactsCorpusMatrix` discovers every shipped
profile, compiles each embedded expression without rewriting the typed `f`
activation, and evaluates the complete rule-by-case matrix through
`actionfacts.Analyze`, `semantic.Project`, and the bounded CEL evaluator.
Non-authoritative structured rows remain legacy-fallback cases, as they do in
production. Regex, judge, live-eval, and HTTP corpus rows carry text rather
than authenticated ActionFacts; the test inventories and reports them as
inapplicable instead of counting them as CEL coverage.
