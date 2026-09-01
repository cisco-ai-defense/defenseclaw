# Security and PII test suite

This is the contributor index for DefenseClaw's layered detection corpus. The
case schema, tier-specific fields, and corpus editing rules live with the data
in
[`internal/gateway/testdata/security_suite/README.md`](../internal/gateway/testdata/security_suite/README.md).

| Target | Scope |
| --- | --- |
| `make security-suite-test` | Deterministic trusted-tool-call, regex/rule, stubbed-judge, and severity benchmark tests |
| `go test ./internal/gateway -run '^TestGuardrailProfilesCELActionFactsCorpusMatrix$' -v` | Every shipped profile's exact typed `f` CEL and checked-AST-translated stock `input` CEL against every authoritative, projectable CEL-targeted tool-call case, with equivalent results and error classifications |
| `AGENTCEL_BIN=/path/to/agentcel go test ./internal/gateway -run '^TestGuardrailPortableCELAgentCELE2E$' -v` | Optional exhaustive process-boundary proof: AgentCEL loads all 147 translated `.cel` rule instances and reproduces their native results over all 180 applicable cases (26,460 evaluations); DefenseClaw does not import AgentCEL |
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
profile, compiles each embedded expression as its native typed `f` activation,
translates the admitted checked AST to canonical stock document CEL with
`input: dyn`, and evaluates both forms through `actionfacts.Analyze`,
`semantic.Project`, and their bounded CEL evaluators. The current gate covers
147 rule instances, 31 unique expressions, and 26,460 native/document
equivalence pairs over 180 authoritative, projectable cases. Its protobuf JSON
document uses snake-case names, emitted defaults and empty lists, canonical
enum strings, and lossless decimal strings for `int64`.
Non-authoritative structured rows remain legacy-fallback cases, as they do in
production. Regex, judge, live-eval, and HTTP corpus rows carry text rather
than authenticated ActionFacts; the test inventories and reports them as
inapplicable instead of counting them as CEL coverage.
