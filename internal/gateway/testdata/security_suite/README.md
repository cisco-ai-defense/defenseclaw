# Security + PII Coverage Suite

A single labeled corpus, split by the layer under test, replayed by
`internal/gateway/security_suite_test.go`. The split makes it explicit
whether a case is exercising the **regex/rule layer**, the **LLM-judge
layer**, or the **end-to-end HTTP** surface.

## Tiers

| Tier | Corpus | Go test | LLM? | CI |
|------|--------|---------|------|----|
| Regex / rule layer | `regex/corpus.jsonl`| `TestSecuritySuiteRegex` | No (deterministic) | Yes |
| LLM-judge layer (targeted) | `judge/corpus.jsonl` | `TestSecuritySuiteJudge` | Stubbed by default; live with `GUARDRAIL_BENCHMARK_LLM=1` | Yes (stubbed) |
| LLM-judge benchmark (broad) | `eval_corpus/{injection,pii,exfil,tool_injection}/corpus.jsonl` | `TestEval*` | Live only | No (opt-in) |
| End-to-end HTTP | `e2e/corpus.jsonl` | `TestSecuritySuiteE2E` | in-process (or external gateway) | Yes |

## Running

```sh
# deterministic tiers (regex + stubbed judge), no secrets:
go test ./internal/gateway/ -run 'TestSecuritySuite(Regex|Judge)' -v

# live judge scoring against a real model:
GUARDRAIL_BENCHMARK_LLM=1 DEFENSECLAW_LLM_KEY=... \
  go test ./internal/gateway/ -run TestSecuritySuiteJudge -v

# end-to-end (in-process by default; set DEFENSECLAW_GATEWAY_URL for an external gateway):
go test ./internal/gateway/ -run TestSecuritySuiteE2E -v
```

## Schema

Every row asserts a correct expected outcome. Severity comparisons use the
shared `severityRank`, so they are independent of action/profile/threshold
mapping.

Common contract fields (all tiers):

- `expected_severity_at_least` — attack must reach at least this tier.
- `forbidden_severity_at_least` — benign / false-positive guard must stay
  strictly below this tier.
- `must_include_findings_substr` — optional substrings every finding list
  must contain (e.g. a rule ID prefix).

### `regex/corpus.jsonl`

- `direction` — `prompt` | `completion` | `tool_call`.
- `tool_name` — optional, used by command-rule confidence tuning.
- `surfaces` — which regex entry points to replay:
  - `scan_all_rules` — the `ScanAllRules` engine shared by the connector
    hook and the `/api/v1/inspect/*` API.
  - `inspector` — `GuardrailInspector` in `regex_only` mode, shared by the
    proxy and sidecar.

`regex/corpus.jsonl` is a single file with two kinds of rows, distinguished
by the `id` prefix:

- **Curated, hand-authored** cases (any id, e.g. `secret/aws-access-key`).
- **Machine-generated** cases whose id starts with `eval-` — do not edit by
  hand.

Both kinds mix attacks and benign false-positive guards; the kind is per
row (`is_attack` plus `expected_severity_at_least` for attacks or
`forbidden_severity_at_least` for benign).

The `eval-` rows are built from the labeled `eval_corpus/` by
`TestGenerateRegexImportFromEvalCorpus` (gated by `SECURITY_SUITE_IMPORT=1`).
It mines the eval corpus for items the regex layer handles deterministically:
benign items the regex layer leaves clean become false-positive guards, and
attacks the regex layer already flags become regression locks. Semantic,
judge-only items are skipped and remain in the live benchmark below. The
generator preserves the curated rows and comment lines verbatim and rewrites
only the `eval-` rows. Regenerate with:

```sh
SECURITY_SUITE_IMPORT=1 go test ./internal/gateway/ -run TestGenerateRegexImportFromEvalCorpus -v
```

### `judge/corpus.jsonl`

- `kind` — `pii` | `injection` | `exfil` | `tool_injection`.
- `response` — scripted judge JSON returned by the mock provider in the
  deterministic tier (ignored in the live tier). The judge code path
  (parsing, suppressions, severity mapping) runs for real; only the model
  answer is fixed. Entities referenced in `response` should appear verbatim
  in `content` so the hallucination filter keeps them.

### `eval_corpus/`

The broad live-judge benchmark (160 labeled items each for injection, PII,
exfil, and tool-injection). These carry labels but no scripted model
output, so they are scored against a real model by `TestEval*` and
`make security-suite-eval`. They also seed the deterministic regex import
above. See `eval_corpus/README.md` for the scorecard details.

### `e2e/corpus.jsonl`

- `endpoint` — `request` | `response` | `tool-response`.
- `tool` — required for `tool-response`.

## Adding a case

Append a line to the relevant `corpus.jsonl`. No code change required.
Cases assert the desired behavior; if a case fails, that is a real
regression (or a desired behavior that is not yet implemented and should
land with its fix).
