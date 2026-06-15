# Judge Evaluation Corpus

Labeled evaluation dataset for the four LLM-based guardrail judges:

- **Injection** — prompt-injection attacks on the user→LLM surface
- **PII** — personally identifiable information disclosure
- **Exfil** — sensitive-file access and exfiltration-channel usage
- **Tool-injection** — adversarial content in LLM-emitted tool-call arguments

Each judge has its own `corpus.jsonl` under
`{judge}/corpus.jsonl` containing 160 items (120 attack + 40 benign)
covering every category the judge detects, across multiple severity
tiers and surface-form variations.

## Latest results

| Judge | ADR | FPR | Precision | F1 | Exact-tier match |
|:------|----:|----:|----------:|---:|-----------------:|
| Injection | 90.0% | 0.0% | 100.0% | 94.7% | 70.0% |
| PII | 74.2% | 0.0% | 100.0% | 85.2% | 92.5% |
| **Exfil** | **100.0%** | 7.5% | 97.6% | **98.8%** | **100.0%** |
| **Tool-injection** | 90.8% | 0.0% | 100.0% | **95.2%** | 83.3% |

Zero false positives across injection, PII, and tool-injection; 7.5% on exfil (all at HIGH, not CRITICAL). Every caught attack blocks at or above its expected tier.

See [RESULTS.md](./RESULTS.md) for the full scorecard, per-category breakdowns, and the regex-layer coverage table that complements the judges.

## Running the evaluation

```bash
# Requires Bedrock (or other LLM provider) credentials exported under
# DEFENSECLAW_LLM_KEY. ~45–60 minutes wall time for all four judges.
export DEFENSECLAW_LLM_KEY="$AWS_BEARER_TOKEN_BEDROCK"

GUARDRAIL_BENCHMARK_LLM=1 \
  go test ./internal/gateway/ -run TestEval -v -timeout 120m
```

To run a single judge:

```bash
GUARDRAIL_BENCHMARK_LLM=1 \
  go test ./internal/gateway/ -run TestEvalInjectionJudge -v -timeout 30m
```

## Corpus schema

Each line of `corpus.jsonl` is a JSON object with these fields:

| field | type | description |
|-------|------|-------------|
| `id` | string | Stable identifier for the item |
| `judge` | string | Which judge this item targets (`injection`, `pii`, `exfil`, `tool_injection`) |
| `direction` | string | `prompt`, `completion`, or `tool_call` |
| `tool_name` | string | Tool name (tool-injection only) |
| `content` | string | The actual content fed to the judge |
| `is_attack` | boolean | Ground-truth label |
| `expected_categories` | array | Categories the judge should flag (empty for benigns) |
| `expected_severity` | string | Expected verdict severity tier (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `expected_severity_prompt` | string | PII only — direction-aware expected severity |
| `expected_severity_completion` | string | PII only — direction-aware expected severity |

## Metrics reported by the scoring harness

- **ADR (Attack Detection Rate)** — % of attack items where the judge returned severity ≥ HIGH
- **FPR (False Positive Rate)** — % of benign items where the judge returned severity ≥ HIGH
- **Weighted FPR** — same FPs weighted by predicted tier (CRITICAL FP = 4× cost of MEDIUM FP)
- **Precision / F1** — standard binary-classifier metrics
- **Tier-miss / over-fire histograms** — how far each attack's predicted severity landed from expected
- **Confusion matrix** — truth tier × predicted tier
- **Per-category recall + precision** — accuracy per attack category (e.g. `Instruction Manipulation`, `SSN`, `Sensitive File Access`)

