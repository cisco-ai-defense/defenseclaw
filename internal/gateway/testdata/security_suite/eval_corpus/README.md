# Judge Evaluation Corpus

This is the **broad live-judge tier** of the security + PII suite (see
[`../README.md`](../README.md) and
[`docs/SECURITY-TEST-SUITE.md`](../../../../../docs/SECURITY-TEST-SUITE.md)).
It is a labeled benchmark scored against a real model; its items also seed
the deterministic regex tier (the generated block of `../regex/corpus.jsonl`).

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

Two complementary rates are reported (see the metric note below):
**Detection** = attack flagged at any tier (`>NONE`); **Block** = attack
flagged at the blocking tier (`>=HIGH`). The gap is attacks the judge
detects but correctly rates LOW (e.g. an IP or an email in a prompt).

| Judge | Detection (>NONE) | Block (>=HIGH) | FPR | Precision |
|:------|------------------:|---------------:|----:|----------:|
| Injection | 90.0% | 90.0% | 0.0% | 100.0% |
| PII | **95.0%** | 76.7% | 0.0% | 100.0% |
| **Exfil** | **100.0%** | **100.0%** | 7.5% | 97.6% |
| Tool-injection | 90.0% | 90.0% | 0.0% | 100.0% |

Zero false positives across injection, PII, and tool-injection; 7.5% on
exfil (all at HIGH, not CRITICAL). PII detects 95% of attacks; the 18-point
block-rate gap is entirely context-dependent PII the judge correctly rates
LOW, not missed detections.

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

- **Detection rate (>NONE)** — % of attack items the judge flagged at any tier above NONE ("did we catch it at all")
- **Block rate (>=HIGH)** — % of attack items the judge returned at severity ≥ HIGH ("did we block it"); the two differ only where a judge has a LOW tier (PII)
- **FPR (False Positive Rate)** — % of benign items where the judge returned severity ≥ HIGH
- **Weighted FPR** — same FPs weighted by predicted tier (CRITICAL FP = 4× cost of MEDIUM FP)
- **Precision / F1** — standard binary-classifier metrics
- **Tier-miss / over-fire histograms** — how far each attack's predicted severity landed from expected
- **Confusion matrix** — truth tier × predicted tier
- **Per-category recall + precision** — accuracy per attack category (e.g. `Instruction Manipulation`, `SSN`, `Sensitive File Access`)

