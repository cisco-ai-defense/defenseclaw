# Security + PII Test Suite

A unified, labeled coverage suite for DefenseClaw's detection logic. It is
split by the layer under test so every result makes clear **whether the
regex/rule layer, the LLM-judge layer, or the end-to-end HTTP surface** is
being exercised.

Corpus and runner live under
[`internal/gateway/testdata/security_suite/`](../internal/gateway/testdata/security_suite/)
and [`internal/gateway/security_suite_test.go`](../internal/gateway/security_suite_test.go).

## Tiers

| Tier | What it tests | Corpus | Go test | LLM | Gateway | CI |
|------|----------------|--------|---------|-----|---------|----|
| Regex | `ScanAllRules` engine (hook + `/inspect` API) and `GuardrailInspector` `regex_only` (proxy + sidecar) | `regex/corpus.jsonl` (curated + generated `eval-` rows) | `TestSecuritySuiteRegex` | No | No | Yes |
| Judge (targeted) | The LLM-judge layer (`RunJudges` / `RunToolJudge`), including suppressions and severity mapping | `judge/corpus.jsonl` | `TestSecuritySuiteJudge` | Stubbed (deterministic) or live | No | Yes (stubbed) |
| Judge (broad benchmark) | LLM-judge detection quality scorecard (ADR/FPR/precision) | `eval_corpus/{injection,pii,exfil,tool_injection}/` | `TestEval*` | Live | No | No (opt-in) |
| E2E | The real HTTP inspect API + audit pipeline on a running gateway | `e2e/corpus.jsonl` | `TestSecuritySuiteE2E` | Live | Yes | No (opt-in) |

The broad judge benchmark (the 640-item `eval_corpus/`, 160 each for
injection / PII / exfil / tool-injection) now lives under the suite. It is a
live-judge scorecard, run by `make security-suite-eval`. Its labeled items
also seed the deterministic regex tier: the generated block of
`regex/corpus.jsonl` is built from `eval_corpus/` (see "Importing" below), so a large share of those
samples is exercised deterministically in CI without an LLM.

The regex layer also has a dedicated severity benchmark with hard
assertions:
[`internal/gateway/testdata/severity_benchmark/labels.json`](../internal/gateway/testdata/severity_benchmark/labels.json)
(`TestSeverityBenchmark`), which now includes deterministic PII cases
(SSN, credit card, and a bare-epoch "not a phone number" control).

## Running

```sh
# Deterministic tiers only (CI-safe, no secrets):
make security-suite-test

# Live judge scoring against a real model (needs DEFENSECLAW_LLM_KEY):
make security-suite-eval

# End-to-end against a running gateway:
DEFENSECLAW_GATEWAY_URL=http://127.0.0.1:18970 \
  go test ./internal/gateway/ -run TestSecuritySuiteE2E -v
```

The deterministic tiers are part of `make gateway-test` / `make test`, so
they run in CI automatically.

## Why three tiers

- The **regex** tier proves the deterministic rule engine catches secrets,
  dangerous commands, sensitive paths, C2 endpoints, and structural PII
  (SSN, credit card) — and that benign imperative tool phrasing, bare
  emails, and numeric output are **not** flagged at this layer.
- The **judge** tier proves the LLM-judge wiring: positive detection (SSN,
  bulk directory PII) and the suppressions that prevent known false
  positives (CLI sender metadata as a username; a Unix epoch as a phone
  number). The model answer is scripted so the surrounding code path
  (parsing, suppressions, severity mapping) is tested reproducibly; the
  same corpus can be scored against a live model on demand.
- The **e2e** tier proves the HTTP handlers and audit pipeline behave the
  same way against a real gateway.

## Importing from the eval corpus

The generated rows of `regex/corpus.jsonl` (those whose id starts with
`eval-`) are built from the labeled `eval_corpus/` by a
gated generator. Benign items the regex layer leaves clean become
false-positive guards; attacks the regex layer already flags become
regression locks; semantic, judge-only items are skipped (they stay in the
live benchmark). Regenerate after changing the eval corpus or the rules:

```sh
SECURITY_SUITE_IMPORT=1 go test ./internal/gateway/ -run TestGenerateRegexImportFromEvalCorpus -v
```

## Adding a case

Append one line to the relevant `corpus.jsonl`. No code change is needed.
See the corpus
[README](../internal/gateway/testdata/security_suite/README.md) for the
per-tier schema. Every case asserts a correct expected outcome; a failing
case is a real regression (or a desired behavior that should land together
with its fix).
