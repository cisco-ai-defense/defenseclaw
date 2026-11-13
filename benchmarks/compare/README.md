# Head-to-head: DefenseClaw against open-source agent guardrails

This directory holds the harness that scores DefenseClaw and the main open-source guardrails on the same public datasets
with the same scorer. The results and the method are on the docs page `guardrails/compare`. The full write-up, with
fairness notes and threats to validity, is `COMPARE.md` in the S7 plan folder. The page data is
`docs-site/data/guardrail-compare.json`.

## What is compared

| Tool | Version | What runs (each tool's documented setup for agent or tool-call security) |
|---|---|---|
| DefenseClaw | the rel/1.0.10 head named in `RUN.json` | (a) rules, default pack; (b) rules, strict pack; (c) rules + System One (Gemini Decision 1); (d) rules + System One + Gemma 4 31B judge |
| Meta LlamaFirewall | `llamafirewall` 1.0.3, `codeshield` 1.0.1 | PromptGuard 2 (86M, and 22M alone) on user input and tool output; AlignmentCheck on every tool call with Llama 4 Maverick, its default model; CodeShield on code in tool calls |
| Meta Llama Guard 4 | `meta-llama/Llama-Guard-4-12B` | prompt classification of the user turn; response classification of the agent's tool call |
| NVIDIA NeMo Guardrails | `nemoguardrails` 0.24.1 | jailbreak detection heuristics and the NemoGuard JailbreakDetect model on input, context-bloat detection on input and tool output, YARA injection detection on tool-call arguments |
| Invariant Guardrails | `invariant-ai` 0.3.5 | its reference rules: prompt injection on user messages and tool output, semgrep on shell commands, the `secrets` default guardrail (log) |
| ProtectAI LLM Guard | `llm-guard` 0.3.16 | PromptInjection (deberta-v3-base v2, ONNX), InvisibleText and Secrets on user input and tool output |
| Guardrails AI | `guardrails-ai` 0.11.0 + hub validators | DetectJailbreak on the user prompt, SecretsPresent on prompts, tool-call arguments and tool output |

Each adapter in `adapters/` documents what its tool scans and why. A surface a tool does not claim is reported as N/A, not as
a miss. The exact package set of every run is frozen in `~/cmp/locks/<tool>.lock.txt` on the bench box and copied into the
evidence folder. Model weights are downloaded from their publishers (`fetch_models.py`) and never committed here. Each
model's own licence applies.

## Datasets

The datasets are public sources only (`sets.py`). They are filtered by `source.dataset` out of the S7 case-v1 corpora, with
ids, payloads and labels unchanged: AgentDojo, MCPTox and InjecAgent (from public-surfaces-v2-n1); DTap, mcphunt and
agentic-redteam (from s2-v2, with the real tool results); the Nemotron terminal benign set (s3, a fixed-seed sample of 1,000
cases per side); extra-public-n1 (Shell Attack Evolution, TerminalBench, agent-trace); llm-labelled-augur-n1 (model labels,
reported separately); prompt-agentdojo; tool-result-agentdojo; and the public rows of windows-shell (Atomic Red Team and
trace-commons). Owner traces, our own authored suites and ledger repros are never selected. `SETS.json` lists the counts,
licences and sha256 of every set file.

**Split.** We report the frozen S7 holdout split (v1). A case is holdout only when it is holdout under every corpus name it has
been scored under before, so no case that an S7 lane could read as tune is reported. Score thresholds are fitted on the tune
side only (`materialize.py --tuned`), with one objective for every tool: the best F1 of flagged cases, pooled over the tune
sets.

## Scoring

Every tool writes one decision row per event in the DefenseClaw harness format, and `s7gate.py score` scores it. That is the
same scorer, label overlay (labels v3.3) and completeness check DefenseClaw is scored with. A case is flagged when any of its
events is flagged. **Block** means the tool stops the call. **Alert** means block or ask/log (DefenseClaw alert, ask or
confirm; LlamaFirewall HUMAN_IN_THE_LOOP_REQUIRED; Invariant log). `aggregate.py` adds Wilson 95% CIs and a case-bootstrap F1
CI, and it checks every count against the scorer's own score files.

## Reproduce

On a c7i.16xlarge (or similar) Ubuntu 24.04 box with the S7 corpora in `~/s7c`:

```bash
python3 -I benchmarks/compare/sets.py --s7c ~/s7c --out ~/s7c/compare/sets           # the published sets
python3 benchmarks/compare/fetch_models.py --hf-home ~/cmp/hf                          # needs a HF token with the Meta licence accepted
bash benchmarks/compare/setup_venvs.sh                                                  # one venv per tool
bash benchmarks/compare/run_all.sh                                                      # every adapter, both sides, then score + aggregate
```

`run_all.sh` runs each adapter with `run.py` (resumable, with an answer cache), turns the raw outputs into decision files with
`materialize.py` (default and tuned thresholds), scores them with `s7gate.py`, builds the DefenseClaw view with `dcview.py` from
an `s7-gate run <label> --corpora corpora_compare.json`, and writes `results.json` with `aggregate.py`. `latency.py` measures
per-call latency and throughput on a fixed sample of 800 events, with the cache off.
