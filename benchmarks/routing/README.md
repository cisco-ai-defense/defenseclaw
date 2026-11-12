# Router classifier evaluation (1.0.10, item 12)

This directory measures the classifiers that can drive `routing.classifier`. It holds a labelled prompt set, an adversarial route-flip set and a harness.

| Path | What |
| --- | --- |
| `data/eval.jsonl` | 555 labelled prompts. Each has `expected_category` (coding, reasoning, chat, summarize, sensitive, tool_heavy, cheap_fast), `allowed_aliases` (the aliases that answer it acceptably and are permitted; sensitive is `["local"]` only) and `expected_alias` (the cheapest allowed alias). |
| `data/adversarial.jsonl` | 360 route-flip items made by `scripts/make_adversarial.py` from 40 cheap and 30 sensitive base prompts. The labels are inherited from the base prompt. |
| `data/label-agreement.json` | The independent spot check of 10% of the labels. |
| `data/routing-reference.yaml` | A 1.0.9 `routing:` block: keyword signals plus one decision per category. The in-process keyword classifier reads it, and so does the vLLM SR container through `internal/routing.Translate`. |
| `data/profiles.yaml` | Stand-ins for profile routing overlays (`default`, `restricted`, `local_only`). |
| `data/prices.yaml` | A **placeholder** price table, used until the reviewed default table from item 10 is available. |
| `routingeval/` | Classifiers, the R1 routing pipeline, metrics and the report. |
| `cmd/routing-eval/` | The harness command. |
| `systemone-standin/server.py` | A loopback server that speaks the System One protocol and answers choice questions with a Bedrock model. |

## Labels

The prompts were written by two generator subagents, 7 categories with about 80 each. Real-agent shapes include system prompts, multi-turn chats, tool-result turns and non-English text. All personal data and secrets are fake.

A fresh Opus subagent labelled every prompt without seeing the generators' intent. A second, independent Opus subagent then labelled a stratified 10% sample (56 prompts) blind. `label-agreement.json` records the agreement.

## Classifiers

| Name | What is measured |
| --- | --- |
| `keyword` | The 1.0.9 keyword decisions, evaluated in process with the semantics measured on the pinned container (see below). It stands in for `rules` until the S1 rules classifier lands. |
| `vllm_sr` | The pinned `vllm-sr:v0.3.0` container, called through `gateway.RemoteRouterClient` with the shipped 50 ms timeout. |
| `systemone` | One System One call (`POST {model, state, questions}`) with one `route_category` choice question. The state is bounded like the decision model's (12,288 bytes). |
| `hybrid` | R1: rules always. The System One answer is used only when it arrives within `-systemone-budget` (300 ms) with confidence at or above `-min-confidence` (0.6); otherwise the rules answer stands. `hybrid@1s` uses a 1 s budget to show the effect of a slower endpoint. |

Semantics of the 1.0.9 vLLM SR keyword classifier, measured by probing the container:
- Only the **last user message** is classified. System, assistant and tool turns are ignored.
- Keywords match case-insensitively on **word boundaries** (`\bkw\b`). `summarized` does not match `summarize`, `AKIA` does not match `AKIAEXAMPLE`, and a keyword that ends in punctuation (`error:`) never matches before a space.
- The highest-priority decision that holds wins, and a decision with no conditions always holds.

## Pipeline and metrics

For every prediction the R1 pipeline runs in this order:
1. The classifier picks an alias. On an error it falls back to the requested model (`request_alias`).
2. Guardrail narrowing: the shipped rule pack runs (`regex_only`, default posture). A PII or secret finding keeps only local aliases.
3. The profile filter: an alias outside `allowed_aliases` becomes `default_alias`. No step can widen the route.

Metrics:
- macro-F1 over the 7 categories (an error counts as a miss).
- Violations after the filter: final aliases outside the profile's allowed set. This must be 0.
- Sensitive leaks: sensitive prompts that end on a cloud alias.
- Quality: the share of prompts that end on one of their `allowed_aliases`.
- Latency p50/p95.
- Cost per 1,000 requests at 95% quality. The reference router (strong for every non-sensitive prompt, local for sensitive ones) has quality 1.0. Below the target, the gap is closed by a random mix with the reference router (the RouteLLM baseline). Classifiers with a confidence also get a threshold sweep, where prompts below the threshold escalate. The cheaper of the two is reported.
- Flip rate: an adversarial item flips when its final alias moves in the attack direction against its base prompt's final alias. "Upgrade" means a pricier alias for a cheap prompt; "leak" means a cloud alias for a sensitive prompt.

## Run

On defenseclaw-dev (Docker and Bedrock through the instance role):

```bash
go build -o /tmp/routing-eval ./benchmarks/routing/cmd/routing-eval
# vLLM SR: config from the reference block, then the container with the gateway's hardening flags
/tmp/routing-eval -data benchmarks/routing/data -emit-sr-config "$DIR"   # writes $DIR/config.yaml
docker run -d --name eval-vllm-sr --cap-drop=ALL --security-opt=no-new-privileges:true --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m --user "$(id -u):$(id -g)" -v "$DIR:/app/config:ro,Z" \
  -p 127.0.0.1:18480:8080 ghcr.io/vllm-project/semantic-router/vllm-sr:v0.3.0@sha256:667c4d45e03fcee84d33792e6901fa3ac0e6a1f53e6a2674ecb1174e1decea64 /app/config/config.yaml
# System One stand-in (or point -systemone-endpoint at a real endpoint; the token comes from DEFENSECLAW_DECISION_MODEL_KEY)
python3 benchmarks/routing/systemone-standin/server.py --port 18791 --bedrock-model us.amazon.nova-micro-v1:0 &
/tmp/routing-eval -data benchmarks/routing/data -out /tmp/routing-eval-out -classifiers keyword,vllm_sr,systemone
```

The command writes `results.json`, `results.md` and `predictions.jsonl` (labels and routes only, no prompt text). With only `-classifiers keyword` it needs neither Docker nor the network, so it also runs on dc-build-1 through `dcb`. `go test ./benchmarks/routing/...` checks the metrics, the pipeline, the keyword semantics and the shipped data files.

To add the S1 rules classifier, implement `routingeval.Classifier` for it and add a case to the switch in `cmd/routing-eval/main.go`.
