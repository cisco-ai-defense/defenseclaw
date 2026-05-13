# Galileo DefenseClaw Demo Datasets

These datasets are for demonstrating DefenseClaw runtime governance in Galileo
SaaS without using the unrelated Cisco Cloud Control demo path.

The datasets live in `datasets/galileo/*.jsonl`. Each row uses Galileo's standard dataset fields:

- `input`: prompt variables for the DefenseClaw runtime governance prompt.
- `ground_truth`: expected behavior for correctness and context-adherence checks.
- `metadata`: scenario labels, expected Agent Control match, expected action, stage, and suggested Galileo metrics.

The reusable prompt template is `prompts/galileo/defenseclaw-runtime-governance.md`.

The Galileo Playground recipe is `playgrounds/galileo/defenseclaw-runtime-governance.playground.json`.

These assets are the primary Galileo Agent Watch / experiment-review path for
the DefenseClaw K8 demo. They are separate from the Cisco Cloud Control
tokenomics demo.

## Dataset Set

- `defenseclaw-safe-ops`
- `defenseclaw-prompt-injection-pre-llm`
- `defenseclaw-dangerous-tool-pre-tool`
- `defenseclaw-pii-post-llm`
- `defenseclaw-ambiguous-admin-intent`
- `defenseclaw-grounded-cluster-review`

## Upload

Install the Galileo SDK in a temporary environment, then upload the datasets and prompt template:

```bash
python3 -m venv /tmp/defenseclaw-galileo-upload
/tmp/defenseclaw-galileo-upload/bin/python -m pip install --upgrade pip galileo

GALILEO_API_KEY="$(kubectl -n defenesclaw get secret defenseclaw-secrets -o jsonpath='{.data.GALILEO_API_KEY}' | base64 --decode)" \
GALILEO_PROJECT="clus-demo" \
GALILEO_PROJECT_ID="0ba7b20d-8262-44c4-b230-547a0cd74b2b" \
GALILEO_LOG_STREAM="clus-demo" \
/tmp/defenseclaw-galileo-upload/bin/python scripts/upload_galileo_demo_datasets.py
```

The uploader skips datasets that already exist by name. Pass `--create-duplicates` only when you intentionally want a new copy.

## Current Galileo SaaS Upload

Console project: `https://app.galileo.ai/project/0ba7b20d-8262-44c4-b230-547a0cd74b2b`

Experiments: `https://app.galileo.ai/project/0ba7b20d-8262-44c4-b230-547a0cd74b2b/experiments`

Project: `clus-demo`

Project ID: `0ba7b20d-8262-44c4-b230-547a0cd74b2b`

Log stream ID: `82b893bd-fa1f-411e-81e8-e12ca66692ad`

| Artifact | Galileo ID | Role |
| --- | --- | --- |
| `defenseclaw-safe-ops` | `1cb6a564-91f8-4c4a-a4b8-9ee9e44e5fdb` | Baseline read-only K8 operations that should pass. |
| `defenseclaw-prompt-injection-pre-llm` | `8633dc49-c9f0-4179-b7be-a9c371910eba` | Maps to `observe-prompt-injection-pre-llm`. |
| `defenseclaw-dangerous-tool-pre-tool` | `fa039b81-a70a-41cd-aacd-4e3c5e2488fe` | Maps to `deny-dangerous-shell-pre-tool`; best bridge to `/api/v1/inspect/tool`. |
| `defenseclaw-pii-post-llm` | `810e5961-5bef-4615-8280-180238b6f1ac` | Maps to `steer-pii-post-llm`. |
| `defenseclaw-ambiguous-admin-intent` | `6a404e8b-5952-44d8-aa4c-7362b319ecca` | Shows approval-seeking behavior for risky admin requests. |
| `defenseclaw-grounded-cluster-review` | `c750e742-59d6-47e0-bc99-c8721386e9eb` | Validates K8 facts, especially `isovalent-demo` and namespace `defenesclaw`. |
| `defenseclaw-runtime-governance` prompt | `1a327ae4-264d-4036-80f6-f8a424158a91` | Runtime governance prompt template. |

Selected prompt version: `2`

Selected prompt version ID: `a7e61200-cc43-4fbe-941f-331095be3f4e`

Prompt variables: `user_prompt`, `cluster_context`, `agent_name`, `guardrail_mode`

Local validation on May 10, 2026 confirmed the dry-run planners reference the
prompt, all six datasets, the selected prompt version, and all six
runtime-evidence experiment targets. This shell did not have the Galileo SDK or
`GALILEO_API_KEY` available, so live SaaS readback should be run from a
credentialed environment before changing object IDs.

## Credential Setup

For the live lab, get the Galileo API key from the `defenesclaw` namespace
without printing it:

```bash
export GALILEO_API_KEY="$(kubectl -n defenesclaw get secret defenseclaw-secrets -o jsonpath='{.data.GALILEO_API_KEY}' | base64 --decode)"
export GALILEO_PROJECT="clus-demo"
export GALILEO_PROJECT_ID="0ba7b20d-8262-44c4-b230-547a0cd74b2b"
export GALILEO_LOG_STREAM_ID="82b893bd-fa1f-411e-81e8-e12ca66692ad"
export GALILEO_CONSOLE_URL="https://app.galileo.ai"
```

Install the SDK into a temporary environment if the repo environment does not
already have it:

```bash
python3 -m venv /tmp/defenseclaw-galileo-upload
/tmp/defenseclaw-galileo-upload/bin/python -m pip install --upgrade pip galileo
```

## Playground

Galileo's console Playground is configured from existing project assets rather than a standalone SDK-created object. The repo now carries the exact Playground recipe so the SaaS setup is repeatable:

```bash
cat playgrounds/galileo/defenseclaw-runtime-governance.playground.json
```

Console setup:

1. Open Galileo project `clus-demo`.
2. Open Playground.
3. Select prompt `defenseclaw-runtime-governance`.
4. Select one of the DefenseClaw datasets from the recipe.
5. Add that dataset's `default_metrics`.
6. Run the Playground and log the result as an experiment when the output is useful for the demo.

The recipe uses model alias `gpt-4.1-nano` with temperature `0.2`, max tokens
`700`, and top_p `1.0`. The metric names are aligned with each JSONL row's
`metadata.galileo_metrics`; use `tool_errors` and `output_pii` where those are
the row-level metrics.

The code-backed equivalent can dry-run the same setup:

```bash
/tmp/defenseclaw-galileo-upload/bin/python scripts/run_galileo_playground_experiment.py --all
```

To start a real Galileo experiment for one dataset:

```bash
GALILEO_API_KEY="$(kubectl -n defenesclaw get secret defenseclaw-secrets -o jsonpath='{.data.GALILEO_API_KEY}' | base64 --decode)" \
/tmp/defenseclaw-galileo-upload/bin/python scripts/run_galileo_playground_experiment.py \
  --dataset defenseclaw-dangerous-tool-pre-tool \
  --execute
```

The prompt-runner path requires Galileo's configured OpenAI integration to have quota. On May 10, 2026, the configured OpenAI integration returned `insufficient_quota`, so prompt-runner experiments could be created but could not complete until that provider key is refreshed.

## Working Runtime Evidence Experiments

The local-function runner logs deterministic DefenseClaw/Agent Control behavior into Galileo without calling an external LLM. This keeps the demo working even when the Playground model provider is out of quota:

```bash
GALILEO_API_KEY="$(kubectl -n defenesclaw get secret defenseclaw-secrets -o jsonpath='{.data.GALILEO_API_KEY}' | base64 --decode)" \
/tmp/defenseclaw-galileo-upload/bin/python scripts/run_galileo_runtime_evidence_experiment.py --all --execute
```

Completed experiment set:

| Dataset | Experiment ID | Console link |
| --- | --- | --- |
| `defenseclaw-safe-ops` | `25777783-d6e3-47fa-ba8b-fda125366a96` | `https://app.galileo.ai/project/0ba7b20d-8262-44c4-b230-547a0cd74b2b/experiments/25777783-d6e3-47fa-ba8b-fda125366a96` |
| `defenseclaw-prompt-injection-pre-llm` | `b559e317-da6d-4ba4-be9e-203612880ecb` | `https://app.galileo.ai/project/0ba7b20d-8262-44c4-b230-547a0cd74b2b/experiments/b559e317-da6d-4ba4-be9e-203612880ecb` |
| `defenseclaw-dangerous-tool-pre-tool` | `5481b4e6-bee9-40d6-b45a-29912f66a94c` | `https://app.galileo.ai/project/0ba7b20d-8262-44c4-b230-547a0cd74b2b/experiments/5481b4e6-bee9-40d6-b45a-29912f66a94c` |
| `defenseclaw-pii-post-llm` | `c94b8a41-2d8d-44db-935c-4b02721e92e5` | `https://app.galileo.ai/project/0ba7b20d-8262-44c4-b230-547a0cd74b2b/experiments/c94b8a41-2d8d-44db-935c-4b02721e92e5` |
| `defenseclaw-ambiguous-admin-intent` | `c06da073-07f9-4a89-90a0-aea0a9e517c1` | `https://app.galileo.ai/project/0ba7b20d-8262-44c4-b230-547a0cd74b2b/experiments/c06da073-07f9-4a89-90a0-aea0a9e517c1` |
| `defenseclaw-grounded-cluster-review` | `f77143fc-fa4b-4be0-9249-6af39ee8357b` | `https://app.galileo.ai/project/0ba7b20d-8262-44c4-b230-547a0cd74b2b/experiments/f77143fc-fa4b-4be0-9249-6af39ee8357b` |

## Demo Flow

1. Run `defenseclaw-safe-ops` to show normal read-only cluster operations.
2. Run `defenseclaw-prompt-injection-pre-llm` to show prompt-injection detection before the LLM step.
3. Run `defenseclaw-dangerous-tool-pre-tool` to show Agent Control deny decisions before shell/tool execution.
4. Run `defenseclaw-pii-post-llm` to show post-LLM steering/redaction behavior.
5. Run `defenseclaw-ambiguous-admin-intent` to show approval-seeking behavior for risky admin requests.
6. Run `defenseclaw-grounded-cluster-review` to show correctness and context adherence around the live `isovalent-demo` cluster.
