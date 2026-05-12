# Matrix recipes

The expanded matrix is large — six dimensions, each with multiple values.
This page lists pre-built filter recipes. Run each one as a one-off (`dctest matrix list`) or persist it (`dctest matrix select --output ...`).

## Smoke (per-PR sanity)

The smallest meaningful slice: one provider, one connector, one role, one profile combo, one scan type.

```bash
dctest matrix select \
  --filter provider=anthropic-claude-sonnet \
  --filter connector=codex \
  --filter role=guardrail+judge-same \
  --filter scan_type=skill \
  --filter fail_mode=fail-open \
  --output runs/smoke.yaml
```

Then `dctest run <run-id> --selection runs/smoke.yaml --cases 'cli-py.*'`.

## Cross-vendor provider parity

Same connector, same role, same policies — switch only the provider.

```bash
dctest matrix select \
  --filter connector=codex \
  --filter role=guardrail-only \
  --filter scan_type=skill \
  --output runs/providers.yaml
```

Run with `--cases 'skills.judge.*,skills.clawshield.*'` to see how each provider behaves.

## Required connectors, default profile, full scan-type set

The PR-blocking "long" matrix.

```bash
dctest matrix select \
  --filter provider=anthropic-claude-sonnet \
  --output runs/long.yaml
```

This produces 3 connectors × 4 roles × 3 sampled profiles × 2 fail-modes × 5 scan-types = 360 cells. Most cases are skip-friendly under each cell.

## Local-only providers

Skip cloud providers entirely; useful for sandboxes without outbound internet.

```bash
dctest matrix select \
  --filter 'provider=vllm-llama-3.1-8b,vllm-qwen-2.5-7b,ollama-llama-3.1,ollama-qwen-2.5' \
  --output runs/local-only.yaml
```

`dctest doctor --selection runs/local-only.yaml` will fail if the vLLM/Ollama endpoints aren't reachable.

## Optional connectors only

To regression-test connectors that are not part of the PR-blocking set.

```bash
dctest matrix select \
  --include-optional \
  --filter 'connector=zeptoclaw,cursor,copilot,geminicli,windsurf,hermes' \
  --filter provider=anthropic-claude-sonnet \
  --output runs/optional-connectors.yaml
```

## Full profile cross-product

```bash
dctest matrix select --full-profiles --output runs/full.yaml
```

This is the maximal matrix; expect ~1000+ cells. Use for nightly cron only.
