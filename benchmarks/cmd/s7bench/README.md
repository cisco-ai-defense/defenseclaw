# s7bench

The S7 guardrail benchmark harness. It replays labelled corpus cases through the real DefenseClaw hook handlers and writes one JSON line
per decision. Build with `-tags s7bench`; it is driven by `s7-gate`, never run by the product.

## Surfaces (`-surface`)

- `hook`: tool calls through the connector's PreToolUse hook (and PostToolUse when the event succeeded). The scored answer is the PreToolUse answer.
- `prompt`: `payload.content` through the connector's UserPromptSubmit hook. **The scored answer is the hook answer**, the one a coding agent
  gets (rel-1-0-10:GAP-0554). The `/llm` proxy text inspection (`InspectText`) is kept only as the diagnostic columns `extra.inspect_action`,
  `extra.inspect_sev` and `extra.inspect_findings`; `s7gate.py score --effects-column inspect` scores that view and `--effects-column hook`
  scores the hook answer of a run made before the fix (`extra.hook_action`). Runs made before the fix scored `InspectText`.
- `tool-result`: each event's result as the PostToolUse `tool_response`; the PostToolUse answer is scored.

## System One answer cache (`-dm-cache-dir`)

A loopback relay in front of `-dm-url` stores every answer under the sha256 of the exact request body, and replays it with `-dm-cache-only`.

`-dm-fill` fills the cache in one pass (rel-1-0-10:GAP-0555). The relay answers a miss at once with a fixed, valid, unsure answer that is never
stored, so the product's decision-model client sees no timeout and its circuit breaker (3 failures, 30 s skip; unchanged) never trips. The
relay's own workers (`-dm-cache-inflight`, `-dm-cache-rpm`, `-dm-cache-tpm`, `-dm-cache-budget`) then fetch every distinct request body
upstream with long retries (Retry-After honoured) and store it. The harness waits for them before it exits: exit 0 means every request is
answered and stored; exit 4 means some are not (run the fill again; stored answers are not sent again). The decisions of a fill run are void
(made with the stub); score a replay with `-dm-cache-only`. A request body does not depend on earlier answers (the history holds prompts, calls and
results only), so one pass covers the corpus; check it with a replay that reports `offline_misses=0`.
