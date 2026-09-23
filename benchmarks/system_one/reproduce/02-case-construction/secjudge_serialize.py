"""SecJudge input serialisation -- FIXED across every stage and context variant.

SecJudge takes one text string; our cases are agent trajectories. To keep the *content*
identical to what the other five backends saw, we do not invent a new rendering: we call the
runner's own `build_state()` to obtain the canonical bounded context for the requested variant
(same byte bounds, same security-term-aware middle-out truncation, same neutralisation of the
framing tags), then flatten it with the runner's own C7 `production_text` tag format.

  C7 -> build_state already returns the production_text STRING; used verbatim, byte for byte.
  C0 -> build_state returns the structured dict; we render the identical tag format from it,
        which for C0 (intent=false, prior_events=0) is exactly the CURRENT_TOOL_CALL block.

So the serialisation is `production_text(variant)`. Nothing is added, dropped or reordered
relative to the context the other backends received at the same variant.

This is nonetheless a DIFFERENT PROMPTING CONTRACT from the Q0-Q4 question grid: SecJudge gets
no policy text, no question, and no instruction variant, because it is a sequence classifier
with a fixed 5-class head rather than a judge. That is a real confound and is declared in the
report, not hidden.
"""

from __future__ import annotations

import json
import sys
from typing import Any

REPO = "$WORK/defenseclaw-system-one"
if REPO not in sys.path:
    sys.path.insert(0, REPO)
    sys.path.insert(0, REPO + "/benchmarks/scripts")

from benchmark_run_system_one import build_state, safe_tool_name  # noqa: E402

CONTEXTS_PATH = REPO + "/benchmarks/system_one/contexts-v1.json"
with open(CONTEXTS_PATH) as _handle:
    CONTEXTS = json.load(_handle)

# Identical wording/format to benchmark_run_system_one.build_state's render_c7().
INTENT_OPEN = '<SESSION_USER_INTENT untrusted="true">'
INTENT_CLOSE = "</SESSION_USER_INTENT>"


def _render_from_dict(state: dict[str, Any]) -> str:
    parts: list[str] = []
    intent = str(state.get("session_user_intent") or "")
    if intent:
        parts.append(f"{INTENT_OPEN}\n{intent}\n{INTENT_CLOSE}")
    for index, event in enumerate(state.get("prior_tool_calls") or [], 1):
        parts.append(
            f'<RECENT_TOOL_CALL index={index} tool="{event["tool_name"]}">\n'
            f"{event['bounded_arguments']}\n</RECENT_TOOL_CALL>"
        )
    current = state.get("current_tool_call") or {}
    tool = safe_tool_name(current.get("tool_name"))
    parts.append(f'<CURRENT_TOOL_CALL tool="{tool}">\n{current.get("bounded_arguments", "")}\n</CURRENT_TOOL_CALL>')
    return "\n".join(parts)


def serialize(intent: str, prior: list[dict], current: dict, variant: str) -> tuple[str, dict]:
    """Return (text, state_meta) for one decision at one context variant."""
    state, meta = build_state(intent, prior, current, variant, CONTEXTS)
    text = state if isinstance(state, str) else _render_from_dict(state)
    return text, meta


def serialize_cmd(intent: str, prior: list[dict], current: dict, variant: str) -> tuple[str, dict]:
    """Bare-command serialisation: the event's own command text with no framing tags.

    Diagnostic alternative, used to separate "SecJudge is weaker" from "our tagged
    production_text framing is out of distribution for SecJudge". Closest to the bare shell
    commands and tool-call payloads in its own training sources (nl2bash-custom, the DefenseClaw
    suite, the JSON-augmented rows). Still bounded by the runner's own byte bounds, so no case
    gets more raw content here than the parity arm received.
    """
    from benchmark_run_system_one import bound_value, event_value

    state, meta = build_state(intent, prior, current, variant, CONTEXTS)
    v = event_value(current)
    args = v["arguments"]
    text = None
    if isinstance(args, dict):
        for key in ("command", "cmd", "argv", "script", "code", "query"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                text = value
                break
    if text is None:
        text = args if isinstance(args, str) and args.strip() else json.dumps(
            args, sort_keys=True, ensure_ascii=False
        )
    bounded, truncated = bound_value(
        str(text), int(CONTEXTS["production_bounds"]["current_event_bytes"])
    )
    new_meta = dict(meta)
    new_meta["truncated"] = bool(meta["truncated"]) or bool(truncated)
    return bounded, new_meta


SERIALISERS = {
    "production_text": serialize,
    "cmd": serialize_cmd,
}


def case_decisions(case: dict, variants: list[str], serialisation: str = "production_text"):
    """Yield (event_index, variant, text, state_meta) in the runner's own order.

    Mirrors benchmark_run_system_one.case_jobs so event indices line up exactly.
    """
    fn = SERIALISERS[serialisation]
    payload = case.get("payload") if isinstance(case.get("payload"), dict) else {}
    intent = str(payload.get("content") or "")
    events = payload.get("events") if isinstance(payload.get("events"), list) else [payload]
    prior: list[dict] = []
    for event_index, raw_event in enumerate(events):
        current = raw_event if isinstance(raw_event, dict) else {}
        for variant in variants:
            text, meta = fn(intent, prior, current, variant)
            yield event_index, variant, text, meta
        prior.append(current)
