# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Shared connector-hook metric classification.

The gateway persists both a structured hook envelope and a legacy
``key=value`` details string.  Overview counters must interpret those two
representations identically, without substring matches such as finding
``action=block`` inside ``raw_action=block``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any, TypeVar

_BLOCK_ACTIONS = frozenset({"block", "deny"})
_ALERT_ACTIONS = frozenset({"alert", "warn"})


def _iter_detail_tokens(value: str) -> Iterator[tuple[str, str]]:
    """Yield exact whitespace-delimited ``key=value`` tokens."""

    text = str(value or "").strip()
    i = 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        key_start = i
        while i < len(text) and text[i] != "=" and not text[i].isspace():
            i += 1
        if i >= len(text) or text[i] != "=":
            while i < len(text) and not text[i].isspace():
                i += 1
            continue
        key = text[key_start:i]
        i += 1
        if not key:
            continue
        if i < len(text) and text[i] == '"':
            i += 1
            chars: list[str] = []
            while i < len(text):
                if text[i] == '"':
                    i += 1
                    break
                if text[i] == "\\" and i + 1 < len(text):
                    i += 1
                chars.append(text[i])
                i += 1
            yield key, "".join(chars)
            continue
        value_start = i
        while i < len(text) and not text[i].isspace():
            i += 1
        yield key, text[value_start:i]


# Hook events that fire after the tool already ran: a finding there cannot
# block the call, whatever the connector's mode (GAP-1303).
_POST_TOOL_HOOK_EVENTS = frozenset({
    "posttooluse", "posttoolusefailure", "posttoolbatch", "toolresult",
    "aftertool", "aftershellexecution", "aftermcpexecution", "afterfileedit",
    "post_tool_call",
})


# Hook events that only observe text already on screen: Claude Code runs
# MessageDisplay async, so a finding there cannot block either (GAP-1531).
_DISPLAY_HOOK_EVENTS = frozenset({"messagedisplay", "post_llm_call"})

# Prompt events an agent gives no veto: in action mode DefenseClaw tells the
# model not to carry the prompt out instead (agent_hook.go
# promptNoticeOnlyEvent). Keyed by (connector, event).
_PROMPT_NOTICE_HOOK_EVENTS = frozenset({("hermes", "pre_llm_call"), ("amp", "agent.start")})

# Copilot CLI has no hook that can stop a prompt and DefenseClaw adds no
# notice there, so a prompt finding is only detected, in every mode
# (GAP-1244). Keyed by (connector, event), events lower-cased.
_PROMPT_DETECTION_ONLY_HOOK_EVENTS = frozenset({
    ("copilot", "userpromptsubmitted"), ("copilot", "userpromptsubmit"),
    ("copilot", "userprompttransformed"),
})

POST_TOOL_DECISION = "detected after the tool ran (cannot block)"
DISPLAY_DECISION = "detected in the displayed reply (cannot block)"
PROMPT_DETECTED_DECISION = "detected in the prompt (cannot block)"
PROMPT_NOTICE_DECISION = "agent told not to carry out the prompt (prompts cannot be blocked)"
OBSERVE_DECISION = "would block (observe mode)"


def detection_only_hook_label(event: str) -> str:
    """Decision label of a finding on a hook event that cannot block, else "".

    Accepts a bare event name or a ``connector:Event`` hook target."""
    connector, _, name = str(event or "").strip().rpartition(":")
    name = name.strip().lower()
    if (connector.strip().lower(), name) in _PROMPT_DETECTION_ONLY_HOOK_EVENTS:
        return PROMPT_DETECTED_DECISION
    if name in _POST_TOOL_HOOK_EVENTS:
        return POST_TOOL_DECISION
    if name in _DISPLAY_HOOK_EVENTS:
        return DISPLAY_DECISION
    return ""


def allowed_finding_hook_label(target: str, mode: str) -> str:
    """Label a finding on a hook call that the agent was allowed to run.

    The hook's audit action stays ``allow``. An action-mode finding is an
    alert to the operator, while a completed or display-only event retains
    its more precise detection label.
    """
    if str(mode or "").strip().lower() != "action":
        return ""
    return detection_only_hook_label(target) or "alert"


def would_block_hook_label(target: str, mode: str) -> str:
    """Decision label of a would-block finding on a connector:Event target.

    A Hermes or Amp prompt finding in action mode was not observed: the model
    was told not to carry the prompt out (GAP-0898)."""
    if label := detection_only_hook_label(target):
        return label
    connector, _, name = str(target or "").strip().rpartition(":")
    prompt_event = (connector.strip().lower(), name.strip().lower())
    if str(mode or "").strip().lower() == "action" and prompt_event in _PROMPT_NOTICE_HOOK_EVENTS:
        return PROMPT_NOTICE_DECISION
    return OBSERVE_DECISION


def parse_detail_tokens(value: str) -> dict[str, str]:
    """Parse exact whitespace-delimited ``key=value`` tokens.

    Quoted values may contain whitespace and escaped quotes.  Malformed tails
    are ignored rather than guessed; the user-facing metric should never turn
    an unrelated substring into an enforcement decision.
    """

    return dict(_iter_detail_tokens(value))


def _structured_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no", ""}:
        return False
    return None


def connector_hook_decision(
    details: str,
    structured: Any = None,
    enforced: Any = None,
) -> str:
    """Return ``allow``, ``alert``, or ``block`` for one hook row.

    Dedicated/structured ``enforced=true`` is authoritative.  Legacy rows
    predate that column, so an effective block outside observe mode remains a
    real block.  A latent block that was downgraded to allow/alert is an alert
    (would-block), never an enforced block.
    """

    tokens = parse_detail_tokens(details)
    payload = _structured_mapping(structured)

    def field(name: str) -> str:
        return str(payload.get(name) or tokens.get(name, "")).strip().lower()

    action = field("action")
    raw_action = field("raw_action")
    mode = field("mode")
    would_block = (
        _optional_bool(payload.get("would_block") if "would_block" in payload else tokens.get("would_block")) is True
    )
    explicit_enforced = _optional_bool(enforced)
    if explicit_enforced is None and "enforced" in payload:
        explicit_enforced = _optional_bool(payload.get("enforced"))

    if explicit_enforced is True:
        return "block"
    if action in _BLOCK_ACTIONS:
        if explicit_enforced is False or mode == "observe":
            return "alert"
        return "block"
    if action in _ALERT_ACTIONS:
        return "alert"
    if raw_action in _ALERT_ACTIONS:
        return "alert"
    if raw_action in _BLOCK_ACTIONS or would_block:
        return "alert"
    return "allow"


def hook_decision_may_block_sql(details: str, structured: str, enforced: str) -> str:
    """SQL pre-check to put before ``dc_hook_decision(...) = 'block'``.

    The classifier is a Python function SQLite calls once per row, about 60 to
    120 us each, so every row it can skip is time saved: it made the alert
    count of ``defenseclaw status`` spend its whole 3-second budget on 25,000
    hook rows (GAP-0199), and ran for minutes on a 1.27 GB audit.db of legacy
    rows (GAP-1487). The pre-check answers what the classifier would, only
    cheaper, and may only err towards "maybe". It reads the same sources in
    the same order:

    * the ``enforced`` column, when set, decides alone;
    * else, in a structured envelope that is a JSON object, an ``enforced``
      key decides (false is never a block), and otherwise its ``action`` does:
      a row blocks only with a block/deny action. The gateway writes NULL in
      the column for a call it did not enforce and omits ``enforced`` from the
      envelope, but always states the ``action``, so its allowed and alert rows
      end here (a bare ``action`` test let every one of 30,180 through,
      GAP-0199);
    * else (no envelope, or one without an ``action``) the legacy ``key=value``
      details decide: a block needs a block/deny ``action`` token. A quoted
      value is left to the classifier, and so is a structured text that does
      not parse as JSON, where the old tests still apply.

    LIKE is case-insensitive, as the classifier is on values.
    """

    tokens = (
        f"({details} LIKE '%action=block%'"
        f" OR {details} LIKE '%action=deny%'"
        f" OR {details} LIKE '%action=\"%')"
    )
    return (
        f"(CASE"
        f" WHEN {enforced} IS NOT NULL THEN CAST({enforced} AS TEXT) NOT IN ('0', '')"
        f" WHEN json_valid({structured}) THEN CASE"
        f" WHEN json_type({structured}, '$.enforced') = 'false' THEN 0"
        f" WHEN json_type({structured}, '$.enforced') <> 'null' THEN 1"
        f" WHEN json_type({structured}, '$.action') = 'text'"
        f" AND json_extract({structured}, '$.action') <> ''"
        f" THEN (json_extract({structured}, '$.action') LIKE '%block%'"
        f" OR json_extract({structured}, '$.action') LIKE '%deny%')"
        f" ELSE {tokens} END"
        f" ELSE ({tokens}"
        f" OR instr(COALESCE({structured}, ''), 'action') > 0"
        f" OR instr(COALESCE({structured}, ''), 'enforced') > 0) END)"
    )


def aggregate_connector_hook_decision(
    details: str,
    structured: Any = None,
    enforced: Any = None,
) -> str:
    """Fast exact-token classifier for SQLite aggregate scans.

    Current gateway rows always carry the legacy action tokens alongside the
    structured envelope.  Avoiding a JSON decode and full token dictionary for
    that common path keeps the two-second aggregate poll cheap.  Structured-
    only/atypical rows fall back to :func:`connector_hook_decision`.
    """

    explicit_enforced = _optional_bool(enforced)
    if explicit_enforced is None and structured:
        structured_text = (
            json.dumps(structured, separators=(",", ":")) if isinstance(structured, dict) else str(structured)
        )
        if '"enforced"' in structured_text:
            return connector_hook_decision(details, structured, enforced)

    if explicit_enforced is True:
        return "block"
    action = ""
    raw_action = ""
    mode = ""
    would_block: bool | None = None
    for key, value in _iter_detail_tokens(details):
        normalized = value.strip().lower()
        if key == "action":
            action = normalized
        elif key == "raw_action":
            raw_action = normalized
        elif key == "mode":
            mode = normalized
        elif key == "would_block":
            would_block = _optional_bool(normalized)
        else:
            continue

        if action in _ALERT_ACTIONS:
            return "alert"
        if action in _BLOCK_ACTIONS and mode:
            return "alert" if explicit_enforced is False or mode == "observe" else "block"
        if action == "allow" and (raw_action in _BLOCK_ACTIONS or raw_action in _ALERT_ACTIONS):
            return "alert"
        if action == "allow" and raw_action and would_block is not None:
            return "alert" if would_block else "allow"

    if not action:
        return connector_hook_decision(details, structured, enforced)
    if action in _BLOCK_ACTIONS:
        if explicit_enforced is False or mode == "observe":
            return "alert"
        return "block"
    if action in _ALERT_ACTIONS:
        return "alert"
    if raw_action in _BLOCK_ACTIONS or raw_action in _ALERT_ACTIONS:
        return "alert"
    if would_block is True:
        return "alert"
    return "allow"


def connector_hook_connector(
    connector: Any,
    structured: Any,
    details: str,
) -> str:
    """Resolve normalized connector identity from dedicated to legacy data."""

    normalized = str(connector or "").strip().lower()
    if normalized:
        return normalized
    payload = _structured_mapping(structured)
    normalized = str(payload.get("connector") or "").strip().lower()
    if normalized:
        return normalized
    return parse_detail_tokens(details).get("connector", "").strip().lower()


# ---------------------------------------------------------------------------
# The verdict of a hook row, whichever kind holds it (S8 R4, #1384).
#
# A hook decision is stored as a ``connector-hook`` row (the defenseclaw.hook.v1
# envelope plus its ``key=value`` details) and as a ``hook_decision`` row (the
# canonical v8 record, body keys ``defenseclaw.*``). Since 1.0.10 a benign
# per-user allow keeps only its ``hook_decision`` row locally (the
# connector-hook record is exported, not written); every other decision, and
# all 1.0.9 data, keeps both rows, linked by the semantic event id of their
# projected records. Both row kinds stay live: every reader takes the verdict
# from :func:`hook_row_decision` and counts a decision once with
# :func:`count_once_hook_rows` or :func:`lone_hook_decision_sql`.
# ---------------------------------------------------------------------------

CONNECTOR_HOOK_ACTION = "connector-hook"
HOOK_DECISION_ACTION = "hook_decision"
# Rows that pair a hook_decision row of the same semantic event: a
# synthetic Stop (connector-hook-synthetic) also has a hook_decision row.
CONNECTOR_HOOK_SYNTHETIC_ACTION = "connector-hook-synthetic"
CONNECTOR_HOOK_PAIR_ACTIONS = (CONNECTOR_HOOK_ACTION, CONNECTOR_HOOK_SYNTHETIC_ACTION)

_HOOK_DECISION_ACTION_KEY = "defenseclaw.guardrail.effective_action"
_HOOK_DECISION_RAW_ACTION_KEY = "defenseclaw.guardrail.raw_action"
_HOOK_DECISION_MODE_KEY = "defenseclaw.guardrail.mode"
_HOOK_DECISION_WOULD_BLOCK_KEY = "defenseclaw.guardrail.would_block"
_HOOK_DECISION_ENFORCED_KEY = "defenseclaw.guardrail.enforced"
_HOOK_DECISION_SEVERITY_KEY = "defenseclaw.security.severity"
_HOOK_DECISION_EVENT_KEY = "defenseclaw.hook.event"

# The body keys a reader needs to classify a hook_decision row; summary
# queries project these instead of the whole record.
HOOK_DECISION_VERDICT_KEYS = (
    _HOOK_DECISION_ACTION_KEY,
    _HOOK_DECISION_RAW_ACTION_KEY,
    _HOOK_DECISION_MODE_KEY,
    _HOOK_DECISION_WOULD_BLOCK_KEY,
    _HOOK_DECISION_ENFORCED_KEY,
    _HOOK_DECISION_SEVERITY_KEY,
    _HOOK_DECISION_EVENT_KEY,
)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _hook_decision_row_decision(structured: Any, enforced: Any) -> str:
    """``allow``, ``alert`` or ``block`` for a ``hook_decision`` row.

    ``structured`` is its record body (``payload_json``, or ``$.body`` of the
    projected record), as a mapping or JSON text; ``enforced`` is the
    audit_events.enforced column. The connector-hook classifier is fed the
    same facts: an enforced call is a block, a block action outside observe
    mode a block, an alert or a latent block an alert. The record states
    enforced=false for every call it did not enforce, while the
    connector-hook row leaves the column NULL there, so only a true value is
    passed on.
    """

    payload = _structured_mapping(structured)
    is_enforced = (
        _optional_bool(enforced) is True or _optional_bool(payload.get(_HOOK_DECISION_ENFORCED_KEY)) is True
    )
    return connector_hook_decision(
        "",
        {
            "action": _text(payload.get(_HOOK_DECISION_ACTION_KEY)).lower(),
            "raw_action": _text(payload.get(_HOOK_DECISION_RAW_ACTION_KEY)).lower(),
            "mode": _text(payload.get(_HOOK_DECISION_MODE_KEY)).lower(),
            "would_block": _optional_bool(payload.get(_HOOK_DECISION_WOULD_BLOCK_KEY)) is True,
        },
        True if is_enforced else None,
    )


def hook_row_decision(action: str, details: str = "", structured: Any = None, enforced: Any = None) -> str:
    """``allow``, ``alert`` or ``block`` for a hook row of either kind; "" for any other row."""

    kind = str(action or "").strip().lower()
    if kind == CONNECTOR_HOOK_ACTION:
        return connector_hook_decision(details, structured, enforced)
    if kind == HOOK_DECISION_ACTION:
        return _hook_decision_row_decision(structured, enforced)
    return ""


def aggregate_hook_row_decision(action: str, details: str = "", structured: Any = None, enforced: Any = None) -> str:
    """SQLite callback form of :func:`hook_row_decision` for aggregate scans."""

    if str(action or "").strip().lower() == CONNECTOR_HOOK_ACTION:
        return aggregate_connector_hook_decision(details, structured, enforced)
    return hook_row_decision(action, details, structured, enforced)


T = TypeVar("T")


def count_once_hook_rows(rows: Iterable[T]) -> list[T]:
    """Keep one row per hook decision, in order; rows of other actions pass through.

    The connector-hook row is the decision when the store has one. A
    hook_decision row is the decision only when it names its semantic event
    and no connector-hook row of that event is among *rows*; a hook_decision
    row with no semantic event id always has its connector-hook row locally
    (the gateway writes a hook_decision row alone only for a correlated call).
    Rows are read through ``action`` and ``semantic_event_id`` attributes.
    """

    items = list(rows)
    paired = {
        str(getattr(row, "semantic_event_id", "") or "")
        for row in items
        if str(getattr(row, "action", "") or "").strip().lower() in CONNECTOR_HOOK_PAIR_ACTIONS
    }
    paired.discard("")
    kept: list[T] = []
    for row in items:
        if str(getattr(row, "action", "") or "").strip().lower() == HOOK_DECISION_ACTION:
            semantic = str(getattr(row, "semantic_event_id", "") or "")
            if not semantic or semantic in paired:
                continue
        kept.append(row)
    return kept


def hook_semantic_event_id_sql(projected: str = "projected_record_json") -> str:
    """SQL expression: the semantic event id of a row's projected record, else NULL."""

    return (
        f"(CASE WHEN json_valid(COALESCE({projected}, ''))"
        f" THEN json_extract({projected}, '$.correlation.semantic_event_id') END)"
    )


def hook_decision_body_sql(payload: str = "payload_json", projected: str = "projected_record_json") -> str:
    """SQL expression: the body of a native record (payload_json, else the projected record's body)."""

    return (
        f"COALESCE(NULLIF({payload}, ''), CASE WHEN json_valid(COALESCE({projected}, ''))"
        f" THEN json_extract({projected}, '$.body') END)"
    )


# audit_hook_lone: the hook_decision rows that are their decision's only
# local hook row, written by a 1.0.10 gateway with the row
# (internal/audit/hook_row_tracking.go, rel-1-0-10:GAP-0316). It answers the
# lone rule by key instead of a pass over every hook row's projected record.
HOOK_ROWS_TABLE = "audit_hook_lone"


def lone_hook_decision_rows_sql(alias: str = "lone") -> str:
    """``FROM ... WHERE ...`` of the lone hook_decision rows, driven from audit_hook_lone.

    Columns of the rows are ``{alias}.<column>``. Use only on a store that has
    the table (:func:`lone_hook_decision_sql` otherwise).
    """

    return (
        f"FROM {HOOK_ROWS_TABLE} AS hook_lone CROSS JOIN audit_events AS {alias} ON {alias}.id = hook_lone.audit_event_id"
        f" WHERE {alias}.action = '{HOOK_DECISION_ACTION}'"
    )


def lone_hook_decision_sql(alias: str = "", table: str = "audit_events", tracked: bool = False) -> str:
    """SQL predicate: the row is a hook_decision row that is its decision's only hook row.

    ``tracked`` reads audit_hook_lone (one key lookup per row). Without it,
    on a store no 1.0.10 gateway has opened, the connector-hook ids of the
    subquery are computed once per statement (an uncorrelated ``NOT IN``), so a
    scan costs one pass over each kind's projected records.
    """

    prefix = f"{alias}." if alias else ""
    if tracked:
        row = f"{alias}.id" if alias else f"{table}.id"
        return (
            f"({prefix}action = '{HOOK_DECISION_ACTION}' AND EXISTS (SELECT 1 FROM {HOOK_ROWS_TABLE} AS hook_lone"
            f" WHERE hook_lone.audit_event_id = {row}))"
        )
    own = hook_semantic_event_id_sql(f"{prefix}projected_record_json")
    sibling = hook_semantic_event_id_sql("sibling.projected_record_json")
    return (
        f"({prefix}action = '{HOOK_DECISION_ACTION}'"
        f" AND {own} IS NOT NULL"
        f" AND {own} NOT IN (SELECT {sibling} FROM {table} AS sibling"
        f" WHERE sibling.action IN ('{CONNECTOR_HOOK_PAIR_ACTIONS[0]}', '{CONNECTOR_HOOK_PAIR_ACTIONS[1]}')"
        f" AND {sibling} IS NOT NULL))"
    )
