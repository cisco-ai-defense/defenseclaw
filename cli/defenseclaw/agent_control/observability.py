"""Asynchronous DefenseClaw enforcement visibility for Agent Control.

The gateway remains the only runtime enforcement authority. This module tails
the configured structured event stream from the separate synchronizer process
and reports final, Agent-Control-managed block decisions through the Agent
Control SDK observability sink.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import uuid
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .models import RULE_PACK_EVALUATOR
from .state import SyncState, utc_now

logger = logging.getLogger(__name__)

MAX_EVENT_LINE_BYTES = 1024 * 1024
MAX_EVENTS_PER_POLL = 1000
MAX_RULE_IDS = 8
MAX_CONTENT_CACHE_ENTRIES = 1024
MAX_FORWARDED_CONTENT_CHARS = 64 * 1024
_HEX_TRACE_ID = re.compile(r"^[0-9a-fA-F]{32}$")


class EventSDK(Protocol):
    def write_events(self, events: Sequence[Any]) -> Any: ...


@dataclass(frozen=True)
class RuleControl:
    control_id: int
    control_name: str
    confidences: dict[str, float]


def build_rule_control_index(controls: list[dict[str, Any]]) -> dict[str, tuple[RuleControl, ...]]:
    """Index effective rule-pack controls by the native rule IDs they own.

    The policy projection layer performs the authoritative closed-schema
    validation before this function is called.  This second defensive pass
    refuses malformed observability identities rather than inventing a control
    ID that Agent Control could not correlate.
    """

    by_rule: dict[str, list[RuleControl]] = {}
    for borrowed in controls:
        if not isinstance(borrowed, dict):
            continue
        control = borrowed.get("control")
        if not isinstance(control, dict):
            continue
        condition = control.get("condition")
        evaluator = condition.get("evaluator") if isinstance(condition, dict) else None
        if not isinstance(evaluator, dict) or evaluator.get("name") != RULE_PACK_EVALUATOR:
            continue
        control_id = borrowed.get("id")
        control_name = borrowed.get("name")
        if isinstance(control_id, bool) or not isinstance(control_id, int) or control_id <= 0:
            logger.warning("Skipping Agent Control rule telemetry with an invalid control id")
            continue
        if not isinstance(control_name, str) or not control_name.strip():
            logger.warning("Skipping Agent Control rule telemetry with an invalid control name")
            continue
        config = evaluator.get("config")
        rule_pack = config.get("rule_pack") if isinstance(config, dict) else None
        rules = rule_pack.get("rules") if isinstance(rule_pack, dict) else None
        if not isinstance(rules, list):
            continue
        confidences: dict[str, float] = {}
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("id")
            confidence = rule.get("confidence")
            if not isinstance(rule_id, str) or not rule_id:
                continue
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                continue
            confidences[rule_id] = float(confidence)
        ref = RuleControl(control_id=control_id, control_name=control_name.strip(), confidences=confidences)
        for rule_id in confidences:
            by_rule.setdefault(rule_id, []).append(ref)

    return {
        rule_id: tuple(sorted(refs, key=lambda ref: (ref.control_id, ref.control_name)))
        for rule_id, refs in by_rule.items()
    }


class EnforcementEventBridge:
    """Tail final block verdicts and enqueue correlated SDK control events."""

    def __init__(
        self,
        *,
        event_log_path: Path,
        agent_name: str,
        sdk: EventSDK,
        state: SyncState,
        include_content: bool = True,
        event_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.event_log_path = event_log_path
        self.agent_name = agent_name
        self.sdk = sdk
        self.state = state
        self.include_content = include_content
        self.event_factory = event_factory or _agent_control_event
        self._controls_by_rule: dict[str, tuple[RuleControl, ...]] = {}
        self._content_by_request: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()

    def update_controls(self, controls: list[dict[str, Any]]) -> None:
        self._controls_by_rule = build_rule_control_index(controls)

    def poll(self) -> bool:
        """Process a bounded number of complete log records.

        Returns ``True`` when the persisted diagnostic/cursor state changed.
        A failed SDK enqueue leaves the cursor on the source record.  Retried
        events have deterministic execution IDs, and Agent Control's event
        store de-duplicates those IDs.
        """

        try:
            fd, file_stat = self._open_event_log()
        except FileNotFoundError:
            return self._set_waiting_for_log()
        except OSError as exc:
            return self._set_error(f"event log unavailable ({type(exc).__name__})")

        changed = False
        try:
            identity = (int(file_stat.st_dev), int(file_stat.st_ino))
            previous = (self.state.observability_log_device, self.state.observability_log_inode)
            source_path = str(self.event_log_path.resolve())
            if self.state.observability_log_path != source_path or previous == (None, None):
                # A newly enabled bridge or a content-mode source change
                # observes new decisions only. It must not upload historical
                # endpoint activity merely because the configured log changed.
                self.state.observability_log_path = source_path
                self.state.observability_log_device, self.state.observability_log_inode = identity
                self.state.observability_log_offset = int(file_stat.st_size)
                self.state.observability_status = "watching"
                self.state.observability_last_error = None
                return True
            if previous != identity:
                # lumberjack renamed the old file and created this one.  The
                # new file is processed from byte zero.
                self.state.observability_log_device, self.state.observability_log_inode = identity
                self.state.observability_log_offset = 0
                changed = True
            elif self.state.observability_log_offset > file_stat.st_size:
                # Copy-truncate or an operator reset.
                self.state.observability_log_offset = 0
                changed = True

            with os.fdopen(fd, "rb", closefd=False) as handle:
                handle.seek(self.state.observability_log_offset)
                for _ in range(MAX_EVENTS_PER_POLL):
                    start_offset = handle.tell()
                    line = handle.readline(MAX_EVENT_LINE_BYTES + 1)
                    if not line:
                        break
                    if len(line) > MAX_EVENT_LINE_BYTES:
                        if not line.endswith(b"\n"):
                            while line and not line.endswith(b"\n"):
                                line = handle.readline(MAX_EVENT_LINE_BYTES + 1)
                        self.state.observability_invalid_records += 1
                        self.state.observability_log_offset = handle.tell()
                        changed = True
                        continue
                    if not line.endswith(b"\n"):
                        # The gateway may still be writing this record.
                        handle.seek(start_offset)
                        break

                    next_offset = handle.tell()
                    try:
                        source = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        self.state.observability_invalid_records += 1
                        self.state.observability_log_offset = next_offset
                        changed = True
                        continue

                    events, relevant = self._events_for_source(source)
                    if relevant:
                        self.state.observability_last_observed_at = _safe_timestamp(source.get("ts")) or utc_now()
                    if relevant and not events:
                        self.state.observability_unmapped_records += 1
                    if events and not self._enqueue(events):
                        self.state.observability_dropped_events += len(events)
                        self.state.observability_status = "degraded"
                        self.state.observability_last_error = "Agent Control SDK observability sink rejected an event"
                        return True
                    if events:
                        self.state.observability_sent_events += len(events)
                        self.state.observability_last_sent_at = utc_now()
                    if relevant:
                        self._forget_content(source)
                    self.state.observability_log_offset = next_offset
                    changed = True

            if self.state.observability_status != "watching" or self.state.observability_last_error is not None:
                self.state.observability_status = "watching"
                self.state.observability_last_error = None
                changed = True
            return changed
        finally:
            os.close(fd)

    def _open_event_log(self) -> tuple[int, os.stat_result]:
        before = self.event_log_path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("unsafe gateway event log")
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and before.st_uid != geteuid():
            raise OSError("gateway event log has unexpected owner")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.event_log_path, flags)
        try:
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise OSError("gateway event log changed while opening")
            return fd, after
        except Exception:
            os.close(fd)
            raise

    def _events_for_source(self, source: Any) -> tuple[list[Any], bool]:
        if not isinstance(source, dict):
            return [], False
        if source.get("event_type") == "llm_prompt":
            self._remember_prompt(source)
            return [], False
        if source.get("event_type") != "verdict":
            return [], False
        verdict = source.get("verdict")
        if not isinstance(verdict, dict) or verdict.get("stage") != "final" or verdict.get("action") != "block":
            return [], False
        raw_rule_ids = verdict.get("rule_ids")
        rule_id_candidates = raw_rule_ids[:MAX_RULE_IDS] if isinstance(raw_rule_ids, list) else []
        rule_ids = list(
            dict.fromkeys(
                rule_id
                for rule_id in rule_id_candidates
                if isinstance(rule_id, str) and rule_id in self._controls_by_rule
            )
        )
        # Older v7 gateway builds populated categories as
        # ``<rule-id>:<title>`` but did not yet populate Verdict.RuleIDs.  Only
        # accept a prefix that is already in the effective control index; do
        # not parse the free-form/redacted reason field.
        if not rule_ids:
            categories = verdict.get("categories")
            if isinstance(categories, list):
                for category in categories[:MAX_RULE_IDS]:
                    if not isinstance(category, str):
                        continue
                    candidate = category.split(":", 1)[0]
                    if candidate in self._controls_by_rule and candidate not in rule_ids:
                        rule_ids.append(candidate)
        controls: dict[int, RuleControl] = {}
        matched_by_control: dict[int, list[str]] = {}
        for rule_id in rule_ids:
            for control in self._controls_by_rule.get(rule_id, ()):
                controls[control.control_id] = control
                matched_by_control.setdefault(control.control_id, []).append(rule_id)

        trace_id = _trace_id(source)
        timestamp = _safe_timestamp(source.get("ts")) or utc_now()
        request_fingerprint = _source_fingerprint(source)
        applies_to = "tool_call" if source.get("direction") == "tool_call" or source.get("tool_name") else "llm_call"
        check_stage = "post" if source.get("direction") == "completion" else "pre"
        content_key = _content_key(source)
        content = self._content_by_request.get(content_key) if content_key is not None else None
        events: list[Any] = []
        for control_id in sorted(controls):
            control = controls[control_id]
            matched_rule_ids = matched_by_control[control_id]
            confidence = max(control.confidences[rule_id] for rule_id in matched_rule_ids)
            span_id = hashlib.sha256(f"{request_fingerprint}:{control_id}".encode()).hexdigest()[:16]
            execution_id = str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"defenseclaw:agent-control:{request_fingerprint}:{control_id}")
            )
            metadata = {
                "source": "defenseclaw.gateway",
                "source_event_type": "verdict",
                "source_action": "block",
                "source_stage": "final",
                "severity": str(source.get("severity") or ""),
                "direction": str(source.get("direction") or ""),
                "rule_ids": matched_rule_ids,
            }
            for key in ("request_id", "evaluation_id", "connector", "policy_id"):
                value = verdict.get(key) if key == "evaluation_id" else source.get(key)
                if isinstance(value, str) and value:
                    metadata[key] = value
            if self.include_content:
                if content:
                    metadata["blocked_input"] = content
                reason = verdict.get("reason")
                if isinstance(reason, str) and reason:
                    metadata["verdict_reason"] = _bounded_content(reason)[0]
                metadata["content_unredacted"] = not _contains_redaction_marker(metadata)
            events.append(
                self.event_factory(
                    control_execution_id=execution_id,
                    trace_id=trace_id,
                    span_id=span_id,
                    agent_name=self.agent_name,
                    control_id=control.control_id,
                    control_name=control.control_name,
                    check_stage=check_stage,
                    applies_to=applies_to,
                    action="deny",
                    matched=True,
                    confidence=confidence,
                    timestamp=timestamp,
                    execution_duration_ms=_nonnegative_number(verdict.get("latency_ms")),
                    evaluator_name=RULE_PACK_EVALUATOR,
                    selector_path="*",
                    metadata=metadata,
                )
            )
        return events, True

    def _remember_prompt(self, source: dict[str, Any]) -> None:
        if not self.include_content:
            return
        content_key = _content_key(source)
        prompt = source.get("llm_prompt")
        if content_key is None or not isinstance(prompt, dict):
            return
        content: dict[str, Any] = {}
        truncated = False
        for source_key, output_key in (
            ("prompt", "prompt"),
            ("raw_request_body", "raw_request_body"),
            ("role", "role"),
            ("source", "source"),
        ):
            value = prompt.get(source_key)
            if isinstance(value, str) and value:
                bounded, was_truncated = _bounded_content(value)
                content[output_key] = bounded
                truncated = truncated or was_truncated
        if not content:
            return
        content["truncated"] = truncated
        self._content_by_request[content_key] = content
        self._content_by_request.move_to_end(content_key)
        while len(self._content_by_request) > MAX_CONTENT_CACHE_ENTRIES:
            self._content_by_request.popitem(last=False)

    def _forget_content(self, source: dict[str, Any]) -> None:
        content_key = _content_key(source)
        if content_key is not None:
            self._content_by_request.pop(content_key, None)

    def _enqueue(self, events: list[Any]) -> bool:
        try:
            result = self.sdk.write_events(events)
        except Exception as exc:
            logger.warning("Agent Control enforcement event enqueue failed (%s)", type(exc).__name__)
            return False
        accepted = getattr(result, "accepted", 0)
        dropped = getattr(result, "dropped", len(events) - accepted if isinstance(accepted, int) else len(events))
        return accepted == len(events) and dropped == 0

    def _set_waiting_for_log(self) -> bool:
        changed = (
            self.state.observability_status != "waiting_for_log" or self.state.observability_last_error is not None
        )
        self.state.observability_status = "waiting_for_log"
        self.state.observability_last_error = None
        return changed

    def _set_error(self, message: str) -> bool:
        changed = self.state.observability_status != "degraded" or self.state.observability_last_error != message
        self.state.observability_status = "degraded"
        self.state.observability_last_error = message
        return changed


def _agent_control_event(**values: Any) -> Any:
    # Optional dependency: import only after the Agent Control integration has
    # been explicitly enabled and the SDK session initialized.
    from agent_control_models import ControlExecutionEvent

    return ControlExecutionEvent(**values)


def _source_fingerprint(source: dict[str, Any]) -> str:
    components = [
        str(source.get("run_id") or ""),
        str(source.get("request_id") or ""),
        str(source.get("ts") or ""),
        str((source.get("verdict") or {}).get("evaluation_id") or ""),
    ]
    return hashlib.sha256("\x1f".join(components).encode("utf-8")).hexdigest()


def _content_key(source: dict[str, Any]) -> tuple[str, str] | None:
    request_id = source.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return None
    run_id = source.get("run_id")
    return (run_id if isinstance(run_id, str) else "", request_id)


def _trace_id(source: dict[str, Any]) -> str:
    candidate = source.get("trace_id")
    if isinstance(candidate, str) and _HEX_TRACE_ID.fullmatch(candidate):
        return candidate.lower()
    return hashlib.sha256(f"defenseclaw-trace:{_source_fingerprint(source)}".encode()).hexdigest()[:32]


def _safe_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    return value


def _nonnegative_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return float(value)


def _bounded_content(value: str) -> tuple[str, bool]:
    if len(value) <= MAX_FORWARDED_CONTENT_CHARS:
        return value, False
    return value[:MAX_FORWARDED_CONTENT_CHARS], True


def _contains_redaction_marker(value: Any) -> bool:
    try:
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return True
    return "<redacted " in rendered
