# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RuntimeControlOutcome:
    decision: str
    severity: str
    reason: str
    policy_id: str


def evaluate_runtime_action(
    action: str,
    target: str | None = None,
    payload: str | None = None,
) -> RuntimeControlOutcome:
    """Deterministic Agent Control-like policy simulator for fixture tests.

    This is not a Galileo substitute. It lets the Cisco Cloud Control demo
    package generate and validate local control evidence with the same decisions
    the UI renders:
    allow, warn, deny, steer, log, and human_review.
    """
    text = " ".join([action or "", target or "", payload or ""]).lower()
    if any(term in text for term in ["delete prod", "drop table", "rm -rf", "exfiltrate"]):
        return RuntimeControlOutcome(
            decision="deny",
            severity="CRITICAL",
            reason="Destructive or exfiltration-like action blocked by runtime policy",
            policy_id="agent-control.destructive-action",
        )
    if any(term in text for term in ["ssn", "api_key", "secret", "password", "passport"]):
        return RuntimeControlOutcome(
            decision="human_review",
            severity="HIGH",
            reason="Sensitive data indicator requires human review before continuing",
            policy_id="agent-control.sensitive-data-review",
        )
    if any(term in text for term in ["expensive-model", "gpt-5", "large-context"]):
        return RuntimeControlOutcome(
            decision="steer",
            severity="MEDIUM",
            reason="Steer to cheaper model or trimmed context due to token/cost pressure",
            policy_id="agent-control.tokenomics-steering",
        )
    if any(term in text for term in ["untrusted", "external url", "web fetch"]):
        return RuntimeControlOutcome(
            decision="warn",
            severity="MEDIUM",
            reason="Untrusted input surface observed; continue with warning and audit",
            policy_id="agent-control.untrusted-input-warning",
        )
    return RuntimeControlOutcome(
        decision="allow",
        severity="INFO",
        reason="Action is read-only or within configured runtime policy",
        policy_id="agent-control.default-allow",
    )


def control_event_from_action(
    timestamp: str,
    action: str,
    target: str | None = None,
    payload: str | None = None,
) -> dict[str, Any]:
    outcome = evaluate_runtime_action(action, target, payload)
    seed = "|".join([timestamp, action or "", target or "", payload or ""]).encode("utf-8")
    digest = hashlib.sha1(seed).hexdigest()[:10]
    return {
        "timestamp": timestamp,
        "control_id": f"ctrl-{digest}",
        "policy_id": outcome.policy_id,
        "decision": outcome.decision,
        "severity": outcome.severity,
        "reason": outcome.reason,
        "target": target,
        "action": action,
    }
