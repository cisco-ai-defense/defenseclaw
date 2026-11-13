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

"""The guardrail cascade (``guardrail.cascade``) as the gateway resolves it.

The gateway is the one resolver (``internal/config/cascade.go``): this module
asks ``defenseclaw-gateway policy cascade --json`` and never re-implements
the precedence, the validation or the fallback.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


def configured(cfg: Any) -> bool:
    """Whether any scope of the configuration sets ``guardrail.cascade``."""
    gc = getattr(cfg, "guardrail", None)
    if gc is None:
        return False
    if getattr(gc, "cascade", None):
        return True
    for entry in (getattr(gc, "connectors", None) or {}).values():
        if getattr(entry, "cascade", None):
            return True
    for profile in (getattr(gc, "profiles", None) or {}).values():
        if getattr(profile, "cascade", None):
            return True
        for entry in (getattr(profile, "connectors", None) or {}).values():
            if getattr(entry, "cascade", None):
                return True
    return False


def gateway_explain(
    connector: str = "", profile: str = "", input_path: str = "", *, as_json: bool = True, timeout: float = 30.0
) -> tuple[Any, str]:
    """Run ``defenseclaw-gateway policy cascade``. Returns (payload, error):
    the parsed JSON (or the text when ``as_json`` is false), else "" and why."""
    from defenseclaw.gateway import resolve_gateway_binary

    binary = resolve_gateway_binary()
    if not binary:
        return None, "defenseclaw-gateway is not installed; the gateway resolves the cascade"
    argv = [binary, "policy", "cascade"]
    if connector:
        argv += ["--connector", connector]
    if profile:
        argv += ["--profile", profile]
    if input_path:
        argv += ["--input", input_path]
    if as_json:
        argv.append("--json")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv, capture_output=True, text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"defenseclaw-gateway policy cascade did not answer ({exc.__class__.__name__})"
    if proc.returncode != 0:
        return None, (proc.stderr.strip() or proc.stdout.strip())[-400:] or "defenseclaw-gateway policy cascade failed"
    if not as_json:
        return proc.stdout, ""
    try:
        return json.loads(proc.stdout), ""
    except ValueError:
        return None, "defenseclaw-gateway policy cascade printed no JSON"


def loosening_notes(cascade: dict[str, Any]) -> list[str]:
    """Settings that let the guardrail do less than the pack would."""
    notes: list[str] = []
    if cascade.get("critical_floor") == "log":
        notes.append("admin.critical_floor is log: a proven CRITICAL finding can end as a log entry")
    policy = cascade.get("policy") or {}
    if policy.get("active") and policy.get("lowest") in {"allow", "log"}:
        notes.append(f"policy.lowest is {policy.get('lowest')}: the Rego policy may silence a flagged call")
    rules = cascade.get("rules") or {}
    unknown = cascade.get("unknown") or {}
    if rules.get("tier") == "strict" and unknown.get("action") != "block":
        notes.append(f"unknown is {unknown.get('action')} in the strict pack (the pack blocks unknown cases)")
    judge = cascade.get("judge") or {}
    if judge.get("runs") not in {None, "off"} and judge.get("max_action") in {"log", "alert"}:
        notes.append(f"judge.max_action is {judge.get('max_action')}: the judge cannot block or ask")
    system_one = cascade.get("system_one") or {}
    if system_one.get("runs") == "alone" and system_one.get("on_unsure") == "rules":
        notes.append("system_one.on_unsure is rules: an unsure System One answer adds nothing")
    return notes
