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

"""Scanner settings derived from config (scanners.skill_scanner / mcp_scanner).

Mirrors ``internal/config/scanner_settings.go``. Everything a scanner does is
derived from config: the policy, the judge (the top-level ``llm:`` block, or
the scanner's own block with ``judge_source: override``), the gate, the
optional analyzers and the scanner environment.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import threading
from collections.abc import Iterator, Mapping
from typing import Any

# The scanner versions this release pins (pyproject.toml; checked by
# cli/tests/test_dependency_contract.py and reported by doctor).
SKILL_SCANNER_DIST = "cisco-ai-skill-scanner"
SKILL_SCANNER_VERSION = "2.2.1"
MCP_SCANNER_DIST = "cisco-ai-mcp-scanner"
# TODO(mcp-scanner 4.8.x): 4.8.x pins litellm==1.93.0 (CVE-2026-84377);
# move when upstream relaxes that pin (see pyproject.toml).
MCP_SCANNER_VERSION = "4.3.0"
# The LiteLLM both scanners call (pyproject.toml: >=1.91.5,<1.92.0). 1.91.5 is
# the first release with the CVE-2026-84377 fix.
LITELLM_DIST = "litellm"
LITELLM_MIN_VERSION = (1, 91, 5)

# The recommended setup (the skill scanner's "Lowest FPR" settings): the
# quiet policy with the LLM judge, block at HIGH, review MEDIUM and above.
POLICY_QUIET = "quiet"
POLICY_CUSTOM = "custom"
POLICY_PRESETS = ("strict", "balanced", "permissive", "low-noise", POLICY_QUIET)
DEFAULT_POLICY = POLICY_QUIET
DEFAULT_FAIL_ON_SEVERITY = "HIGH"
DEFAULT_REVIEW_QUEUE_MIN = "MEDIUM"
RECOMMENDED_JUDGE_MODEL = "anthropic/claude-sonnet-5-5"
JUDGE_INHERIT = "inherit"
JUDGE_OVERRIDE = "override"

# What doctor and the setup wizard say when no judge can run. Rules-only is
# never offered as a recommended setup.
ADD_JUDGE_HINT = "Add an LLM judge (`defenseclaw setup llm`) or the local vLLM option"
# vLLM must serve JSON without whitespace padding, or about half of the
# judge's analyses are lost at the token limit.
VLLM_SERVE_HINT = (
    "vllm serve <weights> --served-model-name <name> "
    "--structured-outputs-config '{\"backend\": \"xgrammar\", \"disable_any_whitespace\": true}'"
)

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# DefenseClaw provider names the scanner reaches through its
# openai-compatible route (a base URL and the served model name).
OPENAI_COMPATIBLE_PROVIDERS = frozenset(
    {"openai-compatible", "custom-openai", "vllm", "lm_studio", "lmstudio", "local"}
)

# Inherited variables of these families never reach a scanner unless
# config sets them (the shell must not change a scan).
_SCANNER_ENV_PREFIXES = ("SKILL_SCANNER_", "AI_DEFENSE_", "MCP_SCANNER_", "VIRUSTOTAL_")


def effective_policy(sc: Any) -> str:
    """The policy name ("" is the recommended quiet preset)."""
    return (getattr(sc, "policy", "") or "").strip() or DEFAULT_POLICY


def effective_fail_on_severity(sc: Any) -> str:
    return (getattr(sc, "fail_on_severity", "") or "").strip().upper() or DEFAULT_FAIL_ON_SEVERITY


def effective_review_queue_min(sc: Any) -> str:
    return (getattr(sc, "review_queue_min", "") or "").strip().upper() or DEFAULT_REVIEW_QUEUE_MIN


def virustotal_enabled(sc: Any) -> bool:
    """analyzers.virustotal.enabled, or the v8 use_virustotal migration input."""
    analyzers = getattr(sc, "analyzers", None)
    vt = getattr(analyzers, "virustotal", None)
    return bool(getattr(vt, "enabled", False) or getattr(sc, "use_virustotal", False))


def aidefense_enabled(sc: Any) -> bool:
    analyzers = getattr(sc, "analyzers", None)
    aid = getattr(analyzers, "aidefense", None)
    return bool(getattr(aid, "enabled", False) or getattr(sc, "use_aidefense", False))


def osv_enabled(sc: Any) -> bool:
    analyzers = getattr(sc, "analyzers", None)
    return bool(getattr(getattr(analyzers, "osv", None), "enabled", False))


def virustotal_key_env(sc: Any) -> str:
    analyzers = getattr(sc, "analyzers", None)
    vt = getattr(analyzers, "virustotal", None)
    return (
        (getattr(vt, "api_key_env", "") or "").strip()
        or (getattr(sc, "virustotal_api_key_env", "") or "").strip()
        or "VIRUSTOTAL_API_KEY"
    )


def derived_admission_actions(sc: Any) -> dict[str, str]:
    """admission.skill.actions when unset: derived from the scanner gate.

    Severities at or above fail_on_severity quarantine, the review band
    [review_queue_min, fail_on_severity) warns, and anything below is
    allowed. An explicit admission.skill.actions wins.
    """
    gate = _SEVERITY_RANK[effective_fail_on_severity(sc)]
    review = _SEVERITY_RANK[effective_review_queue_min(sc)]
    out: dict[str, str] = {}
    for severity, rank in _SEVERITY_RANK.items():
        if rank >= gate:
            out[severity.lower()] = "quarantine"
        elif rank >= review:
            out[severity.lower()] = "warn"
        else:
            out[severity.lower()] = "allow"
    return out


def normalize_mcp_analyzers(raw: Any) -> list[str]:
    """The MCP analyzer list; ``[]`` is auto (YARA, plus the LLM when ready).

    Accepts the v8 comma-separated string or a v9 list. ``"auto"``, ``""``
    and ``[]`` are auto. ``"auto"`` inside a list stands for YARA, so the
    ``auto,llm`` the v8 setup wizard wrote keeps YARA instead of dropping it.
    """
    parts = raw if isinstance(raw, (list, tuple)) else str(raw or "").split(",")
    names: list[str] = []
    auto = False
    for part in parts:
        for piece in str(part).split(","):
            name = piece.strip().lower()
            if not name:
                continue
            if name == "auto":
                auto = True
            elif name not in names:
                names.append(name)
    if names and auto and "yara" not in names:
        names.insert(0, "yara")
    return names


def judge_route(llm: Any, model: str) -> tuple[str | None, str]:
    """The scanner's ``(llm_provider, model)`` for a resolved LLM.

    The scanner's provider override knows anthropic, openai and
    openai-compatible. openai-compatible servers (vLLM, LM Studio, a
    gateway) get the served model name; every other provider routes by its
    LiteLLM model prefix, so no provider is passed.
    """
    prefix = (llm.provider_prefix() if hasattr(llm, "provider_prefix") else "") or ""
    if prefix in OPENAI_COMPATIBLE_PROVIDERS:
        if model.lower().startswith(prefix + "/"):
            model = model[len(prefix) + 1:]
        return "openai-compatible", model
    return None, model


def verified_asset_bytes(path: str, digest: str) -> bytes:
    """Read *path* and check it against ``sha256:<hex>``; raise on mismatch."""
    want = (digest or "").strip().lower()
    if not want.startswith("sha256:") or len(want) != len("sha256:") + 64:
        raise ValueError(f"{path}: digest must be sha256:<64 hex>")
    with open(path, "rb") as fh:
        data = fh.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError(f"{path}: larger than 16 MiB")
    got = hashlib.sha256(data).hexdigest()
    if got != want[len("sha256:"):]:
        raise ValueError(f"{path}: digest mismatch (file is sha256:{got})")
    return data


def _drop_inherited(name: str) -> bool:
    upper = name.upper()
    if upper.startswith("ENABLE_") and upper.endswith("_ANALYZER"):
        return True
    return upper.startswith(_SCANNER_ENV_PREFIXES)


_env_lock = threading.Lock()
_env_depth = 0
_env_saved: dict[str, str | None] = {}


def _remember(name: str) -> None:
    if name not in _env_saved:
        _env_saved[name] = os.environ.get(name)


@contextlib.contextmanager
def scanner_env(values: Mapping[str, str]) -> Iterator[None]:
    """Run a scan with the scanner environment built from config only.

    Sets every non-empty value (config wins over the shell) and removes the
    inherited scanner families (``SKILL_SCANNER_*``, ``ENABLE_*_ANALYZER``,
    ``AI_DEFENSE_*``, ``MCP_SCANNER_*``, ``VIRUSTOTAL_*``) that config did
    not set. The previous environment comes back when the outermost scan
    ends; concurrent scans of one batch share the same derived values.
    """
    global _env_depth
    with _env_lock:
        if _env_depth == 0:
            for name in [n for n in os.environ if _drop_inherited(n)]:
                _remember(name)
                del os.environ[name]
        for name, value in values.items():
            if value:
                _remember(name)
                os.environ[name] = value
        _env_depth += 1
    try:
        yield
    finally:
        with _env_lock:
            _env_depth -= 1
            if _env_depth == 0:
                for name, value in _env_saved.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
                _env_saved.clear()


def recommended_settings_issue(cfg: Any) -> str:
    """Why the skill scanner is not on the recommended setup, or "".

    The recommendation is the quiet policy with the LLM judge. With no
    usable judge the scanner still runs its static rules with the same
    policy, and the fix is a judge, never a rules-only setup.
    """
    from defenseclaw.scanner._llm_env import litellm_model, llm_analyzer_ready

    sc = cfg.scanners.skill_scanner
    llm = cfg.resolve_llm("scanners.skill")
    model = litellm_model(llm)
    if not getattr(sc, "use_llm", False) or not model or not llm_analyzer_ready(llm, model=model):
        return f"the LLM judge is off; {ADD_JUDGE_HINT}"
    if effective_policy(sc) != POLICY_QUIET:
        return f"policy {effective_policy(sc)}; recommended: quiet + judge"
    return ""
