# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The unified decision model: shared helpers for setup, init, doctor, the
TUI and the skill scanner.

The decision model is a small, fast model that speaks the System One
protocol (``POST {model, state, questions}``; answers carry calibrated
probabilities). The gateway runs it in front of the LLM judge on tool calls
(internal/gateway/decision_model.go); ``skill scan`` passes it to the skill
scanner's advisory System One tier. Settings live in ``decision_model:``;
the bearer token lives in the environment or ``~/.defenseclaw/.env``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from defenseclaw.config import (
    DECISION_MODEL_KEY_ENV,
    Config,
    DecisionModelConfig,
    decision_model_url_error,
)

INIT_QUESTION = "Do you want to use a decision model?"
DEFAULT_BASE_URL = "http://127.0.0.1:8791/v1/systemone"
BENCHMARK_URL = "https://huggingface.co/spaces/Vineethsain/defenseclaw-system-one"
DOCS_URL = "https://cisco-ai-defense.github.io/defenseclaw/docs/guardrail/decision-model/"

# A benign probe for --ping and doctor: the disposition question only.
_PING_STATE = {"current_tool_call": {"tool": "Read", "arguments": '{"file_path": "README.md"}'}}
_PING_QUESTIONS = {
    "disposition": {
        "type": "choice",
        "instructions": "Choose allow, confirm, or block for `current_tool_call`.",
        "criteria": {
            "allow": "Safe and bounded.",
            "confirm": "Consequential or uncertain.",
            "block": "Clear high-impact harm.",
        },
    }
}


class DecisionModelError(ValueError):
    """A decision_model setting that cannot be saved."""


def apply_settings(
    cfg: Config,
    *,
    enabled: bool | None = None,
    model: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
    timeout: float | None = None,
    allow_threshold: float | None = None,
    block_threshold: float | None = None,
    on_confident_block: str | None = None,
) -> DecisionModelConfig:
    """Apply the given fields to ``cfg.decision_model`` and validate the
    result. Raises DecisionModelError and leaves cfg unchanged on a bad
    value. The caller saves through the config writer."""
    current = cfg.decision_model
    updated = DecisionModelConfig(**{**current.__dict__})
    if enabled is not None:
        updated.enabled = bool(enabled)
    if model is not None:
        updated.model = model.strip()
    if base_url is not None:
        updated.base_url = base_url.strip()
    if api_key_env is not None:
        name = api_key_env.strip()
        if name == DECISION_MODEL_KEY_ENV:
            name = ""  # the default; keep the file minimal
        updated.api_key_env = name
    if timeout is not None:
        updated.timeout = float(timeout)
    if allow_threshold is not None:
        updated.allow_threshold = float(allow_threshold)
    if block_threshold is not None:
        updated.block_threshold = float(block_threshold)
    if on_confident_block is not None:
        updated.on_confident_block = on_confident_block.strip().lower()
    problem = updated.validation_error()
    if problem:
        raise DecisionModelError(f"decision_model: {problem}")
    cfg.decision_model = updated
    return updated


@dataclass(frozen=True)
class PingResult:
    ok: bool
    detail: str
    latency_ms: int = 0


def ping(
    dm: DecisionModelConfig, data_dir: str, *, timeout: float | None = None, send_token: bool = True
) -> PingResult:
    """Send one benign System One request and check the answer's shape.
    Never prints or returns the token."""
    import requests

    if not dm.base_url.strip() or not dm.model.strip():
        return PingResult(False, "decision_model.base_url and decision_model.model must be set")
    problem = decision_model_url_error(dm.base_url)
    if problem:
        return PingResult(False, problem)
    headers = {"Content-Type": "application/json"}
    bearer = dm.resolved_api_key(data_dir) if send_token else ""
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    body = json.dumps({"model": dm.model, "state": _PING_STATE, "questions": _PING_QUESTIONS})
    started = time.monotonic()
    try:
        resp = requests.post(
            dm.base_url.strip(),
            data=body,
            headers=headers,
            timeout=timeout or max(dm.effective_timeout(), 5.0),
            allow_redirects=False,
        )
    except requests.Timeout:
        return PingResult(False, "timed out")
    except requests.RequestException:
        return PingResult(False, "connection failed")
    latency = int((time.monotonic() - started) * 1000)
    if resp.status_code != 200:
        return PingResult(False, f"HTTP {resp.status_code}", latency)
    answer = _disposition(resp.content)
    if answer is None:
        return PingResult(False, "answer is not a System One disposition choice", latency)
    choice, p_allow = answer
    return PingResult(True, f"answered {choice} (risk {1 - p_allow:.2f}) in {latency} ms", latency)


def _disposition(raw: bytes) -> tuple[str, float] | None:
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        return None
    answers = payload.get("answers") if isinstance(payload, dict) else None
    answer = answers.get("disposition") if isinstance(answers, dict) else None
    if not isinstance(answer, dict) or answer.get("type") != "choice":
        return None
    choice = str(answer.get("choice", "")).lower()
    probs = answer.get("probabilities")
    if choice not in ("allow", "confirm", "block") or not isinstance(probs, dict):
        return None
    try:
        values = {str(k).lower(): float(v) for k, v in probs.items()}
    except (TypeError, ValueError):
        return None
    if "allow" not in values or not 0.98 <= sum(values.values()) <= 1.02:
        return None
    return choice, values["allow"]


def managed_host(cfg: Config) -> bool:
    """A standalone managed host: the gateway reads the token from the
    protected credential decision_model.credential, never the user's env."""
    try:
        return bool(cfg.managed_outside_secure_client())
    except Exception:  # noqa: BLE001 - a probe failure must not hide the setting
        return False


def token(cfg: Config) -> str:
    """The bearer token the CLI may send (ping, skill scan): env or .env
    on a per-user install, none on a managed host."""
    if managed_host(cfg):
        return ""
    return cfg.decision_model.resolved_api_key(cfg.data_dir)


def summary_rows(cfg: Config) -> list[tuple[str, str]]:
    """The setting as label/value rows, the token shown only as set/unset."""
    dm = cfg.decision_model
    key_env = dm.effective_api_key_env()
    key_state = "set" if token(cfg) else "not set (fine for a local server)"
    key_row = ("decision_model.api_key_env", f"{key_env} = {key_state}")
    if managed_host(cfg):
        key_row = ("decision_model.credential", dm.credential or "(none: no token is sent)")
    rows = [
        ("decision_model.enabled", "true" if dm.enabled else "false"),
        ("decision_model.model", dm.model or "(unset)"),
        ("decision_model.base_url", dm.base_url or "(unset)"),
        key_row,
        ("decision_model.timeout", f"{dm.effective_timeout():g}s"),
        ("decision_model.allow_threshold", f"{dm.effective_allow_threshold():.2f}"),
        ("decision_model.block_threshold", f"{dm.effective_block_threshold():.2f}"),
        ("decision_model.on_confident_block", dm.effective_on_confident_block()),
    ]
    return rows


def judge_note(cfg: Config) -> str:
    """Say when the guardrail cannot use the decision model yet."""
    if not cfg.decision_model.active():
        return ""
    if not cfg.guardrail.judge.enabled:
        return (
            "The guardrail runs the decision model in front of the LLM judge, which is off: "
            "tool calls keep today's rule verdicts until you turn the judge on "
            "(defenseclaw setup guardrail --detection-strategy regex_judge). skill scan uses it now."
        )
    return ""


def skill_scanner_options(cfg: Config) -> tuple[dict[str, Any], dict[str, str]]:
    """The skill scanner's System One arguments and environment, or empty
    when the decision model is off. The scanner's tier is advisory only: it
    records a probability and never changes a finding or the verdict."""
    dm = cfg.decision_model
    if not dm.active() or managed_host(cfg):
        # On a managed host the decision model is the gateway's alone.
        return {}, {}
    kwargs = {"system_one_endpoint": dm.base_url.strip(), "system_one_model": dm.model.strip()}
    env: dict[str, str] = {}
    bearer = token(cfg)
    if bearer:
        env["SKILL_SCANNER_SYSTEM_ONE_API_KEY"] = bearer
    return kwargs, env
