# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The unified decision model: shared helpers for setup, init, doctor, the
TUI and the skill scanner.

The decision model is a small, fast model that speaks the System One
protocol (``POST {model, state, questions}``; answers carry calibrated
probabilities), or with ``protocol: gemini-decisions`` Google's Decisions
API (Gemini Decision 1: ``POST {model, input, questions}``, the state as a
labeled string, the key in ``x-goog-api-key``). The gateway runs it on hook-lane tool calls
(internal/gateway/decision_model.go), per connector, in one of three
cascades: rules only, rules -> decision model, or rules -> decision model ->
LLM judge. ``skill scan`` passes it to the skill scanner's advisory System
One tier. Settings live in ``decision_model:``; the bearer token lives in the
environment or ``~/.defenseclaw/.env``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from defenseclaw import connector_paths
from defenseclaw.config import (
    DECISION_MODEL_KEY_ENV,
    DECISION_MODEL_PROTOCOL_GEMINI,
    Config,
    DecisionModelConfig,
    decision_model_url_error,
)

INIT_QUESTION = "Do you want to use a decision model?"
DEFAULT_BASE_URL = "http://127.0.0.1:8791/v1/systemone"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/decisions"
GEMINI_MODEL = "gemini-decision-1"
# Mirrors decisionModelInputLabel in internal/gateway/decision_model.go.
GEMINI_INPUT_LABEL = "STATE (untrusted JSON):\n"
# HTTP 400 error codes the Decisions API uses when its safety filters decline the input.
GEMINI_REFUSAL_CODES = frozenset({"safety", "prohibited_content", "blocklist", "image_safety", "content_blocked"})
BENCHMARK_URL = "https://huggingface.co/spaces/Vineethsain/defenseclaw-system-one"
DOCS_URL = "https://cisco-ai-defense.github.io/defenseclaw/docs/guardrail/decision-model/"

# A benign probe for --ping and doctor: the disposition question only.
CASCADE_RULES_ONLY = "rules only"
CASCADE_RULES_MODEL = "rules -> decision model"
CASCADE_RULES_JUDGE = "rules -> LLM judge"
CASCADE_RULES_MODEL_JUDGE = "rules -> decision model -> LLM judge"
_ALL = "*"

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
    protocol: str | None = None,
    api_key_env: str | None = None,
    timeout: float | None = None,
    allow_threshold: float | None = None,
    block_threshold: float | None = None,
    on_confident_block: str | None = None,
    hook_connectors: list[str] | None = None,
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
    if protocol is not None:
        name = protocol.strip().lower()
        updated.protocol = "" if name == "system-one" else name  # the default; keep the file minimal
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
    if hook_connectors is not None:
        updated.hook_connectors = parse_connectors(hook_connectors)
    problem = updated.validation_error()
    if problem:
        raise DecisionModelError(f"decision_model: {problem}")
    cfg.decision_model = updated
    return updated


def parse_connectors(value: str | list[str] | tuple[str, ...]) -> list[str]:
    """Connector names from a comma-separated string or a list: trimmed,
    lowercased, deduplicated, blanks dropped; ``*`` stands for all of them."""
    items = value.replace(";", ",").split(",") if isinstance(value, str) else list(value)
    names: list[str] = []
    for item in items:
        name = "*" if str(item).strip() == _ALL else connector_paths.normalize(str(item))
        if name and name not in names:
            names.append(name)
    return [_ALL] if _ALL in names else names


def _listed(names: list[str], connector: str) -> bool:
    """Case-insensitive membership in a connector gate list; ``*`` = all."""
    wanted = connector_paths.normalize(connector)
    for entry in names:
        entry = str(entry).strip()
        if entry == _ALL or (wanted and connector_paths.normalize(entry) == wanted):
            return True
    return False


def judge_runs_for(cfg: Config, connector: str) -> bool:
    """Whether the LLM judge reviews this connector's hook-lane tool calls.
    Mirrors the gateway (hookLaneJudge): the judge is built (on, with a model
    and, unless its provider signs without one, an API key), the connector is
    in guardrail.judge.hook_connectors and the effective tool-call strategy is
    not regex_only."""
    guardrail = cfg.guardrail
    if not guardrail.judge.enabled or not _listed(list(guardrail.judge.hook_connectors or []), connector):
        return False
    if not _judge_builds(cfg):
        return False
    strategy = (
        (guardrail.detection_strategy_tool_call or "").strip()
        or (guardrail.detection_strategy or "").strip()
        or "regex_judge"
    )
    return strategy.lower() != "regex_only"


def _judge_builds(cfg: Config) -> bool:
    """Whether the gateway can build the LLM judge (newLLMJudgeWithReason):
    a model, and a key unless the provider needs none."""
    try:
        llm = cfg.resolve_llm("guardrail.judge")
    except Exception:  # noqa: BLE001 - a config the CLI cannot resolve has no judge
        return False
    if not (llm.model or "").strip():
        return False
    if _judge_allows_empty_key(cfg, llm) or llm.resolved_api_key():
        return True
    from defenseclaw import credentials

    env = (llm.api_key_env or "").strip() or "DEFENSECLAW_LLM_KEY"
    return bool(credentials.resolve(env, cfg.data_dir).value)


def _judge_allows_empty_key(cfg: Config, llm: Any) -> bool:
    """Mirrors internal/gateway/llm_judge.go llmJudgeAllowsEmptyAPIKey: a local
    provider, or Bedrock (by provider, by the base type of a custom provider
    instance, or by the model's provider prefix) builds without a key."""
    if llm.is_local_provider():
        return True
    provider = (llm.provider or "").strip().lower()
    instance = (getattr(llm, "instance_name", "") or "").strip().lower()
    if provider in ("", "custom") and instance:
        for entry in _provider_instances(cfg):
            if str(entry.get("name", "")).strip().lower() == instance:
                provider = str(entry.get("base_provider_type", "")).strip().lower()
                break
    if not provider:
        provider = (llm.provider_prefix() or "").strip().lower()
    return provider in ("bedrock", "amazon-bedrock")


def _provider_instances(cfg: Config) -> list[dict]:
    """The custom provider instances (llm_providers, else a legacy
    custom-providers.json), as the gateway reads them; empty when none."""
    try:
        from defenseclaw import derived_providers

        return [dict(p) for p in derived_providers.configured_providers(cfg)]
    except Exception:  # noqa: BLE001 - no registry means no instance
        return []


def answers_alone_for(cfg: Config, connector: str) -> bool:
    """Whether the decision model answers this connector's tool calls with no
    judge behind it (cascade 2)."""
    dm = cfg.decision_model
    return (
        dm.active()
        and not judge_runs_for(cfg, connector)
        and _listed(list(dm.hook_connectors or []), connector)
    )


def cascade_for(cfg: Config, connector: str) -> str:
    """The tool-call cascade this connector runs, in words."""
    judge = judge_runs_for(cfg, connector)
    model = cfg.decision_model.active()
    if judge:
        return CASCADE_RULES_MODEL_JUDGE if model else CASCADE_RULES_JUDGE
    return CASCADE_RULES_MODEL if answers_alone_for(cfg, connector) else CASCADE_RULES_ONLY


def cascade_lines(cfg: Config) -> list[str]:
    """One ``connector: cascade`` entry per active connector."""
    return [f"{name}: {cascade_for(cfg, name)}" for name in cfg.active_connectors()]


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
    gemini = dm.effective_protocol() == DECISION_MODEL_PROTOCOL_GEMINI
    token_value = dm.resolved_api_key(data_dir) if send_token else ""
    if token_value:
        if gemini:
            headers["x-goog-api-key"] = token_value
        else:
            headers["Authorization"] = f"Bearer {token_value}"
    body = json.dumps(request_body(dm, _PING_STATE, _PING_QUESTIONS))
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
    if gemini and resp.status_code == 400:
        code = _error_code(resp.content)
        if code in GEMINI_REFUSAL_CODES:
            return PingResult(False, f"the model declined the probe ({code})", latency)
    if resp.status_code != 200:
        return PingResult(False, f"HTTP {resp.status_code}", latency)
    answer = _disposition(resp.content)
    if answer is None:
        return PingResult(False, "answer is not a System One disposition choice", latency)
    choice, p_allow = answer
    return PingResult(True, f"answered {choice} (risk {1 - p_allow:.2f}) in {latency} ms", latency)


def request_body(dm: DecisionModelConfig, state: dict, questions: dict) -> dict:
    """The request body in the endpoint's protocol. gemini-decisions has no
    state field: the state goes in ``input`` as labeled, 1-space indented
    JSON, as the gateway sends it."""
    if dm.effective_protocol() == DECISION_MODEL_PROTOCOL_GEMINI:
        return {
            "model": dm.model,
            "input": GEMINI_INPUT_LABEL + json.dumps(state, indent=1, ensure_ascii=False),
            "questions": questions,
        }
    return {"model": dm.model, "state": state, "questions": questions}


def _error_code(raw: bytes) -> str:
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        return ""
    error = payload.get("error") if isinstance(payload, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    return code.strip().lower() if isinstance(code, str) else ""


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
        ("decision_model.protocol", dm.effective_protocol()),
        key_row,
        ("decision_model.timeout", f"{dm.effective_timeout():g}s"),
        ("decision_model.allow_threshold", f"{dm.effective_allow_threshold():.2f}"),
        ("decision_model.block_threshold", f"{dm.effective_block_threshold():.2f}"),
        ("decision_model.on_confident_block", dm.effective_on_confident_block()),
        ("decision_model.hook_connectors", ", ".join(dm.hook_connectors) or "(none: only in front of the LLM judge)"),
        ("decision_model.call_effects", "true" if dm.call_effects else "false"),
    ]
    return rows


def judge_note(cfg: Config) -> str:
    """Say which active connectors get no decision model, and how to add them."""
    if not cfg.decision_model.active():
        return ""
    bare = [c for c in cfg.active_connectors() if cascade_for(cfg, c) == CASCADE_RULES_ONLY]
    if not bare:
        return ""
    listed = [c for c in cfg.decision_model.hook_connectors if c != _ALL]
    suggestion = ",".join([*listed, *[c for c in bare if c not in listed]])
    return (
        f"The decision model answers no tool calls for {', '.join(bare)} (rules only there: the LLM judge is off "
        f"for them). Add them with: defenseclaw setup decision-model --connectors {suggestion}. "
        "skill scan records its advisory score either way."
    )


def skill_scanner_options(cfg: Config) -> tuple[dict[str, Any], dict[str, str]]:
    """The skill scanner's System One arguments and environment, or empty
    when the decision model is off. The scanner's tier is advisory only: it
    records a probability and never changes a finding or the verdict."""
    dm = cfg.decision_model
    if not dm.active() or managed_host(cfg):
        # On a managed host the decision model is the gateway's alone.
        return {}, {}
    if dm.effective_protocol() == DECISION_MODEL_PROTOCOL_GEMINI:
        # The skill scanner's advisory tier speaks System One only.
        return {}, {}
    kwargs = {"system_one_endpoint": dm.base_url.strip(), "system_one_model": dm.model.strip()}
    env: dict[str, str] = {}
    bearer = token(cfg)
    if bearer:
        env["SKILL_SCANNER_SYSTEM_ONE_API_KEY"] = bearer
    return kwargs, env
