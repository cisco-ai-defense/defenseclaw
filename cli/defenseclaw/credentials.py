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

"""Central credential registry.

Single source of truth for every environment variable DefenseClaw reads.
Each entry has a predicate that classifies it against the *current*
``Config`` — so a key the operator hasn't opted into is reported as
``NOT_USED`` rather than pestered as missing.

Consumed by:

* ``defenseclaw keys`` (list / set / fill-missing)
* ``defenseclaw quickstart`` (post-install summary)
* ``defenseclaw doctor`` (credentials section, replaces bespoke probes
  with a data-driven loop)

Keep this file free of heavy imports so importing ``credentials`` has
no side effects — it's loaded on every CLI invocation.
"""

from __future__ import annotations

import enum
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from defenseclaw.config import Config


class Requirement(str, enum.Enum):
    """How critical a credential is *given the current config*.

    Using an ``Enum`` with a ``str`` mixin keeps serialization in JSON
    output trivial (``json.dumps`` handles str subclasses natively) while
    still giving us typed comparisons.
    """

    REQUIRED = "REQUIRED"   # Feature is enabled and the key is mandatory.
    OPTIONAL = "OPTIONAL"   # Feature is enabled but the key is optional.
    NOT_USED = "NOT_USED"   # Feature is off — key is irrelevant right now.


@dataclass(frozen=True)
class CredentialSpec:
    """Declarative entry describing one credential we know about.

    ``env_name`` is the *canonical* name used when the operator has
    not overridden it via a ``*_env`` field in config. When
    ``effective_env_name`` is provided, it's consulted at classify
    time and, if it returns a non-empty string, takes precedence.
    This lets the registry track the real env var the user wired up
    (e.g. ``MY_CUSTOM_JUDGE_KEY``) instead of pretending the canonical
    one is expected.
    """

    env_name: str
    feature: str
    description: str
    required: Callable[[Config], Requirement]
    auto_detected: bool = False
    effective_env_name: Callable[[Config], str] | None = None

    def resolve_env_name(self, cfg: Config) -> str:
        """Return the env var name currently in effect for *cfg*."""
        if self.effective_env_name is not None:
            override = self.effective_env_name(cfg)
            if override:
                return override
        return self.env_name


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------
#
# Predicates are intentionally small and self-contained so they can be
# unit-tested without a full ``Config`` fixture. They each take a
# ``Config`` (positional) and return a ``Requirement``.
#
# Convention: when a feature is *disabled* we return ``NOT_USED``, never
# ``OPTIONAL``. ``OPTIONAL`` is reserved for "feature is on and this key
# would add capability but the operator can run without it".


def _openclaw_gateway_token(_cfg: Config) -> Requirement:
    # The gateway always needs an auth token to talk to OpenClaw.
    # We auto-detect it from ~/.openclaw/openclaw.json when available,
    # but it is still required — "REQUIRED but auto-detected" is shown
    # in the keys list UX as a friendly hint.
    return Requirement.REQUIRED


def _judge_api_key(cfg: Config) -> Requirement:
    gc = getattr(cfg, "guardrail", None)
    if gc is None or not gc.enabled:
        return Requirement.NOT_USED
    judge = getattr(gc, "judge", None)
    if judge is None or not judge.enabled:
        return Requirement.NOT_USED
    return Requirement.REQUIRED


def _cisco_ai_defense_key(cfg: Config) -> Requirement:
    gc = getattr(cfg, "guardrail", None)
    if gc is None or not gc.enabled:
        return Requirement.NOT_USED
    # The guardrail has three scanner modes (local | remote | both).
    # Remote and both send traffic to Cisco AI Defense, so the key is
    # required; local-only mode doesn't touch it.
    if gc.scanner_mode in ("remote", "both"):
        return Requirement.REQUIRED
    return Requirement.NOT_USED


def _virustotal_key(cfg: Config) -> Requirement:
    sc = getattr(cfg, "scanners", None)
    if sc is None:
        return Requirement.NOT_USED
    ss = getattr(sc, "skill_scanner", None)
    if ss is None or not getattr(ss, "use_virustotal", False):
        return Requirement.NOT_USED
    return Requirement.REQUIRED


def _splunk_token(cfg: Config) -> Requirement:
    # Splunk observability is opt-in; enabled only when the operator has
    # wired up a sink via `defenseclaw setup observability`.
    sp = getattr(cfg, "splunk", None)
    if sp is None or not getattr(sp, "enabled", False):
        return Requirement.NOT_USED
    return Requirement.REQUIRED


def _inspect_llm_key(cfg: Config) -> Requirement:
    # The inspect_llm analyzer is used by skill-scanner's LLM mode.
    # When the user hasn't turned on --use-llm, the key is not needed.
    sc = getattr(cfg, "scanners", None)
    if sc is None:
        return Requirement.NOT_USED
    ss = getattr(sc, "skill_scanner", None)
    if ss is None or not getattr(ss, "use_llm", False):
        return Requirement.NOT_USED
    # Even when the analyzer is on, operators can point at a local
    # model that needs no key — so it stays OPTIONAL rather than forced.
    return Requirement.OPTIONAL


# --- effective env-name overrides ---
#
# These mirror the predicates and answer "what env var did the operator
# actually configure?". Return "" to keep the canonical name.

def _judge_env(cfg: Config) -> str:
    gc = getattr(cfg, "guardrail", None)
    judge = getattr(gc, "judge", None) if gc is not None else None
    return getattr(judge, "api_key_env", "") if judge is not None else ""


def _cisco_env(cfg: Config) -> str:
    cad = getattr(cfg, "cisco_ai_defense", None)
    return cad.api_key_env if cad is not None else ""


def _virustotal_env(cfg: Config) -> str:
    sc = getattr(cfg, "scanners", None)
    if sc is None:
        return ""
    ss = getattr(sc, "skill_scanner", None)
    return getattr(ss, "virustotal_api_key_env", "") or ""


def _splunk_env(cfg: Config) -> str:
    sp = getattr(cfg, "splunk", None)
    return getattr(sp, "hec_token_env", "") if sp is not None else ""


def _inspect_llm_env(cfg: Config) -> str:
    il = getattr(cfg, "inspect_llm", None)
    return il.api_key_env if il is not None else ""


def _llm_provider_key(cfg: Config) -> Requirement:
    # Generic LLM provider keys (ANTHROPIC/OPENAI/AZURE/etc.) are read
    # by OpenClaw's fetch interceptor from ``auth-profiles.json`` at
    # runtime — DefenseClaw itself never requires them. We surface them
    # as OPTIONAL when the guardrail is on so operators setting up
    # remote providers see the knob exists, and as NOT_USED when the
    # guardrail is disabled (they'd be irrelevant to DefenseClaw).
    gc = getattr(cfg, "guardrail", None)
    if gc is None or not gc.enabled:
        return Requirement.NOT_USED
    return Requirement.OPTIONAL


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CREDENTIALS: tuple[CredentialSpec, ...] = (
    CredentialSpec(
        env_name="OPENCLAW_GATEWAY_TOKEN",
        feature="gateway",
        description="Auth token for the OpenClaw gateway; auto-detected from ~/.openclaw/openclaw.json",
        required=_openclaw_gateway_token,
        auto_detected=True,
    ),
    CredentialSpec(
        env_name="JUDGE_API_KEY",
        feature="guardrail.judge",
        description="API key for the LLM Judge adjudicator (enabled via guardrail.judge.enabled)",
        required=_judge_api_key,
        effective_env_name=_judge_env,
    ),
    CredentialSpec(
        env_name="CISCO_AI_DEFENSE_API_KEY",
        feature="guardrail.remote",
        description="API key for Cisco AI Defense remote scanner (scanner_mode=remote|both)",
        required=_cisco_ai_defense_key,
        effective_env_name=_cisco_env,
    ),
    CredentialSpec(
        env_name="VIRUSTOTAL_API_KEY",
        feature="skill-scanner.virustotal",
        description="VirusTotal API key (skill-scanner --use-virustotal)",
        required=_virustotal_key,
        effective_env_name=_virustotal_env,
    ),
    CredentialSpec(
        env_name="SPLUNK_ACCESS_TOKEN",
        feature="observability.splunk",
        description="Splunk HEC token for audit forwarding",
        required=_splunk_token,
        effective_env_name=_splunk_env,
    ),
    CredentialSpec(
        env_name="ANTHROPIC_API_KEY",
        feature="providers.anthropic",
        description="Anthropic provider key (read by OpenClaw's fetch interceptor at runtime)",
        required=_llm_provider_key,
    ),
    CredentialSpec(
        env_name="OPENAI_API_KEY",
        feature="providers.openai",
        description="OpenAI provider key (read by OpenClaw's fetch interceptor at runtime)",
        required=_llm_provider_key,
    ),
    CredentialSpec(
        env_name="AZURE_OPENAI_API_KEY",
        feature="providers.azure",
        description="Azure OpenAI key (used alongside AZURE_OPENAI_ENDPOINT)",
        required=_llm_provider_key,
    ),
    CredentialSpec(
        env_name="GOOGLE_API_KEY",
        feature="providers.google",
        description="Google / Gemini provider key",
        required=_llm_provider_key,
    ),
    CredentialSpec(
        env_name="OPENROUTER_API_KEY",
        feature="providers.openrouter",
        description="OpenRouter provider key",
        required=_llm_provider_key,
    ),
    CredentialSpec(
        env_name="DEFENSECLAW_INSPECT_LLM_API_KEY",
        feature="skill-scanner.inspect_llm",
        description="Fallback LLM key for skill-scanner's LLM analyzer when inspect_llm.api_key_env is unset",
        required=_inspect_llm_key,
        effective_env_name=_inspect_llm_env,
    ),
)


# Map for fast lookup by env name — used by ``keys set`` and doctor.
_BY_NAME: dict[str, CredentialSpec] = {spec.env_name: spec for spec in CREDENTIALS}


def lookup(env_name: str) -> CredentialSpec | None:
    """Return the registered spec for *env_name*, or None if unknown."""
    return _BY_NAME.get(env_name)


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------
#
# We prefer to read the credential value without importing Click or
# touching cmd_setup's private helpers — keeping this module leaf-level
# makes it safe to import from anywhere. Implementation note: we peek
# at ``~/.defenseclaw/.env`` in addition to ``os.environ`` because the
# CLI process only ``_load_dotenv_into_os()``s after config load, so a
# fresh ``keys list`` run prior to load won't see the .env-only keys
# otherwise.


def _parse_dotenv(path: str) -> dict[str, str]:
    """Tiny, leaf-level .env reader with the same semantics as
    ``cmd_setup._load_dotenv``. Duplicated on purpose so importing
    ``credentials`` doesn't drag in the whole setup module.
    """
    result: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key, value = key.strip(), value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                if key:
                    result[key] = value
    except (FileNotFoundError, PermissionError):
        pass
    return result


@dataclass(frozen=True)
class Resolution:
    """Answer "is this credential set, and where did it come from?"."""

    env_name: str
    value: str
    source: str  # "env" | "dotenv" | "unset"

    @property
    def is_set(self) -> bool:
        return bool(self.value)


def resolve(env_name: str, data_dir: str) -> Resolution:
    """Resolve a credential value for display/use.

    Precedence: OS environment → ``~/.defenseclaw/.env`` → unset. We
    never return the secret back to the caller unmasked except to the
    ``keys set``/``quickstart`` flows that need to write it forward.
    """
    value = os.environ.get(env_name, "")
    if value:
        return Resolution(env_name=env_name, value=value, source="env")
    dotenv_val = _parse_dotenv(os.path.join(data_dir, ".env")).get(env_name, "")
    if dotenv_val:
        return Resolution(env_name=env_name, value=dotenv_val, source="dotenv")
    return Resolution(env_name=env_name, value="", source="unset")


def mask(secret: str) -> str:
    """Reveal only 4 chars on each side; short secrets are fully masked."""
    if len(secret) <= 8:
        return "****" if secret else ""
    return f"{secret[:4]}…{secret[-4:]}"


# ---------------------------------------------------------------------------
# High-level classification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CredentialStatus:
    """What `defenseclaw keys list` / doctor need to know per entry."""

    spec: CredentialSpec
    requirement: Requirement
    resolution: Resolution

    @property
    def missing(self) -> bool:
        """True when the credential is required and unset."""
        return self.requirement is Requirement.REQUIRED and not self.resolution.is_set


def classify(cfg: Config) -> list[CredentialStatus]:
    """Classify every registered credential against the current config.

    The order follows ``CREDENTIALS`` so the UX is stable across runs.
    We resolve ``effective_env_name`` so when the operator has
    configured a custom env var (e.g. ``judge.api_key_env``), we show
    the name they actually wired up — not the canonical default.
    """
    data_dir = getattr(cfg, "data_dir", "") or ""
    statuses: list[CredentialStatus] = []
    for spec in CREDENTIALS:
        env_name = spec.resolve_env_name(cfg)
        statuses.append(
            CredentialStatus(
                spec=spec,
                requirement=spec.required(cfg),
                resolution=resolve(env_name, data_dir),
            )
        )
    return statuses


def missing_required(cfg: Config) -> list[CredentialStatus]:
    """Convenience: only REQUIRED credentials that are currently unset."""
    return [s for s in classify(cfg) if s.missing]
