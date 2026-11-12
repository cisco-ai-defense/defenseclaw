"""Connector-scoped fail-mode resolution and transactional runtime refresh."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from defenseclaw import config as config_module
from defenseclaw.connector_contracts import HOOK_CONTRACTS, connector_lock_contract_invariant
from defenseclaw.connector_paths import (
    amp_policy_plugin_path,
    codex_home,
    connector_config_files,
    connector_home,
    copilot_home,
    hermes_config_path,
    normalize,
)
from defenseclaw.file_lock import _lock_file_exclusive, _unlock_file
from defenseclaw.gateway_path import path_gateway
from defenseclaw.winquote import powershell_command_line

_VALID_MODES = frozenset({"open", "closed"})
_MAX_RUNTIME_FILE = 2 * 1024 * 1024
# The gateway records the digest of the whole hook launcher with no size cap.
# An unstripped Windows source build (make all) of defenseclaw-hook.exe is
# about 148 MiB, so a 128 MiB cap hashed it as '' and reported
# registration-digest-stale on every check (GAP-1922).
_MAX_DIGEST_FILE = 1024 * 1024 * 1024
# The installed mode of a rendered Unix hook: FAIL_MODE="closed" since 1.0.4
# (the hook reads no fail mode from the environment, GAP-0315),
# FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-closed}" in 1.0.3 and older renders and
# in Secure Client renders (#1163).
_FAIL_MODE_PATTERN = re.compile(
    r"^FAIL_MODE=\"(?:(open|closed)|\$\{DEFENSECLAW_FAIL_MODE:-(open|closed)\})\"", re.MULTILINE
)
# A render whose fail mode takes DEFENSECLAW_FAIL_MODE from the agent's
# environment: every 0.8.x and 1.0.3 per-user render, and a Secure Client
# render (#1163). Such a hook runs open when the agent's environment says
# open, whatever its default, so its default is not the mode it runs.
_ENV_FAIL_MODE_PATTERN = re.compile(r"^[ \t]*(?:export[ \t]+)?FAIL_MODE=[^\n]*DEFENSECLAW_FAIL_MODE", re.MULTILINE)
_OPENCODE_FAIL_MODE_PATTERN = re.compile(r'const\s+DC_FAIL_MODE\s*=\s*"(open|closed)"\s*;')
_AMP_FAIL_MODE_PATTERN = re.compile(r'\bconst\s+DC_FAIL_MODE:\s*string\s*=\s*"(open|closed)"')
# A per-user plugin's gateway-outage mode (config.HookOutageFailMode); its
# DC_FAIL_MODE is closed for every other failure.
_OPENCODE_OUTAGE_PATTERN = re.compile(r'const\s+DC_OUTAGE_FAIL_MODE\s*=\s*"(open|closed)"\s*;')
_AMP_OUTAGE_PATTERN = re.compile(r'\bconst\s+DC_OUTAGE_FAIL_MODE:\s*string\s*=\s*"(open|closed)"')
_EXPECTED_CONTRACTS = {
    "amp": frozenset({"amp-plugin-v1"}),
    "claudecode": frozenset({"claudecode-hooks-v1", "claudecode-hooks-v2"}),
    "codex": frozenset(
        {
            "codex-hooks-v1",
            "codex-hooks-v2",
            "codex-hooks-v3",
            "codex-hooks-v3-generic",
            "codex-hooks-v4",
        }
    ),
    "devin": frozenset({"devin-hooks-v1"}),
}
# Copilot CLI, Antigravity and Hermes have no fail-closed hook contract of
# their own: each lets a call run when its hook times out or cannot start.
# Their hooks block every other failure through the agent's native deny when
# the fail mode is closed, so they follow it everywhere except under Secure
# Client (upstream_fail_open).
_UPSTREAM_FAIL_OPEN_CONNECTORS = frozenset({"antigravity", "copilot", "hermes"})
_UPSTREAM_LIMIT_LABELS = {"antigravity": "Antigravity", "copilot": "Copilot", "hermes": "Hermes"}
# The hook script each Unix shell registration must name
# (_unix_registration_freshness): the connectors in _EXPECTED_CONTRACTS and
# Hermes, whose hook reads its event from the payload.
_UNIX_REGISTRATION_HOOK_SCRIPTS = {
    "claudecode": "claude-code-hook.sh",
    "codex": "codex-hook.sh",
    "devin": "devin-hook.sh",
    "hermes": "hermes-hook.sh",
}


def upstream_fail_open(cfg: Any, connector: str) -> bool:
    """Whether *connector*'s hooks fail open whatever is configured.

    Only the Secure Client profile keeps Copilot CLI, Antigravity and Hermes
    open, as its hook render does (CapableHookFailMode). Per-user hooks (the
    Linux and macOS shell hooks and the Windows native hook) and a managed
    deployment outside Secure Client (Config.managed_outside_secure_client)
    block a call they cannot check through the agent's native deny, so they
    follow the configured fail mode; an unset one is closed.
    """
    name = normalize(connector)
    if name not in _UPSTREAM_FAIL_OPEN_CONNECTORS:
        return False
    standalone = getattr(cfg, "managed_outside_secure_client", None)
    if callable(standalone) and standalone():
        return False
    return str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"


def upstream_hook_limit(connector: str) -> str:
    """The vendor limit of a closed Copilot CLI, Antigravity or Hermes hook, or ""."""

    label = _UPSTREAM_LIMIT_LABELS.get(normalize(connector))
    if not label:
        return ""
    return f"DefenseClaw failures block; {label} itself lets a call run when the hook times out or cannot start"


_SHARED_RUNTIME_CONNECTORS = frozenset({"claudecode", "codex"})
_WINDOWS_LAUNCHER_CONNECTORS = frozenset({"claudecode", "codex"})
_SHARED_HOOK_SCRIPTS = frozenset(
    {
        "inspect-tool.sh",
        "inspect-request.sh",
        "inspect-response.sh",
        "inspect-tool-response.sh",
        "_hardening.sh",
    }
)
_LEGACY_SHARED_HOOK_SCRIPTS = _SHARED_HOOK_SCRIPTS - {"_hardening.sh"}


def _is_windows() -> bool:
    return os.name == "nt"


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def normalize_fail_mode(value: object, *, default: str = "closed") -> str:
    raw = str(value or "").strip().lower()
    return raw if raw in _VALID_MODES else default


def managed_windows_verify_command() -> str:
    """The managed Windows deployment's verify as an administrator types it.

    Setup puts no DefenseClaw command on PATH, so the installed CLI is named
    by its path under Program Files, as a PowerShell literal: the form of
    managed.WindowsAdminCommand in the Go CLI (cowork-1-0-8 GAP-0076).
    Program Files comes from the machine registration, never the
    ProgramFiles variable a standard user can set (g072 review 2 S2).
    """
    root = ""
    if sys.platform == "win32":
        from defenseclaw import windows_owner

        root = windows_owner._program_files_dir()
    cli = (root.strip().rstrip("\\") or r"C:\Program Files") + r"\Cisco\DefenseClaw\bin\defenseclaw.exe"
    return powershell_command_line(cli, "enterprise", "windows", "verify", "--profile", "standalone")


@dataclass(frozen=True)
class ConnectorFailModeState:
    connector: str
    desired: str
    configured: str
    runtime: str | None
    sources: tuple[tuple[str, str | None], ...]
    drift: tuple[str, ...]
    # The vendor limit a closed hook of this connector keeps
    # (upstream_hook_limit), or "".
    limit: str = ""
    # False when this process cannot read the mode the installed hook runs:
    # a hook that takes it from the agent's environment when no verified copy
    # of that environment names one (it can run open whatever ``runtime``,
    # its default, says), or a managed native Windows hook, which runs the
    # guardian's authenticated runtime generation.
    runtime_verified: bool = True
    # Reporting context only; the resolver still decides the hook mode.
    deployment: str = ""
    policy_tier: str = ""
    # False when config.yaml saves no hook fail mode for the connector (or
    # globally): ``configured`` is then the normalized default, not a choice
    # the user made, and the note must not name it as one.
    configured_saved: bool = True

    @property
    def _managed_windows_runtime(self) -> bool:
        return any(source == "windows-managed-runtime" for source, _mode in self.sources)

    @property
    def current(self) -> bool:
        return self.runtime_verified and not self.drift and self.runtime == self.desired

    @property
    def effective(self) -> str:
        """Return the mode a reporting surface should present as effective."""

        return self.runtime or self.desired

    @property
    def provenance(self) -> str:
        """Return the source that supplied :attr:`effective`.

        ``registration-lock`` is verification evidence, not an input to the
        runtime selection order.  Every other non-empty runtime source appears
        in the order in which :func:`resolve_connector_fail_mode` applies it,
        so the last one is authoritative.  When no runtime value is readable,
        reporting falls back to configured intent and names that provenance
        explicitly.
        """

        if not self.runtime_verified:
            if self._managed_windows_runtime:
                return "windows-managed-runtime-unverified"
            return "agent-env-unverified"
        if self.runtime is None:
            return "config"
        source = "config"
        for candidate, mode in self.sources:
            # Claude Code's settings env is registration evidence only: no
            # hook reads a fail mode from its environment.
            if candidate in {"config", "registration-lock", "claude-env"} or mode is None:
                continue
            source = candidate
        if source == "config":
            # No installed state names a mode, so the hook fails closed.
            return "no-installed-mode"
        return source

    @property
    def note(self) -> str:
        """Why the effective mode is not the configured guardrail.hook_fail_mode, or "".

        Deployment and policy tier explain a saved value overridden by the
        effective policy. A closed Copilot CLI, Antigravity or Hermes hook
        names the vendor limit it keeps instead.
        """

        notes = []
        if self.limit and self.effective == "closed":
            notes.append(self.limit)
        elif self.configured != self.desired and self.effective == self.desired:
            if self.deployment == "managed":
                reason = f"managed application protection selects hooks fail-{self.desired}"
            elif self.deployment == "secure-client":
                reason = f"Secure Client policy selects hooks fail-{self.desired}"
            elif self.deployment == "per-user" and self.policy_tier:
                reason = f"the {self.policy_tier} per-user policy tier keeps gateway outages fail-{self.desired}"
            elif self.deployment == "per-user":
                reason = f"this per-user deployment keeps hooks fail-{self.desired}"
            else:
                reason = f"the effective policy selects hooks fail-{self.desired}"
            if self.configured_saved:
                notes.append(
                    f"{reason}; guardrail.hook_fail_mode={self.configured} does not control hook failures here"
                )
            else:
                # Nothing is saved: the normalized default (closed) is no
                # value the user chose, so do not name one (GAP-2248).
                notes.append(f"{reason}; guardrail.hook_fail_mode is not set")
        if not self.runtime_verified and self._managed_windows_runtime:
            notes.append(
                "the managed native hook runs the mode of the runtime generation the guardian publishes, "
                f"which this command cannot verify: `{managed_windows_verify_command()}` from an elevated "
                "PowerShell prompt checks it"
            )
        elif not self.runtime_verified:
            default = f" (default {self.runtime})" if self.runtime else ""
            notes.append(
                "the installed hook reads DEFENSECLAW_FAIL_MODE from the agent's environment, which this "
                f"command cannot see: it runs open when the agent sets open{default}"
            )
        return "; ".join(notes)

    def to_report(self) -> dict[str, Any]:
        """Return the canonical JSON-friendly reporting projection."""

        return {
            "effective": self.effective,
            "provenance": self.provenance,
            "note": self.note,
            # None when config.yaml saves no mode: the normalized default is
            # no value the user chose (GAP-0719).
            "configured": self.configured if self.configured_saved else None,
            "desired": self.desired,
            "runtime": self.runtime,
            "current": self.current,
            "runtime_verified": self.runtime_verified,
            "drift": list(self.drift),
            "sources": [
                {"name": source, "mode": mode if source != "config" or self.configured_saved else None}
                for source, mode in self.sources
            ],
        }


# Drift for a hook entry edited so the agent runs a tool call without it
# (hook_integrity.unguarded_tool_call_hooks, rel-1-0-4 GAP-0538).
REGISTRATION_UNGUARDED = "registration-unguarded"


# Drift for a hook entry that runs a script other than the one Setup
# registers (an edited path, a copy in another folder), and for a generated
# hook script that changed since setup, is missing or that another account
# can change (hook_integrity.edited_hook_problems and hook_runtime_problems,
# rel-1-0-4 GAP-0600).
REGISTRATION_FOREIGN = "registration-foreign"
HOOK_RUNTIME_STALE = "hook-runtime-stale"


def registration_unguarded(cfg: Any, connector: str) -> bool:
    """Whether a recorded hook file of *connector* leaves its tool calls unguarded."""

    from defenseclaw.hook_integrity import unguarded_tool_call_hooks

    return bool(unguarded_tool_call_hooks(cfg, normalize(connector)))


def registration_integrity_drift(cfg: Any, connector: str) -> list[str]:
    """The drift of *connector*'s hook registration against DefenseClaw's own current, unmodified hook.

    A registration is healthy only while every entry runs the script Setup
    registered, with the bytes it sealed, owned by this account. An entry
    repointed at an old copy kept ``guardrail fail-mode`` without drift
    (rel-1-0-4 GAP-0600).
    """

    from defenseclaw.hook_integrity import edited_hook_problems, hook_runtime_problems

    name = normalize(connector)
    drift = [REGISTRATION_UNGUARDED] if registration_unguarded(cfg, name) else []
    if _is_windows():
        # Windows runs the native launcher. _windows_registration_freshness
        # checks the connectors in _EXPECTED_CONTRACTS; the others get the
        # doctor's validator of path, bytes and ACL here, which fail-mode
        # skipped for Copilot (rel-1-0-4 GAP-0600).
        if name in _WINDOWS_NATIVE_VALIDATED and name not in _EXPECTED_CONTRACTS:
            native = _windows_native_integrity_drift(cfg, name)
            if native:
                drift.append(native)
        return drift
    if edited_hook_problems(cfg, name):
        drift.append(REGISTRATION_FOREIGN)
    # A missing or damaged token blocks every call; that is not a hook that
    # runs unchecked, and the hook credential checks report it.
    if any(not problem.startswith("hook token ") for problem in hook_runtime_problems(cfg, name)):
        drift.append(HOOK_RUNTIME_STALE)
    return drift


# Connectors whose Windows hook registration the doctor validates natively
# (cmd_doctor._windows_native_hook_check).
_WINDOWS_NATIVE_VALIDATED = frozenset({"antigravity", "copilot", "hermes"})
# A healthy registration, and one a running Hermes host has not reloaded yet
# (its file is DefenseClaw's current hook).
_WINDOWS_NATIVE_CURRENT_STATES = frozenset({"healthy", "pending-reload"})


def _windows_native_integrity_drift(cfg: Any, connector: str) -> str | None:
    """The drift of a Windows registration that is not DefenseClaw's current hook, or None."""

    from defenseclaw.commands.cmd_doctor import _windows_native_hook_check

    try:
        check = _windows_native_hook_check(cfg, connector)
    except Exception:  # noqa: BLE001 - an uninspectable registration is not a verified one.
        return REGISTRATION_FOREIGN
    if check.state in _WINDOWS_NATIVE_CURRENT_STATES:
        return None
    if check.state == "disabled":
        return REGISTRATION_UNGUARDED  # the agent setting turns the hooks off
    return HOOK_RUNTIME_STALE if check.state == "stale" else REGISTRATION_FOREIGN


def _fail_mode_note_context(cfg: Any, guardrail: Any, connector: str) -> tuple[str, str]:
    """Identify the policy that selected a hook mode for status wording."""

    standalone = getattr(cfg, "managed_outside_secure_client", None)
    if callable(standalone) and standalone():
        return "managed", ""
    secure_client = getattr(guardrail, "secure_client_hook_fail_modes", None)
    if callable(secure_client) and secure_client():
        return "secure-client", ""
    tier = getattr(guardrail, "hook_policy_tier", None)
    return "per-user", str(tier(connector)) if callable(tier) else ""


def _hook_fail_mode_saved(guardrail: Any, name: str) -> bool:
    """Whether config.yaml saves a hook fail mode for *name* (or globally).

    GuardrailConfig fills an unset global hook_fail_mode with closed and
    records whether config.yaml saved one (_hook_fail_mode_saved); that
    placeholder is never a mode the user chose.
    """

    entry = guardrail._connector_override(name) if hasattr(guardrail, "_connector_override") else None
    if entry is None:
        entry = (getattr(guardrail, "connectors", {}) or {}).get(name)
    raw = getattr(entry, "hook_fail_mode", "") if entry is not None else ""
    return str(raw or "").strip().lower() in _VALID_MODES or (
        bool(getattr(guardrail, "_hook_fail_mode_saved", True))
        and str(getattr(guardrail, "hook_fail_mode", "") or "").strip().lower() in _VALID_MODES
    )


def resolve_connector_fail_mode(
    cfg: Any,
    connector: str,
    *,
    inspect_effective_policy: bool = True,
) -> ConnectorFailModeState:
    """Resolve desired, installed, and effective runtime fail mode for one connector."""

    name = normalize(connector)
    guardrail = cfg.guardrail
    entry = guardrail._connector_override(name) if hasattr(guardrail, "_connector_override") else None
    if entry is None:
        configured_entries = getattr(guardrail, "connectors", {}) or {}
        entry = configured_entries.get(name)
    raw = getattr(entry, "hook_fail_mode", "") if entry is not None else ""
    saved_value = raw or getattr(guardrail, "hook_fail_mode", "")
    configured = normalize_fail_mode(saved_value)
    configured_saved = _hook_fail_mode_saved(guardrail, name)
    resolver = getattr(guardrail, "effective_hook_fail_mode", None)
    desired = normalize_fail_mode(resolver(name) if callable(resolver) else configured)
    deployment, policy_tier = _fail_mode_note_context(cfg, guardrail, name)
    sources: list[tuple[str, str | None]] = [("config", configured)]
    drift: list[str] = []

    sidecar_drift = _shared_hook_sidecar_drift(cfg)
    if sidecar_drift:
        drift.append(sidecar_drift)
    if name in _UPSTREAM_FAIL_OPEN_CONNECTORS:
        state = replace(
            _resolve_native_deny_fail_mode(cfg, name, configured, desired),
            deployment=deployment,
            policy_tier=policy_tier,
            configured_saved=configured_saved,
        )
        if sidecar_drift:
            return replace(state, drift=(*state.drift, sidecar_drift))
        return state

    runtime_source = _platform_runtime_source(cfg, name)
    sources.append(runtime_source)
    runtime = runtime_source[1]
    if runtime_source[0].endswith("-legacy"):
        drift.append("windows-sidecar-legacy")
    if runtime_source[0] == "windows-managed-runtime":
        drift.append("windows-managed-runtime-unverified")
    if runtime is None and runtime_source[0].startswith("windows-sidecar"):
        # The native Windows hook reads its mode from this sidecar alone and
        # fails closed when the file is missing or unreadable or names no mode
        # for the connector (readHookSidecar), so status reports that.
        runtime = "closed"
    # A 1.0.4 render reads no fail mode from any environment (GAP-0315), so
    # this shell's (which is not the agent's) is never an input here.
    workspace = _connector_workspace(cfg)
    # The part of a hook's environment this process can read: only Claude
    # Code's user settings env, which Claude Code applies over the
    # environment it was started in.
    agent_env: str | None = None
    if name == "claudecode":
        claude_env, registered = _claude_registration_state(workspace)
        # Hook renders from 1.0.3 and older read the mode from Claude Code's
        # settings env until the upgrade's connector refresh re-renders them.
        # A per-user setup writes none there now (a managed one still does)
        # and takes back the value an earlier setup or release wrote; a value
        # the user set stays. It is a runtime input, and so drift when it
        # disagrees, only for a render that reads it (hook-script-env below).
        sources.append(("claude-env", claude_env))
        agent_env = claude_env
        if not registered:
            drift.append("registration-missing")
    # Windows Codex registration is a structured event matrix whose native
    # validator below checks the exact command, launcher, contract, policy,
    # trust, and file identities, so the text probe is not used there.
    elif (
        name == "codex"
        and not _is_windows()
        and not _codex_registration_current(workspace, str(getattr(cfg, "data_dir", "") or ""))
    ):
        drift.append("registration-missing")

    drift.extend(registration_integrity_drift(cfg, name))

    # A managed native Windows hook runs the mode of the guardian's
    # authenticated runtime generation, which this process cannot read: no
    # mode here is verified, so an administrator's change from open to closed
    # is not reported as applied before the guardian has published it.
    runtime_verified = runtime_source[0] != "windows-managed-runtime"
    if runtime_source[0] == "hook-script-env":
        # The render takes its mode from the agent's environment (a 0.8.x or
        # 1.0.3 render the upgrade's refresh has not replaced yet, or a Secure
        # Client render): what it runs is the agent's value when it sets one.
        if agent_env == "open":
            # Open in Claude Code's settings env is open in the hook.
            sources.append(("agent-env", "open"))
            runtime = "open"
        else:
            # Nothing else here shows the agent's environment: the status
            # shell's is not the agent's, and closed in Claude Code's user
            # settings env can still be set open by a project's or managed
            # settings env. So no closed or current claim.
            runtime_verified = False
            drift.append("agent-env-unverified")
        if name in _SHARED_RUNTIME_CONNECTORS:
            # 1.0.4 renders the Claude Code and Codex hooks with the mode
            # baked in on every deployment, so this one is stale: a refresh
            # replaces it.
            drift.append("hook-script-reads-agent-env")

    lock_mode, lock_drift = _registration_lock_state(cfg, name)
    sources.append(("registration-lock", lock_mode))
    # A hook that reads its outage mode from config on every call does not run
    # the lock's recorded mode: a lock that lags a pack switched while the
    # gateway is stopped is no drift (GAP-0272). A missing or malformed lock
    # still is.
    lock_mode_unread = lock_mode is not None and _outage_mode_read_at_call_time(cfg, name, runtime_source)
    if lock_mode != desired and not lock_mode_unread:
        drift.append("registration-stale")
    if lock_drift:
        drift.append(lock_drift)
    if name == "amp":
        amp_registration = _amp_registration_freshness()
        if amp_registration:
            drift.append(amp_registration)
    elif _is_windows() and name in _EXPECTED_CONTRACTS:
        if inspect_effective_policy:
            windows_registration = _windows_registration_freshness(cfg, name)
        else:
            windows_registration = _windows_registration_freshness(
                cfg,
                name,
                inspect_effective_policy=False,
            )
        if windows_registration:
            drift.append(windows_registration)
        if name == "codex" and not inspect_effective_policy:
            drift.append("policy-unverified")
    elif name in _EXPECTED_CONTRACTS:
        unix_registration = _unix_registration_freshness(cfg, name)
        if unix_registration:
            drift.append(unix_registration)

    # A 1.0.4 render (baked shell hook, Windows sidecar, managed runtime)
    # reads no fail mode from Claude Code's settings env: a value the user
    # kept there changes nothing the hook runs, so it is not drift (GAP-1422).
    env_read = runtime_source[0] == "hook-script-env"
    for source, mode in sources:
        if source == "config":
            continue
        if source == "claude-env" and not env_read:
            continue
        if source == "registration-lock" and lock_mode_unread:
            continue
        if mode is None:
            # A per-user setup writes no fail mode into Claude Code's settings
            # env (no 1.0.4 render reads one), so its absence is not drift; a
            # render that reads it reports agent-env-unverified above.
            if source in {"windows-managed-runtime", "claude-env"}:
                continue
            drift.append(f"{source}-missing")
        elif mode != desired:
            drift.append(f"{source}-{mode}")

    return ConnectorFailModeState(
        connector=name,
        desired=desired,
        configured=configured,
        runtime=runtime,
        sources=tuple(sources),
        drift=tuple(dict.fromkeys(drift)),
        runtime_verified=runtime_verified,
        deployment=deployment,
        policy_tier=policy_tier,
        configured_saved=configured_saved,
    )


def _resolve_native_deny_fail_mode(cfg: Any, name: str, configured: str, desired: str) -> ConnectorFailModeState:
    """Resolve a Copilot CLI, Antigravity or Hermes hook from what it renders.

    Their hooks record the mode in the hook script (Linux, macOS) or in
    .hookcfg (the Windows native hook). A rendered mode other than the
    configured one is drift: an open hook while config says closed lets calls
    run with the gateway down. So is a registration lock that records another
    mode, and a live registration that does not run this install's hook with
    each reviewed event exactly: it may still select an older open hook.
    """

    sources: list[tuple[str, str | None]] = [("config", configured)]
    drift: list[str] = []
    runtime_source = _platform_runtime_source(cfg, name)
    sources.append(runtime_source)
    runtime = runtime_source[1]
    if runtime_source[0].endswith("-legacy"):
        drift.append("windows-sidecar-legacy")
    if runtime is None and runtime_source[0].startswith("windows-sidecar"):
        # As for every other connector: the native Windows hook fails closed
        # when its sidecar is missing or names no mode (readHookSidecar).
        runtime = "closed"
    # As for every other connector: a managed native Windows hook runs the
    # guardian's runtime generation, and a render that reads the agent's
    # environment (Secure Client delivery, or a render left from 1.0.3) can
    # run another mode than its default; neither is verified here.
    runtime_verified = runtime_source[0] not in {"windows-managed-runtime", "hook-script-env"}
    if runtime_source[0] == "windows-managed-runtime":
        drift.append("windows-managed-runtime-unverified")
    elif runtime_source[0] == "hook-script-env":
        drift.append("agent-env-unverified")
    # No hook reads a fail mode from any environment (GAP-0315), so neither
    # this shell's DEFENSECLAW_FAIL_MODE nor the agent's is an input here.
    lock_mode, lock_drift = _registration_lock_state(cfg, name)
    sources.append(("registration-lock", lock_mode))
    if lock_mode != desired:
        drift.append("registration-stale")
    if lock_drift:
        drift.append(lock_drift)
    drift.extend(registration_integrity_drift(cfg, name))
    try:
        registration = _native_deny_registration_freshness(cfg, name)
    except Exception:  # noqa: BLE001 - an unreadable registration is not current, never a crash.
        registration = "registration-unverified"
    if registration:
        drift.append(registration)
    # A hook entry the agent skips is drift whatever the fail mode (GAP-0538).
    if registration_unguarded(cfg, name):
        drift.append(REGISTRATION_UNGUARDED)
    for source, mode in sources[1:]:
        if mode is None:
            if source == "windows-managed-runtime":
                continue
            drift.append(f"{source}-missing")
        elif mode != desired:
            drift.append(f"{source}-{mode}")
    return ConnectorFailModeState(
        connector=name,
        desired=desired,
        configured=configured,
        runtime=runtime,
        sources=tuple(sources),
        drift=tuple(dict.fromkeys(drift)),
        limit=upstream_hook_limit(name),
        runtime_verified=runtime_verified,
    )


# The sources that record the mode a connector's installed hook or plugin was
# rendered with (_platform_runtime_source).
_RENDERED_SOURCES = frozenset(
    {"hook-script", "hook-script-env", "windows-sidecar", "windows-sidecar-legacy", "amp-plugin", "opencode-plugin"}
)


def _native_deny_registration_path(cfg: Any, name: str) -> str:
    """Where Setup registers the Copilot CLI, Antigravity or Hermes hook (doctor reads the same file)."""

    if name == "copilot":
        workspace = _connector_workspace(cfg)
        data_dir = os.path.realpath(str(cfg.data_dir))
        inside = False
        if workspace:
            try:
                inside = os.path.commonpath([os.path.realpath(workspace), data_dir]) == data_dir
            except ValueError:
                inside = False
        if workspace and not inside:
            return os.path.join(workspace, ".github", "hooks", "defenseclaw.json")
        return os.path.join(copilot_home(), "hooks", "defenseclaw.json")
    if name == "antigravity":
        return os.path.join(connector_home("antigravity"), "hooks.json")
    return hermes_config_path()


def _native_deny_registration_freshness(cfg: Any, name: str) -> str | None:
    """Drift when the live Copilot CLI, Antigravity or Hermes registration is not this install's hook.

    Copilot and Antigravity name no event in their hook input, so each
    registered command must bind its reviewed event exactly; Hermes' hook
    reads the event from the payload, so its registration must name the hook.
    A Windows Hermes registration that waits for Hermes to restart is current:
    rendering it again changes nothing.
    """

    if str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
        # The administrator-owned registration is enterprise verify's.
        return None
    if _is_windows():
        from defenseclaw.doctor_hooks import (
            _packaged_windows_install_root,
            validate_windows_copilot_hook_registration,
            validate_windows_hook_registration,
        )

        locked = _registration_hook_config_paths(cfg, name)
        config_path = locked[0] if locked else _native_deny_registration_path(cfg, name)
        if name == "hermes":
            try:
                current_config = hermes_config_path()
            except ValueError:
                return "registration-config-binding-stale"
            if locked != (current_config,):
                return "registration-config-binding-stale"
            config_path = current_config
        install_root = _packaged_windows_install_root(str(cfg.data_dir)) or str(Path.home() / ".local" / "bin")
        common = {
            "config_path": config_path,
            "data_dir": str(cfg.data_dir),
            "install_root": install_root,
            "search_path": os.environ.get("PATH", ""),
            "pathext": os.environ.get("PATHEXT", ""),
        }
        if name == "copilot":
            check = validate_windows_copilot_hook_registration(**common, workspace_dir=_connector_workspace(cfg))
        else:
            check = validate_windows_hook_registration(connector=name, **common)
        if check.healthy or check.state == "pending-reload":
            return None
        return f"registration-{check.state}"
    if name == "hermes":
        return _unix_registration_freshness(cfg, name)
    from defenseclaw.doctor_hooks import unix_hook_event_binding_problem

    state, _detail = unix_hook_event_binding_problem(
        name,
        _native_deny_registration_path(cfg, name),
        str(Path(cfg.data_dir) / "hooks" / f"{name}-hook.sh"),
    )
    return f"registration-{state}" if state else None


def report_renders_fail_mode(report: dict[str, Any]) -> bool:
    """Whether the connector of a connector_fail_mode_report has a hook or plugin that records its mode."""

    return any(
        isinstance(source, dict) and source.get("name") in _RENDERED_SOURCES for source in report.get("sources") or ()
    )


def rendered_fail_mode(report: dict[str, Any]) -> str | None:
    """The fail mode the installed hook of a connector_fail_mode_report was rendered with, or None.

    The agent environment does not change the installed mode. A hook rendered
    open stays open until the fail-mode command refreshes its installed policy.
    """

    for source in report.get("sources") or ():
        if isinstance(source, dict) and source.get("name") in _RENDERED_SOURCES:
            mode = source.get("mode")
            return mode if mode in _VALID_MODES else None
    return None


def proxy_model_outage_mode(cfg: Any, connector: str, *, saved: str | None = None) -> str:
    """What the model requests of a proxy-backed connector do while the gateway is down (GAP-0824).

    OpenClaw follows the outage mode its plugin asks the gateway program for
    (Go ``Config.EffectiveHookOutageFailModeForConnector``): open on the default
    and permissive packs, closed on strict, on a managed host and for an explicit
    closed. ZeptoClaw model requests stay blocked. ``saved`` is a mode about to be
    saved, judged by the same rules.
    """

    name = normalize(connector)
    if name != "openclaw":
        return "closed"
    guardrail = cfg.guardrail
    if saved is None:
        return normalize_fail_mode(guardrail.effective_hook_outage_fail_mode(name))
    if guardrail._managed_outage_install() or guardrail.hook_policy_tier(name) == "strict":
        return "closed"
    return normalize_fail_mode(saved)


def proxy_outage_source(cfg: Any, connector: str) -> str:
    """Say where a proxy-backed connector gets its outage mode, in the order the resolver applies it (GAP-0824).

    A managed or Secure Client install takes the administrator mode (an unset one
    is the Secure Client or managed default); a saved mode comes next, except that
    OpenClaw under the strict policy stays closed on a per-user install; an unset
    mode follows the policy tier. ZeptoClaw has no outage mode to explain.
    """

    if normalize(connector) != "openclaw":
        return "model requests are always blocked while the gateway is down; no fail mode applies."
    guardrail = cfg.guardrail
    mode, source = guardrail.hook_fail_mode_resolution(connector)
    effective = normalize_fail_mode(guardrail.effective_hook_outage_fail_mode(connector))
    if source == "secure-client-default":
        return (
            f"set by Secure Client ({effective} unless the administrator chose otherwise); "
            "the policy tier does not change it."
        )
    if source == "managed-default":
        return (
            "set by this managed computer (closed unless the administrator chose open); "
            "the policy tier does not change it."
        )
    if source.startswith("config:"):
        if "application_protection" in source:
            where = "automatic-protection"
        elif ".connectors." in source:
            where = "per-connector"
        else:
            where = "global"
        if guardrail._managed_outage_install():
            return f"the administrator saved {where} mode ({effective}); the policy tier does not change it."
        if effective != mode:
            return (
                f"closed by the strict policy: the saved {where} {mode} mode does not apply to OpenClaw "
                "under the strict tier."
            )
        if where == "global":
            return f"inherited from global default ({effective})."
        return f"the saved {where} mode ({effective}); the policy tier does not change it."
    return f"from the policy tier ({guardrail.hook_policy_tier(connector)} tier); no fail mode is saved."


def proxy_outage_note(mode: str) -> str:
    if mode == "open":
        return "no hooks: model requests continue with a warning while the gateway is down"
    return "no hooks: blocked while the gateway is down"


def proxy_outage_summary(mode: str) -> str:
    """The one-line outage behaviour of a proxy-backed connector, as every fail-mode view prints it."""

    shown = "open" if mode == "open" else "closed"
    return shown + " (proxy-backed, " + proxy_outage_note(mode) + ")"


def proxy_requests_note(cfg: Any, connector: str, *, saved: str | None = None) -> str:
    """What a fail-mode value does to the model requests of a proxy-backed connector."""

    if normalize(connector) != "openclaw":
        return "Its proxied model requests are blocked while the gateway is down, whatever this value says."
    if proxy_model_outage_mode(cfg, connector, saved=saved) == "open":
        return "Its proxied model requests continue with a warning while the gateway is down."
    if saved == "open":
        return (
            "Its proxied model requests are blocked while the gateway is down: the strict policy "
            "(or a managed host) blocks them whatever this value says."
        )
    return "Its proxied model requests are blocked while the gateway is down."


# The connectors whose hook runs a call that its verified gateway took and did
# not answer in time, in the open outage mode, when the call plainly names
# nothing a protected file could be reached through (GAP-0518: Go
# hookpaths.LateOrdinaryCall and hookexec.OrdinaryNoAnswerPayload read only
# Claude Code and Codex tool calls). Every other connector blocks such a call.
_LATE_ORDINARY_CONNECTORS = frozenset({"claudecode", "codex"})

# The kinds of hook failure failure_outcomes tells apart, in the order status
# and doctor print them.
FAILURE_KINDS = (
    ("gateway_down", "gateway down"),
    ("no_answer", "no answer"),
    ("hook_error", "hook or answer error"),
)


def failure_outcomes(cfg: Any, connector: str, effective: str) -> dict[str, str] | None:
    """What the hooks of *connector* do for each kind of failure (#1441).

    A single fail-mode=open read as if every failure let a call run. The
    hooks tell three kinds apart, and the outcome of each follows from the
    effective outage mode, the deployment and the connector, as the hooks
    decide it:

    - gateway_down: no gateway took the call (a refused connection, a
      gateway that is stopped or still restarting). It follows the outage
      mode: allow (with a warning and a hook-failures.jsonl record) when
      open, block when closed. A managed host allows it only when the
      hook proves the gateway service is stopped
      (allow-if-service-stopped).
    - no_answer: a verified gateway took the call, or holds its listener
      and accepts nothing (frozen), and gave no decision before the hook
      deadline. In a per-user open mode Claude Code and Codex allow it with
      the warning when the call names nothing a protected file could be
      reached through (allow-ordinary); every other call, connector and
      deployment blocks.
    - hook_error: an answer the gateway gave (an error status, a
      malformed or cut-off answer), a missing token, another listener on the
      port, an install in progress or a local failure of the hook itself.
      It blocks in every tier.

    None where the breakdown does not apply: Secure Client (its hooks keep
    their own open default), the proxy-backed connectors (no hooks) and a
    connector Secure Client leaves open upstream.
    """

    name = normalize(connector)
    mode = str(effective or "").strip().lower()
    if mode not in _VALID_MODES:
        return None
    from defenseclaw.platform_support import is_proxy_connector

    if is_proxy_connector(name) or upstream_fail_open(cfg, name):
        return None
    deployment, _tier = _fail_mode_note_context(cfg, cfg.guardrail, name)
    if deployment == "secure-client":
        return None
    if mode == "closed":
        return {"gateway_down": "block", "no_answer": "block", "hook_error": "block"}
    if deployment == "managed":
        return {"gateway_down": "allow-if-service-stopped", "no_answer": "block", "hook_error": "block"}
    no_answer = "allow-ordinary" if name in _LATE_ORDINARY_CONNECTORS else "block"
    return {"gateway_down": "allow", "no_answer": no_answer, "hook_error": "block"}


_FAILURE_OUTCOME_TEXT = {
    "allow": "allow with a warning",
    "allow-if-service-stopped": "allow with a warning when the hook proves the gateway service is stopped",
    "allow-ordinary": "allow with a warning unless the call may reach a protected file",
    "block": "block",
}


def failure_outcomes_summary(outcomes: dict[str, str] | None) -> str:
    """The on_failure outcomes of a report as status and doctor print them, or ""."""

    if not outcomes:
        return ""
    parts = []
    for key, label in FAILURE_KINDS:
        outcome = outcomes.get(key) or "unknown"
        parts.append(label + ": " + _FAILURE_OUTCOME_TEXT.get(outcome, outcome))
    return "; ".join(parts)


def connector_fail_mode_report(
    cfg: Any,
    connector: str,
    *,
    inspect_effective_policy: bool = True,
) -> dict[str, Any]:
    """Return the canonical read-only fail-mode report for a connector.

    on_failure (failure_outcomes) says what each kind of hook failure does
    under the effective mode, so effective alone is not read as the
    outcome of every failure (#1441).
    """

    report = _connector_fail_mode_report(cfg, connector, inspect_effective_policy=inspect_effective_policy)
    report["on_failure"] = failure_outcomes(cfg, connector, str(report.get("effective") or ""))
    return report


def _connector_fail_mode_report(
    cfg: Any,
    connector: str,
    *,
    inspect_effective_policy: bool = True,
) -> dict[str, Any]:
    """The report of connector_fail_mode_report without its on_failure outcomes."""

    name = normalize(connector)
    guardrail = cfg.guardrail
    resolver = getattr(guardrail, "effective_hook_fail_mode", None)
    resolved = normalize_fail_mode(resolver(name) if callable(resolver) else getattr(guardrail, "hook_fail_mode", ""))
    saved = _hook_fail_mode_saved(guardrail, name)
    configured = resolved if saved else None
    # The upstream fail-open connectors (Antigravity, Copilot, Hermes) have no
    # runtime record of their own, so they are never in this branch; outside
    # Secure Client they resolve from their rendered hooks below.
    if name in _EXPECTED_CONTRACTS or name == "opencode":
        return resolve_connector_fail_mode(
            cfg,
            name,
            inspect_effective_policy=inspect_effective_policy,
        ).to_report()
    # An unguarded or foreign hook entry is drift whatever the fail mode: the
    # agent does not run DefenseClaw's current hook for the call.
    unguarded = registration_integrity_drift(cfg, name)
    if upstream_fail_open(cfg, name):
        return {
            "effective": "open",
            "provenance": f"{name}-upstream-fail-open",
            "note": "",
            "configured": configured,
            "desired": "open",
            "runtime": "open",
            "current": not unguarded,
            "runtime_verified": True,
            "drift": unguarded,
            "sources": [
                {"name": "config", "mode": configured},
                {"name": f"{name}-upstream", "mode": "open"},
            ],
        }
    from defenseclaw.platform_support import is_proxy_connector

    if is_proxy_connector(name):
        # The proxy connectors (OpenClaw, ZeptoClaw) have no hooks. ZeptoClaw
        # model requests stay blocked while the gateway is down; OpenClaw
        # follows the outage mode the gateway resolves (GAP-0824).
        outage = proxy_model_outage_mode(cfg, name)
        return {
            "effective": outage,
            "provenance": "proxy-backed",
            "note": proxy_outage_note(outage),
            "configured": configured,
            "desired": outage,
            "runtime": None,
            "current": False if unguarded else None,
            "runtime_verified": None,
            "drift": unguarded,
            "sources": [{"name": "proxy", "mode": outage}],
        }
    if name in _UPSTREAM_FAIL_OPEN_CONNECTORS:
        # Outside Secure Client, Copilot CLI, Antigravity and Hermes follow the
        # configured mode and are resolved from their rendered hooks.
        return resolve_connector_fail_mode(
            cfg,
            name,
            inspect_effective_policy=inspect_effective_policy,
        ).to_report()
    return {
        "effective": resolved,
        "provenance": "config",
        "note": "",
        "configured": configured,
        "desired": resolved,
        "runtime": None,
        "current": False if unguarded else None,
        "runtime_verified": None,
        "drift": unguarded,
        "sources": [{"name": "config", "mode": configured}],
    }


def _platform_runtime_source(cfg: Any, connector: str) -> tuple[str, str | None]:
    if connector == "amp":
        return "amp-plugin", _read_amp_plugin_mode(Path(amp_policy_plugin_path()), cfg)
    if connector == "opencode":
        return "opencode-plugin", _read_opencode_plugin_mode(cfg)
    if _is_windows():
        if str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
            # A managed native hook takes its mode from the authenticated
            # runtime generation the guardian publishes, never from
            # hooks/.hookcfg (buildHookOptionsForRuntime). This process cannot
            # authenticate that generation, so it names no mode: the report
            # shows the administrator's mode with the unverified drift.
            return "windows-managed-runtime", None
        mode, legacy = _read_windows_hook_mode(Path(cfg.data_dir) / "hooks" / ".hookcfg", connector)
        if legacy:
            return "windows-sidecar-legacy", mode
        return "windows-sidecar", mode
    script_name = "claude-code-hook.sh" if connector == "claudecode" else f"{connector}-hook.sh"
    hook_dir = Path(cfg.data_dir) / "hooks"
    mode, reads_env = _read_baked_hook_state(hook_dir / script_name)
    if (
        mode == "closed"
        and not reads_env
        and str(getattr(cfg, "deployment_mode", "") or "").strip().lower() != "managed_enterprise"
    ):
        # A current per-user script decides its outage mode from config at
        # call time; older scripts still read their runtime record.
        if _call_time_outage_helper(hook_dir):
            return "hook-script", normalize_fail_mode(cfg.guardrail.effective_hook_outage_fail_mode(connector))
        return "hook-script", _read_flat_hook_record_mode(hook_dir, connector)
    return ("hook-script-env" if reads_env else "hook-script"), mode


def _call_time_outage_helper(hook_dir: Path) -> bool:
    """Whether the installed shell helper decides a per-user outage mode from config at call time."""

    helper = _read_small_file(hook_dir / "_hardening.sh")
    return bool(helper and "defenseclaw-call-time-outage-v1" in helper)


def _outage_mode_read_at_call_time(cfg: Any, connector: str, runtime_source: tuple[str, str | None]) -> bool:
    """Whether a per-user Linux or macOS hook takes its outage mode from config.yaml on every call.

    Such a hook (a closed render with the call-time helper) runs the mode the
    config chooses now, whatever hook_contract_lock.json recorded when the
    gateway last rendered it. A pack switched with the gateway stopped
    rewrites the config and the runtime records, and the lock keeps the old
    mode until the gateway renders the hooks again when it starts: that lag
    changes nothing the hook runs, so it is no runtime drift (GAP-0272).
    """

    if runtime_source[0] != "hook-script" or _is_windows() or connector in {"amp", "opencode"}:
        return False
    if str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
        return False
    hook_dir = Path(cfg.data_dir) / "hooks"
    script_name = "claude-code-hook.sh" if connector == "claudecode" else f"{connector}-hook.sh"
    mode, reads_env = _read_baked_hook_state(hook_dir / script_name)
    return mode == "closed" and not reads_env and _call_time_outage_helper(hook_dir)


def _read_flat_hook_record_mode(hook_dir: Path, connector: str) -> str | None:
    """A per-user connector's outage mode in hooks/.hookcfg.<connector>, as the shell hooks read it.

    ``open`` only for a record that names the connector, says open and has the
    config source; ``closed`` for any other record and for none, as the hook
    reads it.
    """

    data = _read_small_file(hook_dir / f".hookcfg.{connector}")
    if data is None:
        return "closed"
    values: dict[str, str] = {}
    for line in data.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key in values:
            return "closed"
        values[key] = value
    if (
        values.get("DEFENSECLAW_CONNECTOR") == connector
        and values.get("DEFENSECLAW_FAIL_MODE") == "open"
        and values.get("FAIL_MODE_SOURCE") == "config"
    ):
        return "open"
    return "closed"


# The white space Go's strings.TrimSpace strips (unicode.IsSpace), which the
# native hook's sidecar reader applies (readHookSidecar).
_GO_SPACE = (
    "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)
# readHookSidecar's bounds: a larger or deeper sidecar is malformed state.
_WINDOWS_SIDECAR_MAX_BYTES = 64 * 1024
_WINDOWS_SIDECAR_MAX_DEPTH = 32
_INT64 = (-(2**63), 2**63 - 1)
# An integer token too long for Go's int: never a version.
_NOT_AN_INT64 = object()


def _reported_fail_mode(value: str) -> str | None:
    """A recorded mode as status reports it: open or closed as the hook runs
    it, blank as closed, and None for a value no installer writes (the hook
    runs it closed)."""

    trimmed = value.strip(_GO_SPACE)
    if not trimmed:
        return "closed"
    lowered = trimmed.lower() if trimmed.isascii() else ""
    return lowered if lowered in _VALID_MODES else None


def _go_fail_mode(value: str) -> str:
    """nativeHookFailMode: open only for open, any case, after Go's trim."""

    trimmed = value.strip(_GO_SPACE)
    return "open" if trimmed.isascii() and trimmed.lower() == "open" else "closed"


# The only non-ASCII letters Go's strings.ToUpper turns into ASCII ones.
_GO_UPPER_TO_ASCII = {"\u0131": "I", "\u017f": "S"}
# The only non-ASCII letters strings.EqualFold matches to ASCII ones.
_GO_FOLD_TO_ASCII = {"\u017f": "s", "\u212a": "k"}
_WINDOWS_SIDECAR_FIELDS = (
    "version",
    "gateway_addr",
    "fail_modes",
    "legacy_fail_mode",
    "fail_mode_sources",
    "legacy_fail_mode_source",
)


def _windows_sidecar_key(connector: str) -> str:
    """hookSidecarFailModeKey for a key compared with an ASCII connector key:
    Go's trim, Go's upper-casing (no expansions such as ß to SS), then '-',
    '_' and ' ' dropped. A non-ASCII letter Go would map to another non-ASCII
    one is kept as it is: either way the key cannot equal an ASCII one."""

    name = "".join(
        _GO_UPPER_TO_ASCII.get(char, char.upper() if char.isascii() else char) for char in connector.strip(_GO_SPACE)
    )
    for dropped in "-_ ":
        name = name.replace(dropped, "")
    return "DEFENSECLAW_FAIL_MODE_" + name


def _go_fold_equal(key: str, field: str) -> bool:
    """strings.EqualFold against an ASCII lower-case field name."""

    return len(key) == len(field) and all(
        char == want or (char.isascii() and char.lower() == want) or _GO_FOLD_TO_ASCII.get(char) == want
        for char, want in zip(key, field, strict=True)
    )


def _json_nesting_depth(text: str) -> int:
    """jsonNestingDepth: the deepest object or array nesting."""

    depth = deepest = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "}]":
            depth -= 1
    return deepest


def _reject_json_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # A key given twice reads differently to each reader (they take the
    # last), so the native hook closes on it (HookSidecarJSONAmbiguous).
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"key {key!r} is given twice")
        obj[key] = value
    return obj


# A shell variable name: the keys of the KEY=value sidecar of 0.8.x
# (connector.ParseLegacyHookSidecar).
_LEGACY_SIDECAR_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _shared_hook_sidecar_drift(cfg: Any) -> str | None:
    """A malformed shared map is runtime drift even when a baked hook matches."""

    data = _read_small_file(Path(cfg.data_dir) / "hooks" / ".hookcfg")
    if data is None:
        return None
    values, _ = _native_hook_sidecar_values(data)
    return "shared-sidecar-malformed" if _MALFORMED_SIDECAR in values else None


def _read_windows_hook_mode(path: Path, connector: str) -> tuple[str | None, bool]:
    """Read hooks/.hookcfg exactly as the native Windows hook does.

    The contract is readHookSidecar's (internal/cli/hook.go), held to by the
    shared vectors in internal/cli/testdata/windows_hook_sidecar_vectors.json.
    Returns the mode and whether it came from the legacy (unscoped) value;
    ``None`` names no mode, which the hook runs closed.
    """

    data = _read_small_bytes(path)
    if data is None:
        # Missing names no mode; a link, a directory or an oversized file is
        # malformed state, closed.
        return ("closed" if os.path.lexists(path) else None), False
    if len(data) > _WINDOWS_SIDECAR_MAX_BYTES:
        return "closed", False
    # encoding/json reads invalid UTF-8 in a string as U+FFFD and rejects it
    # anywhere else, as a replacement decode and json.loads do.
    text = data.decode("utf-8", errors="replace")
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_int=lambda token: int(token) if len(token) <= 20 else _NOT_AN_INT64,
        )
        parsed = True
    except (ValueError, RecursionError):
        payload = None
        parsed = False
    if parsed and isinstance(payload, dict):
        version = payload.get("version", 0)
        if version is None:
            version = 0
        if type(version) is not int or not _INT64[0] <= version <= _INT64[1]:
            version = 0
        if version >= 2:
            addr = payload.get("gateway_addr")
            legacy = payload.get("legacy_fail_mode")
            legacy_source = payload.get("legacy_fail_mode_source")
            modes = payload.get("fail_modes", {})
            sources = payload.get("fail_mode_sources", {})
            if (
                not all(value is None or isinstance(value, str) for value in (addr, legacy, legacy_source))
                or not isinstance(modes, dict)
                or not all(value is None or isinstance(value, str) for value in modes.values())
                or not isinstance(sources, dict)
                or not all(value is None or isinstance(value, str) for value in sources.values())
                or any(
                    key != field and _go_fold_equal(key, field) for key in payload for field in _WINDOWS_SIDECAR_FIELDS
                )
                or _json_nesting_depth(text) > _WINDOWS_SIDECAR_MAX_DEPTH
            ):
                return "closed", False
            key = _windows_sidecar_key(normalize(connector))
            entries = [value or "" for name, value in modes.items() if _windows_sidecar_key(name) == key]
            if entries:
                # A blank entry is closed, and entries that normalize alike
                # are open only when every one is. An entry no installer
                # writes is no readable mode (the hook runs it closed; doctor
                # fails it), never the legacy open.
                if all(_go_fail_mode(value) == "open" for value in entries):
                    return "open", False
                if any(_reported_fail_mode(value) is None for value in entries):
                    return None, False
                return "closed", False
            if legacy:
                return _go_fail_mode(legacy), True
            return None, False
    # The KEY=value sidecar of 0.8.x, read as readHookSidecar reads it
    # (connector.ParseLegacyHookSidecar): only a document of blank lines, #
    # comments and [export ]KEY=value lines with each key once is one, and a
    # connector's own key comes before the unscoped one. Anything else (JSON
    # that is not a v2 sidecar or does not parse, a byte-order mark or a
    # comment in front of it, a line that is not KEY=value, a key given
    # twice) is malformed state and closed.
    values: dict[str, str] = {}
    for line in text.split("\n"):
        line = line.strip(_GO_SPACE)
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.removeprefix("export ").partition("=")
        key = key.strip(_GO_SPACE)
        if not separator or not _LEGACY_SIDECAR_KEY.fullmatch(key) or key in values:
            return "closed", False
        values[key] = value.strip(_GO_SPACE).strip("\"'")
    scoped = _windows_sidecar_key(normalize(connector))
    value = values.get(scoped) or values.get("DEFENSECLAW_FAIL_MODE") or ""
    return (_go_fail_mode(value) if value else None), True


_AMBIGUOUS_SIDECAR_VALUE = "\x00ambiguous"
_MALFORMED_SIDECAR = "\x00malformed"


def _native_hook_sidecar_key(connector: str) -> str:
    name = connector.strip().upper()
    for char in "-_ ":
        name = name.replace(char, "")
    return "DEFENSECLAW_FAIL_MODE_" + name


def _go_json_field(payload: dict[str, Any], name: str) -> Any:
    """The value Go's decoder gives struct field *name*: keys match case-insensitively, the last one wins."""

    found: Any = None
    for key, value in payload.items():
        if key.lower() == name:
            found = value
    return found


def _go_string_map(values: dict[str, Any]) -> bool:
    """Whether Go decodes *values* into a map[string]string (null entries are empty strings)."""

    return all(value is None or isinstance(value, str) for value in values.values())


def _native_hook_sidecar_values(data: str) -> tuple[dict[str, str], bool]:
    """The KEY=value map the native hook builds from .hookcfg, and whether it was version 2 JSON."""

    try:
        payload = json.loads(data, parse_constant=_reject_json_constant)
        parsed = True
    except (ValueError, RecursionError):
        payload = None
        parsed = False
    if isinstance(payload, dict):
        version = _go_json_field(payload, "version")
        gateway = _go_json_field(payload, "gateway_addr")
        legacy = _go_json_field(payload, "legacy_fail_mode")
        legacy_source = _go_json_field(payload, "legacy_fail_mode_source")
        sources = _go_json_field(payload, "fail_mode_sources")
        has_modes = any(key.lower() == "fail_modes" for key in payload)
        modes = _go_json_field(payload, "fail_modes")
        decodes = (
            (version is None or type(version) is int)
            and (gateway is None or isinstance(gateway, str))
            and (legacy is None or isinstance(legacy, str))
            and (legacy_source is None or isinstance(legacy_source, str))
            and (sources is None or (isinstance(sources, dict) and _go_string_map(sources)))
        )
        if decodes and (version or 0) >= 2:
            if has_modes and (not isinstance(modes, dict) or not _go_string_map(modes)):
                # readHookSidecar: malformed connector state closes every connector.
                return {_MALFORMED_SIDECAR: "closed", "DEFENSECLAW_FAIL_MODE": "closed"}, True
            out: dict[str, str] = {}
            for connector, value in (modes or {}).items():
                key = _native_hook_sidecar_key(str(connector))
                value = value if (value or "").strip() else "closed"
                if key in out and out[key].strip().lower() != value.strip().lower():
                    # Go ranges over the map in random order: either value may win.
                    value = _AMBIGUOUS_SIDECAR_VALUE
                out[key] = value
            if legacy:
                out["DEFENSECLAW_FAIL_MODE"] = legacy
            return out, True
    if parsed or data.lstrip()[:1] in ("{", "["):
        # As readHookSidecar: JSON that is not a v2 sidecar, or that does not
        # parse, is malformed state and closes every connector, never
        # KEY=value lines (1.0.4 lead directive).
        return {_MALFORMED_SIDECAR: "closed", "DEFENSECLAW_FAIL_MODE": "closed"}, True
    out = {}
    for line in data.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.removeprefix("export ").partition("=")
        if not separator:
            continue
        key = key.strip()
        if key:
            out[key] = _go_unquote_or_trim(value.strip())
    return out, False


def _go_unquote_or_trim(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            decoded = json.loads(value)
        except ValueError:
            decoded = None
        if isinstance(decoded, str):
            return decoded
    elif len(value) >= 2 and value[0] == value[-1] == "`" and "`" not in value[1:-1]:
        return value[1:-1]
    return value.strip("\"'")


def _read_baked_hook_state(path: Path) -> tuple[str | None, bool]:
    """Return a Unix hook render's installed mode and whether it reads the environment.

    The mode of a render that reads DEFENSECLAW_FAIL_MODE is only its default.
    """

    data = _read_small_file(path)
    if data is None:
        return None, False
    match = _FAIL_MODE_PATTERN.search(data)
    mode = (match.group(1) or match.group(2)) if match else None
    return mode, _ENV_FAIL_MODE_PATTERN.search(data) is not None


def _read_opencode_plugin_mode(cfg: Any) -> str | None:
    data = _read_small_file(Path(cfg.data_dir) / "hook_contract_lock.json")
    if data is None:
        return None
    try:
        payload = json.loads(data)
    except (TypeError, ValueError):
        return None
    connectors = payload.get("connectors") if isinstance(payload, dict) else None
    entry = connectors.get("opencode") if isinstance(connectors, dict) else None
    locations = entry.get("locations") if isinstance(entry, dict) else None
    paths = locations.get("hook_config_paths") if isinstance(locations, dict) else None
    if not isinstance(paths, list):
        return None
    for raw_path in paths:
        plugin = _read_small_file(Path(str(raw_path)))
        if plugin is None:
            continue
        if "defenseclaw-call-time-outage-v1" in plugin:
            return normalize_fail_mode(cfg.guardrail.effective_hook_outage_fail_mode("opencode"))
        match = _OPENCODE_OUTAGE_PATTERN.search(plugin) or _OPENCODE_FAIL_MODE_PATTERN.search(plugin)
        if match:
            return match.group(1)
    return None


def _read_amp_plugin_mode(path: Path, cfg: Any) -> str | None:
    data = _read_small_file(path)
    if data is None:
        return None
    if "defenseclaw-call-time-outage-v1" in data:
        return normalize_fail_mode(cfg.guardrail.effective_hook_outage_fail_mode("amp"))
    match = _AMP_OUTAGE_PATTERN.search(data) or _AMP_FAIL_MODE_PATTERN.search(data)
    return match.group(1) if match else None


def _amp_registration_freshness() -> str | None:
    """Verify Amp's live user-scoped policy plugin contract."""

    data = _read_small_file(Path(amp_policy_plugin_path()))
    if data is None:
        return "registration-missing"
    for marker in (
        "// defenseclaw-managed-plugin v2",
        "/api/v1/amp/hook",
        'amp.on("session.start"',
        'amp.on("agent.start"',
        'amp.on("tool.call"',
        'amp.on("tool.result"',
        'amp.on("agent.end"',
    ):
        if marker not in data:
            return "registration-command-stale"
    return None


def _connector_workspace(cfg: Any) -> str:
    resolver = getattr(cfg, "connector_workspace_dir", None)
    return str(resolver() or "") if callable(resolver) else ""


def _claude_registration_state(workspace: str = "") -> tuple[str | None, bool]:
    paths = connector_config_files("claudecode", workspace_dir=workspace)
    if not paths:
        return None, False
    data = _read_small_file(Path(paths[0]))
    if data is None:
        return None, False
    try:
        settings = json.loads(data)
    except (TypeError, ValueError):
        return None, False
    if not isinstance(settings, dict):
        return None, False
    env = settings.get("env")
    value = env.get("DEFENSECLAW_FAIL_MODE") if isinstance(env, dict) else None
    mode = str(value or "").strip().lower()
    hooks = settings.get("hooks")
    try:
        hook_registration = json.dumps(hooks, separators=(",", ":")).lower()
    except (TypeError, ValueError):
        hook_registration = ""
    registered = "defenseclaw" in hook_registration and (
        "claudecode" in hook_registration or "claude-code-hook" in hook_registration
    )
    return (mode if mode in _VALID_MODES else None), registered


def codex_windows_hook_config_path(cfg: Any) -> str:
    """Return where native Windows Setup registers Codex hooks without a lock.

    Managed enterprise installs use Codex's legacy managed layer. Per-user
    installs use config.toml because current Codex ignores
    CODEX_HOME/managed_config.toml on Windows.
    """

    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    return str(Path(codex_home()) / ("managed_config.toml" if managed else "config.toml"))


def _codex_registration_current(workspace: str = "", data_dir: str = "") -> bool:
    """Whether Codex's config.toml registers DefenseClaw's hooks.

    The hook commands run the scripts in this install's data directory, so a
    custom DEFENSECLAW_HOME (``~/dchome/hooks/codex-hook.sh``) names no
    "defenseclaw" in the path and still is DefenseClaw's registration
    (GAP-1882).
    """
    paths = connector_config_files("codex", workspace_dir=workspace)
    if not paths:
        return False
    config_path = Path(paths[0])
    data = _read_small_file(config_path)
    if data is None or "[hooks]" not in data:
        return False
    if "defenseclaw" in data.lower():
        return True
    if not data_dir.strip():
        return False
    hook = os.path.join(os.path.expanduser(data_dir), "hooks", "codex-hook.sh")
    return _comparable_path_text(hook) in _comparable_path_text(data)


def _comparable_path_text(text: str) -> str:
    """Path text in one spelling, so a hook command matches its install path.

    A TOML basic string doubles each backslash, a Windows path may use either
    separator, and Windows paths ignore case (GAP-2275).
    """
    return os.path.normcase(text.replace("\\\\", "\\")).replace("\\", "/")


def _registration_lock_state(
    cfg: Any,
    connector: str,
    *,
    readiness: bool = False,
) -> tuple[str | None, str | None]:
    data = _read_small_file(Path(cfg.data_dir) / "hook_contract_lock.json")
    if data is None:
        return None, "registration-lock-missing"
    try:
        payload = json.loads(data)
    except (TypeError, ValueError):
        return None, "registration-lock-malformed"
    connectors = payload.get("connectors") if isinstance(payload, dict) else None
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    if not isinstance(entry, dict):
        return None, "registration-lock-missing"
    value = entry.get("hook_fail_mode") if isinstance(entry, dict) else None
    raw = str(value or "").strip().lower()
    mode = raw if raw in _VALID_MODES else None
    expected_contracts = _EXPECTED_CONTRACTS.get(connector)
    if readiness:
        expected_contracts = frozenset(contract.contract_id for contract in HOOK_CONTRACTS.get(connector, ()))
        if invariant := connector_lock_contract_invariant(connector, entry):
            return mode, f"registration-{invariant}-stale"
    if readiness and _is_windows():
        from defenseclaw.agent_selection import setup_agent_lock_executable_invariant

        if invariant := setup_agent_lock_executable_invariant(str(cfg.data_dir), connector, entry):
            return mode, f"registration-{invariant}-stale"
    if expected_contracts and str(entry.get("contract_id") or "") not in expected_contracts:
        return mode, "registration-contract-stale"
    if expected_contracts and not str(entry.get("hook_script_version") or "").strip():
        return mode, "registration-version-stale"
    digests = entry.get("hook_script_digests")
    if expected_contracts and not isinstance(digests, dict):
        return mode, "registration-digests-missing"
    locations = entry.get("locations")
    configured_paths = locations.get("hook_script_paths") if isinstance(locations, dict) else None
    path_by_name = {
        Path(str(item)).name: Path(str(item))
        for item in (configured_paths if isinstance(configured_paths, list) else [])
        if str(item or "").strip()
    }
    if expected_contracts and not digests:
        return mode, "registration-digests-missing"

    raw_lock_version = payload.get("version", 1)
    if type(raw_lock_version) is not int or raw_lock_version < 1:
        return mode, "registration-lock-malformed"
    lock_version = raw_lock_version
    if lock_version > 2:
        return mode, "registration-lock-version-unsupported"
    shared_digests: dict[str, object] = {}
    requires_shared_runtime = connector in _SHARED_RUNTIME_CONNECTORS
    if lock_version >= 2 and requires_shared_runtime:
        raw_shared = payload.get("shared_hook_script_digests")
        if not isinstance(raw_shared, dict) or not _SHARED_HOOK_SCRIPTS.issubset(raw_shared):
            return mode, "registration-shared-digests-missing"
        shared_digests = raw_shared
    elif lock_version < 2 and requires_shared_runtime:
        # A v1 lock duplicated shared-file expectations in every connector
        # entry.  Divergent values cannot be reconciled by choosing whichever
        # connector happens to match disk; require controlled setup to render
        # canonical bytes and atomically migrate the whole lock to v2.
        legacy_shared = False
        if expected_contracts and not _LEGACY_SHARED_HOOK_SCRIPTS.issubset(digests):
            return mode, "registration-shared-digests-missing"
        for filename in _SHARED_HOOK_SCRIPTS:
            expected_values = {
                str(candidate_digests.get(filename) or "")
                for candidate in (connectors or {}).values()
                if isinstance(candidate, dict)
                for candidate_digests in [candidate.get("hook_script_digests")]
                if isinstance(candidate_digests, dict) and filename in candidate_digests
            }
            legacy_shared = legacy_shared or bool(expected_values)
            if len(expected_values) > 1:
                return mode, "registration-shared-digest-divergent"
        if legacy_shared and len(connectors or {}) > 1:
            return mode, "registration-shared-lock-legacy"
    if _is_windows() and connector in _WINDOWS_LAUNCHER_CONNECTORS:
        digest_names = {str(filename).casefold() for filename in digests}
        if "defenseclaw-hook.exe" not in digest_names:
            return mode, "registration-launcher-digest-missing"
    digest_sets = [digests or {}]
    if lock_version >= 2 and requires_shared_runtime:
        digest_sets.append(shared_digests)
    for digest_set in digest_sets:
        for filename, expected in digest_set.items():
            if lock_version >= 2 and digest_set is digests and str(filename) in _SHARED_HOOK_SCRIPTS:
                # Root shared evidence is authoritative in v2.  Ignore a
                # lingering legacy duplicate until the next locked save strips
                # it; never let the duplicate override the root digest.
                continue
            if expected_contracts and Path(str(filename)).name != str(filename):
                return mode, "registration-digest-path-stale"
            if expected_contracts:
                # Prefer the exact setup-time location recorded by the lock.
                # The Windows launcher can live outside the current process's
                # notion of HOME (service accounts and isolated installs are
                # common); hashing a guessed home path creates false drift.
                path = path_by_name.get(str(filename))
                if path is None:
                    path = (
                        Path.home() / ".local" / "bin" / "defenseclaw-hook.exe"
                        if str(filename).casefold() == "defenseclaw-hook.exe"
                        else Path(cfg.data_dir) / "hooks" / str(filename)
                    )
            else:
                path = path_by_name.get(str(filename), Path(cfg.data_dir) / "hooks" / str(filename))
            actual = _sha256_regular_file(path)
            if actual != str(expected or ""):
                return mode, "registration-digest-stale"
    return mode, None


def connector_registration_lock_state(cfg: Any, connector: str) -> tuple[str | None, str | None]:
    """Expose the existing passive lock/digest validator to readiness callers."""

    return _registration_lock_state(cfg, normalize(connector), readiness=True)


def _windows_registration_freshness(
    cfg: Any,
    connector: str,
    *,
    inspect_effective_policy: bool = True,
) -> str | None:
    """Return drift when the live Windows command/launcher is not current."""

    from defenseclaw.doctor_hooks import (
        _packaged_windows_install_root,
        validate_windows_hook_registration,
    )

    if connector == "devin":
        locked_paths = _registration_hook_config_paths(cfg, connector)
        if len(locked_paths) != 1:
            return "registration-config-binding-stale"
        config_path = locked_paths[0]
    elif connector == "codex":
        # Keep the fail-mode freshness guard on the source Setup recorded:
        # config.toml for per-user installs (current Codex ignores
        # managed_config.toml on Windows), managed_config.toml for managed
        # enterprise installs.
        locked_paths = _registration_hook_config_paths(cfg, connector)
        config_path = locked_paths[0] if locked_paths else codex_windows_hook_config_path(cfg)
    else:
        workspace = _connector_workspace(cfg)
        paths = connector_config_files(connector, workspace_dir=workspace)
        config_path = (
            paths[0]
            if paths
            else str(Path.home() / (".codex/config.toml" if connector == "codex" else ".claude/settings.json"))
        )
    install_root = _packaged_windows_install_root(str(cfg.data_dir))
    if install_root is None:
        install_root = str(Path.home() / ".local" / "bin")
    # Agents can briefly hold their settings or launcher without read sharing.
    # Revalidate all evidence after each wait. A persistent permission fault
    # still refuses the transaction; elapsed time never proves registration.
    for delay in (0, 0.1, 0.2, 0.4, 0.8):
        if delay:
            time.sleep(delay)
        check = validate_windows_hook_registration(
            connector=connector,
            config_path=config_path,
            data_dir=str(cfg.data_dir),
            install_root=install_root,
            search_path=os.environ.get("PATH", ""),
            pathext=os.environ.get("PATHEXT", ""),
            inspect_effective_policy=inspect_effective_policy,
            codex_per_user=(
                connector == "codex"
                and str(getattr(cfg, "deployment_mode", "") or "").strip().lower() != "managed_enterprise"
            ),
        )
        if check.healthy or check.state != "access-denied":
            break
    return None if check.healthy else f"registration-{check.state}"


def _registration_hook_config_paths(cfg: Any, connector: str) -> tuple[str, ...]:
    """Read the exact config targets recorded by the connector contract lock."""

    data = _read_small_file(Path(cfg.data_dir) / "hook_contract_lock.json")
    if data is None:
        return ()
    try:
        payload = json.loads(data)
    except (TypeError, ValueError):
        return ()
    connectors = payload.get("connectors") if isinstance(payload, dict) else None
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    locations = entry.get("locations") if isinstance(entry, dict) else None
    raw_paths = locations.get("hook_config_paths") if isinstance(locations, dict) else None
    if not isinstance(raw_paths, list) or not all(isinstance(path, str) and path for path in raw_paths):
        return ()
    return tuple(raw_paths)


def _unix_registration_freshness(cfg: Any, connector: str) -> str | None:
    """Verify the live Unix agent registration points at this data dir's hook."""

    if connector == "hermes":
        try:
            current = hermes_config_path()
        except ValueError:
            return "registration-config-binding-stale"
        if _registration_hook_config_paths(cfg, connector) != (current,):
            return "registration-config-binding-stale"
        # The fail-mode status must not call a stale open command "closed".
        # Doctor's Hermes validator reads the full event matrix, approvals and
        # sealed target from the active config. The execution probe is
        # Doctor's alone: a host that cannot run it (no unprivileged user
        # namespaces) has a current registration all the same, and the hook's
        # rendered mode is read as its own source (hook-script).
        from defenseclaw.commands.cmd_doctor import _hermes_registration_problem

        return "registration-command-stale" if _hermes_registration_problem(cfg, current) else None

    paths = connector_config_files(connector, workspace_dir=_connector_workspace(cfg))
    script_name = _UNIX_REGISTRATION_HOOK_SCRIPTS.get(connector)
    if not paths or script_name is None:
        return "registration-missing"
    # Devin's registration names devin-hook.sh; checking it for codex-hook.sh
    # reported every current Devin registration as stale (GAP-0027).
    registration = _read_small_file(Path(paths[0]))
    if registration is None:
        return "registration-missing"
    if connector == "claudecode":
        # A packaged per-user Linux install registers the native handlers,
        # which name no hook script: judging them by claude-code-hook.sh
        # reported every fresh or upgraded install stale (rel-1-0-6 GAP-0569).
        native = _claude_per_user_native_registration(cfg)
        if native is not None:
            problem = _claude_native_registration_problem(registration, native, str(cfg.data_dir))
            return problem or _claude_missing_registration_drift(cfg, registration)
    hook = Path(cfg.data_dir).expanduser() / "hooks" / script_name
    # Setup writes the data dir's own spelling; a HOME below a symlinked
    # directory resolves elsewhere, and either names this install's hook
    # (GAP-2371: the resolved form alone reported a fresh registration stale).
    expected = {os.path.normpath(str(hook)), str(hook.resolve())}
    # JSON/TOML string literals escape a backslash when this helper is unit
    # tested from Windows; Unix paths use '/' and are unchanged.
    expected_forms = expected | {form.replace("\\", "\\\\") for form in expected}
    if not any(candidate in registration for candidate in expected_forms):
        return "registration-command-stale"
    return None


def _claude_missing_registration_drift(cfg: Any, registration: str) -> str | None:
    """registration-missing when a required event lost its native handlers, as doctor reports (rel-1-0-2 GAP-0645).

    The shell form keeps the script check above; its tool-guard events are
    hook_integrity's unguarded check, which status reads too.
    """

    try:
        settings = json.loads(registration)
    except ValueError:
        return "registration-command-stale"
    return "registration-missing" if claude_missing_registration(cfg, settings) else None


@dataclass(frozen=True)
class _ClaudeNativeRegistration:
    """The per-user Linux Claude Code handlers Setup writes on this host.

    guard is defenseclaw-hook-post, or "" when it is not installed; native is
    defenseclaw-hook-user; hook_args are the arguments after the launcher.
    """

    guard: str
    native: str
    hook_args: tuple[str, ...]


# claudeCodeMissingHookGuardSeparator (internal/gateway/connector/claudecode.go).
_CLAUDE_MISSING_HOOK_GUARD_SEPARATOR = " || { rc=$?; "
_CLAUDE_MISSING_HOOK_GUARD_MESSAGE = (
    "DefenseClaw blocked this: its Claude Code hook script is missing "
    "or cannot be run. Run the DefenseClaw installer, then defenseclaw quickstart, to repair it, "
    "or remove the DefenseClaw hooks from ~/.claude/settings.json."
)


def _claude_posix_word(value: str) -> str:
    """posixHookCommandWord (internal/gateway/connector/helpers.go)."""

    if value and all((ch.isascii() and ch.isalnum()) or ch in "/._-+=:,@%" for ch in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _claude_native_shell_command(expected: _ClaudeNativeRegistration) -> str:
    """The exact native launcher command Setup writes without a guard binary."""

    command = " ".join(_claude_posix_word(word) for word in (expected.native, *expected.hook_args))
    return (
        command
        + _CLAUDE_MISSING_HOOK_GUARD_SEPARATOR
        + '[ "$rc" -eq 126 ] || [ "$rc" -eq 127 ] || exit "$rc"; '
        + "echo '"
        + _CLAUDE_MISSING_HOOK_GUARD_MESSAGE
        + "' >&2; exit 2; }"
    )


def _claude_loopback_api_addr(addr: str) -> bool:
    """claudeCodeLoopbackGatewayEndpoint("http://" + addr) for a host:port address."""

    if not addr or any(ch in addr for ch in "/?#@\\"):
        return False
    host, separator, port = addr.rpartition(":")
    if not separator or not port.isascii() or not port.isdigit():
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host in {"127.0.0.1", "localhost", "::1"}


def _claude_owner_executable(path: str) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 != 0 and info.st_mode & 0o022 == 0


def _claude_lstat_dir(path: str) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _claude_per_user_native_registration(cfg: Any) -> _ClaudeNativeRegistration | None:
    """The native per-user registration Setup writes here, or None for the shell form.

    Mirrors claudeCodePerUserNativeHook, claudeCodePerUserNativeGuard and
    claudeCodeHookInvocation (internal/gateway/connector/claudecode.go) with
    the gateway's APIAddr (apiListenAddr): Linux, not managed, the account's
    default data directory, a .gateway-helper record naming
    ~/.local/bin/defenseclaw-gateway and an owner-only defenseclaw-hook-user
    beside it. macOS, managed and custom data directories keep the shell hook.
    """

    if _is_windows() or not _is_linux():
        return None
    if str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
        return None
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    if (
        not os.path.isabs(data_dir)
        or os.path.normpath(data_dir) != data_dir
        or data_dir != os.path.join(str(Path.home()), ".defenseclaw")
        or any(ch in data_dir for ch in "\x00\r\n")
    ):
        return None
    gateway = getattr(cfg, "gateway", None)
    try:
        api_port = int(getattr(gateway, "api_port", 18970) or 0)
    except (TypeError, ValueError):
        return None
    api_addr = f"{config_module.api_bind_host(cfg)}:{api_port}"
    if not _claude_loopback_api_addr(api_addr):
        return None
    hooks_dir = os.path.join(data_dir, "hooks")
    if not _claude_lstat_dir(data_dir) or not _claude_lstat_dir(hooks_dir):
        return None
    record = os.path.join(hooks_dir, ".gateway-helper")
    try:
        info = os.lstat(record)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > 4097 or info.st_mode & 0o022:
        return None
    text = _read_small_file(Path(record))
    if text is None:
        return None
    helper = text[:-1] if text.endswith("\n") else text
    if (
        not os.path.isabs(helper)
        or os.path.normpath(helper) != helper
        or any(ch in helper for ch in "\x00\r\n")
        or os.path.basename(helper) != "defenseclaw-gateway"
        or os.path.basename(os.path.dirname(helper)) != "bin"
        or os.path.basename(os.path.dirname(os.path.dirname(helper))) != ".local"
    ):
        return None
    native = os.path.join(os.path.dirname(helper), "defenseclaw-hook-user")
    if not _claude_owner_executable(native):
        return None
    guard = os.path.join(os.path.dirname(native), "defenseclaw-hook-post")
    return _ClaudeNativeRegistration(
        guard=guard if _claude_owner_executable(guard) else "",
        native=native,
        hook_args=("hook", "--connector", "claudecode", "--hook-home", data_dir, "--api-addr", api_addr),
    )


def _claude_owned_handler(handler: dict[str, Any], data_dir: str) -> bool:
    words: list[Any] = [handler.get("command")]
    args = handler.get("args")
    if isinstance(args, list):
        words.extend(args)
    for word in words:
        if not isinstance(word, str):
            continue
        lowered = word.lower()
        if (
            "claude-code-hook" in lowered
            or "defenseclaw-hook" in lowered
            or "/.defenseclaw/" in word
            or data_dir in word
        ):
            return True
    return False


def _claude_native_primary_handler(handler: dict[str, Any], expected: _ClaudeNativeRegistration) -> bool:
    """Whether a handler names the native invocation Setup registers for an event."""

    if expected.guard:
        return handler.get("command") == expected.guard and handler.get("args") == [
            "guard-user-hook", expected.native, *expected.hook_args
        ]
    return handler.get("args") is None and handler.get("command") == _claude_native_shell_command(expected)


def _claude_native_event_fields_current(event: str, group: dict[str, Any], handler: dict[str, Any]) -> bool:
    """Whether a native handler keeps the fields Setup renders for its event."""

    from defenseclaw.doctor_hooks import _CLAUDE_REQUIRED_HOOKS, _matcher_covers

    required = _CLAUDE_REQUIRED_HOOKS.get(event)
    if required is None:
        return True
    matcher, timeout = required
    if not _matcher_covers(event, group.get("matcher"), matcher):
        return False
    if type(handler.get("timeout")) is not int or handler["timeout"] != timeout:
        return False
    if handler.get("async", False) is not (event == "MessageDisplay") or group.get("async") is True:
        return False
    return all(
        item.get("asyncRewake") is not True
        and item.get("async_rewake") is not True
        and item.get("if", "") == ""
        for item in (group, handler)
    )


def _claude_native_registration_problem(
    registration: str, expected: _ClaudeNativeRegistration, data_dir: str
) -> str | None:
    """Whether settings.json holds only the per-user native handlers Setup writes.

    As appendClaudeCodeHookGroups renders them: with the guard installed each
    event runs ``defenseclaw-hook-post guard-user-hook <hook-user> hook ...``
    and, unless asynchronous, the companion ``defenseclaw-hook-user
    fallback-guard-user-hook <hook-post> hook ...`` in the same group;
    without the guard, the launcher's shell command behind the missing-hook
    guard. Any other DefenseClaw handler is stale: a 1.0.7 shell entry left
    behind, another binary or data directory, edited arguments or a missing
    companion. Event coverage is claude_missing_registration's check. Known
    event fields use Doctor's required-hook table; the tool-guard field matrix
    also checks that PreToolUse covers every call for Doctor and status.
    testdata/claudecode_linux_peruser_handlers.json pins this to the Go render.
    """

    stale = "registration-command-stale"
    try:
        settings = json.loads(registration)
    except ValueError:
        return stale
    hooks = settings.get("hooks") if isinstance(settings, dict) else None
    if not isinstance(hooks, dict):
        return stale
    companion_args = ["fallback-guard-user-hook", expected.guard, *expected.hook_args]
    primaries = 0
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(handlers, list):
                continue
            synchronous = companions = 0
            for handler in handlers:
                if not isinstance(handler, dict) or not _claude_owned_handler(handler, data_dir):
                    continue
                if not _claude_native_event_fields_current(event, group, handler):
                    return stale
                command, args = handler.get("command"), handler.get("args")
                if handler.get("type") != "command":
                    return stale
                if _claude_native_primary_handler(handler, expected):
                    primaries += 1
                    if expected.guard:
                        synchronous += handler.get("async") is not True
                elif command == expected.native and args == companion_args:
                    companions += 1
                else:
                    return stale
            if companions != synchronous:
                return stale
    return None if primaries else stale


# claudeCodeAllHookGroups (internal/gateway/connector/claudecode.go): only
# MessageDisplay is registered asynchronously, so it has no companion.
_CLAUDE_ASYNC_EVENTS = frozenset({"MessageDisplay"})


def claude_required_events(cfg: Any) -> tuple[str, ...]:
    """The Claude Code events Setup registers for this install.

    The contract Setup recorded in hook_contract_lock.json names them; without
    a readable record only the tool-guard events of the shared table
    (hook_guard_matrix.TOOL_GUARD_HOOKS) are required.
    """

    from defenseclaw.doctor_hooks import _CLAUDE_CONTRACT_EVENTS
    from defenseclaw.hook_guard_matrix import TOOL_GUARD_HOOKS

    data = _read_small_file(Path(cfg.data_dir) / "hook_contract_lock.json")
    try:
        payload = json.loads(data) if data else None
    except ValueError:
        payload = None
    connectors = payload.get("connectors") if isinstance(payload, dict) else None
    entry = connectors.get("claudecode") if isinstance(connectors, dict) else None
    contract = entry.get("contract_id") if isinstance(entry, dict) else None
    events = _CLAUDE_CONTRACT_EVENTS.get(contract) if isinstance(contract, str) else None
    return tuple(events) if events else tuple(TOOL_GUARD_HOOKS["claudecode"].events)


def claude_missing_registration(cfg: Any, settings: Any) -> tuple[str, str] | None:
    """The first required Claude Code event without the handlers Setup renders here, or None (GAP-0645).

    Returns (event, what is missing). Each event of claude_required_events
    must hold, in one group, the exact registration appendClaudeCodeHookGroups
    writes: on a per-user Linux install with the guard, the guard
    (``defenseclaw-hook-post guard-user-hook ...``) and, for a synchronous
    event, its ``defenseclaw-hook-user fallback-guard-user-hook ...``
    companion; without the guard, the launcher behind the missing-hook guard;
    elsewhere a command that runs claude-code-hook.sh.
    Counting DefenseClaw handlers passed a file that had lost PreToolUse once
    1.0.8 wrote two handlers per synchronous event. Foreign handlers are
    ignored; stale DefenseClaw handlers are _claude_native_registration_problem's.
    """

    hooks = settings.get("hooks") if isinstance(settings, dict) else None
    if not isinstance(hooks, dict):
        hooks = {}
    native = _claude_per_user_native_registration(cfg)
    if native is not None:
        companion_args = ["fallback-guard-user-hook", native.guard, *native.hook_args]

    def guard(handler: dict[str, Any], group: dict[str, Any], event: str, synchronous: bool) -> bool:
        if handler.get("type") != "command" or (synchronous and handler.get("async") is True):
            return False
        if native is None:
            # Which copy of the script runs is the freshness and edited-hook
            # checks' question; this one asks whether the event runs it at all.
            command = handler.get("command")
            return isinstance(command, str) and "claude-code-hook.sh" in command
        return _claude_native_event_fields_current(event, group, handler) and _claude_native_primary_handler(
            handler, native
        )

    def companion(handler: dict[str, Any], group: dict[str, Any], event: str) -> bool:
        return (
            native is not None
            and handler.get("type") == "command"
            and handler.get("async") is not True
            and _claude_native_event_fields_current(event, group, handler)
            and handler.get("command") == native.native
            and handler.get("args") == companion_args
        )

    needs_companion = native is not None and bool(native.guard)
    for event in claude_required_events(cfg):
        synchronous = event not in _CLAUDE_ASYNC_EVENTS
        groups = hooks.get(event)
        guarded = False
        for group in groups if isinstance(groups, list) else ():
            handlers = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(handlers, list):
                continue
            handlers = [handler for handler in handlers if isinstance(handler, dict)]
            if not any(guard(handler, group, event, synchronous) for handler in handlers):
                continue
            guarded = True
            if not (needs_companion and synchronous) or any(companion(handler, group, event) for handler in handlers):
                break
        else:
            if not guarded:
                return event, "hook is not registered"
            return event, "hook has no fallback-guard-user-hook companion (defenseclaw-hook-user) in its group"
    return None


def _read_small_file(path: Path) -> str | None:
    body = _read_small_bytes(path)
    if body is None:
        return None
    try:
        return body.decode("utf-8")
    except UnicodeError:
        return None


def _read_small_bytes(path: Path) -> bytes | None:
    descriptor: int | None = None
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_RUNTIME_FILE:
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_RUNTIME_FILE:
            return None
        if not os.path.samestat(info, opened):
            return None
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            body = handle.read(_MAX_RUNTIME_FILE + 1)
            return body if len(body) <= _MAX_RUNTIME_FILE else None
    except OSError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sha256_regular_file(path: Path) -> str:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_DIGEST_FILE:
            return ""
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > _MAX_DIGEST_FILE
            or not os.path.samestat(before, opened)
        ):
            return ""
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            return ""
        return "sha256:" + digest.hexdigest()
    except OSError:
        return ""
    finally:
        if descriptor is not None:
            os.close(descriptor)


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    existed: bool
    data: bytes = b""
    mode: int = 0o600


@contextmanager
def fail_mode_transaction_lock(cfg: Any) -> Iterator[None]:
    """Serialize config + registration reconciliation across CLI/TUI callers."""

    config_path = str(config_module.config_path_for_data_dir(cfg.data_dir))
    lock_path = config_path + ".fail-mode-transaction.lock"
    Path(lock_path).parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        lock = os.fdopen(descriptor, "r+")
    except BaseException:
        os.close(descriptor)
        raise
    try:
        _lock_file_exclusive(lock, timeout_seconds=None)
        try:
            yield
        finally:
            _unlock_file(lock)
    finally:
        lock.close()


def snapshot_fail_mode_transaction(cfg: Any, connectors: list[str]) -> tuple[FileSnapshot, ...]:
    """Snapshot the registration files a fail-mode change can rewrite.

    config.yaml is not part of it: the caller reverts its modeled change and
    saves again through the single writer, which keeps concurrent edits and
    records the rollback as a new generation.
    """
    hook_dir = Path(cfg.data_dir) / "hooks"
    paths = set(
        {
            hook_dir / ".hookcfg",
            hook_dir / ".hookcfg.legacy",
            Path(cfg.data_dir) / "hook_contract_lock.json",
            hook_dir / "inspect-tool.sh",
            hook_dir / "inspect-request.sh",
            hook_dir / "inspect-response.sh",
            hook_dir / "inspect-tool-response.sh",
            hook_dir / "_hardening.sh",
        }
    )
    workspace = _connector_workspace(cfg)
    for raw_name in connectors:
        name = normalize(raw_name)
        paths.add(hook_dir / f".hook-{name}.token")
        paths.add(hook_dir / f".hookcfg.{name}")
        try:
            config_paths = connector_config_files(name, workspace_dir=workspace)
        except ValueError as exc:
            raise OSError(f"{name} profile binding is invalid: {exc}") from exc
        for config_path in config_paths:
            paths.add(Path(config_path))
        paths.add(hook_dir / f"{name}-hook.sh")
        paths.add(Path(cfg.data_dir) / f"{name}_backup.json")
        backup_dir = Path(cfg.data_dir) / "connector_backups" / name
        for logical_name in ("config", "settings.json", "config.toml", "module", "pth", "openclaw.json"):
            paths.add(backup_dir / f"{logical_name}.json")
        if backup_dir.is_dir():
            paths.update(path for path in backup_dir.rglob("*") if path.is_file())
        if name == "claudecode":
            paths.update(
                {
                    hook_dir / "claude-code-hook.sh",
                    Path(cfg.data_dir) / "claudecode_backup.json",
                    Path(cfg.data_dir) / "connector_backups" / "claudecode" / "settings.json.json",
                }
            )
        elif name == "codex":
            paths.update(
                {
                    hook_dir / "codex-hook.sh",
                    Path(cfg.data_dir) / "codex_config_backup.json",
                    Path(cfg.data_dir) / "codex_backup.json",
                    Path(cfg.data_dir) / "connector_backups" / "codex" / "config.toml.json",
                    Path(cfg.data_dir) / "notify-bridge.sh",
                }
            )
    snapshots: list[FileSnapshot] = []
    for path in sorted(paths, key=str):
        try:
            data, mode = _snapshot_regular_file(path)
            snapshots.append(
                FileSnapshot(
                    path=path,
                    existed=True,
                    data=data,
                    mode=mode,
                )
            )
        except FileNotFoundError:
            snapshots.append(FileSnapshot(path=path, existed=False))
    return tuple(snapshots)


def _snapshot_regular_file(path: Path) -> tuple[bytes, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_RUNTIME_FILE:
        raise OSError(f"unsafe transaction path: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_RUNTIME_FILE:
            raise OSError(f"unsafe opened transaction path: {path}")
        if not os.path.samestat(info, opened):
            raise OSError(f"transaction path changed while opening: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            body = handle.read(_MAX_RUNTIME_FILE + 1)
            if len(body) > _MAX_RUNTIME_FILE:
                raise OSError(f"transaction path grew beyond size limit: {path}")
            return body, stat.S_IMODE(opened.st_mode)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def restore_fail_mode_transaction(snapshots: tuple[FileSnapshot, ...]) -> None:
    errors: list[str] = []
    for snapshot in reversed(snapshots):
        try:
            # A failed save can leave every file untouched. Avoid replacing an
            # immutable original (and rewriting user edits) in that case.
            if snapshot.existed:
                try:
                    current, mode = _snapshot_regular_file(snapshot.path)
                except FileNotFoundError:
                    pass
                else:
                    if current == snapshot.data and mode == snapshot.mode:
                        continue
                snapshot.path.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(prefix=f".{snapshot.path.name}.", dir=snapshot.path.parent)
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(snapshot.data)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(temporary, snapshot.mode)
                    os.replace(temporary, snapshot.path)
                finally:
                    try:
                        os.unlink(temporary)
                    except FileNotFoundError:
                        pass
            else:
                snapshot.path.unlink(missing_ok=True)
        except OSError:
            errors.append(str(snapshot.path))
    if errors:
        raise OSError("rollback failed for runtime files: " + ", ".join(errors))


def reconcile_connector_registration(cfg: Any, connector: str) -> ConnectorFailModeState:
    name = normalize(connector)
    executable = path_gateway(honor_override=False)
    if not executable or (_is_windows() and Path(executable).suffix.lower() != ".exe"):
        raise OSError("native defenseclaw-gateway executable not found")
    environment = os.environ.copy()
    environment[config_module.CONFIG_PATH_ENV] = str(config_module.config_path_for_data_dir(cfg.data_dir))
    try:
        args = [
            executable,
            "connector",
            "reconcile",
            "--connector",
            name,
            "--data-dir",
            str(cfg.data_dir),
        ]
        args.append("--json")
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError(f"connector reconcile failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "connector reconcile failed").splitlines()[0]
        raise OSError(detail[:240])
    state = resolve_connector_fail_mode(cfg, name)
    if _is_windows() and name == "codex":
        # A Codex app-server can briefly hold a just-reconciled registration
        # file. Retry only that read refusal; every attempt still validates
        # the complete live registration before reporting success.
        for _ in range(2):
            if state.current or "registration-access-denied" not in state.drift:
                break
            time.sleep(0.15)
            state = resolve_connector_fail_mode(cfg, name)
    if not state.current:
        raise OSError(
            f"connector runtime verification failed for {state.connector}: "
            + ", ".join(state.drift)
            + ". Run `defenseclaw doctor`, then retry the fail-mode command."
        )
    return state
