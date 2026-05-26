# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the LLM wizard surfaces.

Centralises the provider / model / region / API-key pickers so the
``defenseclaw setup llm`` and ``defenseclaw setup guardrail`` wizards
present identical UX, and so every interactive prompt has a matching
non-interactive ``--flag`` enforcement helper.

Design rules:

* No module ever ``click.prompt``s during ``--non-interactive`` mode.
  Helpers receive an explicit ``non_interactive`` boolean and raise
  :class:`click.UsageError` when a required value is missing — the CLI
  parity test (``internal/tui/cli_parity_test.go``) relies on this so
  the TUI's batch invocations never block on stdin.
* The model catalog is a packaged JSON; custom-provider instances
  contribute ``available_models`` discovered at runtime from
  ``~/.defenseclaw/custom-providers.json``.
* No new state is introduced — helpers mutate :class:`LLMConfig`
  instances in place to match the existing wizard contract.
"""

from __future__ import annotations

import json as _json
import os
import re
from dataclasses import asdict
from importlib.resources import files
from typing import Any

import click

from defenseclaw import ux
from defenseclaw.config import (
    DEFENSECLAW_LLM_KEY_ENV,
    AzureKeyConfig,
    BedrockKeyConfig,
    LLMConfig,
    LLMTLSConfig,
    VertexKeyConfig,
)

_CATALOG_RESOURCE = "_data/llm/model_catalog.json"


# ---------------------------------------------------------------------------
# Catalog loading
# ---------------------------------------------------------------------------


_catalog_cache: dict[str, Any] | None = None


def load_catalog() -> dict[str, Any]:
    """Return the packaged model-catalog JSON.

    Cached after the first load — the file is shipped with the wheel
    and never mutates at runtime.
    """
    global _catalog_cache
    if _catalog_cache is None:
        try:
            raw = files("defenseclaw").joinpath(_CATALOG_RESOURCE).read_text(encoding="utf-8")
            _catalog_cache = _json.loads(raw)
        except (FileNotFoundError, ValueError, ModuleNotFoundError):
            _catalog_cache = {"providers": []}
    return _catalog_cache


def catalog_providers() -> list[dict[str, Any]]:
    return list(load_catalog().get("providers") or [])


def catalog_entry(name: str) -> dict[str, Any] | None:
    """Look up a provider entry by canonical name (case-insensitive)."""
    target = (name or "").strip().lower()
    if not target:
        return None
    for entry in catalog_providers():
        if str(entry.get("name", "")).strip().lower() == target:
            return entry
    return None


# ---------------------------------------------------------------------------
# Custom-provider overlay reads
# ---------------------------------------------------------------------------


def _overlay_path(data_dir: str) -> str:
    return os.path.join(data_dir or os.path.expanduser("~/.defenseclaw"), "custom-providers.json")


def list_custom_instances(data_dir: str) -> list[dict[str, Any]]:
    """Return the custom-providers.json provider entries.

    Returns an empty list when the file is missing or malformed —
    overlay errors are surfaced by ``defenseclaw doctor``, not the
    wizard helpers.
    """
    path = _overlay_path(data_dir)
    try:
        with open(path, encoding="utf-8") as f:
            data = _json.load(f)
    except (FileNotFoundError, ValueError, PermissionError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    providers = data.get("providers") or []
    if not isinstance(providers, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in providers:
        if isinstance(entry, dict) and entry.get("name"):
            out.append(entry)
    return out


def custom_instance(data_dir: str, name: str) -> dict[str, Any] | None:
    target = (name or "").strip().lower()
    if not target:
        return None
    for entry in list_custom_instances(data_dir):
        if str(entry.get("name", "")).strip().lower() == target:
            return entry
    return None


# ---------------------------------------------------------------------------
# Provider picker
# ---------------------------------------------------------------------------


_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _flag_required(non_interactive: bool, flag: str, *, hint: str | None = None) -> None:
    """Raise click.UsageError pointing at the missing flag.

    Centralised so every non-interactive enforcement message reads the
    same way and the TUI surfaces a recognisable error string.
    """
    if not non_interactive:
        return
    msg = f"missing required value under --non-interactive: {flag}"
    if hint:
        msg += f" ({hint})"
    raise click.UsageError(msg)


def pick_provider(
    *,
    current: str,
    catalog: list[dict[str, Any]] | None = None,
    instances: list[dict[str, Any]] | None = None,
    flag_value: str | None,
    non_interactive: bool,
    flag_name: str = "--provider",
) -> str:
    """Resolve a provider id.

    Honors ``flag_value`` first, then falls back to ``current``. In
    non-interactive mode an unset value either keeps ``current`` (if
    non-empty) or raises ``UsageError`` so scripts never silently pin
    the default.
    """
    if flag_value:
        return flag_value.strip().lower()
    if non_interactive:
        if current:
            return current.strip().lower()
        _flag_required(non_interactive, flag_name, hint="e.g. anthropic, bedrock, vertex_ai, azure")
        return ""

    catalog = catalog if catalog is not None else catalog_providers()
    instances = instances if instances is not None else []

    rows: list[tuple[str, str, str]] = []  # (id, label, kind)
    for entry in catalog:
        rows.append(
            (
                str(entry.get("name", "")),
                str(entry.get("label", entry.get("name", ""))),
                str(entry.get("kind", "")),
            )
        )
    if instances:
        rows.append(("__custom_separator__", "── custom providers ──", ""))
        for inst in instances:
            rows.append(
                (
                    f"custom:{inst.get('name', '')}",
                    f"{inst.get('name', '')} (custom: {inst.get('base_url', 'no base_url')})",
                    "custom",
                )
            )

    click.echo()
    ux.subhead("Available providers:")
    valid: list[str] = []
    for idx, (pid, label, kind) in enumerate(rows, start=1):
        if pid == "__custom_separator__":
            click.echo(f"    {label}")
            continue
        valid.append(pid)
        click.echo(f"    [{idx}] {label}")
    click.echo("    [m] type a model id directly (advanced)")
    click.echo()

    default_label = current if current in valid else (valid[0] if valid else "")
    while True:
        raw = click.prompt(
            "  Pick provider (number, name, or 'm' for free-form)",
            default=default_label,
            show_default=bool(default_label),
        ).strip()
        if not raw:
            continue
        # The `m` shortcut bypasses the picker entirely for operators
        # whose model is not in the curated catalog (e.g. a brand-new
        # release the wheel hasn't shipped yet). We return a sentinel
        # `__manual__` value so the caller can route through
        # `pick_model` with a free-text prompt.
        if raw.lower() == "m":
            manual = click.prompt(
                "  Type provider id (e.g. anthropic, openai, bedrock)",
            ).strip().lower()
            if manual:
                return manual
            continue
        if raw.isdigit():
            n = int(raw)
            if 1 <= n <= len(rows):
                pid = rows[n - 1][0]
                if pid == "__custom_separator__":
                    continue
                return pid.removeprefix("custom:") if pid.startswith("custom:") else pid
        lowered = raw.lower()
        for pid in valid:
            tail = pid.removeprefix("custom:") if pid.startswith("custom:") else pid
            if lowered in (pid.lower(), tail.lower()):
                return tail
        click.echo("    Invalid choice — pick a number from the list, type a provider name, or 'm' for free-form.")


def pick_model(
    *,
    current: str,
    provider: str,
    instance: dict[str, Any] | None,
    flag_value: str | None,
    non_interactive: bool,
    flag_name: str = "--model",
) -> str:
    """Pick a model id for the chosen provider.

    When ``instance`` is set, prefers its ``available_models`` over the
    catalog's defaults.
    """
    if flag_value:
        return flag_value.strip()
    if non_interactive:
        if current:
            return current.strip()
        _flag_required(non_interactive, flag_name, hint=f"e.g. {provider}/<model-id>")
        return ""

    models: list[str] = []
    if instance:
        models = [str(m) for m in (instance.get("available_models") or []) if m]
    if not models:
        entry = catalog_entry(provider)
        if entry:
            models = [str(m) for m in (entry.get("models") or []) if m]

    click.echo()
    if models:
        ux.subhead(f"Models for {provider}:")
        for idx, m in enumerate(models, start=1):
            click.echo(f"    [{idx}] {m}")
        click.echo("    [c] type a custom model id")
        click.echo()
        default = current if current in models else models[0]
        while True:
            raw = click.prompt("  Pick model", default=default, show_default=True).strip()
            if raw.isdigit():
                n = int(raw)
                if 1 <= n <= len(models):
                    return models[n - 1]
            if raw == "c":
                return click.prompt("  Type model id").strip()
            if raw in models:
                return raw
            return raw  # accept any free-form id LiteLLM/Bifrost can route
    return click.prompt(
        "  LLM model id (e.g. 'claude-sonnet-4-5', 'gpt-4o', 'llama3.3')",
        default=current or "",
        show_default=bool(current),
    ).strip()


def pick_region(
    *,
    provider: str,
    current: str,
    flag_value: str | None,
    non_interactive: bool,
    flag_name: str = "--region",
) -> str:
    """Pick a region for regional providers (bedrock/vertex)."""
    if flag_value:
        return flag_value.strip()
    if non_interactive:
        if current:
            return current.strip()
        _flag_required(non_interactive, flag_name, hint=f"required for {provider}")
        return ""
    entry = catalog_entry(provider) or {}
    regions = [str(r) for r in (entry.get("regions") or []) if r]
    if regions:
        ux.subhead(f"Common regions for {provider}:")
        for r in regions:
            click.echo(f"    - {r}")
    default = current or (regions[0] if regions else "")
    return click.prompt(
        f"  {provider} region",
        default=default,
        show_default=bool(default),
    ).strip()


def pick_auth_mode(
    *,
    provider: str,
    current: str,
    flag_value: str | None,
    non_interactive: bool,
    flag_name: str = "--auth-mode",
) -> str:
    """Pick the provider-specific auth mode."""
    if flag_value:
        return flag_value.strip().lower()
    entry = catalog_entry(provider) or {}
    modes = [str(m) for m in (entry.get("auth_modes") or []) if m]
    if not modes:
        return current or ""
    if non_interactive:
        if current and current in modes:
            return current
        _flag_required(non_interactive, flag_name, hint="one of " + "/".join(modes))
        return ""
    default = current if current in modes else modes[0]
    return click.prompt(
        f"  {provider} auth mode",
        type=click.Choice(modes),
        default=default,
        show_default=True,
    ).strip().lower()


def pick_key_env(
    *,
    provider: str,
    current: str,
    flag_value: str | None,
    non_interactive: bool,
    flag_name: str = "--api-key-env",
) -> str:
    """Pick the env var name that should hold the LLM API key."""
    if flag_value:
        name = flag_value.strip()
    elif current:
        name = current.strip()
    elif non_interactive:
        return DEFENSECLAW_LLM_KEY_ENV
    else:
        entry = catalog_entry(provider) or {}
        suggestions = [str(k) for k in (entry.get("env_keys") or []) if k]
        suggested = suggestions[0] if suggestions else DEFENSECLAW_LLM_KEY_ENV
        if len(suggestions) > 1:
            click.echo(f"    Common env vars: {', '.join(suggestions)}")
        name = click.prompt(
            "  API key env var name",
            default=suggested,
            show_default=True,
        ).strip()
    if not _ENV_KEY_RE.match(name):
        raise click.BadParameter(
            f"invalid env var name: {name!r} (must be ASCII [A-Za-z_][A-Za-z0-9_]*)"
        )
    return name


def pick_instance_name(
    *,
    data_dir: str,
    current: str,
    flag_value: str | None,
    non_interactive: bool,
    flag_name: str = "--instance-name",
) -> str:
    """Pick a custom-provider instance by name. Returns empty when no
    custom instances are configured / the operator skipped.
    """
    if flag_value is not None:
        return flag_value.strip()
    if non_interactive:
        return current or ""
    instances = list_custom_instances(data_dir)
    if not instances:
        return ""
    names = [str(i.get("name", "")) for i in instances if i.get("name")]
    click.echo()
    ux.subhead("Configured custom-provider instances:")
    for n in names:
        click.echo(f"    - {n}")
    click.echo("    (blank skips and uses a stock provider)")
    choice = click.prompt(
        "  Use a custom-provider instance? (name or blank)",
        default=current or "",
        show_default=bool(current),
    ).strip()
    if choice and choice not in names:
        click.echo(f"    Note: no instance named {choice!r} — will be created if you run setup provider add.")
    return choice


# ---------------------------------------------------------------------------
# Inherit-preflight: detect sibling components that already have a usable
# LLM config, so the wizard can offer "reuse this" instead of prompting
# for every field again.
# ---------------------------------------------------------------------------


_INHERIT_PATHS: tuple[str, ...] = (
    "",  # top-level cfg.llm
    "guardrail",
    "guardrail.judge",
    "scanners.skill",
    "scanners.mcp",
    "scanners.plugin",
)


def list_inherit_candidates(
    cfg: Any,
    *,
    exclude: tuple[str, ...] = (),
) -> list[dict[str, str]]:
    """Return component paths whose resolved LLM has at least a model.

    Drives the interactive "Inherit preflight" prompt in
    ``defenseclaw setup llm`` / ``defenseclaw setup guardrail``: when
    the operator has already configured one component (typically the
    top-level ``llm`` block), the wizard can offer to copy that
    configuration onto the new role rather than re-asking the same
    questions.

    The returned list is ordered most-likely-first (top-level
    ``llm:``, then guardrail.judge, then scanners). ``exclude`` lets a
    caller skip the role being configured.
    """
    excluded = {(e or "").strip() for e in exclude}
    out: list[dict[str, str]] = []
    for path in _INHERIT_PATHS:
        if path in excluded:
            continue
        try:
            resolved = cfg.resolve_llm(path)
        except Exception:
            continue
        provider = (getattr(resolved, "provider", "") or "").strip()
        model = (getattr(resolved, "model", "") or "").strip()
        if not provider and not model:
            continue
        summary = f"{provider or '?'} / {model or '?'}"
        label = path or "llm"
        out.append({"path": label, "summary": summary})
    return out


def preflight_inherit(
    cfg: Any,
    *,
    target_path: str,
    ping_timeout: int = 2,
) -> dict[str, Any] | None:
    """Run the interactive "Inherit preflight" for ``target_path``.

    Lists every sibling component whose LLM is already configured,
    pings each one (best-effort, capped at ``ping_timeout`` seconds),
    and presents a 4-option menu:

    * ``[I]`` Inherit fully  — copy provider/model/api_key_env/...
    * ``[P]`` Partial         — copy then re-prompt for model only
    * ``[R]`` Reconfigure     — skip inheritance, prompt for every field
    * ``[B]`` Back            — abort the wizard

    Returns a dict ``{"action": ..., "source_path": ..., "ping": (ok, msg)}``
    where ``action`` is one of ``inherit``/``partial``/``reconfigure``/``back``.
    Returns ``None`` when no candidates exist (caller proceeds straight
    to the prompt flow).

    The returned ``ping`` tuple is cached so the post-save check in
    ``setup llm`` can reuse it without re-hitting the upstream.
    """
    candidates = list_inherit_candidates(cfg, exclude=(target_path,))
    if not candidates:
        return None

    click.echo()
    ux.section("Inherit Preflight")
    ux.subhead("DefenseClaw found existing LLM configurations on this install:")
    click.echo()

    # Ping each candidate (best-effort) so the operator sees which
    # configurations are actually live before deciding.
    pings: dict[str, tuple[bool, str]] = {}
    for cand in candidates:
        path = cand["path"]
        try:
            resolved = cfg.resolve_llm("" if path == "llm" else path)
        except Exception as exc:
            pings[path] = (False, f"resolve failed: {exc}")
            continue
        ok, msg = ping_llm(resolved, timeout=ping_timeout)
        pings[path] = (ok, msg)

    # Two-panel render: left = role, right = ping outcome.
    width = max(len(c["path"]) for c in candidates)
    for idx, cand in enumerate(candidates, start=1):
        path = cand["path"]
        ok, msg = pings.get(path, (False, "no ping"))
        status = ux.dim("✓ " + msg) if ok else ux.dim("✗ " + msg)
        click.echo(
            f"    [{idx}] {path:<{width}} | {cand['summary']:<32} | {status}"
        )
    click.echo()

    # 4-option menu. The candidate-number choice picks which source to
    # use; the letter choices act on that selection.
    primary = candidates[0]
    primary_path = primary["path"]

    pick_default = "1"
    raw = click.prompt(
        "  Pick source (number) or 'r' to reconfigure / 'b' to back out",
        default=pick_default,
        show_default=True,
    ).strip().lower()

    if raw in ("b", "back"):
        return {"action": "back", "source_path": "", "ping": (False, "back")}
    if raw in ("r", "reconfigure"):
        return {"action": "reconfigure", "source_path": "", "ping": (False, "reconfigure")}

    if raw.isdigit():
        n = int(raw)
        if 1 <= n <= len(candidates):
            primary_path = candidates[n - 1]["path"]

    click.echo()
    click.echo("  " + ux.bold("How should we apply the inherited values?"))
    click.echo("    " + ux.bold("[I]") + " Inherit fully     — copy provider/model/api_key_env/...")
    click.echo("    " + ux.bold("[P]") + " Partial            — copy then re-prompt for model only")
    click.echo("    " + ux.bold("[R]") + " Reconfigure        — skip inheritance, prompt for everything")
    click.echo("    " + ux.bold("[B]") + " Back               — abort")

    action_default = "I"
    action_map = {
        "i": "inherit",
        "inherit": "inherit",
        "p": "partial",
        "partial": "partial",
        "r": "reconfigure",
        "reconfigure": "reconfigure",
        "b": "back",
        "back": "back",
    }
    # Re-prompt until the operator picks a recognised letter rather
    # than silently mapping unknown input to the destructive "inherit"
    # default — typing "x" used to overwrite the role's existing
    # config without consent.
    while True:
        raw = click.prompt(
            "  Action",
            default=action_default,
            show_default=True,
        ).strip().lower()
        action = action_map.get(raw)
        if action:
            break
        click.echo("    Pick one of: I (inherit), P (partial), R (reconfigure), B (back).")
    return {
        "action": action,
        "source_path": primary_path,
        "ping": pings.get(primary_path, (False, "no ping")),
    }


# ---------------------------------------------------------------------------
# Apply structured selections back onto LLMConfig
# ---------------------------------------------------------------------------


def ensure_bedrock(llm: LLMConfig) -> BedrockKeyConfig:
    if llm.bedrock is None:
        llm.bedrock = BedrockKeyConfig()
    return llm.bedrock


def ensure_vertex(llm: LLMConfig) -> VertexKeyConfig:
    if llm.vertex is None:
        llm.vertex = VertexKeyConfig()
    return llm.vertex


def ensure_azure(llm: LLMConfig) -> AzureKeyConfig:
    if llm.azure is None:
        llm.azure = AzureKeyConfig()
    return llm.azure


def ensure_tls(llm: LLMConfig) -> LLMTLSConfig:
    if llm.tls is None:
        llm.tls = LLMTLSConfig()
    return llm.tls


# ---------------------------------------------------------------------------
# Summary panel
# ---------------------------------------------------------------------------


def _mask(value: str) -> str:
    if not value:
        return "(unset)"
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}…{value[-4:]}"


def summary_panel(
    *,
    role: str,
    llm: LLMConfig,
    inherited_from: str | None = None,
    note: str | None = None,
) -> None:
    """Render a two-line "as-saved" summary for the given LLM role."""
    click.echo()
    title = f"{role} LLM"
    if inherited_from:
        title += f" (inherits {inherited_from})"
    ux.section(title)
    rows: list[tuple[str, str]] = []
    rows.append(("provider", llm.provider or "(unset)"))
    rows.append(("model", llm.model or "(unset)"))
    if llm.instance_name:
        rows.append(("instance_name", llm.instance_name))
    if llm.base_url:
        rows.append(("base_url", llm.base_url))
    if llm.region:
        rows.append(("region", llm.region))
    rows.append(("api_key_env", llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV))
    rows.append(("api_key", _mask(llm.resolved_api_key())))
    if llm.bedrock and any(asdict(llm.bedrock).values()):
        rows.append(("bedrock.auth_mode", llm.bedrock.auth_mode))
        if llm.bedrock.region:
            rows.append(("bedrock.region", llm.bedrock.region))
    if llm.vertex and any(asdict(llm.vertex).values()):
        rows.append(("vertex.project_id", llm.vertex.project_id))
        rows.append(("vertex.region", llm.vertex.region))
    if llm.azure and any(v for v in asdict(llm.azure).values() if v):
        rows.append(("azure.endpoint", llm.azure.endpoint))
        rows.append(("azure.api_version", llm.azure.api_version))
        if llm.azure.deployment_aliases:
            aliases = ", ".join(f"{k}={v}" for k, v in llm.azure.deployment_aliases.items())
            rows.append(("azure.deployment_aliases", aliases))
    if llm.tls and (llm.tls.ca_cert_pem or llm.tls.insecure_skip_verify):
        # Render PEM contents as a length summary so the wizard
        # output stays one line per field. Operators verifying the
        # cert should use ``defenseclaw config show`` (or look at
        # the overlay file) rather than scrolling through a multi-
        # line PEM block embedded in the summary table.
        pem = llm.tls.ca_cert_pem or ""
        rows.append(
            (
                "tls.ca_cert_pem",
                f"(set, {len(pem)} bytes)" if pem else "(unset)",
            )
        )
        rows.append(("tls.insecure_skip_verify", str(llm.tls.insecure_skip_verify).lower()))
    width = max((len(k) for k, _ in rows), default=8)
    for key, val in rows:
        click.echo(f"    {key + ':':<{width + 1}s} {val}")
    if note:
        click.echo()
        ux.subhead(note)
    click.echo()


# ---------------------------------------------------------------------------
# Live reachability ping (post-save validation)
# ---------------------------------------------------------------------------


def ping_llm(llm: LLMConfig, *, timeout: int = 5) -> tuple[bool, str]:
    """Best-effort reachability probe.

    Returns ``(ok, message)``. Never raises — the wizard renders the
    message verbatim and continues regardless. The actual ping logic
    lives in ``defenseclaw.llm.ping`` so the same helper is reusable
    by ``defenseclaw doctor``.
    """
    try:
        from defenseclaw.llm import ping as _ping
    except Exception as exc:  # pragma: no cover - defensive
        return (False, f"could not import llm.ping: {exc}")
    try:
        return _ping(llm, timeout=timeout)
    except Exception as exc:  # pragma: no cover - defensive
        return (False, f"ping raised {type(exc).__name__}: {exc}")
