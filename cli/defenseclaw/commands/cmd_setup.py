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

"""defenseclaw setup — Configure DefenseClaw settings and integrations.

Mirrors internal/cli/setup.go.
"""

from __future__ import annotations

import json as _json
import os
import shutil
import socket
import subprocess

import click

from defenseclaw.config import DEFENSECLAW_LLM_KEY_ENV
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.paths import bundled_extensions_dir, splunk_bridge_bin

# Key used to stash the pre-invocation config.yaml mtime in the Click
# context so the post-invocation hook can tell whether a `setup`
# subcommand actually mutated config on disk. Using ``ctx.meta``
# (Click's per-context scratchpad) keeps this out of the shared
# ``AppContext`` object so unrelated command modules don't accidentally
# collide with it.
_SETUP_CFG_MTIME_KEY = "defenseclaw._setup_config_mtime_before"

# Set by :func:`_restart_defense_gateway` when a subcommand has
# already restarted the sidecar explicitly (e.g.
# ``setup guardrail --restart``); the auto-restart result callback
# below honors this flag and becomes a no-op to avoid a double bounce.
_SETUP_RESTART_HANDLED_KEY = "defenseclaw._setup_restart_handled"


def _config_yaml_path_from_ctx(ctx: click.Context) -> str | None:
    """Return ``<data_dir>/config.yaml`` when the AppContext is loaded.

    Some setup subcommands (notably ``setup migrate-llm``) are invoked
    before :func:`defenseclaw.main.cli` populates ``app.cfg``; in that
    case the mtime-snapshot hook silently skips and the result callback
    will also skip the restart. That's fine — those commands manage
    their own restart prompts.
    """
    app = ctx.find_object(AppContext)
    if app is None or app.cfg is None:
        return None
    data_dir = getattr(app.cfg, "data_dir", None)
    if not data_dir:
        return None
    return os.path.join(data_dir, "config.yaml")


def _safe_mtime(path: str | None) -> float | None:
    if not path:
        return None
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


@click.group()
@click.pass_context
def setup(ctx: click.Context) -> None:
    """Configure DefenseClaw components."""
    # Snapshot config.yaml's mtime before the subcommand runs. The
    # result callback below (``_auto_restart_sidecar_after_setup``)
    # compares this to the post-invocation mtime and only restarts the
    # sidecar when the file actually changed — so read-only subcommands
    # like ``setup llm --show`` don't bounce a running gateway.
    ctx.meta[_SETUP_CFG_MTIME_KEY] = _safe_mtime(_config_yaml_path_from_ctx(ctx))


# Register `defenseclaw setup observability` (unified OTel + audit sinks).
# Imported here rather than at module top so the subcommand surface can
# grow without cluttering cmd_setup.py.
from defenseclaw.commands.cmd_setup_observability import observability  # noqa: E402

setup.add_command(observability)

# Register `defenseclaw setup local-observability` (bundled
# Prom/Loki/Tempo/Grafana stack driver). Mirrors the `setup splunk
# --logs` pattern: preflights Docker, drives a docker-compose bridge,
# and wires config.yaml to point the gateway at the local collector.
from defenseclaw.commands.cmd_setup_local_observability import (  # noqa: E402
    local_observability,
)

setup.add_command(local_observability)

# Register `defenseclaw setup webhook` (Slack/PagerDuty/Webex/generic
# notifiers). Distinct from `setup observability add webhook` (generic
# HTTP JSONL audit-log forwarder) — see docs/OBSERVABILITY.md for the
# disambiguation.
from defenseclaw.commands.cmd_setup_webhook import webhook  # noqa: E402

setup.add_command(webhook)

# Register `defenseclaw setup provider` (custom-providers.json overlay).
# Drives the Layer-4 "add a new LLM endpoint without a release" flow
# that the shape-detection rails and the Go /v1/config/providers
# endpoint rely on. See cmd_setup_provider.py for the full rationale.
from defenseclaw.commands.cmd_setup_provider import provider  # noqa: E402

setup.add_command(provider)


# --------------------------------------------------------------------------
# `defenseclaw setup migrate-llm`
# --------------------------------------------------------------------------
# Rewrites ~/.defenseclaw/config.yaml to scrub legacy v4 LLM fields
# (``inspect_llm:``, ``default_llm_*``, and the bare
# ``guardrail.{model,api_key_env,api_base}`` / ``guardrail.judge.*``
# slots) after the values have been copied into the unified top-level
# ``llm:`` block. The load-time migration in
# :func:`defenseclaw.config._migrate_llm_fields` is idempotent and
# additive — it never clears the legacy slots — so operators upgrading
# from v4 will keep round-tripping a redundant copy of the same values
# in their YAML until they run this command.
#
# Safety posture: we snapshot the current file to ``config.yaml.bak``
# before writing so operators always have a one-command undo. The
# command is intentionally idempotent; running it twice is a no-op and
# is safe inside CI pipelines.
@setup.command("migrate-llm")
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would change without modifying config.yaml.",
)
@click.option(
    "--no-backup",
    is_flag=True,
    default=False,
    help="Skip writing config.yaml.bak (advanced; use only when orchestrated by a VCS).",
)
@pass_ctx
def migrate_llm(app: AppContext, dry_run: bool, no_backup: bool) -> None:
    """Rewrite config.yaml to the unified v5 LLM shape.

    Copies ``inspect_llm``, ``default_llm_*``, and legacy ``guardrail``
    fields into ``llm:`` (if not already merged), then clears the v4
    slots so a round-trip through ``config.load()``/``save()`` produces
    a minimal YAML. Writes a ``config.yaml.bak`` alongside the live
    file unless ``--no-backup`` is passed.
    """
    import shutil

    cfg = app.cfg
    # Surface what we're about to remove before touching disk, so
    # operators eyeballing CI logs can sanity-check the change.
    legacy_summary: list[str] = []
    il = getattr(cfg, "inspect_llm", None)
    if il is not None and (il.model or il.provider or il.api_key_env or il.api_key or il.base_url):
        legacy_summary.append(
            f"inspect_llm: provider={il.provider!r} model={il.model!r} "
            f"api_key_env={il.api_key_env!r} base_url={il.base_url!r}"
        )
    if cfg.default_llm_model:
        legacy_summary.append(f"default_llm_model={cfg.default_llm_model!r}")
    if cfg.default_llm_api_key_env:
        legacy_summary.append(f"default_llm_api_key_env={cfg.default_llm_api_key_env!r}")
    if cfg.guardrail.model or cfg.guardrail.api_key_env or cfg.guardrail.api_base:
        legacy_summary.append(
            f"guardrail: model={cfg.guardrail.model!r} "
            f"api_key_env={cfg.guardrail.api_key_env!r} api_base={cfg.guardrail.api_base!r}"
        )
    jc = cfg.guardrail.judge
    if jc.model or jc.api_key_env or jc.api_base:
        legacy_summary.append(
            f"guardrail.judge: model={jc.model!r} api_key_env={jc.api_key_env!r} api_base={jc.api_base!r}"
        )

    if not legacy_summary:
        click.echo("  Config already in v5 shape — nothing to migrate.")
        # Still scrub the one-shot warning flag so a follow-up load
        # doesn't re-emit it in the same process.
        if hasattr(cfg, "_llm_migration_warned"):
            cfg._llm_migration_warned = False  # type: ignore[attr-defined]
        return

    click.echo("  Legacy v4 LLM fields detected:")
    for line in legacy_summary:
        click.echo(f"    - {line}")
    click.echo()
    click.echo("  Unified llm: block (post-migration):")
    llm = cfg.llm
    click.echo(f"    provider={llm.provider!r}, model={llm.model!r}, api_key_env={llm.api_key_env!r}")
    click.echo(f"    base_url={llm.base_url!r}, timeout={llm.timeout}, max_retries={llm.max_retries}")
    click.echo()

    if dry_run:
        click.echo("  --dry-run: no files modified.")
        return

    # Backup before we mutate. We use the app's configured data_dir
    # rather than os.path.expanduser so this works inside sandboxed
    # tests and portable installs.
    cfg_path = os.path.join(cfg.data_dir, "config.yaml")
    if not no_backup and os.path.exists(cfg_path):
        backup_path = cfg_path + ".bak"
        shutil.copy2(cfg_path, backup_path)
        click.echo(f"  Backed up {cfg_path} -> {backup_path}")

    # Clear the legacy slots. This mirrors _clear_legacy_llm_fields()
    # but is kept inline so the command has no hidden behavior — an
    # operator reading the source sees exactly which fields are
    # cleared.
    if il is not None:
        il.provider = ""
        il.model = ""
        il.api_key = ""
        il.api_key_env = ""
        il.base_url = ""
        il.timeout = 0
        il.max_retries = 0
    cfg.default_llm_model = ""
    cfg.default_llm_api_key_env = ""
    cfg.guardrail.model = ""
    cfg.guardrail.api_key_env = ""
    cfg.guardrail.api_base = ""
    jc.model = ""
    jc.api_key_env = ""
    jc.api_base = ""

    cfg.save()
    click.echo(f"  Wrote {cfg_path} (v5 shape).")


# --------------------------------------------------------------------------
# `defenseclaw setup llm`
# --------------------------------------------------------------------------
# First-class CLI entry point for (re)configuring the unified top-level
# ``llm:`` block. Before this subcommand existed, operators had three
# partial paths to the same config:
#
#   * ``scripts/setup-llm.sh`` — shell script invoked by ``make all``,
#     but invisible from ``defenseclaw --help``.
#   * ``defenseclaw setup skill-scanner`` / ``mcp-scanner`` — prompt for
#     LLM settings as a side effect, but scoped to that scanner.
#   * Hand-editing ``~/.defenseclaw/.env`` + ``config.yaml``.
#
# Exposing ``_configure_llm`` as ``defenseclaw setup llm`` gives the
# unified configurator a stable, discoverable surface. It's a thin
# wrapper — the prompt logic lives in ``_configure_llm`` so the init
# wizard and this command stay in lockstep.
@setup.command("llm")
@click.option(
    "--show",
    is_flag=True,
    default=False,
    help="Print the current unified LLM config and exit (no prompts).",
)
@pass_ctx
def setup_llm(app: AppContext, show: bool) -> None:
    """Configure the unified top-level ``llm:`` block.

    Prompts for provider, model, API key env var, and base URL, writing
    the values to ``~/.defenseclaw/config.yaml`` (config) and
    ``~/.defenseclaw/.env`` (secret, chmod 0600). Every LLM-using
    component (guardrail judge, MCP scanner, skill scanner, plugin
    scanner) resolves through this block via ``Config.resolve_llm``, so
    a single edit reroutes them all.

    Use ``--show`` to inspect the current resolved values without
    modifying anything. This is the CLI equivalent of
    ``scripts/setup-llm.sh`` and the LLM section of ``defenseclaw init``.
    """
    cfg = app.cfg
    llm = cfg.llm

    if show:
        resolved = cfg.resolve_llm("")
        click.echo()
        click.echo("  Unified LLM configuration")
        click.echo("  ─────────────────────────")
        click.echo(f"    provider:    {resolved.provider or '(unset)'}")
        click.echo(f"    model:       {resolved.model or '(unset)'}")
        key_env = resolved.api_key_env or DEFENSECLAW_LLM_KEY_ENV
        key_val = resolved.resolved_api_key()
        key_state = _mask(key_val) if key_val else "(not set)"
        click.echo(f"    api_key_env: {key_env} = {key_state}")
        if resolved.base_url:
            click.echo(f"    base_url:    {resolved.base_url}")
        click.echo(f"    timeout:     {resolved.timeout}s")
        click.echo(f"    max_retries: {resolved.max_retries}")
        click.echo()
        click.echo(
            "  To change: run 'defenseclaw setup llm' without --show.",
        )
        return

    click.echo()
    click.echo("  Unified LLM configuration")
    click.echo("  ─────────────────────────")
    click.echo(
        "  Every LLM-using component (guardrail judge, MCP scanner,"
    )
    click.echo(
        "  skill scanner, plugin scanner) resolves through this block"
    )
    click.echo(
        "  by default. Per-component overrides live under"
    )
    click.echo(
        "  scanners.*.llm / guardrail.{llm,judge.llm}."
    )
    click.echo()
    if llm.model:
        click.echo(f"  Current: model={llm.model}, api_key_env={llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV}")
        click.echo()

    _configure_llm(cfg, cfg.data_dir)
    cfg.save()

    click.echo()
    click.echo(f"  ✓ Saved to {os.path.join(cfg.data_dir, 'config.yaml')}")
    click.echo()
    click.echo("  Next: defenseclaw doctor       # verify the unified LLM is reachable")


# Register `defenseclaw setup observability` (unified OTel + audit sinks).
# Imported here rather than at module top so the subcommand surface can
# grow without cluttering cmd_setup.py.
from defenseclaw.commands.cmd_setup_observability import observability  # noqa: E402

setup.add_command(observability)

# Register `defenseclaw setup local-observability` (bundled
# Prom/Loki/Tempo/Grafana stack driver). Mirrors the `setup splunk
# --logs` pattern: preflights Docker, drives a docker-compose bridge,
# and wires config.yaml to point the gateway at the local collector.
from defenseclaw.commands.cmd_setup_local_observability import (  # noqa: E402
    local_observability,
)

setup.add_command(local_observability)

# Register `defenseclaw setup webhook` (Slack/PagerDuty/Webex/generic
# notifiers). Distinct from `setup observability add webhook` (generic
# HTTP JSONL audit-log forwarder) — see docs/OBSERVABILITY.md for the
# disambiguation.
from defenseclaw.commands.cmd_setup_webhook import webhook  # noqa: E402

setup.add_command(webhook)



@setup.command("skill-scanner")
@click.option("--use-llm", is_flag=True, default=None, help="Enable LLM analyzer")
@click.option("--use-behavioral", is_flag=True, default=None, help="Enable behavioral analyzer")
@click.option("--enable-meta", is_flag=True, default=None, help="Enable meta-analyzer")
@click.option("--use-trigger", is_flag=True, default=None, help="Enable trigger analyzer")
@click.option("--use-virustotal", is_flag=True, default=None, help="Enable VirusTotal scanner")
@click.option("--use-aidefense", is_flag=True, default=None, help="Enable AI Defense analyzer")
@click.option("--llm-provider", default=None, type=click.Choice(["anthropic", "openai"]),
              help="LLM provider (anthropic or openai)")
@click.option("--llm-model", default=None, help="LLM model name")
@click.option("--llm-consensus-runs", type=int, default=None, help="LLM consensus runs (0=disabled)")
@click.option("--policy", default=None, help="Scan policy preset (strict, balanced, permissive)")
@click.option("--lenient", is_flag=True, default=None, help="Tolerate malformed skills")
@click.option("--verify/--no-verify", default=True, help="Run connectivity checks after setup (default: on)")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_skill_scanner(
    app: AppContext,
    use_llm, use_behavioral, enable_meta, use_trigger,
    use_virustotal, use_aidefense,
    llm_provider, llm_model, llm_consensus_runs,
    policy, lenient, verify, non_interactive,
) -> None:
    """Configure skill-scanner analyzers, API keys, and policy.

    Interactively configure how skill-scanner runs. Enables LLM analysis,
    behavioral dataflow analysis, meta-analyzer filtering, and more.

    LLM settings land in the unified top-level ``llm:`` block (see
    ``Config.resolve_llm`` for the merge semantics) so skill, MCP,
    plugin, and guardrail scanners all share the same defaults. Cisco
    AI Defense settings continue to live in ``cisco_ai_defense``.

    Use --non-interactive with flags for CI/scripted configuration.
    """
    sc = app.cfg.scanners.skill_scanner
    llm = app.cfg.llm
    aid = app.cfg.cisco_ai_defense

    if non_interactive:
        if use_llm is not None:
            sc.use_llm = use_llm
        if use_behavioral is not None:
            sc.use_behavioral = use_behavioral
        if enable_meta is not None:
            sc.enable_meta = enable_meta
        if use_trigger is not None:
            sc.use_trigger = use_trigger
        if use_virustotal is not None:
            sc.use_virustotal = use_virustotal
        if use_aidefense is not None:
            sc.use_aidefense = use_aidefense
        if llm_provider is not None:
            llm.provider = llm_provider
        if llm_model is not None:
            llm.model = llm_model
        if llm_consensus_runs is not None:
            sc.llm_consensus_runs = llm_consensus_runs
        if policy is not None:
            sc.policy = policy
        if lenient is not None:
            sc.lenient = lenient
    else:
        _interactive_setup(sc, llm, aid, app.cfg)

    # In non-interactive mode, a successful write to cfg.llm should
    # still scrub the legacy inspect_llm block so the YAML converges on
    # the v5 shape.
    if non_interactive and (llm.provider or llm.model):
        _clear_legacy_llm_fields(app.cfg)

    app.cfg.save()
    _print_summary(sc, llm, aid)

    if verify:
        from defenseclaw.commands.cmd_doctor import _check_scanners, _check_virustotal, _DoctorResult
        click.echo("  ── Verifying scanner configuration ──")
        r = _DoctorResult()
        _check_scanners(app.cfg, r)
        _check_virustotal(app.cfg, r)
        click.echo()
        if r.failed:
            click.echo("  Tip: fix the issues above, then run 'defenseclaw doctor' to re-check.")
            click.echo()

    if app.logger:
        parts = [f"use_llm={sc.use_llm}", f"use_behavioral={sc.use_behavioral}", f"enable_meta={sc.enable_meta}"]
        if llm.provider:
            parts.append(f"llm_provider={llm.provider}")
        if sc.policy:
            parts.append(f"policy={sc.policy}")
        app.logger.log_action("setup-skill-scanner", "config", " ".join(parts))


def _interactive_setup(sc, llm, aid, cfg) -> None:
    """Skill scanner interactive wizard.

    Takes the parent ``cfg`` rather than just ``data_dir`` so the LLM
    helper can clean up legacy ``inspect_llm`` fields and so other
    cross-cutting concerns stay addressable without widening callers.
    """
    data_dir = cfg.data_dir
    click.echo()
    click.echo("  Skill Scanner Configuration")
    click.echo("  ────────────────────────────")
    click.echo(f"  Binary: {sc.binary}")
    click.echo()

    sc.use_behavioral = click.confirm("  Enable behavioral analyzer (dataflow analysis)?", default=sc.use_behavioral)
    sc.use_llm = click.confirm("  Enable LLM analyzer (semantic analysis)?", default=sc.use_llm)

    if sc.use_llm:
        _configure_llm(cfg, data_dir)
        sc.enable_meta = click.confirm("  Enable meta-analyzer (false positive filtering)?", default=sc.enable_meta)
        sc.llm_consensus_runs = click.prompt(
            "  LLM consensus runs (0 = disabled)", type=int, default=sc.llm_consensus_runs,
        )
    # NB: disabling the skill scanner's LLM analyzer no longer clears
    # the unified cfg.llm block — the MCP scanner, plugin scanner, and
    # guardrail judge all share it. If the operator truly wants to
    # remove the key they should edit ~/.defenseclaw/.env directly or
    # run `defenseclaw setup migrate-llm --clear`.

    sc.use_trigger = click.confirm("  Enable trigger analyzer (vague description checks)?", default=sc.use_trigger)
    sc.use_virustotal = click.confirm("  Enable VirusTotal binary scanner?", default=sc.use_virustotal)
    if sc.use_virustotal:
        _prompt_and_save_secret("VIRUSTOTAL_API_KEY", sc.virustotal_api_key, data_dir)
        sc.virustotal_api_key = ""
        sc.virustotal_api_key_env = "VIRUSTOTAL_API_KEY"
    else:
        sc.virustotal_api_key = ""
        sc.virustotal_api_key_env = ""

    sc.use_aidefense = click.confirm("  Enable Cisco AI Defense analyzer?", default=sc.use_aidefense)
    if sc.use_aidefense:
        _configure_cisco_ai_defense(aid, data_dir)
    else:
        aid.api_key = ""
        aid.api_key_env = ""

    click.echo()
    valid_policies = ["strict", "balanced", "permissive", "none"]
    val = click.prompt(
        "  Scan policy preset",
        type=click.Choice(valid_policies),
        default=sc.policy if sc.policy in valid_policies else "none",
        show_default=True,
    )
    sc.policy = "" if val == "none" else val

    sc.lenient = click.confirm("  Lenient mode (tolerate malformed skills)?", default=sc.lenient)


# Local LLM providers that run on-box and don't require an API key.
# Kept in lockstep with _LOCAL_LLM_PROVIDERS in defenseclaw/config.py and
# IsLocalProvider() in internal/config/config.go.
_LOCAL_LLM_WIZARD_PROVIDERS = {"ollama", "vllm", "lm_studio", "lmstudio"}

# Default base URLs for local providers so the wizard can offer a sane
# prefill. Operators can still override to point at a shared LAN host.
_LOCAL_LLM_DEFAULT_BASE_URL = {
    "ollama":    "http://127.0.0.1:11434",
    "vllm":      "http://127.0.0.1:8000/v1",
    "lm_studio": "http://127.0.0.1:1234/v1",
    "lmstudio":  "http://127.0.0.1:1234/v1",
}

# Provider choices offered in the wizard. Cloud providers first (most
# operators), then local runtimes. The list is a superset of guardrail's
# KNOWN_PROVIDERS so the wizard can configure Ollama/vLLM without edits
# to that module.
_WIZARD_LLM_PROVIDERS = [
    "anthropic", "openai", "openrouter", "azure", "gemini", "gemini-openai",
    "groq", "mistral", "cohere", "deepseek", "xai", "bedrock", "vertex_ai",
    "ollama", "vllm", "lm_studio",
]


def _configure_llm(cfg, data_dir: str) -> None:
    """Prompt for unified ``llm:`` settings (provider, model, API key).

    Writes to the top-level ``cfg.llm`` block — the single source of
    truth consumed by guardrail (Bifrost), MCP scanner, skill scanner,
    and the plugin scanner via :meth:`Config.resolve_llm`. Per-scanner
    overrides can be added later by editing ``scanners.*.llm`` or
    ``guardrail.judge.llm`` directly.

    The API key is stored in ``~/.defenseclaw/.env`` (never in
    ``config.yaml``) under the canonical ``DEFENSECLAW_LLM_KEY`` env
    var, so rotating it requires a single edit rather than one per
    scanner. Operators who need a custom env var name can still set
    ``cfg.llm.api_key_env`` by hand.

    Local providers (ollama, vllm, lm_studio) skip the API key prompt
    entirely and instead prompt for a base URL with a sensible default
    — these runtimes don't authenticate incoming requests.
    """
    from defenseclaw.guardrail import detect_api_key_env
    llm = cfg.llm

    default_provider = llm.provider if llm.provider in _WIZARD_LLM_PROVIDERS else "anthropic"
    llm.provider = click.prompt(
        "  LLM provider (cloud: anthropic/openai/..., local: ollama/vllm/lm_studio)",
        type=click.Choice(_WIZARD_LLM_PROVIDERS),
        default=default_provider,
    )
    llm.model = click.prompt(
        "  LLM model id (e.g. 'claude-3-5-sonnet-20241022', 'gpt-4o', 'llama3.1')",
        default=llm.model or "",
        show_default=bool(llm.model),
    )

    if llm.provider in _LOCAL_LLM_WIZARD_PROVIDERS:
        # Local runtimes: no API key. Prompt for the endpoint URL with a
        # sensible default so the scanner can find the loopback server.
        default_base = llm.base_url or _LOCAL_LLM_DEFAULT_BASE_URL.get(llm.provider, "")
        llm.base_url = click.prompt(
            f"  {llm.provider} base URL",
            default=default_base,
            show_default=True,
        )
        llm.api_key = ""
        llm.api_key_env = ""
    else:
        # Cloud providers: prompt once for the unified key and store it
        # under DEFENSECLAW_LLM_KEY so every scanner / guardrail call
        # picks it up via Config.resolve_llm(...).
        #
        # If the operator already has a provider-specific env var in
        # their .env (e.g. ANTHROPIC_API_KEY), we surface that as the
        # suggested target so existing setups keep working without
        # forcing a rename; otherwise we default to the canonical
        # DEFENSECLAW_LLM_KEY.
        existing_env = llm.api_key_env
        suggested_env = existing_env or DEFENSECLAW_LLM_KEY_ENV
        env_name = click.prompt(
            "  API key env var (leave as DEFENSECLAW_LLM_KEY for the unified key)",
            default=suggested_env,
            show_default=True,
        )
        # Hint the user where to put the key when they've customised
        # the env var to something provider-specific (e.g. when sharing
        # a laptop with other tools that read ANTHROPIC_API_KEY).
        if env_name != DEFENSECLAW_LLM_KEY_ENV:
            guessed = detect_api_key_env(f"{llm.provider}/{llm.model}")
            if env_name != guessed and guessed != "LLM_API_KEY":
                click.echo(
                    f"    Note: LiteLLM's native env var for {llm.provider} is {guessed}; "
                    f"we'll still read {env_name} because you set it explicitly."
                )
        _prompt_and_save_secret(env_name, llm.api_key, data_dir)
        llm.api_key = ""
        llm.api_key_env = env_name
        llm.base_url = click.prompt(
            "  LLM base URL (leave blank to use provider default)",
            default=llm.base_url or "", show_default=bool(llm.base_url),
        )

    llm.timeout = click.prompt("  LLM timeout (seconds)", type=int, default=llm.timeout or 30)
    llm.max_retries = click.prompt("  LLM max retries", type=int, default=llm.max_retries or 2)

    # Clear legacy v4 fields so the next save() doesn't re-emit a stale
    # inspect_llm: block. The v5 migration in config.load() copies
    # inspect_llm → llm one-way when llm is empty, so leaving the old
    # block populated after a successful wizard run would round-trip a
    # redundant copy of the same values into YAML.
    _clear_legacy_llm_fields(cfg)


def _clear_legacy_llm_fields(cfg) -> None:
    """Zero out v4-era LLM fields after a successful wizard write.

    Idempotent. Only called once the caller has populated ``cfg.llm``.
    """
    il = getattr(cfg, "inspect_llm", None)
    if il is not None:
        il.provider = ""
        il.model = ""
        il.api_key = ""
        il.api_key_env = ""
        il.base_url = ""
        il.timeout = 0
        il.max_retries = 0
    # Top-level v4 fallbacks.
    if hasattr(cfg, "default_llm_model"):
        cfg.default_llm_model = ""
    if hasattr(cfg, "default_llm_api_key_env"):
        cfg.default_llm_api_key_env = ""


# Back-compat alias: older call sites (and any out-of-tree scripts)
# still reference _configure_inspect_llm. Kept as a thin shim; both
# spellings write to the unified block now.
def _configure_inspect_llm(llm, data_dir: str) -> None:  # pragma: no cover
    """DEPRECATED: use :func:`_configure_llm` with the full Config.

    Retained so external callers (e.g. TUI shelling out to Python) keep
    working during the migration window. Mutates the provided LLMConfig
    directly; cannot clean up legacy ``inspect_llm`` fields because it
    doesn't have the parent Config in hand.
    """
    from defenseclaw.guardrail import detect_api_key_env
    default_provider = llm.provider if llm.provider in _WIZARD_LLM_PROVIDERS else "anthropic"
    llm.provider = click.prompt(
        "  LLM provider",
        type=click.Choice(_WIZARD_LLM_PROVIDERS),
        default=default_provider,
    )
    llm.model = click.prompt("  LLM model name", default=llm.model or "", show_default=bool(llm.model))
    if llm.provider in _LOCAL_LLM_WIZARD_PROVIDERS:
        default_base = llm.base_url or _LOCAL_LLM_DEFAULT_BASE_URL.get(llm.provider, "")
        llm.base_url = click.prompt(f"  {llm.provider} base URL", default=default_base)
        llm.api_key = ""
        llm.api_key_env = ""
    else:
        env_name = detect_api_key_env(f"{llm.provider}/{llm.model}")
        _prompt_and_save_secret(env_name, llm.api_key, data_dir)
        llm.api_key = ""
        llm.api_key_env = env_name
        llm.base_url = click.prompt(
            "  LLM base URL (leave blank to use provider default)",
            default=llm.base_url or "", show_default=bool(llm.base_url),
        )
    llm.timeout = click.prompt("  LLM timeout (seconds)", type=int, default=llm.timeout or 30)
    llm.max_retries = click.prompt("  LLM max retries", type=int, default=llm.max_retries or 2)


def _configure_cisco_ai_defense(aid, data_dir: str) -> None:
    """Prompt for shared cisco_ai_defense settings (endpoint, API key).

    The API key is stored in ~/.defenseclaw/.env, not in config.yaml.
    """
    aid.endpoint = click.prompt(
        "  Cisco AI Defense endpoint URL",
        default=aid.endpoint,
    )
    _prompt_and_save_secret("CISCO_AI_DEFENSE_API_KEY", aid.api_key, data_dir)
    aid.api_key = ""
    aid.api_key_env = "CISCO_AI_DEFENSE_API_KEY"


def _prompt_and_save_secret(env_name: str, current: str, data_dir: str) -> None:
    """Prompt for a secret, save it to ~/.defenseclaw/.env, and set it in os.environ.

    The value is never returned — callers should store only the *env var name*
    in config.yaml (via the corresponding ``*_env`` field).
    """
    dotenv_path = os.path.join(data_dir, ".env")
    dotenv_val = _load_dotenv(dotenv_path).get(env_name, "")
    env_val = os.environ.get(env_name, "")
    effective = current or env_val or dotenv_val
    if effective:
        hint = _mask(effective)
    else:
        hint = "(not set)"
    val = click.prompt(f"  {env_name} [{hint}]", default="", show_default=False)
    secret = val or effective
    if secret:
        _save_secret_to_dotenv(env_name, secret, data_dir)


def _mask(key: str) -> str:
    if len(key) <= 8:
        return "****"
    return key[:4] + "..." + key[-4:]


def _load_dotenv(path: str) -> dict[str, str]:
    """Read a KEY=VALUE .env file into a dict."""
    result: dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                if k:
                    result[k] = v
    except FileNotFoundError:
        pass
    return result


def _write_dotenv(path: str, entries: dict[str, str]) -> None:
    """Write entries to a .env file with mode 0600.

    Note: ``O_CREAT`` only applies the ``0o600`` mode on *initial*
    creation. When the file already exists (common on repeat runs),
    the previous permission bits survive. We chmod() after the write
    so that repeated invocations keep converging on 0600, even if a
    stray ``chmod 644`` happened out-of-band.
    """
    lines = [f"{k}={v}\n" for k, v in sorted(entries.items())]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.writelines(lines)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Best-effort: on some filesystems chmod is a no-op. We've
        # already written the data, so don't fail the caller here.
        pass


def _print_summary(sc, llm, aid) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    rows: list[tuple[str, str, str]] = [
        ("scanners.skill_scanner", "use_behavioral", str(sc.use_behavioral).lower()),
        ("scanners.skill_scanner", "use_llm", str(sc.use_llm).lower()),
    ]
    if sc.use_llm:
        rows.append(("llm", "provider", llm.provider))
        if llm.model:
            rows.append(("llm", "model", llm.model))
        rows.append(("scanners.skill_scanner", "enable_meta", str(sc.enable_meta).lower()))
        if sc.llm_consensus_runs > 0:
            rows.append(("scanners.skill_scanner", "llm_consensus_runs", str(sc.llm_consensus_runs)))
        api_key = llm.resolved_api_key()
        if api_key:
            rows.append(("llm", "api_key_env", llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV))
        if llm.base_url:
            rows.append(("llm", "base_url", llm.base_url))
    if sc.use_trigger:
        rows.append(("scanners.skill_scanner", "use_trigger", "true"))
    if sc.use_virustotal:
        rows.append(("scanners.skill_scanner", "use_virustotal", "true"))
        vt_key = sc.resolved_virustotal_api_key()
        if vt_key:
            rows.append(("scanners.skill_scanner", "virustotal_api_key_env", sc.virustotal_api_key_env or "(in .env)"))
    if sc.use_aidefense:
        rows.append(("scanners.skill_scanner", "use_aidefense", "true"))
        rows.append(("cisco_ai_defense", "endpoint", aid.endpoint))
    if sc.policy:
        rows.append(("scanners.skill_scanner", "policy", sc.policy))
    if sc.lenient:
        rows.append(("scanners.skill_scanner", "lenient", "true"))

    for section, key, val in rows:
        click.echo(f"    {section}.{key + ':':<22s} {val}")
    click.echo()


# ---------------------------------------------------------------------------
# setup mcp-scanner
# ---------------------------------------------------------------------------

@setup.command("mcp-scanner")
@click.option("--analyzers", default=None, help="Comma-separated analyzer list (yara,api,llm,behavioral,readiness)")
@click.option("--llm-provider", default=None, type=click.Choice(["anthropic", "openai"]),
              help="LLM provider (anthropic or openai)")
@click.option("--llm-model", default=None, help="LLM model for semantic analysis")
@click.option("--scan-prompts", is_flag=True, default=None, help="Scan MCP prompts")
@click.option("--scan-resources", is_flag=True, default=None, help="Scan MCP resources")
@click.option("--scan-instructions", is_flag=True, default=None, help="Scan server instructions")
@click.option("--verify/--no-verify", default=True, help="Run connectivity checks after setup (default: on)")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_mcp_scanner(
    app: AppContext,
    analyzers,
    llm_provider, llm_model,
    scan_prompts, scan_resources, scan_instructions,
    verify: bool,
    non_interactive,
) -> None:
    """Configure mcp-scanner analyzers and scan options.

    Interactively configure how mcp-scanner runs. MCP servers are managed
    via ``defenseclaw mcp set/unset`` rather than directory watching.

    LLM settings land in the unified top-level ``llm:`` block (shared
    with skill/plugin scanners and guardrail). Cisco AI Defense settings
    continue to live in ``cisco_ai_defense``.

    Use --non-interactive with flags for CI/scripted configuration.
    """
    mc = app.cfg.scanners.mcp_scanner
    llm = app.cfg.llm
    aid = app.cfg.cisco_ai_defense

    if non_interactive:
        if analyzers is not None:
            mc.analyzers = analyzers
        if llm_provider is not None:
            llm.provider = llm_provider
        if llm_model is not None:
            llm.model = llm_model
        if scan_prompts is not None:
            mc.scan_prompts = scan_prompts
        if scan_resources is not None:
            mc.scan_resources = scan_resources
        if scan_instructions is not None:
            mc.scan_instructions = scan_instructions
    else:
        _interactive_mcp_setup(mc, app.cfg)

    # In non-interactive mode, when the operator passed --llm-provider
    # or --llm-model we also want the YAML to converge on v5 shape.
    if non_interactive and (llm.provider or llm.model):
        _clear_legacy_llm_fields(app.cfg)

    app.cfg.save()
    _print_mcp_summary(mc, llm, aid)

    if verify:
        from defenseclaw.commands.cmd_doctor import _check_scanners, _DoctorResult
        click.echo("  ── Verifying scanner configuration ──")
        r = _DoctorResult()
        _check_scanners(app.cfg, r)
        click.echo()
        if r.failed:
            click.echo("  Tip: fix the issues above, then run 'defenseclaw doctor' to re-check.")
            click.echo()

    if app.logger:
        parts = [f"analyzers={mc.analyzers or 'default'}"]
        if llm.provider:
            parts.append(f"llm_provider={llm.provider}")
        if llm.model:
            parts.append(f"llm_model={llm.model}")
        parts.append("mcp_managed_via=openclaw_config")
        app.logger.log_action("setup-mcp-scanner", "config", " ".join(parts))


def _interactive_mcp_setup(mc, cfg) -> None:
    # Read model presence from the unified llm: block so the "enable
    # LLM analyzer?" default tracks whatever the shared config already
    # holds, regardless of which scanner first populated it.
    llm = cfg.llm
    aid = cfg.cisco_ai_defense

    click.echo()
    click.echo("  MCP Scanner Configuration")
    click.echo("  ──────────────────────────")
    click.echo(f"  Binary: {mc.binary}")
    click.echo()

    mc.analyzers = click.prompt(
        "  Analyzers (comma-separated, e.g. yara,behavioral,readiness)",
        default=mc.analyzers or "yara",
    )

    use_llm = click.confirm("  Enable LLM analyzer?", default=bool(llm.model))
    if use_llm:
        _configure_llm(cfg, cfg.data_dir)
        if "llm" not in mc.analyzers:
            mc.analyzers = f"{mc.analyzers},llm" if mc.analyzers else "llm"

    click.echo()
    use_api = click.confirm("  Enable API analyzer (Cisco AI Defense)?", default=False)
    if use_api:
        _configure_cisco_ai_defense(aid, cfg.data_dir)
        if "api" not in mc.analyzers:
            mc.analyzers = f"{mc.analyzers},api" if mc.analyzers else "api"

    click.echo()
    mc.scan_prompts = click.confirm("  Scan MCP prompts?", default=mc.scan_prompts)
    mc.scan_resources = click.confirm("  Scan MCP resources?", default=mc.scan_resources)
    mc.scan_instructions = click.confirm("  Scan server instructions?", default=mc.scan_instructions)



def _print_mcp_summary(mc, llm, aid) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    rows: list[tuple[str, str, str]] = [
        ("scanners.mcp_scanner", "analyzers", mc.analyzers or "(all)"),
    ]
    if llm.provider:
        rows.append(("llm", "provider", llm.provider))
    if llm.model:
        rows.append(("llm", "model", llm.model))
        if llm.api_key_env:
            rows.append(("llm", "api_key_env", llm.api_key_env))
        if llm.base_url:
            rows.append(("llm", "base_url", llm.base_url))
    if aid.endpoint:
        rows.append(("cisco_ai_defense", "endpoint", aid.endpoint))
    if mc.scan_prompts:
        rows.append(("scanners.mcp_scanner", "scan_prompts", "true"))
    if mc.scan_resources:
        rows.append(("scanners.mcp_scanner", "scan_resources", "true"))
    if mc.scan_instructions:
        rows.append(("scanners.mcp_scanner", "scan_instructions", "true"))

    for section, key, val in rows:
        click.echo(f"    {section}.{key + ':':<22s} {val}")
    click.echo()


# ---------------------------------------------------------------------------
# setup rotate-token  (plan B5 / S0.5)
# ---------------------------------------------------------------------------


def _rotate_token_dotenv_path(app: AppContext) -> str:
    """Resolve ~/.defenseclaw/.env relative to the configured DataDir."""
    data_dir = app.cfg.data_dir or os.path.expanduser("~/.defenseclaw")
    return os.path.join(data_dir, ".env")


def _rotate_token_atomic_write(dotenv_path: str, new_token: str) -> None:
    """Rewrite the dotenv file with the new token, preserving every
    other line. Atomic via os.replace; mode 0o600.

    Mirrors internal/gateway/firstboot.go appendEnvLine semantics so a
    Python-side rotation produces the same byte-shape on disk as the
    Go-side first-boot synthesis.
    """
    parent = os.path.dirname(dotenv_path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)

    lines: list[str] = []
    if os.path.exists(dotenv_path):
        with open(dotenv_path, encoding="utf-8") as fh:
            for raw in fh.read().splitlines():
                stripped = raw.strip()
                if stripped.startswith("DEFENSECLAW_GATEWAY_TOKEN="):
                    continue
                lines.append(raw)
    while lines and not lines[-1].strip():
        lines.pop()
    lines.append(f"DEFENSECLAW_GATEWAY_TOKEN={new_token}")
    body = "\n".join(lines) + "\n"

    tmp = dotenv_path + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, body.encode("utf-8"))
    finally:
        os.close(fd)
    # Belt-and-suspenders: chmod in case the umask widened the perms.
    os.chmod(tmp, 0o600)
    os.replace(tmp, dotenv_path)


def _rotate_token_run_gateway(args: list[str]) -> tuple[int, str, str]:
    """Run a defenseclaw-gateway subcommand. Returns (rc, stdout, stderr)."""
    binary = shutil.which("defenseclaw-gateway")
    if not binary:
        raise click.ClickException(
            "defenseclaw-gateway binary not found on PATH. Install it before running rotate-token "
            "(the connector teardown/setup hooks need it to refresh hook scripts)."
        )
    proc = subprocess.run(
        [binary, *args],
        capture_output=True,
        check=False,
    )
    return proc.returncode, proc.stdout.decode("utf-8", errors="replace"), proc.stderr.decode("utf-8", errors="replace")


@setup.command("rotate-token")
@click.option(
    "--connector",
    default=None,
    help="Override the active connector (default: read from config).",
)
@click.option(
    "--no-restart",
    is_flag=True,
    help="Skip the connector teardown/setup that refreshes hook .token files.",
)
@click.option(
    "--yes",
    is_flag=True,
    help="Skip the confirmation prompt and rotate immediately.",
)
@pass_ctx
def rotate_token_cmd(app: AppContext, connector: str | None, no_restart: bool, yes: bool) -> None:
    """Rotate the DEFENSECLAW_GATEWAY_TOKEN.

    Generates a new 32-byte CSPRNG hex token, rewrites
    ~/.defenseclaw/.env atomically (mode 0o600), and refreshes the
    per-connector hook scripts so they pick up the new token. The
    operator must restart their agent (claude / codex / openclaw /
    zeptoclaw) for the new credential to take effect.

    Plan B5 / S0.5.
    """
    import secrets

    dotenv_path = _rotate_token_dotenv_path(app)
    if not yes:
        click.confirm(
            f"This will rotate DEFENSECLAW_GATEWAY_TOKEN in {dotenv_path}\n"
            "and refresh hook scripts for the active connector. Continue?",
            abort=True,
        )

    new_token = secrets.token_hex(32)
    _rotate_token_atomic_write(dotenv_path, new_token)
    click.echo(f"Rotated DEFENSECLAW_GATEWAY_TOKEN in {dotenv_path} (mode 0o600).")

    active = connector or (app.cfg.guardrail.connector if app.cfg.guardrail.connector else None)
    if not active:
        click.echo("  (no active connector configured; skipping hook refresh)")
        return

    if no_restart:
        click.echo("  --no-restart specified; hook .token files were NOT refreshed.")
        click.echo("  Run `defenseclaw-gateway connector setup` manually to apply the new token.")
        return

    # Bounce the connector so the hook scripts pick up the new token.
    click.echo(f"  Refreshing hook scripts for connector={active!r}…")
    rc1, _so, se = _rotate_token_run_gateway(["connector", "teardown"])
    if rc1 != 0:
        click.echo(
            "  WARNING: connector teardown returned non-zero; old hook scripts may persist.\n"
            f"  stderr: {se.strip()}"
        )
    rc2, _so, se = _rotate_token_run_gateway(["connector", "setup"])
    if rc2 != 0:
        raise click.ClickException(
            "connector setup failed after token rotation; the gateway may be in an inconsistent state.\n"
            f"stderr: {se.strip()}"
        )

    click.echo("  Hook scripts refreshed.")
    click.echo()
    click.echo("Next step: restart the agent (claude / codex / openclaw / zeptoclaw) so")
    click.echo("the new token is picked up by its inspect / hook subprocess invocations.")


# ---------------------------------------------------------------------------
# setup gateway
# ---------------------------------------------------------------------------

@setup.command("gateway")
@click.option("--remote", is_flag=True, help="Configure for a remote OpenClaw gateway (requires auth token)")
@click.option("--host", default=None, help="Gateway host")
@click.option("--port", type=int, default=None, help="Gateway WebSocket port")
@click.option("--api-port", type=int, default=None, help="Sidecar REST API port")
@click.option("--token", default=None, help="Gateway auth token")
@click.option("--ssm-param", default=None, help="AWS SSM parameter name for token")
@click.option("--ssm-region", default=None, help="AWS region for SSM")
@click.option("--ssm-profile", default=None, help="AWS CLI profile for SSM")
@click.option("--verify/--no-verify", default=True, help="Run connectivity checks after setup (default: on)")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_gateway(
    app: AppContext,
    remote: bool,
    host, port, api_port, token,
    ssm_param, ssm_region, ssm_profile,
    verify: bool,
    non_interactive: bool,
) -> None:
    """Configure gateway connection for the DefenseClaw sidecar.

    By default configures for a local OpenClaw instance (auth token from
    ~/.defenseclaw/.env when OpenClaw requires it).
    Use --remote to configure for a remote gateway that requires an auth token,
    optionally fetched from AWS SSM Parameter Store.
    """
    gw = app.cfg.gateway

    data_dir = app.cfg.data_dir

    if non_interactive:
        if host is not None:
            gw.host = host
        if port is not None:
            gw.port = port
        if api_port is not None:
            gw.api_port = api_port
        if token is not None:
            _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", token, data_dir)
            gw.token = ""
            gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
        elif ssm_param:
            fetched = _fetch_ssm_token(ssm_param, ssm_region or "us-east-1", ssm_profile)
            if fetched:
                _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", fetched, data_dir)
                gw.token = ""
                gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
            else:
                click.echo("error: failed to fetch token from SSM", err=True)
                raise SystemExit(1)
        elif remote and not gw.resolved_token():
            click.echo("  ⚠ --remote specified but no auth token configured", err=True)
            click.echo("    Provide --token or --ssm-param, or set OPENCLAW_GATEWAY_TOKEN", err=True)
        elif not gw.resolved_token():
            detected = _detect_openclaw_gateway_token(app.cfg.claw.config_file)
            if detected:
                _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", detected, data_dir)
                gw.token = ""
                gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
    elif remote:
        _interactive_gateway_remote(gw, data_dir)
    else:
        _interactive_gateway_local(gw, app.cfg.claw.config_file, data_dir)

    app.cfg.save()
    _print_gateway_summary(gw)

    if verify:
        from defenseclaw.commands.cmd_doctor import _check_openclaw_gateway, _check_sidecar, _DoctorResult
        click.echo("  ── Verifying gateway connectivity ──")
        r = _DoctorResult()
        _check_openclaw_gateway(app.cfg, r)
        _check_sidecar(app.cfg, r)
        click.echo()
        if r.failed:
            click.echo("  Tip: fix the issues above, then run 'defenseclaw doctor' to re-check.")
            click.echo()

    if app.logger:
        mode = "remote" if (remote or gw.resolved_token()) else "local"
        app.logger.log_action("setup-gateway", "config", f"mode={mode} host={gw.host} port={gw.port}")


def _interactive_gateway_local(gw, openclaw_config_file: str, data_dir: str) -> None:
    click.echo()
    click.echo("  Gateway Configuration (local)")
    click.echo("  ─────────────────────────────")
    click.echo()

    gw.host = click.prompt("  Gateway host", default=gw.host)
    gw.port = click.prompt("  Gateway port", default=gw.port, type=int)
    gw.api_port = click.prompt("  Sidecar API port", default=gw.api_port, type=int)
    gw.token = ""
    detected = _detect_openclaw_gateway_token(openclaw_config_file)
    if detected:
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", detected, data_dir)
        click.echo(f"  OpenClaw token saved to ~/.defenseclaw/.env ({_mask(detected)})")
    gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
    click.echo()
    click.echo("  Auth: token is read from OPENCLAW_GATEWAY_TOKEN in ~/.defenseclaw/.env when set.")
    click.echo("  OpenClaw may require this even for 127.0.0.1.")


def _interactive_gateway_remote(gw, data_dir: str) -> None:
    click.echo()
    click.echo("  Gateway Configuration (remote)")
    click.echo("  ──────────────────────────────")
    click.echo()

    gw.host = click.prompt("  Gateway host", default=gw.host)
    gw.port = click.prompt("  Gateway port", default=gw.port, type=int)
    gw.api_port = click.prompt("  Sidecar API port", default=gw.api_port, type=int)

    click.echo()
    use_ssm = click.confirm("  Fetch token from AWS SSM Parameter Store?", default=True)

    token_value: str = ""
    if use_ssm:
        param = click.prompt(
            "  SSM parameter name",
            default="/openclaw/openclaw-bedrock/gateway-token",
        )
        region = click.prompt("  AWS region", default="us-east-1")
        profile = click.prompt("  AWS CLI profile", default="devops")

        click.echo("  Fetching token from SSM...", nl=False)
        fetched = _fetch_ssm_token(param, region, profile)
        if fetched:
            token_value = fetched
            click.echo(f" ok ({_mask(fetched)})")
        else:
            click.echo(" failed")
            click.echo("  Falling back to manual entry.")
            _prompt_and_save_secret("OPENCLAW_GATEWAY_TOKEN", gw.token, data_dir)
            gw.token = ""
            gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
            return
    else:
        _prompt_and_save_secret("OPENCLAW_GATEWAY_TOKEN", gw.token, data_dir)

    if token_value:
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", token_value, data_dir)

    gw.token = ""
    gw.token_env = "OPENCLAW_GATEWAY_TOKEN"

    if not gw.resolved_token():
        click.echo("  warning: no token set — sidecar will fail to connect to a remote gateway", err=True)


def _detect_openclaw_gateway_token(openclaw_config_file: str) -> str:
    """Read the gateway auth token from openclaw.json (gateway.auth.token)."""
    from pathlib import Path

    path = openclaw_config_file
    if path.startswith("~/"):
        path = str(Path.home() / path[2:])
    try:
        with open(path) as f:
            cfg = _json.load(f)
        return cfg.get("gateway", {}).get("auth", {}).get("token", "")
    except (OSError, ValueError, KeyError):
        return ""


def _fetch_ssm_token(param: str, region: str, profile: str | None) -> str | None:
    cmd = [
        "aws", "ssm", "get-parameter",
        "--name", param,
        "--with-decryption",
        "--query", "Parameter.Value",
        "--output", "text",
        "--region", region,
    ]
    if profile:
        cmd.extend(["--profile", profile])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


# ---------------------------------------------------------------------------
# Connector metadata (mirrors internal/gateway/connector/*.go)
# ---------------------------------------------------------------------------

_CONNECTOR_NAMES_FALLBACK = ["openclaw", "zeptoclaw", "claudecode", "codex"]


def _fetch_connector_names(cfg=None) -> list[str]:
    """Query the sidecar /v1/connectors endpoint for available connectors.

    Falls back to the hardcoded list if the sidecar is unreachable.
    """
    import urllib.request

    host = "127.0.0.1"
    port = 0
    if cfg and hasattr(cfg, "guardrail"):
        host = getattr(cfg.guardrail, "host", None) or "127.0.0.1"
        port = getattr(cfg.guardrail, "port", 0) or 0
    if not port:
        return list(_CONNECTOR_NAMES_FALLBACK)
    try:
        url = f"http://{host}:{port}/v1/connectors"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = _json.loads(resp.read())
            names = [c.get("name") or c.get("id") for c in data.get("connectors", [])]
            return [n for n in names if n] or list(_CONNECTOR_NAMES_FALLBACK)
    except Exception:
        return list(_CONNECTOR_NAMES_FALLBACK)


_CONNECTOR_NAMES = _CONNECTOR_NAMES_FALLBACK

_CONNECTOR_META: dict[str, dict[str, str]] = {
    "openclaw": {
        "label": "OpenClaw",
        "description": "fetch interceptor + before_tool_call plugin",
        "tool_mode": "both",
        "subprocess_policy": "sandbox",
    },
    "zeptoclaw": {
        "label": "ZeptoClaw",
        "description": "api_base redirect + proxy response-scan",
        "tool_mode": "both",
        "subprocess_policy": "sandbox",
    },
    "claudecode": {
        "label": "Claude Code",
        "description": "env var + PreToolUse hook script",
        "tool_mode": "both",
        "subprocess_policy": "sandbox",
    },
    "codex": {
        "label": "Codex",
        "description": "env var + hook script + response-scan",
        "tool_mode": "both",
        "subprocess_policy": "sandbox",
    },
}

_CONNECTOR_CHANGE_SURFACES: dict[str, tuple[str, ...]] = {
    "openclaw": (
        "~/.openclaw/openclaw.json plugin allow/load entries",
        "~/.openclaw/extensions/defenseclaw/",
        "~/.defenseclaw/hooks/ and subprocess policy files",
    ),
    "zeptoclaw": (
        "~/.zeptoclaw/config.json providers.*.api_base",
        "~/.zeptoclaw/config.json safety.allow_private_endpoints",
        "~/.defenseclaw/hooks/ and subprocess policy files",
    ),
    "claudecode": (
        "~/.claude/settings.json hooks",
        "~/.claude/settings.json env OTEL_* / CLAUDE_CODE_ENABLE_TELEMETRY",
        "Claude Code Project CodeGuard plugin (installed once and left enabled)",
        "~/.defenseclaw/hooks/ and subprocess policy files",
    ),
    "codex": (
        "~/.codex/config.toml hooks / features.codex_hooks",
        "~/.codex/config.toml otel / notify",
        "~/.codex/skills/software-security Project CodeGuard skill (installed once and left enabled)",
        "~/.defenseclaw/hooks/ and notify bridge files",
    ),
}


def _print_connector_mutation_notice(connector: str, *, switching_from: str | None = None) -> None:
    """Tell operators which agent-owned files DefenseClaw will edit.

    The Go connector setup stores hash-checked snapshots before touching
    these files. On teardown, unchanged files are restored byte-for-byte;
    drifted files fall back to removing only DefenseClaw-owned hooks,
    OTel env, notify, plugin, and proxy entries.
    """
    label = _CONNECTOR_META.get(connector, {}).get("label", connector)
    prefix = f"  DefenseClaw will update {label} integration files"
    if switching_from and switching_from != connector:
        old = _CONNECTOR_META.get(switching_from, {}).get("label", switching_from)
        prefix = f"  Switching from {old} first tears down its DefenseClaw integration, then updates {label}"
    click.echo(prefix + ":")
    for surface in _CONNECTOR_CHANGE_SURFACES.get(connector, ()):
        click.echo(f"    - {surface}")
    click.echo("  A hash-checked backup is stored before edits; teardown restores or surgically removes only DefenseClaw-owned entries.")


def _read_picked_connector(data_dir: str | None) -> str | None:
    """Read the connector hint written by ``scripts/install.sh``.

    The installer records the operator's chosen connector at
    ``<data_dir>/picked_connector`` (a single-line plaintext file) so
    that subsequent CLI invocations can default to it without
    re-prompting. We treat the file as advisory: the canonical runtime
    value lives in ``guardrail.connector`` once setup has run, but the
    hint lets the *first* `defenseclaw setup guardrail` after install
    pick up the operator's intent.

    The function is intentionally tolerant — a missing file, an
    unreadable file, or an unrecognized value all yield ``None`` so
    callers can fall through to detection / defaults.
    """
    if not data_dir:
        return None
    path = os.path.join(data_dir, "picked_connector")
    try:
        # Bound the read to defend against a tampered or accidentally
        # huge file: the legitimate contents are a 4-10 byte connector
        # name. We never interpret the file as code.
        with open(path, encoding="utf-8") as fh:
            raw = fh.read(64)
    except OSError:
        return None
    name = raw.strip().lower()
    if name in _CONNECTOR_NAMES:
        return name
    return None


def _detect_connector(data_dir: str | None = None) -> str | None:
    """Guess the active agent framework, preferring the install-time hint.

    Resolution order:
      1. ``<data_dir>/picked_connector`` (written by ``scripts/install.sh
         --connector ...``) — the operator's explicit choice at install
         time.
      2. Filesystem heuristics over the agent's own state directories
         (``~/.claude``, ``~/.codex``, ``~/.zeptoclaw/config.json``).

    Returns ``None`` when neither source is conclusive so the caller
    can fall back to ``"openclaw"``.
    """
    picked = _read_picked_connector(data_dir)
    if picked:
        return picked
    home = os.path.expanduser("~")
    if os.path.isdir(os.path.join(home, ".claude")):
        return "claudecode"
    if os.path.isdir(os.path.join(home, ".codex")):
        return "codex"
    if os.path.isfile(os.path.join(home, ".zeptoclaw", "config.json")):
        return "zeptoclaw"
    return None


def _select_connector_interactive(current: str, data_dir: str | None = None) -> str:
    """Present a numbered menu and return the selected connector name.

    ``data_dir`` is forwarded to ``_detect_connector`` so the install-time
    ``picked_connector`` hint can seed the menu's default. We only
    override ``current`` when it is empty or still the historical
    fallback ("openclaw") — operators who already configured a non-
    default connector should not see their choice silently flipped by
    a leftover hint file.
    """
    detected = _detect_connector(data_dir)
    default = current
    if not default or default == "openclaw":
        default = detected or "openclaw"
    click.echo()
    click.echo("  Which agent framework are you using?")
    click.echo()
    for i, name in enumerate(_CONNECTOR_NAMES, 1):
        meta = _CONNECTOR_META[name]
        marker = " *" if name == default else ""
        click.echo(f"    {i}. {meta['label']:<14s} — {meta['description']}{marker}")
    click.echo()
    default_idx = _CONNECTOR_NAMES.index(default) + 1 if default in _CONNECTOR_NAMES else None
    raw = click.prompt(
        "  Selection",
        type=click.IntRange(1, len(_CONNECTOR_NAMES)),
        default=default_idx,
    )
    return _CONNECTOR_NAMES[raw - 1]


def _print_connector_info(name: str) -> None:
    """Print connector details after selection."""
    meta = _CONNECTOR_META.get(name, {})
    if not meta:
        return
    tool_mode = meta["tool_mode"]
    if tool_mode == "both":
        tool_display = "pre-execution + response-scan"
    else:
        tool_display = tool_mode
    click.echo(f"    Connector:         {meta['label']} ({name})")
    click.echo(f"    Tool inspection:   {tool_display}")
    click.echo(f"    Subprocess policy: {meta['subprocess_policy']}")
    click.echo()
    _print_connector_mutation_notice(name)
    if tool_mode == "response-scan":
        click.echo()
        click.secho(
            f"    Warning: {meta['label']} does not support pre-execution tool hooks.",
            fg="yellow",
        )
        click.echo(
            "      Tool calls are scanned in LLM responses only (response-scan mode)."
        )
        click.echo(
            "      DefenseClaw can block the response but cannot prevent individual"
        )
        click.echo(
            "      tool execution if the response has already been delivered."
        )


# ---------------------------------------------------------------------------
# setup guardrail
# ---------------------------------------------------------------------------

@setup.command("guardrail")
@click.option("--disable", is_flag=True, help="Disable guardrail and revert OpenClaw config")
# ``--connector`` is the canonical name (matches scripts/install.sh and
# /v1/connectors). ``--agent`` is kept as an alias for backward
# compatibility with existing scripts and docs. Both bind to the same
# ``agent_name`` parameter; supplying both flags will simply use the
# last one parsed by Click, which is consistent with Click's standard
# behavior for aliased options.
@click.option("--connector", "--agent", "agent_name",
              type=click.Choice(_CONNECTOR_NAMES, case_sensitive=False), default=None,
              help="Agent framework connector (openclaw, claudecode, codex, zeptoclaw). "
                   "Alias: --agent. Defaults to <data_dir>/picked_connector when set "
                   "by the installer, else filesystem auto-detection, else openclaw.")
@click.option("--mode", "guard_mode", type=click.Choice(["observe", "action"]), default=None,
              help="Guardrail mode")
@click.option("--scanner-mode", type=click.Choice(["local", "remote"]), default=None,
              help="Scanner mode (local patterns or remote Cisco API)")
@click.option("--cisco-endpoint", default=None, help="Cisco AI Defense API endpoint")
@click.option("--cisco-api-key-env", default=None, help="Env var name holding Cisco AI Defense API key")
@click.option("--cisco-timeout-ms", type=int, default=None, help="Cisco AI Defense timeout (ms)")
@click.option("--port", "guard_port", type=int, default=None, help="Guardrail proxy port")
@click.option("--block-message", default=None,
              help="Custom message shown when a request is blocked (empty = default)")
@click.option("--detection-strategy",
              type=click.Choice(["regex_only", "regex_judge", "judge_first"]), default=None,
              help="Detection strategy (regex_only, regex_judge, judge_first)")
@click.option("--judge-model", default=None, help="LLM judge model (e.g. anthropic/claude-sonnet-4-20250514)")
@click.option("--judge-api-base", default=None, help="LLM judge API base URL (e.g. Bifrost URL)")
@click.option("--judge-api-key-env", default=None, help="Env var name for judge API key")
@click.option("--restart/--no-restart", default=True,
              help="Restart gateway and openclaw after setup (default: on)")
@click.option("--verify/--no-verify", default=True,
              help="Run connectivity checks after setup (default: on)")
@click.option("--non-interactive", "--accept-defaults", is_flag=True,
              help="Use flags instead of prompts (alias: --accept-defaults)")
@pass_ctx
def setup_guardrail(
    app: AppContext,
    disable: bool,
    agent_name: str | None,
    guard_mode, guard_port,
    scanner_mode, cisco_endpoint, cisco_api_key_env, cisco_timeout_ms,
    block_message,
    detection_strategy, judge_model, judge_api_base, judge_api_key_env,
    restart: bool,
    verify: bool,
    non_interactive: bool,
) -> None:
    """Configure the LLM guardrail (routes LLM traffic through the Go proxy for inspection).

    Routes all LLM traffic through the built-in Go guardrail proxy.
    Every prompt and response is inspected for prompt injection, secrets,
    PII, and data exfiltration patterns.

    Use --connector (alias: --agent) to select the agent framework
    connector (openclaw, claudecode, codex, zeptoclaw). The connector
    determines how LLM traffic is intercepted, how tool calls are
    inspected, and what subprocess enforcement policy is applied. When
    omitted, the value defaults to the install-time hint at
    ``<data_dir>/picked_connector`` (written by ``scripts/install.sh
    --connector ...``), then to any previously saved choice in
    ``guardrail.connector``, then to ``openclaw``.

    Two modes:
      observe — log findings, never block (default, recommended to start)
      action  — block prompts/responses that match security policies

    Use --disable to turn off the guardrail and restore direct LLM access.
    """

    gc = app.cfg.guardrail

    if disable:
        # Always restart on disable — leaving the proxy running defeats the
        # purpose of disabling. The fetch interceptor also needs OpenClaw
        # to restart (which happens automatically when openclaw.json changes).
        _disable_guardrail(app, gc, restart=True)
        return

    aid = app.cfg.cisco_ai_defense

    if non_interactive:
        # Connector resolution order in non-interactive mode:
        #   1. explicit --connector / --agent flag (operator intent always wins)
        #   2. existing gc.connector if already set to a non-default value
        #      (preserves prior `setup guardrail` choice across re-runs)
        #   3. <data_dir>/picked_connector hint written by install.sh
        #      (operator intent at install time)
        #   4. fallback to "openclaw" (historical default)
        # We deliberately do NOT run filesystem auto-detect (the
        # ``~/.claude`` / ``~/.codex`` heuristic) in non-interactive mode:
        # those directories often pre-exist on developer workstations
        # and would silently flip the connector behind the operator's
        # back during scripted installs. Filesystem detection is only
        # used in the interactive picker where the operator can see and
        # confirm the suggested default.
        if agent_name:
            gc.connector = agent_name
        elif not gc.connector or gc.connector == "openclaw":
            picked = _read_picked_connector(getattr(app.cfg, "data_dir", None))
            if picked:
                gc.connector = picked
        gc.mode = guard_mode or gc.mode or "observe"
        gc.scanner_mode = scanner_mode or gc.scanner_mode or "local"
        if cisco_endpoint is not None:
            aid.endpoint = cisco_endpoint
        if cisco_api_key_env is not None:
            aid.api_key_env = cisco_api_key_env
        if cisco_timeout_ms is not None:
            aid.timeout_ms = cisco_timeout_ms
        gc.port = guard_port or gc.port or 4000
        if block_message is not None:
            gc.block_message = block_message
        if detection_strategy is not None:
            gc.detection_strategy = detection_strategy
        if judge_model is not None:
            gc.judge.model = judge_model
            gc.judge.enabled = True
        if judge_api_base is not None:
            gc.judge.api_base = judge_api_base
        if judge_api_key_env is not None:
            gc.judge.api_key_env = judge_api_key_env
            # Mirror the interactive path (see _interactive_guardrail_setup):
            # when the operator supplies a NEW env var that diverges from the
            # unified DEFENSECLAW_LLM_KEY, share it into the v5 top-level
            # ``llm.api_key_env`` so every other LLM-using component
            # (MCP/skill/plugin scanners) resolves through the same key.
            # Writing to the deprecated v4 ``default_llm_api_key_env`` would
            # be scrubbed by ``setup migrate-llm`` on next load and silently
            # undo this setting.
            unified_env = app.cfg.llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV
            if (
                judge_api_key_env
                and judge_api_key_env != DEFENSECLAW_LLM_KEY_ENV
                and judge_api_key_env != unified_env
                and not app.cfg.llm.api_key_env
            ):
                app.cfg.llm.api_key_env = judge_api_key_env
        gc.enabled = True

        # Apply sensible strategy defaults when judge is enabled
        if gc.judge.enabled:
            if not gc.detection_strategy or gc.detection_strategy == "regex_only":
                gc.detection_strategy = "regex_judge"
            if not getattr(gc, "detection_strategy_completion", None):
                gc.detection_strategy_completion = "regex_only"

        if gc.scanner_mode in ("remote", "both"):
            key_env = aid.api_key_env or "CISCO_AI_DEFENSE_API_KEY"
            if scanner_mode:
                if not aid.endpoint:
                    click.echo("  ✗ --scanner-mode=remote requires --cisco-endpoint or a configured endpoint", err=True)
                    raise SystemExit(1)
                if not os.environ.get(key_env):
                    click.echo(f"  ✗ --scanner-mode=remote but ${key_env} is not set", err=True)
                    raise SystemExit(1)
            elif not aid.endpoint or not os.environ.get(key_env):
                gc.scanner_mode = "local"
                click.echo("  ℹ Cisco AI Defense credentials not configured — using local scanner only")
    else:
        _interactive_guardrail_setup(app, gc, agent_name=agent_name)

    if not gc.enabled:
        click.echo("  Guardrail not enabled. Run again without declining to configure.")
        return

    ok, warnings = execute_guardrail_setup(app, save_config=True)
    if not ok:
        return

    aid = app.cfg.cisco_ai_defense

    # --- Summary ---
    click.echo()
    connector_label = _CONNECTOR_META.get(gc.connector or "openclaw", {}).get("label", gc.connector)
    rows = [
        ("guardrail.connector", f"{connector_label} ({gc.connector})"),
        ("guardrail.mode", gc.mode),
        ("guardrail.port", str(gc.port)),
        ("guardrail.model", gc.model),
        ("guardrail.model_name", gc.model_name),
        ("guardrail.api_key_env", gc.api_key_env),
        ("guardrail.detection_strategy", gc.detection_strategy),
    ]
    if gc.api_base:
        rows.append(("guardrail.api_base", gc.api_base[:60] + "..." if len(gc.api_base) > 60 else gc.api_base))
    if gc.block_message:
        truncated = gc.block_message[:60] + "..." if len(gc.block_message) > 60 else gc.block_message
        rows.append(("guardrail.block_message", truncated))
    if gc.judge.enabled:
        rows.append(("guardrail.judge.enabled", "true"))
        rows.append(("guardrail.judge.model", gc.judge.model))
        if gc.judge.api_base:
            judge_api_base = gc.judge.api_base
            if len(judge_api_base) > 60:
                judge_api_base = judge_api_base[:60] + "..."
            rows.append(("guardrail.judge.api_base", judge_api_base))
        rows.append(("guardrail.judge.api_key_env", gc.judge.api_key_env))
        if gc.judge.fallbacks:
            rows.append(("guardrail.judge.fallbacks", ", ".join(gc.judge.fallbacks)))
    if gc.scanner_mode in ("remote", "both"):
        rows.append(("cisco_ai_defense.endpoint", aid.endpoint))
        rows.append(("cisco_ai_defense.api_key_env", aid.api_key_env))
        rows.append(("cisco_ai_defense.timeout_ms", str(aid.timeout_ms)))
    for key, val in rows:
        click.echo(f"    {key + ':':<30s} {val}")
    click.echo()

    if warnings:
        click.echo("  ── Warnings ──────────────────────────────────────────")
        for w in warnings:
            click.echo(f"  ⚠ {w}")
        click.echo()

    if restart:
        _restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=gc.connector or "openclaw",
        )
    else:
        click.echo("  Next steps:")
        click.echo("    Restart the defenseclaw sidecar for changes to take effect:")
        click.echo("       defenseclaw-gateway restart")
        click.echo()

    click.echo("  To disable and revert:")
    click.echo("    defenseclaw setup guardrail --disable")
    click.echo()

    if app.logger:
        app.logger.log_action(
            "setup-guardrail", "config",
            f"mode={gc.mode} scanner_mode={gc.scanner_mode} port={gc.port} model={gc.model}",
        )


# ---------------------------------------------------------------------------
# setup codex / setup claude-code  —  observability-only aliases
# ---------------------------------------------------------------------------
#
# These are thin wrappers around the existing observability-only branch
# of ``setup guardrail``. They exist because operators who only want
# telemetry (no traffic interception, no enforcement) currently have to
# walk through the full ``setup guardrail`` wizard, answer "yes" to a
# single confirm, and trust that the wizard does the right thing under
# the hood. The aliases shortcut that:
#
#   defenseclaw setup codex          → observability-only for Codex
#   defenseclaw setup claude-code    → observability-only for Claude Code
#
# Both commands also flip ``claw.mode`` so the rest of the CLI/TUI
# (skill scanner, MCP scanner, plugin scanner, overview panels) reads
# from the matching connector's source-of-truth files (``~/.codex`` or
# ``~/.claude``) instead of OpenClaw's default ``~/.openclaw`` layout.
# Without this flip, ``defenseclaw scan skills`` after ``setup codex``
# would scan ``~/.openclaw/skills`` and miss every Codex skill — a
# foot-gun we explicitly want to close.
#
# Enforcement (proxy data path, blocking) stays disabled. Operators who
# later want to engage enforcement edit
# ``guardrail.codex_enforcement_enabled`` /
# ``guardrail.claudecode_enforcement_enabled`` in ~/.defenseclaw/config.yaml
# and restart the gateway — see docs/OBSERVABILITY.md §9.

# Stable hint filename used by ``defenseclaw setup guardrail`` and
# ``defenseclaw quickstart`` to default the connector picker after a
# fresh install. Mirrors the ``picked_connector`` constant baked into
# scripts/install.sh — keeping these in sync means re-running the
# alias commands here updates the hint just like the installer would.
_PICKED_CONNECTOR_FILENAME = "picked_connector"


def _write_picked_connector_hint(data_dir: str | None, connector: str) -> None:
    """Persist *connector* as the install-time picked-connector hint.

    Writes ``<data_dir>/picked_connector`` atomically (tmp file +
    ``os.replace``). Failures are non-fatal and surface as a warning —
    a stale hint never blocks setup, it only affects the *default*
    selected by future ``defenseclaw setup guardrail`` invocations.

    The bound on contents is intentional: the file is one short word
    (``codex`` / ``claudecode`` / ``openclaw`` / ``zeptoclaw``) and
    ``_read_picked_connector`` rejects anything outside ``_CONNECTOR_NAMES``,
    so even a corrupted write can never escalate to remote code paths.
    """
    if not data_dir:
        return
    if connector not in _CONNECTOR_NAMES:
        return
    try:
        os.makedirs(data_dir, exist_ok=True)
        path = os.path.join(data_dir, _PICKED_CONNECTOR_FILENAME)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(connector + "\n")
        os.replace(tmp, path)
    except OSError as exc:
        click.echo(
            f"  ⚠ Failed to update picked_connector hint: {exc}",
            err=True,
        )


def _apply_connector_observability_only(
    app: AppContext,
    *,
    connector: str,
    restart: bool,
) -> bool:
    """Pin DefenseClaw to *connector* in observability-only mode.

    Idempotent: running twice yields the same on-disk state. The
    function:

      1. Sets ``guardrail.connector`` and ``claw.mode`` to *connector*
         so the active-connector resolver
         (``Config.active_connector``) returns *connector* even if a
         future ``guardrail.enabled = false`` toggle is applied.
      2. Disables the matching enforcement flag
         (``gc.codex_enforcement_enabled`` / ``gc.claudecode_enforcement_enabled``)
         so the Go gateway's ``Connector.Setup()`` skips proxy
         binding, openai_base_url / ANTHROPIC_BASE_URL rewriting, and
         the subprocess-policy enforcement that come bundled with
         "guardrail" mode for these connectors.
      3. Sets ``gc.enabled=True``, ``gc.mode='observe'``,
         ``gc.scanner_mode='local'``, ``gc.detection_strategy='regex_only'``
         — sensible defaults so the YAML stays loadable if the
         operator later flips enforcement on. The Go gateway never
         reads these in observability mode.
      4. Persists config.yaml and writes the
         ``<data_dir>/picked_connector`` hint.
      5. When ``restart`` is true, bounces the gateway so its
         ``Connector.Setup()`` wires hooks + native OTel exporter +
         (codex only) the notify bridge against the running sidecar.

    Returns True on success, False on any persistence error.
    """
    if connector not in ("codex", "claudecode"):
        click.echo(
            f"  ✗ observability-only mode is only supported for "
            f"codex/claudecode (got {connector!r})",
            err=True,
        )
        return False

    cfg = app.cfg
    gc = cfg.guardrail

    cfg.claw.mode = connector
    gc.connector = connector
    gc.enabled = True
    gc.mode = "observe"
    gc.scanner_mode = "local"
    gc.port = gc.port or 4000
    gc.detection_strategy = "regex_only"
    gc.detection_strategy_completion = "regex_only"
    gc.judge.enabled = False

    if connector == "codex":
        gc.codex_enforcement_enabled = False
    else:
        gc.claudecode_enforcement_enabled = False

    try:
        cfg.save()
        click.echo("  ✓ Config saved to ~/.defenseclaw/config.yaml")
    except OSError as exc:
        click.echo(f"  ✗ Failed to save config: {exc}", err=True)
        return False

    _write_picked_connector_hint(getattr(cfg, "data_dir", None), connector)
    click.echo(f"  ✓ Active connector set to {connector!r} (claw.mode={connector})")

    _write_guardrail_runtime(cfg.data_dir, gc)

    if restart:
        click.echo()
        click.echo("  Restarting gateway to wire connector telemetry...")
        _restart_services(
            cfg.data_dir,
            cfg.gateway.host,
            cfg.gateway.port,
            connector=connector,
        )
        click.echo(f"  ✓ {_CONNECTOR_META[connector]['label']} connector setup complete")

    if app.logger:
        app.logger.log_action(
            "setup-connector-observability",
            "config",
            f"connector={connector} mode=observability_only enforcement=disabled",
        )

    return True


def _print_connector_observability_banner(connector: str) -> None:
    label = _CONNECTOR_META[connector]["label"]
    enforcement_flag = (
        "codex_enforcement_enabled"
        if connector == "codex"
        else "claudecode_enforcement_enabled"
    )
    click.echo()
    click.echo(f"  DefenseClaw — {label} observability setup")
    click.echo("  ─────────────────────────────────────────────────────────")
    click.echo()
    click.echo(f"  This wires {label} telemetry into DefenseClaw WITHOUT")
    click.echo("  inserting a proxy in the data path. No traffic is")
    click.echo("  intercepted, no requests are blocked.")
    click.echo()
    click.echo("  Telemetry channels:")
    click.echo(
        "    • Hooks      — tool calls, prompt-submit, agent stop "
        f"→ /api/v1/{connector}/hook"
    )
    click.echo(
        "    • Native OTel — model + token counts, raw API bodies "
        "→ /v1/logs and /v1/metrics"
    )
    if connector == "codex":
        click.echo(
            "    • Notify     — agent-turn-complete events "
            "→ /api/v1/codex/notify"
        )
    click.echo()
    click.echo(f"  To later turn enforcement on, set guardrail.{enforcement_flag}=true")
    click.echo("  in ~/.defenseclaw/config.yaml and restart the gateway.")
    click.echo()
    _print_connector_mutation_notice(connector)
    click.echo()


def _print_observability_summary(connector: str) -> None:
    """One-screen summary surfaced after a successful alias run."""
    label = _CONNECTOR_META[connector]["label"]
    click.echo()
    click.echo("  Summary")
    click.echo("  ───────")
    rows = [
        ("connector", f"{label} ({connector})"),
        ("claw.mode", connector),
        ("guardrail.enabled", "true (observability-only)"),
        ("guardrail.mode", "observe"),
        ("enforcement", "disabled"),
    ]
    for k, v in rows:
        click.echo(f"    {k + ':':<22s} {v}")
    click.echo()
    click.echo("  Next steps:")
    click.echo(
        "    • Verify gateway picked up the new connector: "
        "defenseclaw-gateway status"
    )
    click.echo(
        "    • Optionally launch the bundled local stack: "
        "defenseclaw setup local-observability up"
    )
    click.echo(
        f"    • Tail audit events for the new connector: "
        f"defenseclaw audit tail --connector {connector}"
    )
    click.echo()
    click.echo("  To revert and restore direct LLM access:")
    click.echo("    defenseclaw setup guardrail --disable")
    click.echo()


def _local_observability_already_up(data_dir: str) -> bool:
    """Best-effort check: are the bundled stack containers already running?

    We probe the Grafana port — the cheapest signal that ``setup
    local-observability up`` has run successfully. False positives are
    benign (we'll just call ``up`` again, which is idempotent), but we
    err on "skip the auto-up" when uncertain so we don't shadow a
    pre-existing operator-managed stack.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            return s.connect_ex(("127.0.0.1", 3000)) == 0
    except OSError:
        return False


def _maybe_bring_up_local_stack(app: AppContext, *, auto: bool) -> None:
    """Optionally bootstrap the bundled local OTel stack.

    Honours ``--with-local-stack`` (auto=True) by invoking the existing
    ``local_observability up`` Click command in-process. We never run
    it in non-interactive mode without an explicit flag — Docker
    starts are heavyweight, can fail noisily, and we don't want a
    quick ``setup codex --non-interactive`` to hang for 30s in CI.
    """
    if not auto:
        return

    if _local_observability_already_up(app.cfg.data_dir):
        click.echo(
            "  ✓ Local observability stack already reachable on :3000 "
            "(skipping `up`)"
        )
        return

    try:
        from defenseclaw.commands.cmd_setup_local_observability import (
            up_cmd,
        )
    except ImportError as exc:
        click.echo(
            f"  ⚠ Could not load local-observability bridge: {exc}",
            err=True,
        )
        return

    click.echo()
    click.echo("  Bringing up bundled local observability stack...")
    ctx = click.get_current_context()
    try:
        ctx.invoke(
            up_cmd,
            timeout=180,
            no_wait=False,
            no_config=False,
            endpoint=None,
            signals="traces,metrics,logs",
            service_name="defenseclaw",
            with_audit_sink=True,
        )
    except SystemExit:
        # ``up_cmd`` raises SystemExit(1) on Docker preflight failure.
        # Don't propagate — observability mode is still useful without
        # the local stack (operators can target a remote SIEM via
        # ``defenseclaw setup observability add ...``). Just warn.
        click.echo(
            "  ⚠ Local stack failed to start; continuing without it. "
            "Re-run `defenseclaw setup local-observability up` after "
            "fixing Docker.",
            err=True,
        )


def _setup_observability_alias(
    app: AppContext,
    *,
    connector: str,
    yes: bool,
    restart: bool,
    with_local_stack: bool,
) -> None:
    """Shared body for ``setup codex`` and ``setup claude-code``.

    Splitting this out (rather than calling each Click command from
    the other) keeps the wiring linear: each Click command parses its
    own flags, then defers to this helper for the actual work.
    """
    if connector not in ("codex", "claudecode"):
        raise click.ClickException(
            f"unsupported connector for observability alias: {connector!r}"
        )

    _print_connector_observability_banner(connector)

    if not yes:
        if not click.confirm(
            f"  Configure DefenseClaw for {_CONNECTOR_META[connector]['label']} "
            "observability now?",
            default=True,
        ):
            click.echo("  Aborted — no changes made.")
            return

    ok = _apply_connector_observability_only(
        app, connector=connector, restart=restart,
    )
    if not ok:
        raise click.ClickException(
            f"failed to configure {connector} observability — see errors above"
        )

    _maybe_bring_up_local_stack(app, auto=with_local_stack)
    _print_observability_summary(connector)


@setup.command("codex")
@click.option(
    "--yes", "-y", "yes", is_flag=True,
    help="Skip the confirmation prompt (non-interactive).",
)
@click.option(
    "--restart/--no-restart", default=True, show_default=True,
    help=(
        "Restart defenseclaw-gateway after applying changes "
        "(needed so the connector's hook scripts + OTel block are wired)."
    ),
)
@click.option(
    "--with-local-stack/--no-local-stack", default=False, show_default=True,
    help=(
        "Also bring up the bundled Prom/Loki/Tempo/Grafana stack via "
        "`defenseclaw setup local-observability up` once config is saved."
    ),
)
@pass_ctx
def setup_codex(app: AppContext, yes: bool, restart: bool, with_local_stack: bool) -> None:
    """Configure DefenseClaw for Codex observability (no enforcement).

    Alias for the observability-only path of ``setup guardrail`` with
    ``--connector codex``. Pins ``claw.mode=codex`` so the TUI, skill
    scanner, MCP scanner, and plugin scanner read from ``~/.codex/``
    instead of the OpenClaw default layout.

    Wires three telemetry channels at gateway boot:

    \b
      • Hooks   — SessionStart / UserPromptSubmit / PreToolUse /
                  PostToolUse / PermissionRequest / Stop events
      • OTel    — native Codex log + metric exporter pointing at the
                  gateway's /v1/logs and /v1/metrics
      • Notify  — agent-turn-complete webhooks via the bundled
                  notify-bridge.sh shim

    No proxy listener binds; Codex talks directly to its native
    upstream. Enforcement code stays in place behind
    ``guardrail.codex_enforcement_enabled`` — flip to ``true`` and
    restart the gateway to re-engage the proxy.
    """
    _setup_observability_alias(
        app,
        connector="codex",
        yes=yes,
        restart=restart,
        with_local_stack=with_local_stack,
    )


@setup.command("claude-code")
@click.option(
    "--yes", "-y", "yes", is_flag=True,
    help="Skip the confirmation prompt (non-interactive).",
)
@click.option(
    "--restart/--no-restart", default=True, show_default=True,
    help=(
        "Restart defenseclaw-gateway after applying changes "
        "(needed so the connector's hook scripts + OTel env vars are wired)."
    ),
)
@click.option(
    "--with-local-stack/--no-local-stack", default=False, show_default=True,
    help=(
        "Also bring up the bundled Prom/Loki/Tempo/Grafana stack via "
        "`defenseclaw setup local-observability up` once config is saved."
    ),
)
@pass_ctx
def setup_claude_code(
    app: AppContext, yes: bool, restart: bool, with_local_stack: bool,
) -> None:
    """Configure DefenseClaw for Claude Code observability (no enforcement).

    Alias for the observability-only path of ``setup guardrail`` with
    ``--connector claudecode``. Pins ``claw.mode=claudecode`` so the
    TUI, skill scanner, MCP scanner, and plugin scanner read from
    ``~/.claude/`` instead of the OpenClaw default layout.

    Wires two telemetry channels at gateway boot:

    \b
      • Hooks — PreToolUse / PostToolUse / UserPromptSubmit / Stop /
                PermissionRequest events via Claude Code's hook system
      • OTel  — native Claude Code OTel exporter (env-driven) pointing
                at the gateway's /v1/logs and /v1/metrics

    No proxy listener binds; Claude Code talks directly to its native
    upstream. Enforcement code stays in place behind
    ``guardrail.claudecode_enforcement_enabled`` — flip to ``true`` and
    restart the gateway to re-engage the proxy.
    """
    _setup_observability_alias(
        app,
        connector="claudecode",
        yes=yes,
        restart=restart,
        with_local_stack=with_local_stack,
    )


# Connectors that go through the DefenseClaw proxy (port 4000) and
# therefore support the full guardrail enforcement surface (block,
# observe, scanner_mode, judge, etc.). The complement set
# {codex, claudecode} is observability-only — they talk directly to
# their native upstream and DefenseClaw collects telemetry via
# hook scripts and OTel without sitting in the data path.
_GUARDRAIL_SUPPORTING_CONNECTORS = frozenset({"openclaw", "zeptoclaw"})
_OBSERVABILITY_ONLY_CONNECTORS = frozenset({"codex", "claudecode"})


def _apply_connector_mode_switch(
    app: AppContext,
    *,
    new_connector: str,
    restart: bool,
) -> bool:
    """Switch the active claw connector with smart guardrail inheritance.

    Inheritance rules (intentionally asymmetric — the user wants
    "switch fast, don't surprise me"):

      • openclaw ↔ zeptoclaw
            Inherit the current ``guardrail.*`` config verbatim. Both
            connectors run the same proxy-mode pipeline so whatever
            ``mode`` / ``scanner_mode`` / ``judge`` / etc. was set
            stays set. Only ``claw.mode`` and ``guardrail.connector``
            change.

      • {openclaw|zeptoclaw} → {codex|claudecode}
            Switch to observability-only template via
            ``_apply_connector_observability_only``: the proxy stops
            binding, the Go gateway wires hook scripts + OTel
            exporter, and the matching ``*_enforcement_enabled`` flag
            is forced to false. Existing ``mode`` / scanner /  judge
            settings stay on disk so flipping back later restores the
            previous posture.

      • {codex|claudecode} → {openclaw|zeptoclaw}
            Treat as a "guardrail-supporting but don't auto-block"
            switch: enable guardrail in observe mode so the proxy
            binds and we collect telemetry, but never turn enforcement
            on without an explicit ``defenseclaw setup guardrail`` run.
            This matches the user's stated intent ("only observability
            and no guardrails when switching between
            zeptoclaw/openclaw and codex/claude code") while keeping
            the proxy listener live, since openclaw/zeptoclaw require
            it to function.

      • {codex|claudecode} ↔ {codex|claudecode}
            Both observability-only — apply the destination's
            template so the right enforcement flag is cleared and the
            ``connector`` field is realigned.

    Returns True on success, False on persistence error.
    """
    cfg = app.cfg
    gc = cfg.guardrail
    prev = (cfg.claw.mode or "openclaw").strip().lower()
    if prev not in _CONNECTOR_NAMES:
        prev = "openclaw"

    if new_connector not in _CONNECTOR_NAMES:
        click.echo(
            f"  ✗ unknown connector {new_connector!r} — "
            f"expected one of {sorted(_CONNECTOR_NAMES)}",
            err=True,
        )
        return False

    if prev == new_connector:
        click.echo(
            f"  • Already on {_CONNECTOR_META[new_connector]['label']} "
            f"({new_connector}) — nothing to change."
        )
        # Persisting the picked-connector hint is still cheap and
        # idempotent; do it so a reinstall sees the right default.
        _write_picked_connector_hint(getattr(cfg, "data_dir", None), new_connector)
        return True

    # Branch on the destination kind. Source kind only matters for
    # the third bullet above (recover guardrail state when leaving
    # observability-only).
    if new_connector in _OBSERVABILITY_ONLY_CONNECTORS:
        click.echo(
            f"  Switching {_CONNECTOR_META[prev]['label']} → "
            f"{_CONNECTOR_META[new_connector]['label']} "
            f"(observability-only — proxy disabled)"
        )
        _print_connector_mutation_notice(new_connector, switching_from=prev)
        return _apply_connector_observability_only(
            app, connector=new_connector, restart=restart,
        )

    # Destination is openclaw or zeptoclaw.
    cfg.claw.mode = new_connector
    gc.connector = new_connector

    if prev in _GUARDRAIL_SUPPORTING_CONNECTORS:
        # openclaw ↔ zeptoclaw: pure inheritance. We only re-pin
        # claw.mode + guardrail.connector. ``gc.enabled``, ``gc.mode``,
        # ``gc.scanner_mode``, judge config, ports, block message —
        # all left exactly as the operator configured them.
        click.echo(
            f"  Switching {_CONNECTOR_META[prev]['label']} → "
            f"{_CONNECTOR_META[new_connector]['label']} "
            f"(inheriting current guardrail config)"
        )
    else:
        # codex/claudecode → openclaw/zeptoclaw: the proxy needs to
        # bind so guardrail traffic flows, but we deliberately leave
        # enforcement off (mode=observe). Operators who want enforce
        # mode run ``defenseclaw setup guardrail`` next.
        click.echo(
            f"  Switching {_CONNECTOR_META[prev]['label']} → "
            f"{_CONNECTOR_META[new_connector]['label']} "
            f"(observe-only — run `defenseclaw setup guardrail` "
            f"to enable enforcement)"
        )
        gc.enabled = True
        gc.mode = "observe"
        if not gc.port:
            gc.port = 4000
        if not gc.scanner_mode:
            gc.scanner_mode = "local"
        if not gc.detection_strategy:
            gc.detection_strategy = "regex_only"
        if not gc.detection_strategy_completion:
            gc.detection_strategy_completion = "regex_only"
        # Don't auto-enable judge — that's an opt-in toggle that
        # implies an LLM API call per inspection. Leave whatever was
        # there.

    _print_connector_mutation_notice(new_connector, switching_from=prev)

    try:
        cfg.save()
        click.echo("  ✓ Config saved to ~/.defenseclaw/config.yaml")
    except OSError as exc:
        click.echo(f"  ✗ Failed to save config: {exc}", err=True)
        return False

    _write_picked_connector_hint(getattr(cfg, "data_dir", None), new_connector)
    click.echo(
        f"  ✓ Active connector set to {new_connector!r} "
        f"(claw.mode={new_connector})"
    )

    # Refresh the runtime guardrail snapshot so the gateway picks up
    # connector + mode without restarting when the operator chooses
    # --no-restart. Restart still required for a different connector
    # because OpenClawConnector.Setup / ZeptoClawConnector.Setup runs
    # at boot only, but the runtime snapshot keeps the proxy honest
    # in the meantime.
    if hasattr(cfg, "data_dir"):
        _write_guardrail_runtime(cfg.data_dir, gc)

    if restart:
        click.echo()
        click.echo("  Restarting gateway to wire connector hooks + OTel...")
        _restart_services(
            cfg.data_dir,
            cfg.gateway.host,
            cfg.gateway.port,
            connector=new_connector,
        )

    if app.logger:
        app.logger.log_action(
            "setup-connector-mode",
            "config",
            f"from={prev} to={new_connector}",
        )
    return True


@setup.command("mode")
@click.argument(
    "connector",
    type=click.Choice(
        sorted(("openclaw", "zeptoclaw", "codex", "claudecode")),
        case_sensitive=False,
    ),
)
@click.option(
    "--restart/--no-restart", default=True, show_default=True,
    help=(
        "Restart defenseclaw-gateway after switching. The gateway "
        "selects its connector at boot only, so a switch without "
        "restart leaves the previous connector handling traffic "
        "until the next bounce."
    ),
)
@click.option(
    "--yes", "-y", "yes", is_flag=True,
    help="Reserved for symmetry with other setup commands; this command "
         "is non-interactive by default and never prompts.",
)
@pass_ctx
def setup_mode(app: AppContext, connector: str, restart: bool, yes: bool) -> None:
    """Switch the active claw connector with smart guardrail inheritance.

    \b
    Inheritance rules:
      openclaw ↔ zeptoclaw         inherit current guardrail config
      → codex / claudecode         observability-only (proxy off)
      from codex / claudecode      observe-only (proxy on, no enforce)

    The TUI Overview's [m] action calls this command directly.

    Examples:

    \b
        defenseclaw setup mode openclaw
        defenseclaw setup mode codex --no-restart
    """
    _ = yes  # reserved
    connector = connector.strip().lower()
    ok = _apply_connector_mode_switch(
        app, new_connector=connector, restart=restart,
    )
    if not ok:
        raise click.ClickException(
            f"failed to switch to {connector!r} — see errors above"
        )


@setup.command("redaction")
@click.argument(
    "action",
    type=click.Choice(("on", "off", "status"), case_sensitive=False),
)
@click.option(
    "--restart/--no-restart", default=True, show_default=True,
    help=(
        "Restart defenseclaw-gateway after toggling. The redaction "
        "kill-switch is read at sidecar boot, so a flip without "
        "restart leaves the previous state in effect for the running "
        "process. Use --no-restart only when the sidecar is offline."
    ),
)
@click.option(
    "--yes", "-y", "yes", is_flag=True,
    help="Skip the interactive confirmation prompt when turning "
         "redaction off. Required for non-TTY callers (TUI, scripts).",
)
@pass_ctx
def setup_redaction(app: AppContext, action: str, restart: bool, yes: bool) -> None:
    """Persistently enable or disable PII / prompt redaction.

    \b
    DefenseClaw redacts user prompts, judge bodies, evidence
    windows, and verdict reasons by default before they reach any
    sink (stderr, audit DB, OTel logs, Splunk HEC, webhooks). For
    single-tenant lab installs that need to see raw content
    end-to-end (prompt-engineering debugging, false-positive
    triage), this command flips the persistent kill-switch
    documented in OBSERVABILITY.md.

    \b
    WARNING: when redaction is OFF, the audit DB and every
    downstream telemetry sink will store raw PII. Only use this in
    deployments where every sink lives inside the same trust
    boundary as the sidecar.

    \b
    Examples:
      defenseclaw setup redaction status
      defenseclaw setup redaction off --yes
      defenseclaw setup redaction on
    """
    action = action.strip().lower()
    cfg = app.cfg
    current = bool(cfg.privacy.disable_redaction)

    if action == "status":
        env_override = os.environ.get("DEFENSECLAW_DISABLE_REDACTION", "").strip().lower()
        env_on = env_override in {"1", "true", "yes", "on"}
        click.echo("  Redaction state:")
        click.echo(
            f"    config (privacy.disable_redaction): "
            f"{'OFF (raw passthrough)' if current else 'ON (redacted)'}"
        )
        click.echo(
            f"    env (DEFENSECLAW_DISABLE_REDACTION): "
            f"{'set (' + env_override + ')' if env_override else '(unset)'}"
        )
        effective = current or env_on
        click.echo(
            f"    effective at sidecar boot: "
            f"{'OFF — raw content will be persisted to ALL sinks' if effective else 'ON — placeholders only'}"
        )
        return

    desired = action == "off"  # off = disable_redaction = True
    if desired == current:
        state = "OFF" if current else "ON"
        click.echo(f"  • Redaction is already {state}; nothing to change.")
        return

    if desired and not yes:
        # Loud, multi-line warning so the operator can't miss the
        # privacy implications of the flip. Click.confirm reads
        # from stdin; CI / TUI callers pass --yes to bypass.
        click.echo()
        click.echo("  ⚠️  TURNING REDACTION OFF")
        click.echo()
        click.echo("  This will persistently disable PII redaction in the sidecar.")
        click.echo("  After restart, EVERY sink (audit DB, OTel logs, Splunk HEC,")
        click.echo("  webhooks, gateway.log) will receive UNREDACTED prompts,")
        click.echo("  judge bodies, evidence windows, and verdict reasons.")
        click.echo()
        click.echo("  Only proceed if every downstream sink lives inside the")
        click.echo("  same trust boundary as this install.")
        click.echo()
        click.confirm("  Disable redaction?", abort=True)

    cfg.privacy.disable_redaction = desired

    try:
        cfg.save()
    except OSError as exc:
        click.echo(f"  ✗ Failed to save config: {exc}", err=True)
        raise click.ClickException("config save failed") from exc

    new_state = "OFF (raw passthrough)" if desired else "ON (redacted)"
    click.echo(f"  ✓ privacy.disable_redaction set to {desired!s}")
    click.echo(f"  ✓ Redaction state on next sidecar boot: {new_state}")

    if restart:
        click.echo()
        click.echo("  Restarting gateway so the redaction state takes effect...")
        _restart_services(
            cfg.data_dir,
            cfg.gateway.host,
            cfg.gateway.port,
            connector=cfg.active_connector(),
        )
    else:
        click.echo()
        click.echo("  ⚠ Skipped restart (--no-restart). The running sidecar still")
        click.echo("    enforces the previous redaction state. Restart manually:")
        click.echo("       defenseclaw-gateway restart")

    if app.logger:
        app.logger.log_action(
            "setup-redaction-toggle",
            "config",
            f"disable_redaction={desired!s}",
        )


def execute_guardrail_setup(
    app: AppContext,
    *,
    save_config: bool = True,
) -> tuple[bool, list[str]]:
    """Run guardrail setup steps.

    Returns (success, warnings).  When *save_config* is False the caller
    is responsible for calling ``app.cfg.save()`` (used by ``init`` which
    saves once at the end).

    All connector-specific setup (plugin install, config patching, hook
    scripts, subprocess shims/sandbox) is handled by the Go gateway's
    ``Connector.Setup()`` at sidecar startup. This function only persists
    the Python-side config and writes the guardrail runtime JSON.
    """
    gc = app.cfg.guardrail
    warnings: list[str] = []
    connector_name = gc.connector or "openclaw"

    click.echo()

    meta = _CONNECTOR_META.get(connector_name, {})
    if meta:
        tool_mode = meta["tool_mode"]
        if tool_mode == "both":
            tool_display = "pre-execution + response-scan"
        else:
            tool_display = tool_mode
        click.echo(f"  ✓ Connector: {meta.get('label', connector_name)} ({connector_name})")
        click.echo(f"  ✓ Tool inspection: {tool_display}")
        click.echo(f"  ✓ Subprocess policy: {meta['subprocess_policy']}")
    else:
        click.echo(f"  ✓ Connector: {connector_name} (plugin)")

    click.echo("  ✓ Connector setup will run automatically when the gateway starts")

    # --- Save DefenseClaw config ---
    if save_config:
        try:
            app.cfg.save()
            click.echo("  ✓ Config saved to ~/.defenseclaw/config.yaml")
        except OSError as exc:
            click.echo(f"  ✗ Failed to save config: {exc}")
            warnings.append("Config not saved — settings will be lost on next run")

    # --- Write guardrail_runtime.json ---
    _write_guardrail_runtime(app.cfg.data_dir, gc)

    return True, warnings


def _interactive_guardrail_setup(
    app: AppContext, gc, *, agent_name: str | None = None,
) -> None:

    click.echo()
    click.echo("  LLM Guardrail Setup")
    click.echo("  ────────────────────")
    click.echo()
    click.echo("  Scans every LLM prompt and response for:")
    click.echo("    • Prompt injection and jailbreak attempts")
    click.echo("    • Secrets, API keys, and credentials")
    click.echo("    • PII leakage (names, emails, SSNs, credit cards)")
    click.echo(
        "    • Data exfiltration: credential-file reads (/etc/passwd, "
        "~/.ssh, ~/.aws), out-of-band channels"
    )
    click.echo()

    # --- Step 0: Connector selection ---
    if agent_name and agent_name in _CONNECTOR_META:
        gc.connector = agent_name
    else:
        gc.connector = _select_connector_interactive(
            gc.connector or "openclaw",
            data_dir=getattr(app.cfg, "data_dir", None),
        )
    click.echo()
    _print_connector_info(gc.connector)
    click.echo()

    # Codex and Claude Code default to observability-only mode: hooks +
    # native OTel telemetry, NO traffic interception. The Go-side
    # connector Setup gates every enforcement code path on the matching
    # ``*_enforcement_enabled`` flag (see ``CodexEnforcementEnabled`` /
    # ``ClaudeCodeEnforcementEnabled`` in internal/config/config.go),
    # and the Python wizard mirrors that here: skip every prompt that
    # only matters when the proxy is in the data path (enforcement
    # mode, scanner engine, LLM judge config, block message). The
    # operator can flip enforcement on later by editing config.yaml
    # directly — re-running ``defenseclaw setup guardrail`` will then
    # run the full prompt set.
    #
    # OpenClaw and ZeptoClaw fall through to the full-prompts path
    # because they were designed around traffic interception from day
    # one and have no observability-only equivalent.
    observability_only = gc.connector in ("codex", "claudecode")
    if observability_only:
        proxy_port = gc.port or 4000
        click.echo("  ┌──────────────────────────────────────────────────────────────┐")
        click.echo("  │  Observability mode (enforcement disabled by default)        │")
        click.echo("  └──────────────────────────────────────────────────────────────┘")
        click.echo()
        click.echo("  Codex / Claude Code talk DIRECTLY to their native upstream;")
        click.echo("  DefenseClaw is NOT in the data path. Telemetry runs end-to-end via:")
        click.echo()
        click.echo("    • Hooks: tool-call events (PreToolUse, PostToolUse,")
        click.echo("      UserPromptSubmit, Stop, PermissionRequest) → /api/v1/<connector>/hook")
        click.echo("    • OTel: native exporter writes structured logs + metrics")
        click.echo("      (raw API bodies, model + token counts) to /v1/logs and /v1/metrics")
        click.echo("    • Notify: agent-turn-complete events (codex only) → /api/v1/codex/notify")
        click.echo()
        click.echo("  No proxy listener binds; no openai_base_url / ANTHROPIC_BASE_URL")
        click.echo("  override is written. Existing enforcement code stays in place behind")
        click.echo("  the guardrail." + ("codex_enforcement_enabled" if gc.connector == "codex" else "claudecode_enforcement_enabled") + " flag — flip to true in")
        click.echo("  ~/.defenseclaw/config.yaml + restart the gateway to re-engage the proxy.")
        click.echo()

        if not click.confirm("  Enable observability for " + gc.connector + "?", default=True):
            gc.enabled = False
            return

        # Sensible "if-you-ever-flip-enforcement-on" defaults so the
        # config.yaml stays loadable. The Go gateway never reads these
        # fields when enforcement is off — they live as forward-looking
        # state for the operator who later wants to switch modes.
        gc.enabled = True
        gc.mode = "observe"
        gc.scanner_mode = "local"
        gc.port = proxy_port
        gc.judge.enabled = False
        gc.detection_strategy = "regex_only"
        gc.detection_strategy_completion = "regex_only"
        if gc.connector == "codex":
            gc.codex_enforcement_enabled = False
        else:
            gc.claudecode_enforcement_enabled = False
        click.echo()
        click.echo("  ✓ Observability mode enabled (no traffic interception)")
        click.echo("  ✓ Hooks + OTel + notify telemetry will be wired automatically at gateway boot")
        click.echo()
        return

    model_name = gc.model_name or gc.model or ""
    if model_name:
        click.echo(f"  Detected LLM:  {model_name}")
    proxy_port = gc.port or 4000
    click.echo(f"  Proxy port:    {proxy_port} (traffic rerouted automatically)")
    click.echo()

    if not click.confirm("  Enable guardrail?", default=True):
        gc.enabled = False
        return

    gc.enabled = True

    click.echo()
    click.echo("  Enforcement mode:")
    click.echo("    [1] observe — log and alert only, never block (recommended to start)")
    click.echo("    [2] action  — block requests that match security policies")
    current_mode = gc.mode or "observe"
    mode_default = "1" if current_mode == "observe" else "2"
    mode_choice = click.prompt(
        "  Select mode", type=click.Choice(["1", "2"]), default=mode_default,
    )
    gc.mode = "observe" if mode_choice == "1" else "action"

    click.echo()
    click.echo("  Scanner engine:")
    click.echo("    [1] local  — built-in pattern matching, no network calls (fastest)")
    click.echo("    [2] remote — Cisco AI Defense cloud API (higher accuracy, requires API key)")
    sm_current = gc.scanner_mode or "local"
    if sm_current == "both":
        sm_current = "local"
    sm_default = "1" if sm_current == "local" else "2"
    sm_choice = click.prompt(
        "  Select engine", type=click.Choice(["1", "2"]), default=sm_default,
    )
    gc.scanner_mode = "local" if sm_choice == "1" else "remote"

    if gc.scanner_mode in ("remote", "both"):
        click.echo()
        click.echo("  Cisco AI Defense Configuration")
        click.echo("  ──────────────────────────────")
        aid = app.cfg.cisco_ai_defense
        aid.endpoint = click.prompt(
            "  API endpoint", default=aid.endpoint,
        )
        cisco_key_env = aid.api_key_env or "CISCO_AI_DEFENSE_API_KEY"
        env_val = os.environ.get(cisco_key_env, "")
        if env_val:
            click.echo(f"  API key env var: {cisco_key_env} ({_mask(env_val)})")
        else:
            click.echo(f"  API key env var: {cisco_key_env} (not set)")
            click.echo(f"    Set it before starting: export {cisco_key_env}=your-key")
        aid.api_key_env = click.prompt(
            "  API key env var name", default=cisco_key_env,
        )
        aid.timeout_ms = click.prompt(
            "  Timeout (ms)", default=aid.timeout_ms, type=int,
        )

    gc.port = proxy_port

    # --- LLM Judge section ---
    click.echo()
    click.echo("  LLM Judge (reduces false positives)")
    click.echo("  ────────────────────────────────────")
    click.echo("  Uses an LLM to verify detections and catch novel attacks.")
    click.echo("  Works with any OpenAI-compatible API (Bifrost, OpenAI, Anthropic, etc.)")
    click.echo()
    click.echo("  Three judge kinds run on every prompt when enabled:")
    click.echo("    • injection — overrides / jailbreaks (kind=injection)")
    click.echo("    • pii       — names, emails, SSNs, secrets (kind=pii)")
    click.echo(
        "    • exfil     — credential-file reads & out-of-band channels "
        "(kind=exfil)"
    )
    click.echo("  Tool calls additionally run the tool_injection judge.")
    click.echo()

    enable_judge = click.confirm("  Enable LLM judge?", default=gc.judge.enabled)
    gc.judge.enabled = enable_judge

    if enable_judge:
        click.echo()
        click.echo("  Detection strategy:")
        click.echo("    [1] regex_only  — regex patterns only, no LLM calls (fastest)")
        click.echo("    [2] regex_judge — regex triages, LLM verifies ambiguous matches (recommended)")
        click.echo("    [3] judge_first — LLM runs primary detection, regex as safety net (most accurate)")
        strategy_map = {"1": "regex_only", "2": "regex_judge", "3": "judge_first"}
        current_strat = gc.detection_strategy or "regex_judge"
        strat_default = {"regex_only": "1", "regex_judge": "2", "judge_first": "3"}.get(current_strat, "2")
        strat_choice = click.prompt(
            "  Select strategy", type=click.Choice(["1", "2", "3"]), default=strat_default,
        )
        gc.detection_strategy = strategy_map[strat_choice]

        click.echo()

        # V5 UX: when the operator has already configured the unified
        # top-level ``llm:`` block (common after ``make all`` runs
        # ``scripts/setup-llm.sh``), default the judge to INHERIT those
        # values — empty judge fields fall through ``Config.resolve_llm``
        # to the top-level block and pick up ``DEFENSECLAW_LLM_KEY``
        # automatically. This avoids the legacy UX where the judge
        # prompted for a separate ``JUDGE_API_KEY`` that diverged from
        # the unified key.
        top_llm = app.cfg.llm
        has_unified_llm = bool(top_llm.model) and bool(top_llm.resolved_api_key())
        judge_already_customised = bool(
            gc.judge.model or gc.judge.api_base or gc.judge.api_key_env,
        )

        inherit_unified = False
        if has_unified_llm and not judge_already_customised:
            click.echo("  Judge can reuse your unified LLM settings:")
            click.echo(f"    model:       {top_llm.model}")
            if top_llm.base_url:
                click.echo(f"    base URL:    {top_llm.base_url}")
            click.echo(
                "    api key:     "
                f"{top_llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV} (inherited)"
            )
            click.echo()
            inherit_unified = click.confirm(
                "  Inherit the unified LLM for the judge?", default=True,
            )

        if inherit_unified:
            # Empty strings on the judge block mean "fall back to the
            # top-level ``llm:`` block" — see resolve_llm("guardrail.judge").
            gc.judge.model = ""
            gc.judge.api_base = ""
            gc.judge.api_key_env = ""
            click.echo(
                f"  ✓ Judge will use {top_llm.model} via "
                f"{top_llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV}."
            )
        else:
            # Pre-fill each prompt from the top-level ``llm:`` block so
            # operators who DO want to override only have to retype the
            # fields they're actually changing.
            default_api_base = gc.judge.api_base or top_llm.base_url or ""
            gc.judge.api_base = click.prompt(
                "  LLM API base URL (e.g. http://localhost:8080/v1 for Bifrost)",
                default=default_api_base,
                show_default=bool(default_api_base),
            )
            default_model = gc.judge.model or top_llm.model or ""
            gc.judge.model = click.prompt(
                "  Model (e.g. anthropic/claude-sonnet-4-20250514)",
                default=default_model,
                show_default=bool(default_model),
            )

            # Default to the unified ``DEFENSECLAW_LLM_KEY`` — NOT the
            # legacy ``JUDGE_API_KEY``. The operator can still override
            # it to a per-component env var; when they do, we'll prompt
            # for the secret value below. When they accept the default
            # unified key, the secret is already persisted to ``.env``
            # via ``scripts/setup-llm.sh`` or ``defenseclaw setup llm``,
            # so we skip the redundant secret prompt.
            default_key_env = (
                gc.judge.api_key_env
                or top_llm.api_key_env
                or DEFENSECLAW_LLM_KEY_ENV
            )
            gc.judge.api_key_env = click.prompt(
                "  API key env var name", default=default_key_env,
            )
            env_val = os.environ.get(gc.judge.api_key_env, "")
            if env_val:
                click.echo(f"    Current value: {_mask(env_val)} (set)")
            else:
                click.echo(f"    {gc.judge.api_key_env} is not set in environment")

            # Only prompt for a secret value when the operator picked a
            # custom env var that ISN'T already satisfied by the unified
            # key. ``DEFENSECLAW_LLM_KEY`` is expected to be wired up by
            # ``scripts/setup-llm.sh`` before this code runs; re-asking
            # for it here confuses operators who just set it.
            unified_env = top_llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV
            if gc.judge.api_key_env != unified_env or not env_val:
                _prompt_and_save_secret(gc.judge.api_key_env, "", app.cfg.data_dir)

        click.echo()
        if click.confirm("  Configure fallback models?", default=bool(gc.judge.fallbacks)):
            fallbacks: list[str] = []
            for i in range(1, 6):
                fb = click.prompt(f"    Fallback model {i} (blank to finish)", default="", show_default=False)
                if not fb:
                    break
                fallbacks.append(fb)
            gc.judge.fallbacks = fallbacks
        else:
            gc.judge.fallbacks = []

        gc.judge.injection = True
        gc.judge.pii = True
        gc.judge.pii_prompt = True
        gc.judge.pii_completion = True
        # Data-exfiltration judge runs alongside injection + PII on
        # every prompt. It exists because polite-tone /etc/passwd-shaped
        # prompts slip through the injection judge ("not adversarial
        # phrasing") and the PII judge ("no literal PII emitted yet").
        # Audit rows for this judge appear with kind=exfil and follow
        # the same retention / redaction rules as the other kinds.
        gc.judge.exfil = True

        # Completion-side strategy defaults to regex_only (no judge latency)
        if not getattr(gc, "detection_strategy_completion", None):
            gc.detection_strategy_completion = "regex_only"

        # Only prompt to "share" the judge key across scanners when the
        # operator chose a CUSTOM env var AND the unified block isn't
        # already pointing somewhere. If they inherited the unified
        # ``DEFENSECLAW_LLM_KEY`` there's nothing to share (every
        # scanner already resolves through it via
        # ``Config.resolve_llm``); if ``llm.api_key_env`` is already
        # set to a different value, silently overwriting it would
        # disrupt the MCP/skill/plugin scanners — so we refuse to
        # clobber and leave the operator to run ``defenseclaw setup
        # llm`` explicitly. We write to ``llm.api_key_env`` (v5)
        # rather than the deprecated ``default_llm_api_key_env`` (v4)
        # so ``defenseclaw setup migrate-llm`` doesn't silently undo
        # the change on the next run.
        custom_judge_key = (
            gc.judge.api_key_env
            and gc.judge.api_key_env != DEFENSECLAW_LLM_KEY_ENV
            and gc.judge.api_key_env != (top_llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV)
        )
        if custom_judge_key and not app.cfg.llm.api_key_env:
            if click.confirm(
                f"  Use {gc.judge.api_key_env} as the shared LLM key for all scanners too?",
                default=True,
            ):
                app.cfg.llm.api_key_env = gc.judge.api_key_env
    else:
        gc.detection_strategy = "regex_only"
        gc.detection_strategy_completion = "regex_only"

    if click.confirm("  Configure advanced options?", default=False):
        gc.port = click.prompt("  Guardrail proxy port", default=gc.port, type=int)
        if gc.mode == "action":
            click.echo()
            if gc.block_message:
                preview = gc.block_message[:80] + ("..." if len(gc.block_message) > 80 else "")
                click.echo(f"  Current block message: \"{preview}\"")
            else:
                click.echo("  Default block message: \"I'm unable to process this request. DefenseClaw detected...\"")
            if click.confirm("  Use a custom block message?", default=bool(gc.block_message)):
                gc.block_message = click.prompt("  Block message", default=gc.block_message or "")
            else:
                gc.block_message = ""



def _disable_guardrail(app: AppContext, gc, *, restart: bool = False) -> None:
    connector_name = gc.connector or "openclaw"
    meta = _CONNECTOR_META.get(connector_name, {})

    click.echo()
    click.echo("  Disabling LLM guardrail...")
    if meta:
        click.echo(f"  Connector: {meta.get('label', connector_name)} ({connector_name})")

    gc.enabled = False

    try:
        app.cfg.save()
        click.echo("  ✓ Config saved (guardrail.enabled = false)")
    except OSError as exc:
        click.echo(f"  ✗ Failed to save config: {exc}")
        click.echo("    Guardrail may re-enable on next run")

    # Restart the gateway so it runs conn.Teardown() — the sidecar checks
    # guardrail.enabled on boot and calls Teardown instead of Setup when
    # disabled. This restores agent configs (hooks, api_base, plugins,
    # shims) to their pre-DefenseClaw state.
    click.echo()
    click.echo("  Restarting gateway to run connector teardown...")
    _restart_services(
        app.cfg.data_dir,
        app.cfg.gateway.host,
        app.cfg.gateway.port,
        connector=connector_name,
    )
    click.echo(f"  ✓ {meta.get('label', connector_name)} connector teardown complete")
    click.echo()

    if app.logger:
        app.logger.log_action("setup-guardrail", "config", f"disabled connector={connector_name}")


def _write_guardrail_runtime(data_dir: str, gc) -> None:
    """Write guardrail_runtime.json so the Python guardrail module can hot-reload settings."""
    import json

    runtime_file = os.path.join(data_dir, "guardrail_runtime.json")
    payload = {
        "mode": gc.mode,
        "scanner_mode": gc.scanner_mode,
        "block_message": gc.block_message,
    }
    try:
        os.makedirs(data_dir, exist_ok=True)
        with open(runtime_file, "w") as f:
            json.dump(payload, f)
        click.echo(f"  ✓ Guardrail runtime config written to {runtime_file}")
    except OSError as exc:
        click.echo(f"  ⚠ Failed to write runtime config: {exc}")


def _print_guardrail_summary(gc, openclaw_config_file: str, *, restart: bool = False) -> None:
    click.echo()
    click.echo("  ✓ Config saved to ~/.defenseclaw/config.yaml")
    click.echo("  ✓ Guardrail proxy configured (built into Go binary)")
    click.echo(f"  ✓ OpenClaw config patched: {openclaw_config_file}")
    if gc.original_model:
        click.echo(f"  ✓ Original model saved for revert: {gc.original_model}")
    click.echo()

    rows = [
        ("mode", gc.mode),
        ("scanner_mode", gc.scanner_mode),
        ("port", str(gc.port)),
        ("model", gc.model),
        ("model_name", gc.model_name),
        ("api_key_env", gc.api_key_env),
    ]
    for key, val in rows:
        click.echo(f"    guardrail.{key + ':':<16s} {val}")
    click.echo()


def _find_plugin_source() -> str | None:
    """Locate the built OpenClaw plugin.

    Checks ~/.defenseclaw/extensions/defenseclaw first (production install),
    then the repo source tree (dev).
    """
    d = bundled_extensions_dir()
    resolved = str(d.resolve())
    if os.path.isdir(resolved) and os.path.isfile(os.path.join(resolved, "package.json")):
        return resolved
    return None


def _uninstall_plugin_from_sandbox(sandbox_home: str) -> None:
    """Remove the DefenseClaw plugin from the sandbox user's OpenClaw extensions."""
    import shutil

    target_dir = os.path.join(sandbox_home, ".openclaw", "extensions", "defenseclaw")
    if os.path.isdir(target_dir):
        try:
            shutil.rmtree(target_dir)
            click.echo(f"  ✓ Sandbox plugin removed from {target_dir}")
        except OSError as exc:
            click.echo(f"  ✗ Could not remove sandbox plugin: {exc}")
    else:
        click.echo("  ✓ Sandbox plugin not installed (nothing to remove)")


# ---------------------------------------------------------------------------
# Service restart helpers
# ---------------------------------------------------------------------------

def _is_pid_alive(pid_file: str) -> bool:
    """Check if the process in the given PID file is alive (signal 0)."""
    try:
        with open(pid_file) as f:
            raw = f.read().strip()
        try:
            pid = int(raw)
        except ValueError:
            import json as _json
            pid = _json.loads(raw)["pid"]
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ValueError, KeyError, ProcessLookupError, PermissionError, OSError):
        return False


def _restart_services(
    data_dir: str,
    oc_host: str = "127.0.0.1",
    oc_port: int = 18789,
    connector: str = "openclaw",
) -> None:
    """Restart defenseclaw-gateway and, when OpenClaw is the selected
    connector, restart the OpenClaw gateway too so it picks up the
    freshly-registered defenseclaw plugin. Other connectors manage
    their own processes; defenseclaw-gateway is the only process we
    always need to bounce."""
    click.echo("  Restarting services...")
    click.echo("  ──────────────────────")

    _restart_defense_gateway(data_dir)

    if connector == "openclaw":
        _restart_openclaw_gateway()
        _check_openclaw_gateway(oc_host, oc_port)
    else:
        click.echo(f"  {connector} connector: traffic will route through defenseclaw-gateway proxy.")

    click.echo()


def _restart_openclaw_gateway() -> None:
    """Ask OpenClaw to restart its gateway service so the updated
    plugin registration (written by OpenClawConnector.Setup) takes
    effect. No-op when the `openclaw` CLI isn't on PATH — operators
    using a non-standard OpenClaw install can restart manually."""
    click.echo("  openclaw-gateway: restarting...", nl=False)
    try:
        result = subprocess.run(
            ["openclaw", "gateway", "restart"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            click.echo(" ✓")
        else:
            click.echo(" ✗")
            err = (result.stderr or result.stdout or "").strip()
            if err:
                for line in err.splitlines()[:3]:
                    click.echo(f"    {line}")
    except FileNotFoundError:
        click.echo(" ✗ (openclaw CLI not found)")
        click.echo("    Install OpenClaw or restart its gateway manually.")
    except subprocess.TimeoutExpired:
        click.echo(" ✗ (timed out)")


def _restart_defense_gateway(data_dir: str, *, start_if_stopped: bool = True) -> None:
    # Mark the current Click context as "restart handled" so the
    # `setup` group's auto-restart result callback doesn't bounce the
    # gateway a second time on its way out. Safe to call outside Click
    # (returns None).
    try:
        ctx = click.get_current_context(silent=True)
    except RuntimeError:
        ctx = None
    if ctx is not None:
        ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True

    pid_file = os.path.join(data_dir, "gateway.pid")
    was_running = _is_pid_alive(pid_file)
    if not was_running and not start_if_stopped:
        click.echo("  defenseclaw-gateway: not running — skipping restart.")
        click.echo("    Start it with: defenseclaw-gateway start")
        return

    action = "restarting" if was_running else "starting"
    click.echo(f"  defenseclaw-gateway: {action}...", nl=False)

    cmd = ["defenseclaw-gateway", "restart"] if was_running else ["defenseclaw-gateway", "start"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            click.echo(" ✓")
        else:
            click.echo(" ✗")
            err = (result.stderr or result.stdout or "").strip()
            if err:
                for line in err.splitlines()[:3]:
                    click.echo(f"    {line}")
    except FileNotFoundError:
        click.echo(" ✗ (binary not found)")
        click.echo("    Build with: make gateway")
    except subprocess.TimeoutExpired:
        click.echo(" ✗ (timed out)")


@setup.result_callback()
@click.pass_context
def _auto_restart_sidecar_after_setup(ctx: click.Context, *_args, **_kwargs) -> None:
    """Auto-restart the defenseclaw-gateway after any ``setup`` subcommand
    that mutates config.yaml.

    Motivation: the running gateway reads ``config.yaml`` at startup
    only. Before this hook, operators could run e.g.
    ``defenseclaw setup splunk`` and still see ``telemetry — disabled in
    config`` from ``defenseclaw doctor`` because the sidecar was
    reporting its stale in-memory view. We now trigger a restart
    automatically whenever a setup subcommand actually writes to
    config.yaml (detected via mtime delta captured in the group
    callback above).

    Skip conditions:
      * ``app.cfg`` isn't loaded (e.g. ``setup --help``, or a recovery
        invocation that bypassed the loader) — nothing to do.
      * config.yaml mtime unchanged — the subcommand was read-only
        (``setup llm --show``, etc.).
      * Gateway PID file shows the process is not running — we don't
        auto-start a sidecar an operator deliberately stopped. A hint
        is printed so they can start it manually if desired.
    """
    app = ctx.find_object(AppContext)
    if app is None or app.cfg is None:
        return

    # Subcommand already handled the restart itself (e.g. `setup
    # guardrail --restart`) — don't bounce the gateway a second time.
    if ctx.meta.get(_SETUP_RESTART_HANDLED_KEY):
        return

    cfg_path = _config_yaml_path_from_ctx(ctx)
    before = ctx.meta.get(_SETUP_CFG_MTIME_KEY)
    after = _safe_mtime(cfg_path)
    if cfg_path is None or after is None or before == after:
        return

    data_dir = app.cfg.data_dir
    pid_file = os.path.join(data_dir, "gateway.pid")
    if not _is_pid_alive(pid_file):
        click.echo("")
        click.echo("  Config updated. Gateway is not running — "
                   "changes will take effect on next start.")
        click.echo("    Start it with: defenseclaw-gateway start")
        return

    click.echo("")
    click.echo("  Auto-restarting defenseclaw-gateway to apply config changes…")
    _restart_defense_gateway(data_dir, start_if_stopped=False)


def _openclaw_gateway_healthy(host: str, port: int, timeout: float = 5.0) -> bool:
    """Probe the OpenClaw gateway HTTP health endpoint."""
    import urllib.error
    import urllib.request

    url = f"http://{host}:{port}/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _check_openclaw_gateway(host: str = "127.0.0.1", port: int = 18789) -> None:
    """Verify the OpenClaw gateway remains healthy after a config change.

    OpenClaw watches openclaw.json and auto-restarts on certain changes
    (e.g. plugins.allow).  A full restart cycle takes ~30s, so a quick
    health check can give a false positive — the gateway answers, then
    goes down for the restart.  We therefore:

      1. Wait up to 30s for the gateway to become healthy.
      2. Keep monitoring for another 30s to make sure it *stays* healthy
         through any config-triggered restart.
      3. If it goes unhealthy during that window, wait up to 60s for
         recovery before giving up.
    """
    import time

    initial_wait = 30
    stable_window = 30
    recovery_timeout = 60
    poll_interval = 3

    click.echo("  agent gateway: monitoring...", nl=False)

    start = time.monotonic()

    # Phase 1 — wait for initial healthy response
    healthy = False
    while time.monotonic() - start < initial_wait:
        if _openclaw_gateway_healthy(host, port):
            healthy = True
            break
        time.sleep(poll_interval)

    if not healthy:
        click.echo(" not running")
        click.echo("    Gateway did not respond within 30s.")
        click.echo("    Start manually: defenseclaw-gateway start")
        return

    # Phase 2 — confirm stability for stable_window seconds
    click.echo(" up", nl=False)
    stable_start = time.monotonic()
    went_unhealthy = False

    while time.monotonic() - stable_start < stable_window:
        time.sleep(poll_interval)
        if not _openclaw_gateway_healthy(host, port):
            went_unhealthy = True
            click.echo(" → restarting...", nl=False)
            break

    if not went_unhealthy:
        elapsed = int(time.monotonic() - start)
        click.echo(f" ✓ (healthy, stable for {elapsed}s)")
        return

    # Phase 3 — gateway went unhealthy (config-triggered restart);
    #           wait up to recovery_timeout for it to come back
    recovery_start = time.monotonic()
    recovered = False
    while time.monotonic() - recovery_start < recovery_timeout:
        if _openclaw_gateway_healthy(host, port):
            recovered = True
            break
        time.sleep(poll_interval)

    if recovered:
        elapsed = int(time.monotonic() - start)
        click.echo(f" ✓ (recovered after restart, {elapsed}s)")
    else:
        elapsed = int(time.monotonic() - start)
        click.echo(f" ✗ (unhealthy after {elapsed}s)")
        click.echo("    Gateway did not recover after config-triggered restart.")
        click.echo("    Check: defenseclaw-gateway status")
        click.echo("    Logs: ~/.defenseclaw/logs/gateway.err.log")


def _looks_like_secret(value: str) -> bool:
    """Detect if a value looks like an actual secret rather than an env var name."""
    if not value:
        return False
    prefixes = ("sk-", "sk-ant-", "sk-proj-", "ghp_", "gho_", "xoxb-", "xoxp-")
    if any(value.startswith(p) for p in prefixes):
        return True
    if len(value) > 30 and not value.isupper():
        return True
    return False


def _prompt_env_var_name(default: str) -> str:
    """Prompt for an env var name, rejecting values that look like actual secrets."""
    while True:
        val = click.prompt("  Env var name (e.g. ANTHROPIC_API_KEY)", default=default)
        if _looks_like_secret(val):
            click.echo("  That looks like an actual API key, not an env var name.")
            click.echo("  Enter the NAME of the environment variable (e.g. ANTHROPIC_API_KEY).")
            continue
        return val


def _print_gateway_summary(gw) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    resolved = gw.resolved_token()
    rows = [
        ("host", gw.host),
        ("port", str(gw.port)),
        ("api_port", str(gw.api_port)),
        ("token", f"via {gw.token_env} (in .env)" if resolved else "(none — local mode)"),
    ]

    for key, val in rows:
        click.echo(f"    gateway.{key + ':':<12s} {val}")
    click.echo()

    if resolved:
        click.echo("  Start the sidecar with:")
        click.echo("    defenseclaw-gateway")
    else:
        click.echo("  Start the sidecar with:")
        click.echo("    defenseclaw-gateway")
        click.echo("  (local mode — ensure OpenClaw is running on this machine)")
    click.echo()


# ---------------------------------------------------------------------------
# setup splunk
# ---------------------------------------------------------------------------

_SPLUNK_O11Y_INGEST_TEMPLATE = "ingest.{realm}.observability.splunkcloud.com"
_SPLUNK_GENERAL_TERMS_URL = "https://www.splunk.com/en_us/legal/splunk-general-terms.html"

_SPLUNK_LOCAL_HEC_DEFAULTS = {
    "hec_endpoint": "http://127.0.0.1:8088/services/collector/event",
    "index": "defenseclaw_local",
    "source": "defenseclaw",
    "sourcetype": "defenseclaw:json",
}


@setup.command("splunk")
@click.option("--o11y", "enable_o11y", is_flag=True, default=False,
              help="Enable Splunk Observability Cloud (OTLP traces + metrics)")
@click.option("--logs", "enable_logs", is_flag=True, default=False,
              help="Enable local Splunk via Docker (HEC logs + dashboards, Free mode)")
@click.option("--realm", default=None, help="Splunk O11y realm (e.g. us1, us0, eu0)")
@click.option("--access-token", default=None, help="Splunk O11y access token")
@click.option("--app-name", default=None, help="OTEL service name (default: defenseclaw)")
@click.option("--index", "logs_index", default=None, help="HEC index for --logs (default: defenseclaw_local)")
@click.option("--source", "logs_source", default=None, help="HEC source for --logs (default: defenseclaw)")
@click.option("--sourcetype", "logs_sourcetype", default=None,
              help="HEC sourcetype for --logs (default: defenseclaw:json)")
@click.option("--traces/--no-traces", "enable_traces", default=None,
              help="Enable/disable trace export (O11y)")
@click.option("--metrics/--no-metrics", "enable_metrics", default=None,
              help="Enable/disable metrics export (O11y)")
@click.option("--logs-export/--no-logs-export", "enable_logs_export",
              default=None, help="Enable/disable logs export (O11y)")
@click.option("--disable", is_flag=True, help="Disable Splunk integration(s)")
@click.option("--accept-splunk-license", is_flag=True,
              help="Acknowledge the Splunk General Terms for local Splunk enablement")
@click.option("--show-credentials", is_flag=True, help="Show Splunk Web login credentials")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_splunk(
    app: AppContext,
    enable_o11y: bool,
    enable_logs: bool,
    realm: str | None,
    access_token: str | None,
    app_name: str | None,
    logs_index: str | None,
    logs_source: str | None,
    logs_sourcetype: str | None,
    enable_traces: bool | None,
    enable_metrics: bool | None,
    enable_logs_export: bool | None,
    disable: bool,
    accept_splunk_license: bool,
    show_credentials: bool,
    non_interactive: bool,
) -> None:
    """Configure Splunk integration for DefenseClaw.

    Two independent pipelines are available:

    \b
      --o11y   Splunk Observability Cloud (traces + metrics via OTLP HTTP)
               No local infrastructure needed. Requires a Splunk access token.
    \b
      --logs   Local Splunk (Docker, HEC logs + dashboards)
               Starts the bundled profile in Splunk Free mode from day 1.
               Requires Docker.

    Both can run simultaneously. Without flags, runs an interactive wizard.
    """
    if show_credentials:
        _show_splunk_credentials(app.cfg.data_dir)
        return

    if disable:
        _disable_splunk(app, enable_o11y, enable_logs, non_interactive)
        return

    if not enable_o11y and not enable_logs and not non_interactive:
        _interactive_splunk_setup(app, realm, access_token, app_name)
        return

    if not enable_o11y and not enable_logs and non_interactive:
        click.echo("  error: specify --o11y, --logs, or both with --non-interactive", err=True)
        raise SystemExit(1)

    did_o11y = False
    did_logs = False

    if enable_o11y:
        _setup_o11y(app, realm or "us1", access_token, app_name or "defenseclaw",
                    non_interactive=non_interactive,
                    traces=enable_traces, metrics=enable_metrics,
                    logs_export=enable_logs_export)
        did_o11y = True

    if enable_logs:
        did_logs = _setup_logs(
            app,
            non_interactive=non_interactive,
            accept_splunk_license=accept_splunk_license,
            index=logs_index,
            source=logs_source,
            sourcetype=logs_sourcetype,
        )

    if not did_o11y and not did_logs:
        return

    # Note: no app.cfg.save() here — the observability writer invoked
    # from _apply_o11y_config / _apply_logs_config already persists to
    # config.yaml atomically while preserving unmodeled sections
    # (audit_sinks, otel.resource.attributes). Calling cfg.save() again
    # would serialize the dataclass only and drop those sections.
    click.echo("  Config saved to ~/.defenseclaw/config.yaml")
    click.echo()
    _print_splunk_status(app)
    _print_splunk_next_steps(did_o11y, did_logs)

    if app.logger:
        parts: list[str] = []
        if did_o11y:
            parts.append("o11y=enabled")
        if did_logs:
            parts.append("logs=enabled")
        app.logger.log_action("setup-splunk", "config", " ".join(parts))


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------

def _interactive_splunk_setup(
    app: AppContext,
    realm: str | None,
    access_token: str | None,
    app_name: str | None,
) -> None:
    click.echo()
    click.echo("  Splunk Integration Setup")
    click.echo("  ────────────────────────")
    click.echo()
    click.echo("  DefenseClaw supports two Splunk pipelines. You can enable one or both.")
    click.echo()
    click.echo("  1. Splunk Observability Cloud (O11y)")
    click.echo("     Sends traces + metrics + logs via OTLP HTTP directly to Splunk cloud.")
    click.echo("     No local infrastructure needed. Requires a Splunk O11y access token.")
    click.echo()
    click.echo("  2. Local Splunk (Logs)")
    click.echo("     Spins up a local Splunk container via Docker in Free mode from day 1.")
    click.echo("     Audit events are sent via HEC. Includes pre-built dashboards for DefenseClaw.")
    click.echo("     Requires Docker.")
    click.echo()

    did_o11y = False
    did_logs = False

    if click.confirm("  Enable Splunk Observability Cloud (traces + metrics)?", default=False):
        _interactive_o11y(app, realm, access_token, app_name)
        did_o11y = True
        click.echo()

    if click.confirm("  Enable local Splunk (Docker, HEC logs, Free mode)?", default=False):
        did_logs = _interactive_logs(app)

    if not did_o11y and not did_logs:
        click.echo()
        click.echo("  No Splunk pipelines enabled. Run again to configure.")
        return

    # observability.apply_preset() already persisted to config.yaml;
    # calling cfg.save() here would drop audit_sinks (see note in
    # setup_splunk()).
    click.echo()
    click.echo("  Config saved to ~/.defenseclaw/config.yaml")
    click.echo()
    _print_splunk_status(app)
    _print_splunk_next_steps(did_o11y, did_logs)

    if app.logger:
        parts = []
        if did_o11y:
            parts.append("o11y=enabled")
        if did_logs:
            parts.append("logs=enabled")
        app.logger.log_action("setup-splunk", "config", " ".join(parts))


def _interactive_o11y(
    app: AppContext,
    realm: str | None,
    access_token: str | None,
    app_name: str | None,
) -> None:
    click.echo()
    click.echo("  Splunk Observability Cloud")
    click.echo("  ──────────────────────────")
    click.echo()

    realm = click.prompt("  Realm (e.g. us1, us0, eu0)", default=realm or "us1")
    access_token = _prompt_splunk_token(access_token)
    app_name = click.prompt("  Service name", default=app_name or "defenseclaw")

    click.echo()
    click.echo("  Signals to export:")
    enable_traces = click.confirm("    Enable traces?", default=True)
    enable_metrics = click.confirm("    Enable metrics?", default=True)
    enable_logs = click.confirm("    Enable logs (to Log Observer)?", default=False)

    _apply_o11y_config(
        app, realm, access_token, app_name,
        enable_traces=enable_traces,
        enable_metrics=enable_metrics,
        enable_logs=enable_logs,
    )


def _prompt_splunk_token(current: str | None) -> str:
    env_val = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
    if current:
        hint = _mask(current)
    elif env_val:
        hint = f"from env: {_mask(env_val)}"
    else:
        hint = "(not set)"

    val = click.prompt(f"  Access token [{hint}]", default="", show_default=False, hide_input=True)
    if val:
        return val
    return current or env_val


def _interactive_logs(app: AppContext) -> bool:
    click.echo()
    click.echo("  Local Splunk")
    click.echo("  ────────────")
    click.echo()

    if not _accept_splunk_license_interactive():
        click.echo("  Local Splunk enablement cancelled.")
        return False

    ok = _preflight_docker()
    if not ok:
        return False

    index = click.prompt("  Index name", default="defenseclaw_local")
    source = click.prompt("  Source", default="defenseclaw")
    sourcetype = click.prompt("  Sourcetype", default="defenseclaw:json")

    _apply_logs_config(app, index=index, source=source, sourcetype=sourcetype,
                       bootstrap_bridge=True)
    return True


# ---------------------------------------------------------------------------
# Non-interactive setup helpers
# ---------------------------------------------------------------------------

def _setup_o11y(
    app: AppContext,
    realm: str,
    access_token: str | None,
    app_name: str,
    *,
    non_interactive: bool,
    traces: bool | None = None,
    metrics: bool | None = None,
    logs_export: bool | None = None,
) -> None:
    token = access_token or os.environ.get("SPLUNK_ACCESS_TOKEN", "")
    if not token and non_interactive:
        click.echo("  error: --access-token required (or set SPLUNK_ACCESS_TOKEN env var)", err=True)
        raise SystemExit(1)
    if not token:
        token = _prompt_splunk_token(None)
    if not token:
        click.echo("  error: access token is required for Splunk O11y", err=True)
        raise SystemExit(1)

    _apply_o11y_config(
        app, realm, token, app_name,
        enable_traces=traces if traces is not None else True,
        enable_metrics=metrics if metrics is not None else True,
        enable_logs=logs_export if logs_export is not None else False,
    )
    click.echo(f"  Splunk O11y configured (realm={realm})")


def _setup_logs(
    app: AppContext,
    *,
    non_interactive: bool,
    accept_splunk_license: bool,
    index: str | None = None,
    source: str | None = None,
    sourcetype: str | None = None,
) -> bool:
    if not _ensure_splunk_license_acceptance(
        accept_splunk_license=accept_splunk_license,
        non_interactive=non_interactive,
    ):
        return False

    ok = _preflight_docker()
    if not ok:
        if non_interactive:
            click.echo("  error: Docker is required for --logs", err=True)
            raise SystemExit(1)
        return False

    _apply_logs_config(
        app,
        index=index or "defenseclaw_local",
        source=source or "defenseclaw",
        sourcetype=sourcetype or "defenseclaw:json",
        bootstrap_bridge=True,
    )
    click.echo("  Local Splunk configured (Free mode from day 1)")
    return True


def _print_splunk_license_notice() -> None:
    click.echo("  Local Splunk enablement requires acceptance of the Splunk General Terms:")
    click.echo(f"    {_SPLUNK_GENERAL_TERMS_URL}")
    click.echo("  If you do not agree, do not download, start, access, or use the software.")
    click.echo()


def _accept_splunk_license_interactive() -> bool:
    _print_splunk_license_notice()
    return click.confirm(
        "  Do you accept the Splunk General Terms for this local Splunk workflow?",
        default=False,
    )


def _ensure_splunk_license_acceptance(
    *,
    accept_splunk_license: bool,
    non_interactive: bool,
) -> bool:
    if accept_splunk_license:
        return True

    if non_interactive:
        click.echo("  error: --accept-splunk-license is required with --logs --non-interactive", err=True)
        click.echo(f"         Review the Splunk General Terms: {_SPLUNK_GENERAL_TERMS_URL}", err=True)
        raise SystemExit(1)

    if not _accept_splunk_license_interactive():
        click.echo("  Local Splunk enablement cancelled.")
        return False

    return True


# ---------------------------------------------------------------------------
# Config writers
# ---------------------------------------------------------------------------

def _apply_o11y_config(
    app: AppContext,
    realm: str,
    access_token: str,
    app_name: str,
    *,
    enable_traces: bool,
    enable_metrics: bool,
    enable_logs: bool,
) -> None:
    """Thin alias over ``observability.apply_preset("splunk-o11y", ...)``.

    Kept for flag-level back-compat with ``setup splunk --o11y``. The
    single writer lives in ``defenseclaw.observability.writer``.
    """
    from defenseclaw.observability import apply_preset

    signals = tuple(
        s for s, on in (
            ("traces", enable_traces),
            ("metrics", enable_metrics),
            ("logs", enable_logs),
        ) if on
    )
    apply_preset(
        "splunk-o11y",
        {"realm": realm},
        app.cfg.data_dir,
        # Use app_name for service.name in otel.resource.attributes so
        # operators see the expected name in Splunk O11y UI. The writer
        # also stamps preset_id / preset_name alongside.
        name=app_name,
        enabled=True,
        signals=signals or ("traces",),
        secret_value=access_token or None,
    )
    # OTEL_SERVICE_NAME stays a sibling env var: the OTel SDK env takes
    # precedence over resource.attributes.service.name, so this keeps the
    # effective service name even if the user later edits the YAML.
    _save_secret_to_dotenv("OTEL_SERVICE_NAME", app_name, app.cfg.data_dir)
    # Reload config so cfg.otel reflects the YAML we just wrote. Pin the
    # reload to app.cfg.data_dir (not the default ~/.defenseclaw) so
    # unit tests that point at a temp dir see their own writes — the
    # CLI path always matches because production callers set
    # DEFENSECLAW_HOME to the same dir.
    _reload_cfg_from_data_dir(app)


def _apply_logs_config(
    app: AppContext,
    *,
    index: str,
    source: str,
    sourcetype: str,
    bootstrap_bridge: bool,
) -> None:
    """Thin alias over ``observability.apply_preset("splunk-hec", ...)``.

    For local-Splunk the bridge is still launched here because it's a
    *deploy* step (docker-compose up) not a config write. The returned
    contract (HEC URL + token) is then funneled into the observability
    writer so it lands in ``audit_sinks[]`` in the same shape as any
    other HEC destination.
    """
    contract: dict[str, str] | None = None
    if bootstrap_bridge:
        contract = _bootstrap_bridge(app.cfg.data_dir)
        if not contract:
            raise SystemExit(1)

    hec_url = (contract or {}).get("hec_url", _SPLUNK_LOCAL_HEC_DEFAULTS["hec_endpoint"])
    hec_token = (contract or {}).get("hec_token", "")

    # Pull host/port from the contract URL so the preset writer derives a
    # stable name ("splunk-hec-127-0-0-1") and the endpoint matches exactly.
    from urllib.parse import urlparse

    parsed = urlparse(hec_url)
    host = parsed.hostname or "127.0.0.1"
    port = str(parsed.port or 8088)

    from defenseclaw.observability import apply_preset

    apply_preset(
        "splunk-hec",
        {
            "host": host,
            "port": port,
            # Pass the bootstrap URL verbatim so the bridge's chosen
            # scheme (http for local docker-compose free-mode, https
            # otherwise) survives into config.yaml unchanged.
            "endpoint": hec_url,
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "verify_tls": "false",
        },
        app.cfg.data_dir,
        enabled=True,
        secret_value=hec_token or None,
    )
    _reload_cfg_from_data_dir(app)


def _reload_cfg_from_data_dir(app: AppContext) -> None:
    """Reload ``app.cfg`` from ``app.cfg.data_dir``.

    ``config.load()`` only reads from ``DEFENSECLAW_HOME`` (or the
    default ``~/.defenseclaw``). Tests build the ``Config`` directly
    with a temp ``data_dir`` and never set the env var, so a bare
    ``config.load()`` call would read the user's real home and
    overwrite the test's in-memory state. We temporarily pin
    ``DEFENSECLAW_HOME`` to ``app.cfg.data_dir`` across the reload so
    the writer's atomic YAML update is the only input. Production
    callers already set ``DEFENSECLAW_HOME`` to ``data_dir`` so this
    is a no-op there.
    """
    from defenseclaw import config as cfg_mod

    data_dir = app.cfg.data_dir
    previous = os.environ.get("DEFENSECLAW_HOME")
    os.environ["DEFENSECLAW_HOME"] = data_dir
    try:
        app.cfg = cfg_mod.load()
    finally:
        if previous is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = previous


# ---------------------------------------------------------------------------
# Bridge bootstrap
# ---------------------------------------------------------------------------

def _resolve_bridge_bin(data_dir: str) -> str | None:
    """Locate the splunk-claw-bridge script. Checks ~/.defenseclaw/splunk-bridge/
    first (seeded by init), then the bundled source."""
    return splunk_bridge_bin(data_dir)


def _bootstrap_bridge(data_dir: str) -> dict[str, str] | None:
    """Start the local Splunk bridge and return the connection contract."""
    bridge = _resolve_bridge_bin(data_dir)
    if not bridge:
        click.echo("  Splunk bridge runtime not found.")
        click.echo("  Run 'defenseclaw init' to seed it, or install from source.")
        return None

    click.echo("  Starting local Splunk (this takes ~2 minutes)...")
    try:
        result = subprocess.run(
            [bridge, "up", "--output", "json"],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            click.echo(f"  Bridge startup failed (exit {result.returncode})")
            err = (result.stderr or result.stdout or "").strip()
            for line in err.splitlines()[:5]:
                click.echo(f"    {line}")
            return None

        contract = _json.loads(result.stdout.strip())
        click.echo("  Local Splunk is ready")
        web_url = contract.get("splunk_web_url", "http://127.0.0.1:8000")
        click.echo(f"    Web UI: {web_url}")
        if str(contract.get("license_group", "")).lower() == "free":
            click.echo("    License: Free")
        click.echo()
        click.echo("  Splunk Web login:")
        click.echo("    Username:  admin")
        env_file = os.path.join(data_dir, "splunk-bridge", "env", ".env")
        click.echo(f"    Password:  (stored in {env_file})")
        click.echo("    Note: Free mode may still show a login page — use these credentials")
        return contract
    except subprocess.TimeoutExpired:
        click.echo("  Bridge startup timed out after 5 minutes")
        return None
    except (_json.JSONDecodeError, OSError) as exc:
        click.echo(f"  Bridge startup error: {exc}")
        return None


# ---------------------------------------------------------------------------
# Docker pre-flight
# ---------------------------------------------------------------------------

def _preflight_docker() -> bool:
    """Check Docker is installed and running. Return True if OK."""
    click.echo("  Pre-flight checks:")
    docker = shutil.which("docker")
    if not docker:
        click.echo("    Docker installed... NOT FOUND")
        click.echo("    Install Docker: https://docs.docker.com/get-docker/")
        return False
    click.echo("    Docker installed... ok")

    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            click.echo("    Docker daemon running... NOT RUNNING")
            click.echo("    Start Docker and try again.")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        click.echo("    Docker daemon running... NOT RUNNING")
        return False
    click.echo("    Docker daemon running... ok")

    for port, label in [(8000, "Splunk Web"), (8088, "HEC")]:
        if _port_in_use(port):
            click.echo(f"    Port {port} ({label})... IN USE")
            click.echo(f"    Free port {port} or stop the existing Splunk instance.")
            return False
        click.echo(f"    Port {port} ({label})... available")

    return True


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


# ---------------------------------------------------------------------------
# Disable
# ---------------------------------------------------------------------------

def _disable_splunk(
    app: AppContext,
    o11y_only: bool,
    logs_only: bool,
    non_interactive: bool,
) -> None:
    disable_both = not o11y_only and not logs_only

    click.echo()
    click.echo("  Disabling Splunk integration...")

    from defenseclaw.observability import list_destinations, set_destination_enabled

    if disable_both or o11y_only:
        # Flip otel.enabled via the observability writer so unmodeled
        # fields (resource.attributes, etc.) are preserved.
        try:
            set_destination_enabled("otel", False, app.cfg.data_dir)
        except ValueError:
            # No otel: block — nothing to disable.
            pass
        click.echo("    Splunk O11y (OTLP): disabled")

    if disable_both or logs_only:
        # Find every splunk_hec audit sink and flip enabled=false. The
        # legacy Config.splunk dataclass hydrates from the first enabled
        # one, so the gateway will see it as disabled on next load.
        dests = list_destinations(app.cfg.data_dir)
        disabled_any = False
        for d in dests:
            if d.kind == "splunk_hec" and d.enabled:
                try:
                    set_destination_enabled(d.name, False, app.cfg.data_dir)
                    disabled_any = True
                except ValueError:
                    continue
        if disabled_any:
            click.echo("    Splunk Enterprise (HEC): disabled")
        else:
            # Still report a "disabled" status so operators (and CI
            # smoke-tests) can grep for it; the parenthetical clarifies
            # there was nothing to flip.
            click.echo("    Splunk Enterprise (HEC): disabled (no active sinks found)")
        _stop_bridge(app.cfg.data_dir)

    # Refresh in-memory cfg so callers (and tests) see the YAML state
    # the writer just produced.
    _reload_cfg_from_data_dir(app)

    click.echo("  Config saved")
    click.echo()

    if app.logger:
        parts = []
        if disable_both or o11y_only:
            parts.append("o11y=disabled")
        if disable_both or logs_only:
            parts.append("logs=disabled")
        app.logger.log_action("setup-splunk", "config", " ".join(parts))


def _stop_bridge(data_dir: str) -> None:
    bridge = _resolve_bridge_bin(data_dir)
    if not bridge:
        return
    try:
        subprocess.run(
            [bridge, "down"], capture_output=True, text=True, timeout=60,
        )
        click.echo("    Local Splunk container stopped")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        click.echo("    Could not stop local Splunk container (may not be running)")


# ---------------------------------------------------------------------------
# Secret storage
# ---------------------------------------------------------------------------

def _save_secret_to_dotenv(key: str, value: str, data_dir: str) -> None:
    """Write a secret to ~/.defenseclaw/.env (mode 0600).

    Also sets os.environ so that resolver methods (e.g.
    ``resolved_token()``, ``resolved_api_key()``) return the correct
    value within the same process without requiring a restart.
    """
    if not value:
        return
    dotenv_path = os.path.join(data_dir, ".env")
    existing = _load_dotenv(dotenv_path)
    existing[key] = value
    _write_dotenv(dotenv_path, existing)
    os.environ[key] = value


# ---------------------------------------------------------------------------
# Status display
# ---------------------------------------------------------------------------

def _print_splunk_status(app: AppContext) -> None:
    otel = app.cfg.otel
    sc = app.cfg.splunk

    if otel.enabled:
        click.echo("  Splunk Observability Cloud (OTLP):")
        click.echo("    Status:      enabled")
        if otel.traces.endpoint:
            realm = otel.traces.endpoint.replace("ingest.", "").replace(".observability.splunkcloud.com", "")
            click.echo(f"    Realm:       {realm}")
        if otel.traces.enabled:
            click.echo(f"    Traces:      {otel.traces.endpoint}{otel.traces.url_path}")
        else:
            click.echo("    Traces:      disabled")
        if otel.metrics.enabled:
            click.echo(f"    Metrics:     {otel.metrics.endpoint}{otel.metrics.url_path}")
        else:
            click.echo("    Metrics:     disabled")
        if otel.logs.enabled:
            click.echo(f"    Logs:        {otel.logs.endpoint}{otel.logs.url_path}")
        else:
            click.echo("    Logs:        disabled")
        dotenv_path = os.path.join(app.cfg.data_dir, ".env")
        dotenv = _load_dotenv(dotenv_path)
        svc = dotenv.get("OTEL_SERVICE_NAME", os.environ.get("OTEL_SERVICE_NAME", "defenseclaw"))
        click.echo(f"    Service:     {svc}")
        click.echo()

    if sc.enabled:
        click.echo("  Splunk Enterprise (HEC):")
        click.echo("    Status:      enabled")
        click.echo(f"    HEC:         {sc.hec_endpoint}")
        click.echo(f"    Index:       {sc.index}")
        click.echo(f"    Source:      {sc.source}")
        click.echo(f"    Sourcetype:  {sc.sourcetype}")
        click.echo()

    if not otel.enabled and not sc.enabled:
        click.echo("  No Splunk integrations are currently enabled.")
        click.echo()


def _print_splunk_next_steps(did_o11y: bool, did_logs: bool) -> None:
    click.echo("  Next steps:")
    click.echo("    1. Start (or restart) the DefenseClaw sidecar:")
    click.echo("       defenseclaw-gateway restart")
    if did_logs:
        click.echo("    2. Open local Splunk Web at http://127.0.0.1:8000")
        click.echo("       Log in with admin / the password from setup output above.")
        click.echo("       To view credentials later: defenseclaw setup splunk --show-credentials")
        click.echo("    3. Validate data in local Splunk")
    click.echo()
    click.echo("  To disable:")
    if did_o11y and did_logs:
        click.echo("    defenseclaw setup splunk --disable            # both")
        click.echo("    defenseclaw setup splunk --disable --o11y     # O11y only")
        click.echo("    defenseclaw setup splunk --disable --logs     # local only")
    elif did_o11y:
        click.echo("    defenseclaw setup splunk --disable --o11y")
    elif did_logs:
        click.echo("    defenseclaw setup splunk --disable --logs")


def _show_splunk_credentials(data_dir: str) -> None:
    """Display Splunk Web login credentials from the bridge .env file."""
    env_file = os.path.join(data_dir, "splunk-bridge", "env", ".env")
    password = None
    if os.path.isfile(env_file):
        try:
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SPLUNK_PASSWORD="):
                        password = line.split("=", 1)[1]
                        break
        except OSError:
            pass

    if not password:
        click.echo("  Splunk credentials not found.")
        click.echo(f"  Expected env file: {env_file}")
        click.echo("  Run 'defenseclaw setup splunk --logs' to start local Splunk.")
        return

    click.echo()
    click.echo("  Splunk Web Credentials")
    click.echo("  ──────────────────────")
    click.echo("    URL:       http://127.0.0.1:8000")
    click.echo("    Username:  admin")
    click.echo(f"    Password:  {password}")
    click.echo()
