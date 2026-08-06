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

import copy
import hashlib
import http.client
import json as _json
import os
import queue
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import click

# Tasteful TTY-aware color helpers. Imported as a module rather than
# pulled name-by-name so the wizard call sites read like
# ``ux.section("Hook fail mode")`` and the source of the color
# convention is obvious to anybody auditing this file.
from defenseclaw import connector_paths, platform_support, terminal_checkbox, ux
from defenseclaw.audit_actions import (
    ACTION_SETUP_GATEWAY,
    ACTION_SETUP_GUARDRAIL,
    ACTION_SETUP_HOOK_CONNECTOR,
    ACTION_SETUP_MCP_SCANNER,
    ACTION_SETUP_NOTIFICATIONS_SET,
    ACTION_SETUP_NOTIFICATIONS_TOGGLE,
    ACTION_SETUP_SKILL_SCANNER,
    ACTION_SETUP_SPLUNK,
)
from defenseclaw.bundle_refresh import (
    SPLUNK_COMPOSE_PROJECT,
    RefreshResult,
    is_compose_project_running,
    refresh_splunk_bridge,
)
from defenseclaw.commands.redaction_status import print_redaction_status_hint
from defenseclaw.config import (
    CONFIG_PATH_ENV,
    DEFENSECLAW_LLM_KEY_ENV,
    HILTConfig,
    PerConnectorGuardrailConfig,
    config_path_for_data_dir,
    locked_config_yaml,
    locked_file_update,
)
from defenseclaw.config import (
    load as load_config,
)
from defenseclaw.connector_contracts import (
    HOOK_CONTRACTS,
    STATUS_KNOWN,
    STATUS_NOT_GATED,
    STATUS_UNKNOWN,
    STATUS_UNVERSIONED,
    compare_agent_versions,
    connector_lock_contract_invariant,
    normalize_connector,
    resolve_connector_contract,
)
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.file_permissions import (
    MAX_DOTENV_BYTES,
    atomic_write_private_bytes,
    delete_file_durable,
    dotenv_key_is_valid,
    open_regular_file_no_follow,
    windows_acl_write_error,
)
from defenseclaw.inventory import agent_discovery
from defenseclaw.logger import CanonicalObservabilityUnavailableError
from defenseclaw.notification_capabilities import desktop_notification_capability
from defenseclaw.paths import bundled_extensions_dir, bundled_splunk_bridge_dir, splunk_bridge_bin
from defenseclaw.platform_support import (
    LOCAL_SHELL_STACKS_UNSUPPORTED_REASON,
    local_shell_stacks_supported,
)
from defenseclaw.safety import DotenvValueError, reject_symlink, sanitize_dotenv_value

_supports_terminal_redraw = terminal_checkbox.supports_terminal_redraw
_checkbox_key_name = terminal_checkbox.checkbox_key_name
_render_checkbox_menu = terminal_checkbox.render_checkbox_menu

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
# Set only by the bare connector batch after it has staged every selected
# target. The result callback consumes this exact roster to make that batch's
# default restart a synchronous readiness gate, without changing restart
# policy for unrelated setup subcommands that merely share the same config.
_SETUP_BATCH_READINESS_KEY = "defenseclaw._setup_batch_readiness_connectors"
_SETUP_BATCH_ROLLBACK_KEY = "defenseclaw._setup_batch_rollback_snapshot"
_CONNECTOR_RUNTIME_READY_TIMEOUT_SECONDS = 60.0
_CONNECTOR_RUNTIME_READY_ABSOLUTE_CAP_SECONDS = 300.0


@dataclass(frozen=True)
class _ConnectorRuntimeReadiness:
    ready: bool
    connector: str = ""
    invariant: str = ""
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ready


_GATEWAY_API_READY_TIMEOUT_SECONDS = 45.0
_DEFENSE_GATEWAY_LIFECYCLE_TIMEOUT_SECONDS = 60
_DEFENSE_GATEWAY_STATUS_TIMEOUT_SECONDS = 10
_DEFENSE_GATEWAY_STOP_TIMEOUT_SECONDS = 15
_TOKEN_ROTATION_LIFECYCLE_TIMEOUT_SECONDS = 120
_TOKEN_ROTATION_TRANSACTION_FLAG = "--rotation-transaction"
_TOKEN_ROTATION_CLEANUP_FLAG = "--rotation-cleanup"
_TOKEN_ROTATION_CONNECTOR_STATE_FLAG = "--rotation-connector-state"
_GATEWAY_TOKEN_ENV = "DEFENSECLAW_GATEWAY_TOKEN"
_LEGACY_GATEWAY_TOKEN_ENV = "OPENCLAW_GATEWAY_TOKEN"
_DEFENSECLAW_HOME_ENV = "DEFENSECLAW_HOME"
_DEFENSECLAW_DATA_DIR_ENV = "DEFENSECLAW_DATA_DIR"
_TOKEN_ROTATION_CHILD_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    # The native launcher replaces these selectors with installer-recorded
    # connector homes; preserve that binding across every rotation child.
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "COPILOT_HOME",
    "DEFENSECLAW_CURSOR_CONFIG_HOME",
    "WINDSURF_USER_HOME",
    "WINDSURF_HOOK_CONFIG_PATH",
    "OPENCODE_CONFIG_DIR",
    "OMNIGENT_CONFIG",
    "OMNIGENT_CONFIG_HOME",
    "HERMES_HOME",
)
_NATIVE_SPLUNK_CONFIG_SNAPSHOT_ATTR = "_native_splunk_config_snapshot"
_NATIVE_SPLUNK_DOTENV_SNAPSHOT_ATTR = "_native_splunk_dotenv_snapshot"


def _log_setup_action(
    app: AppContext,
    action: str,
    details: str,
    *,
    allow_offline: bool,
) -> None:
    """Audit a setup mutation without breaking explicit offline staging.

    Canonical admission and server responses remain fail-closed.  The only
    exception is a setup command that explicitly selected ``--no-restart``
    while the gateway runtime is absent or unreachable; that mode stages
    configuration for the next gateway start.
    """

    if not app.logger:
        return
    try:
        app.logger.log_action(action, "config", details)
    except CanonicalObservabilityUnavailableError:
        if not allow_offline:
            raise
        click.echo(
            "  ⚠ Change saved, but the gateway runtime is unavailable; the canonical setup audit "
            "event was not recorded. Start defenseclaw-gateway before the next change.",
            err=True,
        )


def _config_yaml_path_from_ctx(ctx: click.Context) -> str | None:
    """Return the active config path when the AppContext is loaded.

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
    return str(config_path_for_data_dir(data_dir))


def _safe_mtime(path: str | None) -> float | None:
    if not path:
        return None
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


@click.group(invoke_without_command=True)
@click.option(
    "--connector",
    "-c",
    "batch_connectors",
    multiple=True,
    help=(
        "(no subcommand) Configure this hook connector as part of a batch. "
        "Repeatable: `-c hermes -c codex`. Combine with --detected/--all."
    ),
)
@click.option(
    "--detected",
    "batch_detected",
    is_flag=True,
    help="(no subcommand) Add every locally-detected hook connector to the batch.",
)
@click.option(
    "--all",
    "batch_all",
    is_flag=True,
    help="(no subcommand) Add every supported hook connector to the batch.",
)
@click.option(
    "--mode",
    "batch_mode",
    type=click.Choice(["observe", "action"], case_sensitive=False),
    default="observe",
    show_default=True,
    help="(no subcommand) Enforcement mode for the batch-selected connectors.",
)
@click.option(
    "--restart/--no-restart",
    "batch_restart",
    default=True,
    show_default=True,
    help="(no subcommand) Restart defenseclaw-gateway after a batch/picker setup.",
)
@click.option(
    "--yes",
    "-y",
    "batch_yes",
    is_flag=True,
    help="(no subcommand) Skip batch mode/judge prompts (use defaults).",
)
@click.pass_context
def setup(
    ctx: click.Context,
    batch_connectors: tuple[str, ...],
    batch_detected: bool,
    batch_all: bool,
    batch_mode: str,
    batch_restart: bool,
    batch_yes: bool,
) -> None:
    """Configure DefenseClaw components.

    Legacy behavior:
    Multi-connector:
      One gateway enforces N agent-native connectors (codex, claudecode,
      hermes, antigravity, omnigent, and others) tracked under guardrail.connectors. Add one
      with 'defenseclaw setup <connector>' (choose Add when prompted),
      remove with 'defenseclaw setup remove <name>'. Scope policy per peer
      with 'defenseclaw guardrail ... --connector X', and inspect the
      roster with 'defenseclaw status' / 'defenseclaw guardrail status'.
      Note: OpenClaw/ZeptoClaw use the proxy path and cannot be multi peers.

    Legacy warning:
    Batch (no subcommand):
      'defenseclaw setup' with no subcommand launches an interactive
      active-connector picker (detected connectors pre-checked), then
      batch mode / optional judge connector pickers. For scripting, select
      connectors with repeatable '-c/--connector', '--detected', and/or
      '--all' (e.g. 'defenseclaw setup -c hermes -c codex --mode action').
    """
    # Snapshot config.yaml's mtime before the subcommand runs. The
    # result callback below (``_auto_restart_sidecar_after_setup``)
    # compares this to the post-invocation mtime and only restarts the
    # sidecar when the file actually changed — so read-only subcommands
    # like ``setup llm --show`` don't bounce a running gateway.
    ctx.meta[_SETUP_CFG_MTIME_KEY] = _safe_mtime(_config_yaml_path_from_ctx(ctx))

    if ctx.invoked_subcommand is not None:
        # A subcommand (setup codex, setup guardrail, …) will run; the
        # group-level batch flags only apply to the bare `setup` form.
        if batch_connectors or batch_detected or batch_all:
            click.echo(
                "  ⚠ --connector/--detected/--all are ignored when a setup "
                "subcommand is given; use them with bare `defenseclaw setup`.",
                err=True,
            )
        return

    # SU-11: bare `defenseclaw setup` is repurposed (Hybrid C) from "print
    # help" to an interactive multi-connector picker (+ scripting flags).
    _dispatch_bare_setup(
        ctx,
        ctx.find_object(AppContext),
        connectors=list(batch_connectors),
        detected=batch_detected,
        all_connectors=batch_all,
        mode=batch_mode,
        restart=batch_restart,
        yes=batch_yes,
    )


# Register canonical v8 destination setup.
# Imported here rather than at module top so the subcommand surface can
# grow without cluttering cmd_setup.py.
from defenseclaw.commands.cmd_setup_observability import observability  # noqa: E402

setup.add_command(observability)

# Register the first-class Galileo cloud/self-hosted setup workflow. It writes
# a named OTLP destination through the shared observability writer, so Galileo
# can coexist with local-observability and every other OTLP backend.
from defenseclaw.commands.cmd_setup_galileo import galileo  # noqa: E402

setup.add_command(galileo)

# Register `defenseclaw setup local-observability` (bundled
# Prom/Loki/Tempo/Grafana stack driver). It preflights Docker, drives the
# compose bridge, and wires a canonical local-observability destination.
from defenseclaw.commands.cmd_setup_local_observability import (  # noqa: E402
    local_observability,
)

setup.add_command(local_observability)

# Import the Terraform-backed Splunk O11y dashboard installer so the
# interactive Splunk wizard can reuse the same idempotent apply path and
# the command group can be registered below.
from defenseclaw.commands.cmd_setup_splunk_o11y_dashboards import (  # noqa: E402
    apply_dashboards,
    splunk_o11y_dashboards,
)

# Register `defenseclaw setup webhook` (Slack/PagerDuty/Webex/generic
# notifiers). Distinct from `setup observability add webhook` (generic
# HTTP JSONL audit-log forwarder) — see the published webhook guide for the
# disambiguation:
# https://cisco-ai-defense.github.io/defenseclaw/docs/setup/webhooks/
from defenseclaw.commands.cmd_setup_webhook import webhook  # noqa: E402

setup.add_command(webhook)

# Register `defenseclaw setup provider` (custom-providers.json overlay).
# Drives the Layer-4 "add a new LLM endpoint without a release" flow
# that the shape-detection rails and the Go /v1/config/providers
# endpoint rely on. See cmd_setup_provider.py for the full rationale.
from defenseclaw.commands.cmd_setup_provider import provider  # noqa: E402

setup.add_command(provider)


# Local LLM providers that run on-box and don't require an API key.
# This is intentionally a *subset* of ``_LOCAL_LLM_PROVIDERS`` in
# ``defenseclaw/config.py`` and ``IsLocalProvider()`` in
# ``internal/config/config.go`` — the wizard only offers entries that
# have a sensible default base URL. The generic ``local`` alias is
# excluded because it has no canonical endpoint; operators choosing
# that route configure ``llm.base_url`` directly in ``config.yaml``.
_LOCAL_LLM_WIZARD_PROVIDERS = {"ollama", "vllm", "lm_studio", "lmstudio"}

# Default base URLs for local providers so the wizard can offer a sane
# prefill. Operators can still override to point at a shared LAN host.
_LOCAL_LLM_DEFAULT_BASE_URL = {
    "ollama": "http://127.0.0.1:11434",
    "vllm": "http://127.0.0.1:8000/v1",
    "lm_studio": "http://127.0.0.1:1234/v1",
    "lmstudio": "http://127.0.0.1:1234/v1",
}

# Provider choices offered in the wizard. Cloud providers first (most
# operators), then local runtimes. Kept in lockstep with
# ``_RECOGNIZED_LLM_PROVIDERS`` in ``defenseclaw/config.py`` so any
# provider the resolver accepts is also pickable in the wizard. The
# scanner wrappers and the LiteLLM bridge are provider-agnostic — any
# entry here works end-to-end with a unified ``DEFENSECLAW_LLM_KEY`` +
# ``DEFENSECLAW_LLM_MODEL``.
_WIZARD_LLM_PROVIDERS = [
    "anthropic",
    "openai",
    "openrouter",
    "azure",
    "gemini",
    "gemini-openai",
    "groq",
    "mistral",
    "cohere",
    "deepseek",
    "xai",
    "bedrock",
    "vertex_ai",
    "fireworks_ai",
    "perplexity",
    "huggingface",
    "replicate",
    "together_ai",
    "cerebras",
    "ollama",
    "vllm",
    "lm_studio",
]


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
        ux.subhead("Config already in v5 shape — nothing to migrate.")
        # Still scrub the one-shot warning flag so a follow-up load
        # doesn't re-emit it in the same process.
        if hasattr(cfg, "_llm_migration_warned"):
            cfg._llm_migration_warned = False  # type: ignore[attr-defined]
        return

    ux.section("Legacy v4 LLM fields detected")
    for line in legacy_summary:
        click.echo(f"    {ux.dim('-')} {line}")
    click.echo()
    ux.section("Unified llm: block (post-migration)")
    llm = cfg.llm
    click.echo(f"    provider={llm.provider!r}, model={llm.model!r}, api_key_env={llm.api_key_env!r}")
    click.echo(f"    base_url={llm.base_url!r}, timeout={llm.timeout}, max_retries={llm.max_retries}")
    click.echo()

    if dry_run:
        ux.subhead("--dry-run: no files modified.")
        return

    # Backup before we mutate. We use the app's configured data_dir
    # rather than os.path.expanduser so this works inside sandboxed
    # tests and portable installs.
    cfg_path = str(config_path_for_data_dir(cfg.data_dir))
    if not no_backup and os.path.exists(cfg_path):
        backup_path = cfg_path + ".bak"
        shutil.copy2(cfg_path, backup_path)
        ux.ok(f"Backed up {cfg_path} -> {backup_path}")

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
    ux.ok(f"Wrote {cfg_path} (v5 shape).")


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
@click.option(
    "--provider",
    type=click.Choice(_WIZARD_LLM_PROVIDERS + ["custom"], case_sensitive=False),
    default=None,
    help=(
        "LLM provider to write non-interactively. Use 'custom' with "
        "--instance-name to bind a custom-providers.json instance."
    ),
)
@click.option("--model", default=None, help="LLM model id to write non-interactively.")
@click.option(
    "--api-key-env",
    default=None,
    help="Environment variable name holding the LLM API key.",
)
@click.option(
    "--api-key",
    default=None,
    help="Secret value to persist into ~/.defenseclaw/.env under --api-key-env.",
)
@click.option("--base-url", default=None, help="Provider base URL override.")
@click.option("--timeout", type=int, default=None, help="LLM timeout in seconds.")
@click.option("--max-retries", type=int, default=None, help="LLM retry count.")
@click.option(
    "--region",
    default=None,
    help="Generic provider region (Bedrock, Vertex, etc.). Stored on llm.region.",
)
@click.option(
    "--instance-name",
    default=None,
    help=(
        "Custom-provider instance name as registered via "
        "`defenseclaw setup provider add`. Selects the overlay entry whose "
        "base_url, env keys, and TLS settings are applied at resolve time."
    ),
)
@click.option(
    "--inherit-from",
    type=click.Choice(["guardrail", "guardrail.judge", "scanners.skill", "scanners.mcp", "scanners.plugin"]),
    default=None,
    help=(
        "Copy a resolved component config (provider/model/api_key_env/base_url) "
        "into the unified top-level llm block before applying other flags."
    ),
)
@click.option(
    "--inherit/--no-inherit",
    "inherit_preflight",
    default=None,
    help=(
        "Run the interactive 'inherit preflight' that lists sibling LLM "
        "configs (per-scanner / guardrail / judge) and offers to reuse "
        "one. Defaults to on in interactive mode, off under --non-interactive."
    ),
)
@click.option(
    "--role",
    type=click.Choice(["unified", "agent", "judge"]),
    default="unified",
    show_default=True,
    help=(
        "Where to write the LLM settings. 'unified' updates the top-level "
        "llm: block (default). 'judge' writes to guardrail.judge.llm so a "
        "hook-based connector can keep its own agent LLM. 'agent' writes "
        "to the top-level llm: block AND leaves guardrail.judge.llm empty "
        "so it inherits through the unified merge."
    ),
)
@click.option(
    "--auth-mode",
    default=None,
    help=(
        "Generic auth mode flag. When --provider bedrock, maps to "
        "--bedrock-auth-mode; --provider azure maps to --azure-auth-mode; "
        "--provider vertex_ai maps to --vertex-auth-mode."
    ),
)
@click.option("--bedrock-region", default=None, help="AWS region for Bedrock (e.g. us-east-1).")
@click.option(
    "--bedrock-auth-mode",
    type=click.Choice(["api_key", "iam_credentials", "profile", "instance_role"]),
    default=None,
    help="Bedrock auth strategy.",
)
@click.option("--bedrock-access-key-env", default=None, help="Env var holding AWS access key ID for Bedrock.")
@click.option("--bedrock-secret-key-env", default=None, help="Env var holding AWS secret access key for Bedrock.")
@click.option("--bedrock-session-token-env", default=None, help="Env var holding AWS session token for Bedrock.")
@click.option("--bedrock-profile-name", default=None, help="AWS profile name when bedrock-auth-mode=profile.")
@click.option("--bedrock-inference-profile", default=None, help="Bedrock inference-profile prefix (e.g. 'us.').")
@click.option(
    "--bedrock-deployment",
    "bedrock_deployment_aliases",
    multiple=True,
    help="Bedrock model alias formatted ``alias=model-id`` (repeatable).",
)
@click.option("--vertex-project-id", default=None, help="GCP project ID for Vertex AI.")
@click.option("--vertex-region", default=None, help="GCP region/location for Vertex AI.")
@click.option(
    "--vertex-auth-mode",
    type=click.Choice(["service_account", "adc", "workload_identity"]),
    default=None,
    help="Vertex auth strategy.",
)
@click.option(
    "--vertex-service-account-json-env",
    default=None,
    help="Env var holding the path to the Vertex service-account JSON.",
)
@click.option("--azure-endpoint", default=None, help="Azure OpenAI endpoint (e.g. https://name.openai.azure.com).")
@click.option("--azure-api-version", default=None, help="Azure OpenAI api-version (e.g. 2024-10-21).")
@click.option(
    "--azure-auth-mode",
    type=click.Choice(["api_key", "managed_identity"]),
    default=None,
    help="Azure auth strategy.",
)
@click.option(
    "--azure-deployment-alias",
    "azure_deployment_aliases",
    multiple=True,
    help="Azure deployment alias formatted ``model=deployment`` (repeatable).",
)
@click.option(
    "--tls-ca-cert-file",
    default=None,
    type=click.Path(exists=False, dir_okay=False),
    help="PEM CA bundle for self-signed LLM endpoints (inline-stored on llm.tls.ca_cert_pem).",
)
@click.option(
    "--insecure-skip-verify",
    is_flag=True,
    default=False,
    help="Disable TLS verification for this LLM endpoint (lab use only).",
)
@click.option(
    "--ping/--no-ping",
    "run_ping",
    default=False,
    help="After saving, send a one-shot 'ping' request via LiteLLM to verify reachability.",
)
@click.option(
    "--non-interactive",
    "--accept-defaults",
    is_flag=True,
    help="Use flags/current defaults instead of prompting.",
)
@pass_ctx
def setup_llm(
    app: AppContext,
    show: bool,
    provider: str | None,
    model: str | None,
    api_key_env: str | None,
    api_key: str | None,
    base_url: str | None,
    timeout: int | None,
    max_retries: int | None,
    region: str | None,
    instance_name: str | None,
    inherit_from: str | None,
    inherit_preflight: bool | None,
    role: str,
    auth_mode: str | None,
    bedrock_region: str | None,
    bedrock_auth_mode: str | None,
    bedrock_access_key_env: str | None,
    bedrock_secret_key_env: str | None,
    bedrock_session_token_env: str | None,
    bedrock_profile_name: str | None,
    bedrock_inference_profile: str | None,
    bedrock_deployment_aliases: tuple[str, ...],
    vertex_project_id: str | None,
    vertex_region: str | None,
    vertex_auth_mode: str | None,
    vertex_service_account_json_env: str | None,
    azure_endpoint: str | None,
    azure_api_version: str | None,
    azure_auth_mode: str | None,
    azure_deployment_aliases: tuple[str, ...],
    tls_ca_cert_file: str | None,
    insecure_skip_verify: bool,
    run_ping: bool,
    non_interactive: bool,
) -> None:
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

    target_path = _role_to_target_path(role)
    llm = _target_llm_block(cfg, target_path)

    # --auth-mode delegates to the appropriate provider-typed flag so an
    # operator who only knows "I want IAM creds for Bedrock" doesn't have
    # to remember the long-form flag name.
    if auth_mode is not None:
        prov = (provider or llm.provider or "").strip().lower()
        if prov == "bedrock" and bedrock_auth_mode is None:
            bedrock_auth_mode = auth_mode
        elif prov in ("azure", "azure_openai") and azure_auth_mode is None:
            azure_auth_mode = auth_mode
        elif prov in ("vertex_ai", "vertex", "gemini") and vertex_auth_mode is None:
            vertex_auth_mode = auth_mode
        else:
            ux.warn(
                f"--auth-mode is only honored for bedrock/azure/vertex_ai providers; "
                f"current provider is {prov!r} — ignoring."
            )

    if show:
        resolved = cfg.resolve_llm(target_path)
        click.echo()
        ux.section("Unified LLM configuration")
        click.echo(f"    {ux.dim('provider:')}    {resolved.provider or '(unset)'}")
        click.echo(f"    {ux.dim('model:')}       {resolved.model or '(unset)'}")
        key_env = resolved.api_key_env or DEFENSECLAW_LLM_KEY_ENV
        key_val = resolved.resolved_api_key()
        key_state = _mask(key_val) if key_val else "(not set)"
        click.echo(f"    {ux.dim('api_key_env:')} {key_env} = {key_state}")
        if resolved.base_url:
            click.echo(f"    {ux.dim('base_url:')}    {resolved.base_url}")
        click.echo(f"    {ux.dim('timeout:')}     {resolved.timeout}s")
        click.echo(f"    {ux.dim('max_retries:')} {resolved.max_retries}")
        ux.subhead(
            "To change: run 'defenseclaw setup llm' without --show.",
        )
        return

    if non_interactive:
        _configure_llm_non_interactive(
            cfg,
            cfg.data_dir,
            provider=provider,
            model=model,
            api_key_env=api_key_env,
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            region=region,
            instance_name=instance_name,
            inherit_from=inherit_from,
            target_path=target_path,
            bedrock_region=bedrock_region,
            bedrock_auth_mode=bedrock_auth_mode,
            bedrock_access_key_env=bedrock_access_key_env,
            bedrock_secret_key_env=bedrock_secret_key_env,
            bedrock_session_token_env=bedrock_session_token_env,
            bedrock_profile_name=bedrock_profile_name,
            bedrock_inference_profile=bedrock_inference_profile,
            bedrock_deployment_aliases=bedrock_deployment_aliases,
            vertex_project_id=vertex_project_id,
            vertex_region=vertex_region,
            vertex_auth_mode=vertex_auth_mode,
            vertex_service_account_json_env=vertex_service_account_json_env,
            azure_endpoint=azure_endpoint,
            azure_api_version=azure_api_version,
            azure_auth_mode=azure_auth_mode,
            azure_deployment_aliases=azure_deployment_aliases,
            tls_ca_cert_file=tls_ca_cert_file,
            insecure_skip_verify=insecure_skip_verify,
        )
        cfg.save()

        click.echo()
        ux.ok(f"Saved to {config_path_for_data_dir(cfg.data_dir)}")
        resolved = cfg.resolve_llm(target_path)
        key_env = resolved.api_key_env or DEFENSECLAW_LLM_KEY_ENV
        key_state = _mask(os.environ.get(key_env, "")) if os.environ.get(key_env, "") else "(not set)"
        label_prefix = "llm" if not target_path else f"{target_path}.llm"
        ux.kv(f"{label_prefix}.provider", resolved.provider or "(unset)")
        ux.kv(f"{label_prefix}.model", resolved.model or "(unset)")
        ux.kv(f"{label_prefix}.api_key_env", f"{key_env} = {key_state}")
        if resolved.base_url:
            ux.kv(f"{label_prefix}.base_url", resolved.base_url)
        if resolved.instance_name:
            ux.kv(f"{label_prefix}.instance_name", resolved.instance_name)
            _echo_custom_provider_enforcement(cfg)
        if run_ping:
            _run_llm_ping(resolved)
        return

    click.echo()
    ux.section("Unified LLM configuration")
    ux.subhead("Every LLM-using component (guardrail judge, MCP scanner,")
    ux.subhead("skill scanner, plugin scanner) resolves through this block")
    ux.subhead("by default. Per-component overrides live under")
    ux.subhead("scanners.*.llm / guardrail.{llm,judge.llm}.")
    click.echo()
    if llm.model:
        click.echo(f"  Current: model={llm.model}, api_key_env={llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV}")
        click.echo()

    preflight_result: dict[str, Any] | None = None
    if inherit_preflight is not False:
        preflight_result = _maybe_inherit_existing_llm(
            cfg,
            target_path=target_path,
            inherit_from=inherit_from,
        )
    if preflight_result and preflight_result.get("action") == "inherit":
        # Operator picked "Inherit fully" — skip the full prompt
        # walkthrough and go straight to save.
        _clear_legacy_llm_fields(cfg)
    elif preflight_result and preflight_result.get("action") == "partial":
        # Inherit-then-prompt-for-model: keep the inherited fields,
        # but let the operator type a different model id.
        target_llm = _target_llm_block(cfg, target_path)
        target_llm.model = click.prompt(
            "  LLM model id (overrides the inherited model)",
            default=target_llm.model or "",
            show_default=bool(target_llm.model),
        ).strip()
        _clear_legacy_llm_fields(cfg)
    else:
        _configure_llm(cfg, cfg.data_dir, target_path=target_path)
    cfg.save()

    click.echo()
    ux.ok(f"Saved to {config_path_for_data_dir(cfg.data_dir)}")
    click.echo()
    ux.subhead("Next: defenseclaw doctor       # verify the unified LLM is reachable")
    if run_ping:
        _run_llm_ping(cfg.resolve_llm(target_path))


@setup.command("skill-scanner")
@click.option("--use-llm", is_flag=True, default=None, help="Enable LLM analyzer")
@click.option("--use-behavioral", is_flag=True, default=None, help="Enable behavioral analyzer")
@click.option("--enable-meta", is_flag=True, default=None, help="Enable meta-analyzer")
@click.option("--use-trigger", is_flag=True, default=None, help="Enable trigger analyzer")
@click.option("--use-virustotal", is_flag=True, default=None, help="Enable VirusTotal scanner")
@click.option("--use-aidefense", is_flag=True, default=None, help="Enable AI Defense analyzer")
@click.option(
    "--llm-provider",
    default=None,
    type=click.Choice(["anthropic", "openai"]),
    help="LLM provider (anthropic or openai)",
)
@click.option("--llm-model", default=None, help="LLM model name")
@click.option("--llm-consensus-runs", type=int, default=None, help="LLM consensus runs (0=disabled)")
@click.option(
    "--policy",
    default=None,
    type=click.Choice(["strict", "balanced", "permissive", "none"], case_sensitive=False),
    help="Scan policy preset (strict, balanced, permissive, none)",
)
@click.option("--lenient", is_flag=True, default=None, help="Tolerate malformed skills")
@click.option("--verify/--no-verify", default=True, help="Run connectivity checks after setup (default: on)")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_skill_scanner(
    app: AppContext,
    use_llm,
    use_behavioral,
    enable_meta,
    use_trigger,
    use_virustotal,
    use_aidefense,
    llm_provider,
    llm_model,
    llm_consensus_runs,
    policy,
    lenient,
    verify,
    non_interactive,
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
            sc.policy = "" if policy.lower() == "none" else policy.lower()
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

        ux.section("Verifying scanner configuration")
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
        app.logger.log_action(ACTION_SETUP_SKILL_SCANNER, "config", " ".join(parts))


def _interactive_setup(sc, llm, aid, cfg) -> None:
    """Skill scanner interactive wizard.

    Takes the parent ``cfg`` rather than just ``data_dir`` so the LLM
    helper can clean up legacy ``inspect_llm`` fields and so other
    cross-cutting concerns stay addressable without widening callers.
    """
    data_dir = cfg.data_dir
    click.echo()
    ux.section("Skill Scanner Configuration")
    click.echo(f"  {ux.dim('Binary:')} {sc.binary}")
    click.echo()

    sc.use_behavioral = click.confirm("  Enable behavioral analyzer (dataflow analysis)?", default=sc.use_behavioral)
    sc.use_llm = click.confirm("  Enable LLM analyzer (semantic analysis)?", default=sc.use_llm)

    if sc.use_llm:
        _configure_llm(cfg, data_dir)
        sc.enable_meta = click.confirm("  Enable meta-analyzer (false positive filtering)?", default=sc.enable_meta)
        sc.llm_consensus_runs = click.prompt(
            "  LLM consensus runs (0 = disabled)",
            type=int,
            default=sc.llm_consensus_runs,
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


_LLM_ROLE_TO_TARGET_PATH: dict[str, str] = {
    "unified": "",
    "agent": "",
    "judge": "guardrail.judge",
}


def _role_to_target_path(role: str) -> str:
    """Map a ``--role`` value to a target_path accepted by
    :func:`_target_llm_block` / :meth:`Config.resolve_llm`.
    """
    return _LLM_ROLE_TO_TARGET_PATH.get(role, "")


def _configure_llm(cfg, data_dir: str, *, target_path: str = "") -> None:
    """Prompt for unified ``llm:`` settings (provider, model, API key).

    Writes to the target block selected by ``target_path`` (defaults to
    the top-level ``cfg.llm`` block — the single source of truth
    consumed by guardrail (Bifrost), MCP scanner, skill scanner, and
    the plugin scanner via :meth:`Config.resolve_llm`). Per-scanner
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
    from defenseclaw.commands._llm_picker import (  # noqa: PLC0415
        custom_instance,
        list_custom_instances,
        pick_auth_mode,
        pick_key_env,
        pick_model,
        pick_provider,
        pick_region,
        summary_panel,
    )
    from defenseclaw.guardrail import detect_api_key_env  # noqa: PLC0415

    llm = _target_llm_block(cfg, target_path)

    default_provider = llm.provider if llm.provider in _WIZARD_LLM_PROVIDERS else "anthropic"
    instances = list_custom_instances(data_dir)
    llm.provider = pick_provider(
        current=default_provider,
        instances=instances,
        flag_value=None,
        non_interactive=False,
    )
    instance_obj = custom_instance(data_dir, llm.instance_name) if llm.instance_name else None
    llm.model = pick_model(
        current=llm.model or "",
        provider=llm.provider,
        instance=instance_obj,
        flag_value=None,
        non_interactive=False,
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
        # Surface LiteLLM's native env-var name as a hint when the
        # operator hasn't already pinned a custom one (so they can
        # reuse an existing ANTHROPIC_API_KEY / OPENAI_API_KEY).
        guessed = detect_api_key_env(f"{llm.provider}/{llm.model}")
        if not existing_env and guessed and guessed != "LLM_API_KEY" and guessed != DEFENSECLAW_LLM_KEY_ENV:
            click.echo(f"    Note: LiteLLM's native env var for {llm.provider} is {guessed}.")
        env_name = pick_key_env(
            provider=llm.provider,
            current=suggested_env,
            flag_value=None,
            non_interactive=False,
        )
        _prompt_and_save_secret(env_name, llm.api_key, data_dir)
        llm.api_key = ""
        llm.api_key_env = env_name
        llm.base_url = click.prompt(
            "  LLM base URL (leave blank to use provider default)",
            default=llm.base_url or "",
            show_default=bool(llm.base_url),
        )

    # Provider-typed prompts: region + auth-mode for bedrock / vertex / azure.
    prov = (llm.provider or "").strip().lower()
    if prov in ("bedrock", "vertex_ai", "vertex", "gemini", "azure", "azure_openai"):
        region_default = ""
        if prov == "bedrock" and llm.bedrock is not None:
            region_default = llm.bedrock.region
        elif prov in ("vertex_ai", "vertex", "gemini") and llm.vertex is not None:
            region_default = llm.vertex.region
        region_value = pick_region(
            provider=prov,
            current=region_default,
            flag_value=None,
            non_interactive=False,
        )
        auth_default = ""
        if prov == "bedrock" and llm.bedrock is not None:
            auth_default = llm.bedrock.auth_mode
        elif prov in ("vertex_ai", "vertex", "gemini") and llm.vertex is not None:
            auth_default = llm.vertex.auth_mode
        elif prov in ("azure", "azure_openai") and llm.azure is not None:
            auth_default = llm.azure.auth_mode
        auth_value = pick_auth_mode(
            provider=prov,
            current=auth_default,
            flag_value=None,
            non_interactive=False,
        )
        if prov == "bedrock":
            _apply_llm_provider_typed_flags(
                llm,
                bedrock_region=region_value,
                bedrock_auth_mode=auth_value,
            )
        elif prov in ("vertex_ai", "vertex", "gemini"):
            _apply_llm_provider_typed_flags(
                llm,
                vertex_region=region_value,
                vertex_auth_mode=auth_value,
            )
        elif prov in ("azure", "azure_openai"):
            _apply_llm_provider_typed_flags(
                llm,
                azure_auth_mode=auth_value,
            )

    llm.timeout = click.prompt("  LLM timeout (seconds)", type=int, default=llm.timeout or 30)
    llm.max_retries = click.prompt("  LLM max retries", type=int, default=llm.max_retries or 2)

    # Clear legacy v4 fields so the next save() doesn't re-emit a stale
    # inspect_llm: block. The v5 migration in config.load() copies
    # inspect_llm → llm one-way when llm is empty, so leaving the old
    # block populated after a successful wizard run would round-trip a
    # redundant copy of the same values into YAML.
    _clear_legacy_llm_fields(cfg)

    click.echo()
    summary_panel(role=("unified" if not target_path else "judge"), llm=llm)


def _configure_llm_non_interactive(
    cfg,
    data_dir: str,
    *,
    provider: str | None = None,
    model: str | None = None,
    api_key_env: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    timeout: int | None = None,
    max_retries: int | None = None,
    region: str | None = None,
    instance_name: str | None = None,
    inherit_from: str | None = None,
    target_path: str = "",
    bedrock_region: str | None = None,
    bedrock_auth_mode: str | None = None,
    bedrock_access_key_env: str | None = None,
    bedrock_secret_key_env: str | None = None,
    bedrock_session_token_env: str | None = None,
    bedrock_profile_name: str | None = None,
    bedrock_inference_profile: str | None = None,
    bedrock_deployment_aliases: tuple[str, ...] = (),
    vertex_project_id: str | None = None,
    vertex_region: str | None = None,
    vertex_auth_mode: str | None = None,
    vertex_service_account_json_env: str | None = None,
    azure_endpoint: str | None = None,
    azure_api_version: str | None = None,
    azure_auth_mode: str | None = None,
    azure_deployment_aliases: tuple[str, ...] = (),
    tls_ca_cert_file: str | None = None,
    insecure_skip_verify: bool = False,
) -> None:
    """Apply unified ``llm:`` settings without prompting.

    Secret values supplied through ``--api-key`` are written to the
    env-backed ``.env`` store and never persisted into ``config.yaml``.

    Provider-typed flags (``bedrock_*`` / ``vertex_*`` / ``azure_*``) and
    TLS flags populate the corresponding sub-blocks on :class:`LLMConfig`;
    ``instance_name`` selects a custom-providers.json overlay entry whose
    ``base_url``, env keys, and TLS settings are applied at resolve time.

    ``target_path`` routes the write to a non-default block — for
    example ``"guardrail.judge"`` so a hook-based connector can keep
    its own agent LLM while DefenseClaw judges with a different model.
    """
    _apply_llm_inherit(cfg, inherit_from=inherit_from, target_path=target_path)

    llm = _target_llm_block(cfg, target_path)
    if provider is not None:
        llm.provider = provider.strip().lower()
    elif not llm.provider:
        llm.provider = "anthropic"

    if model is not None:
        llm.model = model.strip()
    if region is not None:
        llm.region = region.strip()
    if instance_name is not None:
        llm.instance_name = instance_name.strip()

    is_local = llm.provider in _LOCAL_LLM_WIZARD_PROVIDERS
    if is_local:
        llm.api_key = ""
        llm.api_key_env = ""
        if base_url is not None:
            llm.base_url = base_url.strip()
        elif not llm.base_url:
            llm.base_url = _LOCAL_LLM_DEFAULT_BASE_URL.get(llm.provider, "")
    else:
        env_name = (api_key_env or llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV).strip()
        if not env_name:
            env_name = DEFENSECLAW_LLM_KEY_ENV
        if api_key:
            _save_secret_to_dotenv(env_name, api_key, data_dir)
        llm.api_key = ""
        llm.api_key_env = env_name
        if base_url is not None:
            llm.base_url = base_url.strip()

    if timeout is not None:
        llm.timeout = timeout
    elif not llm.timeout:
        llm.timeout = 30
    if max_retries is not None:
        llm.max_retries = max_retries
    elif not llm.max_retries:
        llm.max_retries = 2

    _apply_llm_provider_typed_flags(
        llm,
        bedrock_region=bedrock_region,
        bedrock_auth_mode=bedrock_auth_mode,
        bedrock_access_key_env=bedrock_access_key_env,
        bedrock_secret_key_env=bedrock_secret_key_env,
        bedrock_session_token_env=bedrock_session_token_env,
        bedrock_profile_name=bedrock_profile_name,
        bedrock_inference_profile=bedrock_inference_profile,
        bedrock_deployment_aliases=bedrock_deployment_aliases,
        vertex_project_id=vertex_project_id,
        vertex_region=vertex_region,
        vertex_auth_mode=vertex_auth_mode,
        vertex_service_account_json_env=vertex_service_account_json_env,
        azure_endpoint=azure_endpoint,
        azure_api_version=azure_api_version,
        azure_auth_mode=azure_auth_mode,
        azure_deployment_aliases=azure_deployment_aliases,
        tls_ca_cert_file=tls_ca_cert_file,
        insecure_skip_verify=insecure_skip_verify,
    )

    _clear_legacy_llm_fields(cfg)


def _apply_llm_inherit(cfg, *, inherit_from: str | None, target_path: str) -> None:
    """Copy a resolved component config into the unified or sub-block llm.

    ``target_path`` is either ``""`` (top-level ``cfg.llm``) or a component
    path accepted by :meth:`Config.resolve_llm` (e.g. ``"guardrail.judge"``).

    ``inherit_from`` selects the *source* component. The source's
    resolved fields (provider/model/api_key_env/base_url/region/
    instance_name and the provider-typed sub-blocks) are copied into the
    target block; further flag/prompt overrides win because they run
    after this step.
    """
    if not inherit_from:
        return
    try:
        src = cfg.resolve_llm(inherit_from)
    except Exception as exc:
        raise click.ClickException(f"--inherit-from {inherit_from!r}: could not resolve source: {exc}") from exc

    target_llm = _target_llm_block(cfg, target_path)
    target_llm.provider = src.provider or target_llm.provider
    target_llm.model = src.model or target_llm.model
    if src.api_key_env:
        target_llm.api_key_env = src.api_key_env
    if getattr(src, "base_url", ""):
        target_llm.base_url = src.base_url
    if getattr(src, "region", ""):
        target_llm.region = src.region
    if getattr(src, "instance_name", ""):
        target_llm.instance_name = src.instance_name
    for attr in ("bedrock", "vertex", "azure", "tls"):
        src_val = getattr(src, attr, None)
        if src_val is not None:
            setattr(target_llm, attr, _clone_dataclass(src_val))


def _maybe_inherit_existing_llm(cfg, *, target_path: str, inherit_from: str | None) -> dict[str, Any] | None:
    """Wrapper around :func:`_apply_llm_inherit` for the interactive
    path: applies the flag if present, otherwise runs the
    :func:`preflight_inherit` two-panel card with per-candidate ping
    and a four-option menu (Inherit / Partial / Reconfigure / Back).

    Returns the preflight result dict so the caller can act on
    ``"partial"`` (re-prompt only the changed field) or ``"back"``
    (abort the wizard) — or ``None`` when ``inherit_from`` was already
    supplied / no candidates exist.
    """
    if inherit_from:
        _apply_llm_inherit(cfg, inherit_from=inherit_from, target_path=target_path)
        return None
    try:
        from defenseclaw.commands._llm_picker import (  # noqa: PLC0415
            preflight_inherit,
        )
    except ImportError:
        return None
    target = _target_llm_block(cfg, target_path)
    # If the target is already populated, don't badger the operator —
    # they ran the wizard with the intent to *update* the block.
    if (target.provider or "").strip() or (target.model or "").strip():
        return None
    result = preflight_inherit(cfg, target_path=target_path)
    if not result:
        return None
    action = result.get("action")
    src = result.get("source_path") or ""
    if action == "back":
        raise click.Abort()
    if action == "reconfigure":
        return result
    if src:
        # Both "inherit" and "partial" copy first; "partial" causes
        # the caller to immediately re-prompt for the model.
        _apply_llm_inherit(cfg, inherit_from=src, target_path=target_path)
        ux.ok(f"inherited from {src}")
    return result


def _target_llm_block(cfg, target_path: str):
    """Return the mutable :class:`LLMConfig` for ``target_path``.

    Supports ``""`` (top-level), ``"guardrail"``, ``"guardrail.judge"``,
    ``"scanners.skill"``, ``"scanners.mcp"``, and ``"scanners.plugin"``.
    """
    if not target_path:
        return cfg.llm
    if target_path == "guardrail":
        return cfg.guardrail.llm
    if target_path == "guardrail.judge":
        return cfg.guardrail.judge.llm
    if target_path == "scanners.skill":
        return cfg.scanners.skill_scanner.llm
    if target_path == "scanners.mcp":
        return cfg.scanners.mcp_scanner.llm
    if target_path == "scanners.plugin":
        return cfg.scanners.plugin_llm
    raise click.ClickException(f"unknown llm target path: {target_path!r}")


def _clone_dataclass(value):
    """Best-effort copy of a dataclass instance (provider-typed blocks)."""
    from dataclasses import replace  # noqa: PLC0415

    try:
        return replace(value)
    except TypeError:
        return value


def _apply_llm_provider_typed_flags(
    llm,
    *,
    bedrock_region: str | None = None,
    bedrock_auth_mode: str | None = None,
    bedrock_access_key_env: str | None = None,
    bedrock_secret_key_env: str | None = None,
    bedrock_session_token_env: str | None = None,
    bedrock_profile_name: str | None = None,
    bedrock_inference_profile: str | None = None,
    bedrock_deployment_aliases: tuple[str, ...] = (),
    vertex_project_id: str | None = None,
    vertex_region: str | None = None,
    vertex_auth_mode: str | None = None,
    vertex_service_account_json_env: str | None = None,
    azure_endpoint: str | None = None,
    azure_api_version: str | None = None,
    azure_auth_mode: str | None = None,
    azure_deployment_aliases: tuple[str, ...] = (),
    tls_ca_cert_file: str | None = None,
    insecure_skip_verify: bool = False,
) -> None:
    """Populate the provider-typed sub-blocks on ``llm`` from CLI flags.

    Initializes the nested dataclass lazily so a config that doesn't
    use Bedrock/Vertex/Azure stays free of empty sub-blocks (and is
    pruned by :func:`config._strip_empty_llm` on save).
    """
    from defenseclaw.config import (  # noqa: PLC0415
        AzureKeyConfig,
        BedrockKeyConfig,
        LLMTLSConfig,
        VertexKeyConfig,
    )

    bedrock_touched = any(
        v not in (None, "")
        for v in (
            bedrock_region,
            bedrock_auth_mode,
            bedrock_access_key_env,
            bedrock_secret_key_env,
            bedrock_session_token_env,
            bedrock_profile_name,
            bedrock_inference_profile,
        )
    ) or bool(bedrock_deployment_aliases)
    if bedrock_touched:
        if llm.bedrock is None:
            llm.bedrock = BedrockKeyConfig()
        b = llm.bedrock
        if bedrock_region is not None:
            b.region = bedrock_region.strip()
        if bedrock_auth_mode is not None:
            b.auth_mode = bedrock_auth_mode.strip().lower()
        if bedrock_access_key_env is not None:
            b.access_key_env = bedrock_access_key_env.strip()
        if bedrock_secret_key_env is not None:
            b.secret_key_env = bedrock_secret_key_env.strip()
        if bedrock_session_token_env is not None:
            b.session_token_env = bedrock_session_token_env.strip()
        if bedrock_profile_name is not None:
            b.profile_name = bedrock_profile_name.strip()
        if bedrock_inference_profile is not None:
            b.inference_profile = bedrock_inference_profile.strip()
        for raw in bedrock_deployment_aliases:
            if "=" not in raw:
                raise click.BadParameter(f"--bedrock-deployment expects ``alias=model`` (got {raw!r})")
            mname, _, dname = raw.partition("=")
            mname, dname = mname.strip(), dname.strip()
            if not mname or not dname:
                raise click.BadParameter(f"--bedrock-deployment both sides required (got {raw!r})")
            b.deployment_aliases[mname] = dname

    vertex_touched = any(
        v not in (None, "")
        for v in (vertex_project_id, vertex_region, vertex_auth_mode, vertex_service_account_json_env)
    )
    if vertex_touched:
        if llm.vertex is None:
            llm.vertex = VertexKeyConfig()
        v = llm.vertex
        if vertex_project_id is not None:
            v.project_id = vertex_project_id.strip()
        if vertex_region is not None:
            v.region = vertex_region.strip()
        if vertex_auth_mode is not None:
            v.auth_mode = vertex_auth_mode.strip().lower()
        if vertex_service_account_json_env is not None:
            v.service_account_json_env = vertex_service_account_json_env.strip()

    azure_touched = any(v not in (None, "") for v in (azure_endpoint, azure_api_version, azure_auth_mode)) or bool(
        azure_deployment_aliases
    )
    if azure_touched:
        if llm.azure is None:
            llm.azure = AzureKeyConfig()
        a = llm.azure
        if azure_endpoint is not None:
            a.endpoint = azure_endpoint.strip()
        if azure_api_version is not None:
            a.api_version = azure_api_version.strip()
        if azure_auth_mode is not None:
            a.auth_mode = azure_auth_mode.strip().lower()
        for raw in azure_deployment_aliases:
            if "=" not in raw:
                raise click.BadParameter(f"--azure-deployment-alias expects ``model=deployment`` (got {raw!r})")
            mname, _, dname = raw.partition("=")
            mname, dname = mname.strip(), dname.strip()
            if not mname or not dname:
                raise click.BadParameter(f"--azure-deployment-alias both sides required (got {raw!r})")
            a.deployment_aliases[mname] = dname

    tls_touched = bool(tls_ca_cert_file) or insecure_skip_verify
    if tls_touched:
        if insecure_skip_verify and tls_ca_cert_file:
            raise click.BadParameter("--insecure-skip-verify and --tls-ca-cert-file are mutually exclusive.")
        if llm.tls is None:
            llm.tls = LLMTLSConfig()
        if tls_ca_cert_file:
            if not os.path.isfile(tls_ca_cert_file):
                raise click.BadParameter(f"--tls-ca-cert-file: not found: {tls_ca_cert_file!r}")
            with open(tls_ca_cert_file, encoding="utf-8") as f:
                pem = f.read()
            if "BEGIN CERTIFICATE" not in pem:
                raise click.BadParameter(f"--tls-ca-cert-file: {tls_ca_cert_file!r} is not a PEM certificate")
            llm.tls.ca_cert_pem = pem
            # A later CA pin replaces a prior skip-verify opt-in (F-0141).
            llm.tls.insecure_skip_verify = False
        if insecure_skip_verify:
            llm.tls.insecure_skip_verify = True
            ux.warn(
                "--insecure-skip-verify enabled for llm.tls; the gateway will trust "
                "ANY server certificate. Use only in trusted labs."
            )


def _run_llm_ping(resolved) -> None:
    """Call :func:`defenseclaw.llm.ping` against a resolved LLMConfig
    and print the outcome. Errors are caught so a flaky network does
    not block the wizard save.
    """
    try:
        from defenseclaw import llm as llm_mod  # noqa: PLC0415
    except Exception as exc:
        ux.warn(f"llm.ping unavailable: {exc}")
        return
    ok, msg = llm_mod.ping(resolved)
    if ok:
        ux.ok(f"llm ping: {msg}")
    else:
        ux.warn(f"llm ping failed: {msg}")


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
            default=llm.base_url or "",
            show_default=bool(llm.base_url),
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


def _prompt_and_save_secret(
    env_name: str,
    current: str,
    data_dir: str,
    *,
    _pending_secrets: list[_PendingGuardrailSecret] | None = None,
) -> None:
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
    val = click.prompt(
        f"  {env_name} [{hint}]",
        default="",
        show_default=False,
        hide_input=True,
    )
    secret = val or effective
    if secret:
        if _pending_secrets is None:
            _save_secret_to_dotenv(env_name, secret, data_dir)
        else:
            if not dotenv_key_is_valid(env_name):
                raise DotenvValueError(f"invalid dotenv key: {env_name!r}")
            sanitize_dotenv_value(secret, key=env_name)
            for pending in _pending_secrets:
                if pending.env_name == env_name:
                    pending.clear()
            _pending_secrets[:] = [pending for pending in _pending_secrets if pending.env_name != env_name]
            _pending_secrets.append(_PendingGuardrailSecret(env_name, secret))


def _mask(key: str) -> str:
    if len(key) <= 8:
        return "****"
    return key[:4] + "..." + key[-4:]


def _parse_dotenv_lines(lines) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in lines:
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
    return result


def _parse_dotenv_snapshot(payload: bytes | None) -> dict[str, str]:
    if payload is None:
        return {}
    return _parse_dotenv_lines(payload.decode().splitlines())


def _load_dotenv(path: str) -> dict[str, str]:
    """Read a KEY=VALUE .env file into a dict."""
    try:
        with open(path) as f:
            return _parse_dotenv_lines(f)
    except FileNotFoundError:
        return {}


def _snapshot_regular_file(path: str, *, what: str) -> tuple[bytes | None, int | None]:
    reject_symlink(path, what=what)
    try:
        _ensure_regular_file(os.lstat(path).st_mode, path)
    except FileNotFoundError:
        return None, None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, None
    with os.fdopen(fd, "rb") as handle:
        file_stat = os.fstat(handle.fileno())
        _ensure_regular_file(file_stat.st_mode, path)
        mode = file_stat.st_mode & 0o777
        return handle.read(), mode


def _restore_regular_file_snapshot(path: str, payload: bytes | None, mode: int | None, *, what: str) -> None:
    if payload is None:
        try:
            _ensure_regular_file(os.lstat(path).st_mode, path)
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    reject_symlink(path, what=what)
    try:
        _ensure_regular_file(os.lstat(path).st_mode, path)
    except FileNotFoundError:
        pass
    restored_mode = mode if mode is not None else 0o600
    atomic_write_private_bytes(path, payload)
    if os.name != "nt":
        os.chmod(path, restored_mode)


def _ensure_regular_file(mode: int, path: str) -> None:
    if not stat.S_ISREG(mode):
        raise OSError(f"file is not a regular file: {path}")


def _snapshot_dotenv(path: str) -> tuple[bytes | None, int | None]:
    """Capture exact dotenv bytes and mode for transactional rollback."""
    return _snapshot_regular_file(path, what="dotenv file")


def _restore_dotenv_snapshot(path: str, payload: bytes | None, mode: int | None) -> None:
    """Restore a dotenv snapshot without normalizing comments or quoting."""
    _restore_regular_file_snapshot(path, payload, mode, what="dotenv file")


def _write_dotenv(path: str, entries: dict[str, str]) -> None:
    with locked_file_update(path):
        _write_dotenv_locked(path, entries)


def _write_dotenv_locked(path: str, entries: dict[str, str]) -> None:
    """Write entries to a .env file with owner-only access.

    Note: ``O_CREAT`` only applies the ``0o600`` mode on *initial*
    creation. Tighten the open descriptor before writing so repeat runs also
    converge on POSIX 0600 or the equivalent protected Windows DACL.
    """
    body = "".join(f"{key}={sanitize_dotenv_value(value, key=key)}\n" for key, value in sorted(entries.items()))
    atomic_write_private_bytes(path, body.encode("utf-8"))


def _load_config_for_data_dir(data_dir: str):
    old_home = os.environ.get("DEFENSECLAW_HOME")
    os.environ["DEFENSECLAW_HOME"] = data_dir
    try:
        return load_config()
    finally:
        if old_home is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = old_home


def _config_trusted_bin_prefixes(cfg) -> list[str]:
    ai = getattr(cfg, "ai_discovery", None)
    values = getattr(ai, "trusted_binary_prefixes", []) if ai is not None else []
    return [str(p).strip() for p in (values or []) if str(p).strip()]


def _set_config_trusted_bin_prefixes(
    cfg,
    prefixes: list[str],
    *,
    locked_path: str | None = None,
) -> None:
    ai = getattr(cfg, "ai_discovery", None)
    if ai is None:
        return
    deduped: list[str] = []
    seen: set[str] = set()
    for raw in prefixes:
        resolved, _err = agent_discovery.validate_trusted_prefix(raw)
        key = resolved or str(raw).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(key)
    ai.trusted_binary_prefixes = deduped
    if locked_path is None:
        cfg.save()
    else:
        cfg._save_locked(locked_path)


def _add_trusted_bin_prefix(prefix: str, data_dir: str, cfg=None) -> bool:
    """Add a directory to ai_discovery.trusted_binary_prefixes in config.yaml."""
    if any(ch in prefix for ch in ("\n", "\r", "\x00")):
        raise DotenvValueError("trusted binary prefix contains a control character")
    cfg = cfg or _load_config_for_data_dir(data_dir)
    parts = _config_trusted_bin_prefixes(cfg)
    resolved, _err = agent_discovery.validate_trusted_prefix(prefix)
    entry = resolved or prefix
    prefix_key = agent_discovery._path_key(os.path.realpath(os.path.abspath(entry)))
    added = not any(agent_discovery._path_key(os.path.realpath(os.path.abspath(part))) == prefix_key for part in parts)
    if added:
        parts.append(entry)
        _set_config_trusted_bin_prefixes(cfg, parts)
    return added


# ---------------------------------------------------------------------------
# `defenseclaw setup trusted-paths` — manage the binary-discovery allow-list.
#
# Built-in defaults live in agent_discovery._TRUSTED_BIN_PREFIXES_DEFAULT and
# are read-only here. New operator additions persist to config.yaml under
# ai_discovery.trusted_binary_prefixes. Legacy .env / process env entries are
# still listed and honored for backward compatibility.
# ---------------------------------------------------------------------------


def _trusted_prefix_status(resolved: str) -> str:
    """Classify a resolved prefix for trusted-paths list output."""
    if not os.path.exists(resolved):
        return "missing"
    if not os.path.isdir(resolved):
        return "not-a-dir"
    _path, error = agent_discovery.validate_trusted_prefix(resolved)
    if error:
        if "write access" in error or "writable" in error:
            return "unsafe-permissions"
        return "error"
    return "ok"


def _default_resolved_prefixes() -> set[str]:
    """Resolved absolute paths of the built-in (non-removable) defaults."""
    out: set[str] = set()
    for raw in agent_discovery._TRUSTED_BIN_PREFIXES_DEFAULT:
        resolved, _ = agent_discovery.validate_trusted_prefix(raw)
        if resolved:
            out.add(resolved)
    return out


def _collect_trusted_prefixes(data_dir: str, cfg=None) -> list[dict[str, object]]:
    """Unified trusted-prefix view: built-in defaults + config + legacy env."""
    cfg = cfg or _load_config_for_data_dir(data_dir)
    dotenv_path = os.path.join(data_dir, ".env")
    config_file = _config_trusted_bin_prefixes(cfg)
    env_file_raw = _load_dotenv(dotenv_path).get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
    env_file = [p.strip() for p in env_file_raw.split(os.pathsep) if p.strip()]
    proc_raw = os.environ.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
    proc = [p.strip() for p in proc_raw.split(os.pathsep) if p.strip()]
    env_only = [p for p in proc if p not in env_file and p not in config_file]

    rows: list[dict[str, object]] = []
    seen: set[str] = set()

    def _push(raw: str, source: str, removable: bool) -> None:
        resolved, _err = agent_discovery.validate_trusted_prefix(raw)
        if not resolved or resolved in seen:
            return
        seen.add(resolved)
        rows.append(
            {
                "path": raw,
                "resolved": resolved,
                "source": source,
                "status": _trusted_prefix_status(resolved),
                "removable": removable,
            }
        )

    for raw in agent_discovery._TRUSTED_BIN_PREFIXES_DEFAULT:
        _push(raw, "default", False)
    for raw in config_file:
        _push(raw, "config", True)
    for raw in env_file:
        _push(raw, "legacy .env", True)
    for raw in env_only:
        _push(raw, "env", False)
    return rows


def _emit_trusted_path_result(as_json: bool, *, ok: bool, path: str, message: str) -> None:
    if as_json:
        click.echo(_json.dumps({"ok": ok, "path": path, "message": message}, indent=2))
    elif ok:
        ux.ok(f"{message}: {path}" if path else message)
    else:
        ux.err(f"{message}: {path}" if path else message)


@setup.group("trusted-paths")
def trusted_paths() -> None:
    """Manage directories DefenseClaw trusts for connector-binary discovery.

    Legacy examples:
    Action-mode setup reads a connector's version by executing its binary, but
    only when that binary lives under a trusted prefix — a guard against a
    hostile binary planted on $PATH. Built-in defaults cover system and
    Homebrew locations; trust additional roots here for bespoke installs.
    Additions persist to ~/.defenseclaw/config.yaml under ai_discovery.trusted_binary_prefixes.
    """


@trusted_paths.command("list")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON instead of a table.")
@pass_ctx
def trusted_paths_list(app: AppContext, as_json: bool) -> None:
    """List trusted binary prefixes (built-in defaults + operator-added)."""
    rows = _collect_trusted_prefixes(app.cfg.data_dir, cfg=app.cfg)
    if as_json:
        click.echo(_json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo(f"  {ux.dim('No trusted prefixes configured.')}")
        return
    click.echo()
    src_w = max(len(str(r["source"])) for r in rows)
    st_w = max(len(str(r["status"])) for r in rows)
    for r in rows:
        mark = "✓" if r["status"] == "ok" else "✗"
        source = str(r["source"]).ljust(src_w)
        status = str(r["status"]).ljust(st_w)
        line = f"  {mark}  {ux.dim(source)}  {status}  {r['resolved']}"
        if r["removable"]:
            line += f"  {ux.dim('(removable)')}"
        click.echo(line)
    click.echo()
    click.echo(f"  {ux.dim('Add with: defenseclaw setup trusted-paths add <dir>')}")
    click.echo()


@trusted_paths.command("add")
@click.argument("directory")
@click.option("--force", is_flag=True, help="Record the path even when it is missing or has unsafe permissions.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON instead of text.")
@pass_ctx
def trusted_paths_add(app: AppContext, directory: str, force: bool, as_json: bool) -> None:
    """Trust DIRECTORY for connector-binary discovery (persisted to config.yaml)."""
    resolved, err = agent_discovery.validate_trusted_prefix(directory)
    if not resolved:
        _emit_trusted_path_result(as_json, ok=False, path=directory, message=f"invalid path ({err})")
        click.get_current_context().exit(1)
    if resolved in _default_resolved_prefixes():
        _emit_trusted_path_result(as_json, ok=True, path=resolved, message="already trusted by default; nothing to do")
        return
    if err and not force:
        _emit_trusted_path_result(
            as_json,
            ok=False,
            path=resolved,
            message=f"refusing to trust ({err}); re-run with --force to override",
        )
        click.get_current_context().exit(1)
    added = _add_trusted_bin_prefix(resolved, app.cfg.data_dir, cfg=app.cfg)
    message = "added to trusted prefixes" if added else "already an operator-added trusted prefix"
    if err and force:
        message += f" (forced despite: {err})"
    _emit_trusted_path_result(as_json, ok=True, path=resolved, message=message)


@trusted_paths.command("remove")
@click.argument("directory")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON instead of text.")
@pass_ctx
def trusted_paths_remove(app: AppContext, directory: str, as_json: bool) -> None:
    """Remove an operator-added trusted prefix (never a built-in default)."""
    resolved, _err = agent_discovery.validate_trusted_prefix(directory)
    if resolved in _default_resolved_prefixes():
        _emit_trusted_path_result(
            as_json, ok=False, path=resolved, message="refusing to remove a built-in default prefix"
        )
        click.get_current_context().exit(1)
    data_dir = app.cfg.data_dir
    target = (directory or "").strip()
    dotenv_path = os.path.join(data_dir, ".env")
    config_file = str(config_path_for_data_dir(data_dir))
    with locked_config_yaml(config_file), locked_file_update(dotenv_path):
        removed = _remove_trusted_path_files_locked(app, target, resolved, dotenv_path, config_file)

    process_entries = [
        value.strip()
        for value in os.environ.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "").split(os.pathsep)
        if value.strip()
    ]
    kept_process = [
        value
        for value in process_entries
        if value != target and agent_discovery.validate_trusted_prefix(value)[0] != resolved
    ]
    if len(kept_process) != len(process_entries):
        if kept_process:
            os.environ["DEFENSECLAW_TRUSTED_BIN_PREFIXES"] = os.pathsep.join(kept_process)
        else:
            os.environ.pop("DEFENSECLAW_TRUSTED_BIN_PREFIXES", None)
        removed = True

    if not removed:
        _emit_trusted_path_result(
            as_json,
            ok=False,
            path=resolved,
            message="not an operator-added trusted prefix; nothing to remove",
        )
        click.get_current_context().exit(1)
    _emit_trusted_path_result(as_json, ok=True, path=resolved, message="removed from trusted prefixes")


def _remove_trusted_path_files_locked(
    app: AppContext,
    target: str,
    resolved: str,
    dotenv_path: str,
    config_file: str,
) -> bool:
    """Update config and dotenv while both sibling locks remain held."""

    config_entries = _config_trusted_bin_prefixes(app.cfg)
    kept_config = [
        entry
        for entry in config_entries
        if entry != target and agent_discovery.validate_trusted_prefix(entry)[0] != resolved
    ]
    dotenv_snapshot, dotenv_mode = _snapshot_dotenv(dotenv_path)
    existing = _parse_dotenv_snapshot(dotenv_snapshot)
    current = existing.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
    entries = [p.strip() for p in current.split(os.pathsep) if p.strip()]
    kept = [e for e in entries if e != target and agent_discovery.validate_trusted_prefix(e)[0] != resolved]
    config_changed = len(kept_config) != len(config_entries)
    dotenv_changed = len(kept) != len(entries)
    if dotenv_changed:
        new_val = os.pathsep.join(kept)
        if new_val:
            existing["DEFENSECLAW_TRUSTED_BIN_PREFIXES"] = new_val
        else:
            existing.pop("DEFENSECLAW_TRUSTED_BIN_PREFIXES", None)

    removed = config_changed or dotenv_changed
    try:
        if dotenv_changed:
            _write_dotenv_locked(dotenv_path, existing)
        if config_changed:
            _set_config_trusted_bin_prefixes(app.cfg, kept_config, locked_path=config_file)
    except BaseException:
        rollback_error = None
        if dotenv_changed:
            try:
                _restore_dotenv_snapshot(dotenv_path, dotenv_snapshot, dotenv_mode)
            except BaseException as exc:
                if rollback_error is None:
                    rollback_error = exc
        if config_changed:
            ai = getattr(app.cfg, "ai_discovery", None)
            if ai is not None:
                ai.trusted_binary_prefixes = config_entries
        if rollback_error is not None:
            raise rollback_error
        raise
    return removed


def _emit_untrusted_prefix_setup_hints(resolved_binary: str, parent: str) -> None:
    """Actionable remediation when action-mode setup cannot probe a connector binary."""
    ux.subhead(f"  Binary resolves to: {resolved_binary}")
    ux.subhead(f"  Trust it with: defenseclaw setup trusted-paths add {parent}")
    ux.subhead("  `trusted-paths add` writes ~/.defenseclaw/config.yaml (ai_discovery.trusted_binary_prefixes).")


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
@click.option(
    "--llm-provider",
    default=None,
    type=click.Choice(["anthropic", "openai"]),
    help="LLM provider (anthropic or openai)",
)
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
    llm_provider,
    llm_model,
    scan_prompts,
    scan_resources,
    scan_instructions,
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

        ux.section("Verifying scanner configuration")
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
        app.logger.log_action(ACTION_SETUP_MCP_SCANNER, "config", " ".join(parts))


def _interactive_mcp_setup(mc, cfg) -> None:
    # Read model presence from the unified llm: block so the "enable
    # LLM analyzer?" default tracks whatever the shared config already
    # holds, regardless of which scanner first populated it.
    llm = cfg.llm
    aid = cfg.cisco_ai_defense

    click.echo()
    ux.section("MCP Scanner Configuration")
    click.echo(f"  {ux.dim('Binary:')} {mc.binary}")
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


@dataclass(frozen=True, repr=False)
class _RotateTokenDotenvSnapshot:
    existed: bool
    body: bytes
    mode: int | None


@dataclass(repr=False)
class _PendingGuardrailSecret:
    """One local-only judge secret awaiting the guardrail commit boundary."""

    env_name: str
    value: str

    def clear(self) -> None:
        self.value = ""


@dataclass(repr=False)
class _GuardrailSecretKeyTransaction:
    """Exact, local-only custody for one transaction-owned secret key."""

    env_name: str
    dotenv_before_existed: bool
    dotenv_before_value: bytes | None
    dotenv_published_value: bytes
    dotenv_changed: bool
    process_before_existed: bool = False
    process_before_value: str | None = None
    process_published_value: str = ""
    process_changed: bool = False

    def clear(self) -> None:
        self.dotenv_before_value = None
        self.dotenv_published_value = b""
        self.process_before_value = None
        self.process_published_value = ""


@dataclass(repr=False)
class _GuardrailSecretTransaction:
    """Secret-safe exact rollback state for one guardrail publication."""

    dotenv_path: str
    dotenv_before: _RotateTokenDotenvSnapshot
    dotenv_after: _RotateTokenDotenvSnapshot
    dotenv_after_sha256: str
    dotenv_after_authoritative: bool
    keys: tuple[_GuardrailSecretKeyTransaction, ...]

    def clear(self) -> None:
        for key in self.keys:
            key.clear()
        self.dotenv_before = _RotateTokenDotenvSnapshot(False, b"", None)
        self.dotenv_after = _RotateTokenDotenvSnapshot(False, b"", None)
        self.dotenv_after_sha256 = ""
        self.dotenv_after_authoritative = False


@dataclass(frozen=True, repr=False)
class _GuardrailSecretRollbackStatus:
    """Bounded, secret-free result of a compare-before-restore rollback."""

    codes: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.codes


class _GuardrailSecretFailure(click.ClickException):
    """Public-safe sentinel with no retained secret-bearing exception."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"guardrail secret transaction failed safely ({code})")


def _clear_pending_guardrail_secrets(pending_secrets: list[_PendingGuardrailSecret]) -> None:
    for pending in pending_secrets:
        pending.clear()
    pending_secrets.clear()


def _guardrail_secret_rollback_status(*codes: str) -> _GuardrailSecretRollbackStatus:
    return _GuardrailSecretRollbackStatus(tuple(dict.fromkeys(code for code in codes if code)))


def _guardrail_dotenv_snapshot_sha256(snapshot: _RotateTokenDotenvSnapshot) -> str:
    digest = hashlib.sha256()
    digest.update(b"1" if snapshot.existed else b"0")
    digest.update(b"\0")
    digest.update(str(snapshot.mode if snapshot.mode is not None else -1).encode("ascii"))
    digest.update(b"\0")
    digest.update(snapshot.body)
    return digest.hexdigest()


def _guardrail_dotenv_snapshot_matches(
    current: _RotateTokenDotenvSnapshot,
    expected: _RotateTokenDotenvSnapshot,
    expected_sha256: str,
) -> bool:
    return current == expected and _guardrail_dotenv_snapshot_sha256(current) == expected_sha256


def _dotenv_snapshot_raw_key_state(
    snapshot: _RotateTokenDotenvSnapshot,
    key: str,
) -> tuple[bool, bytes | None]:
    """Return the last exact raw value for *key* without exposing it."""

    key_bytes = key.encode("ascii")
    requested_key = key_bytes.upper() if os.name == "nt" else key_bytes
    found = False
    value: bytes | None = None
    for line in snapshot.body.splitlines():
        candidate = line.strip()
        existing_key, separator, existing_value = candidate.partition(b"=")
        compared_key = existing_key.strip()
        if os.name == "nt":
            compared_key = compared_key.upper()
        if separator and compared_key == requested_key:
            found = True
            value = existing_value
    return found, value


def _dotenv_restore_raw_key_render(
    snapshot: _RotateTokenDotenvSnapshot,
    key: str,
    existed: bool,
    value: bytes | None,
) -> bytes:
    """Restore one owned key while retaining every unrelated current byte."""

    key_bytes = key.encode("ascii")
    requested_key = key_bytes.upper() if os.name == "nt" else key_bytes
    restored = False
    lines: list[bytes] = []
    for line in snapshot.body.splitlines(keepends=True):
        candidate = line.rstrip(b"\r\n").strip()
        existing_key, separator, _existing_value = candidate.partition(b"=")
        compared_key = existing_key.strip()
        if os.name == "nt":
            compared_key = compared_key.upper()
        if not separator or compared_key != requested_key:
            lines.append(line)
            continue
        if existed and not restored:
            terminator = line[len(line.rstrip(b"\r\n")) :]
            lines.append(key_bytes + b"=" + (value or b"") + terminator)
            restored = True
    body = b"".join(lines)
    if existed and not restored:
        newline = b"\r\n" if b"\r\n" in snapshot.body else b"\n"
        if body and not body.endswith((b"\r", b"\n")):
            body += newline
        body += key_bytes + b"=" + (value or b"") + newline
    return body


def _set_guardrail_secret_process_value(env_name: str, value: str) -> None:
    os.environ[env_name] = value


def _restore_guardrail_secret_transaction(
    transaction: _GuardrailSecretTransaction,
) -> _GuardrailSecretRollbackStatus:
    """Compare-before-restore only state still owned by this transaction."""

    status_codes: list[str] = []
    try:
        with locked_file_update(transaction.dotenv_path):
            current = _rotate_token_snapshot_locked(transaction.dotenv_path)
            if transaction.dotenv_after_authoritative and _guardrail_dotenv_snapshot_matches(
                current,
                transaction.dotenv_after,
                transaction.dotenv_after_sha256,
            ):
                _rotate_token_restore_locked(
                    transaction.dotenv_path,
                    transaction.dotenv_before,
                )
            else:
                restored = current
                for key in transaction.keys:
                    if not key.dotenv_changed:
                        continue
                    current_existed, current_value = _dotenv_snapshot_raw_key_state(
                        restored,
                        key.env_name,
                    )
                    if not current_existed or current_value != key.dotenv_published_value:
                        status_codes.append("dotenv-owned-key-conflict")
                        continue
                    restored = _RotateTokenDotenvSnapshot(
                        existed=True,
                        body=_dotenv_restore_raw_key_render(
                            restored,
                            key.env_name,
                            key.dotenv_before_existed,
                            key.dotenv_before_value,
                        ),
                        mode=restored.mode,
                    )
                if restored.body != current.body:
                    atomic_write_private_bytes(transaction.dotenv_path, restored.body)
                    if os.name != "nt" and current.mode is not None:
                        os.chmod(transaction.dotenv_path, current.mode)
    except BaseException:  # Restore process keys even when file custody fails.
        status_codes.append("dotenv-rollback-error")
    for key in transaction.keys:
        if not key.process_changed:
            continue
        try:
            current_existed = key.env_name in os.environ
            current_value = os.environ.get(key.env_name)
            if not current_existed or current_value != key.process_published_value:
                status_codes.append("process-owned-key-conflict")
                continue
            if key.process_before_existed and key.process_before_value is not None:
                os.environ[key.env_name] = key.process_before_value
            else:
                os.environ.pop(key.env_name, None)
        except BaseException:  # Restore every changed key independently.
            status_codes.append("process-rollback-error")
    transaction.clear()
    return _guardrail_secret_rollback_status(*status_codes)


def _publish_pending_guardrail_secrets(
    pending_secrets: list[_PendingGuardrailSecret],
    data_dir: str,
) -> _GuardrailSecretTransaction | None:
    """Atomically publish deferred judge secrets and return rollback custody."""

    if not pending_secrets:
        return None
    dotenv_path = os.path.join(data_dir, ".env")
    updates: tuple[tuple[str, str], ...] = ()
    dotenv_before: _RotateTokenDotenvSnapshot | None = None
    dotenv_after: _RotateTokenDotenvSnapshot | None = None
    dotenv_after_authoritative = False
    key_transactions: list[_GuardrailSecretKeyTransaction] = []
    publication_failed = False
    try:
        updates = tuple(
            (
                pending.env_name,
                sanitize_dotenv_value(pending.value, key=pending.env_name),
            )
            for pending in pending_secrets
        )
        with locked_file_update(dotenv_path):
            dotenv_before = _rotate_token_snapshot_locked(dotenv_path)
            for env_name, value in updates:
                before_existed, before_value = _dotenv_snapshot_raw_key_state(
                    dotenv_before,
                    env_name,
                )
                published_value = value.encode("utf-8")
                key_transactions.append(
                    _GuardrailSecretKeyTransaction(
                        env_name=env_name,
                        dotenv_before_existed=before_existed,
                        dotenv_before_value=before_value,
                        dotenv_published_value=published_value,
                        dotenv_changed=(not before_existed or before_value != published_value),
                        process_published_value=value,
                    )
                )
            try:
                _save_secrets_to_dotenv_locked(
                    dotenv_path,
                    dotenv_before,
                    updates,
                )
            except BaseException:
                publication_failed = True
            try:
                dotenv_after = _rotate_token_snapshot_locked(dotenv_path)
                dotenv_after_authoritative = True
            except BaseException:
                publication_failed = True
    except BaseException:
        publication_failed = True
    if publication_failed and dotenv_before is not None and dotenv_after is None:
        try:
            with locked_file_update(dotenv_path):
                dotenv_after = _rotate_token_snapshot_locked(dotenv_path)
        except BaseException:
            dotenv_after = None
    transaction: _GuardrailSecretTransaction | None = None
    if dotenv_before is not None and dotenv_after is not None:
        if publication_failed:
            for key in key_transactions:
                after_existed, after_value = _dotenv_snapshot_raw_key_state(
                    dotenv_after,
                    key.env_name,
                )
                key.dotenv_changed = bool(
                    key.dotenv_changed and after_existed and after_value == key.dotenv_published_value
                )
        transaction = _GuardrailSecretTransaction(
            dotenv_path=dotenv_path,
            dotenv_before=dotenv_before,
            dotenv_after=dotenv_after,
            dotenv_after_sha256=_guardrail_dotenv_snapshot_sha256(dotenv_after),
            dotenv_after_authoritative=dotenv_after_authoritative,
            keys=tuple(key_transactions),
        )
    if not publication_failed and transaction is not None:
        for key in transaction.keys:
            key.process_before_existed = key.env_name in os.environ
            key.process_before_value = os.environ.get(key.env_name)
            if key.process_before_existed and key.process_before_value == key.process_published_value:
                continue
            process_update_failed = False
            try:
                _set_guardrail_secret_process_value(
                    key.env_name,
                    key.process_published_value,
                )
            except BaseException:
                process_update_failed = True
            key.process_changed = bool(
                key.env_name in os.environ and os.environ.get(key.env_name) == key.process_published_value
            )
            if process_update_failed:
                publication_failed = True
                break
    if publication_failed or transaction is None:
        rollback_status = _guardrail_secret_rollback_status("publication-custody-unavailable")
        if transaction is not None:
            try:
                rollback_status = _restore_guardrail_secret_transaction(transaction)
            except BaseException:
                rollback_status = _guardrail_secret_rollback_status("publication-rollback-error")
        _clear_pending_guardrail_secrets(pending_secrets)
        failure_code = (
            "publication-failed-restored" if rollback_status.complete else "publication-failed-rollback-incomplete"
        )
        raise _GuardrailSecretFailure(failure_code) from None
    _clear_pending_guardrail_secrets(pending_secrets)
    return transaction


def _rotate_token_snapshot_locked(dotenv_path: str) -> _RotateTokenDotenvSnapshot:
    """Capture the exact dotenv bytes while the caller owns its lock."""

    if not os.path.lexists(dotenv_path):
        return _RotateTokenDotenvSnapshot(existed=False, body=b"", mode=None)
    reject_symlink(dotenv_path)
    info = os.lstat(dotenv_path)
    if not stat.S_ISREG(info.st_mode):
        raise click.ClickException("Gateway dotenv is not a regular file; refusing token rotation.")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(dotenv_path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(info, opened):
            raise click.ClickException("Gateway dotenv identity changed while opening; refusing token rotation.")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            body = stream.read(MAX_DOTENV_BYTES + 1)
            if len(body) > MAX_DOTENV_BYTES:
                raise click.ClickException(
                    f"Gateway dotenv exceeds the {MAX_DOTENV_BYTES}-byte safety limit; refusing token rotation."
                )
            return _RotateTokenDotenvSnapshot(
                existed=True,
                body=body,
                mode=stat.S_IMODE(opened.st_mode),
            )
    finally:
        if fd >= 0:
            os.close(fd)


def _dotenv_upsert_render(
    snapshot: _RotateTokenDotenvSnapshot,
    key: str,
    value: str,
) -> bytes:
    """Replace one dotenv key while retaining every unrelated byte."""
    if not dotenv_key_is_valid(key):
        raise DotenvValueError(f"invalid dotenv key: {key!r}")
    safe_value = sanitize_dotenv_value(value, key=key).encode("utf-8")
    key_bytes = key.encode("ascii")
    requested_key = key_bytes.upper() if os.name == "nt" else key_bytes
    replaced = False
    lines: list[bytes] = []
    for line in snapshot.body.splitlines(keepends=True):
        candidate = line.rstrip(b"\r\n").strip()
        existing_key, separator, _existing_value = candidate.partition(b"=")
        compared_key = existing_key.strip()
        if os.name == "nt":
            compared_key = compared_key.upper()
        if separator and compared_key == requested_key:
            if replaced:
                continue
            terminator = line[len(line.rstrip(b"\r\n")) :]
            lines.append(key_bytes + b"=" + safe_value + terminator)
            replaced = True
            continue
        lines.append(line)
    body = b"".join(lines)
    newline = b"\r\n" if b"\r\n" in snapshot.body else b"\n"
    if not replaced:
        if body and not body.endswith((b"\r", b"\n")):
            body += newline
        body += key_bytes + b"=" + safe_value + newline
    return body


def _save_secrets_to_dotenv_locked(
    dotenv_path: str,
    snapshot: _RotateTokenDotenvSnapshot,
    updates: tuple[tuple[str, str], ...],
) -> None:
    """Publish a validated dotenv batch once while the caller owns its lock."""

    rendered = snapshot
    for key, value in updates:
        rendered = _RotateTokenDotenvSnapshot(
            existed=True,
            body=_dotenv_upsert_render(rendered, key, value),
            mode=rendered.mode,
        )
    if not snapshot.existed or rendered.body != snapshot.body:
        atomic_write_private_bytes(dotenv_path, rendered.body)


def _rotate_token_render(snapshot: _RotateTokenDotenvSnapshot, new_token: str) -> bytes:
    """Canonicalize gateway-token lines and retain every unrelated byte.

    Once the canonical credential is rotated, retaining a legacy
    ``OPENCLAW_GATEWAY_TOKEN`` line leaves an exposed fallback credential on
    disk and can silently regain precedence after a later configuration edit.
    Remove both exact token keys (including duplicates), then append exactly
    one canonical value. Similar-looking unrelated keys remain byte-for-byte
    intact.
    """

    safe_token = sanitize_dotenv_value(new_token, key=_GATEWAY_TOKEN_ENV).encode("utf-8")
    token_prefix = (_GATEWAY_TOKEN_ENV + "=").encode("ascii")
    token_keys = {
        _GATEWAY_TOKEN_ENV.encode("ascii"),
        _LEGACY_GATEWAY_TOKEN_ENV.encode("ascii"),
    }

    def is_token_line(line: bytes) -> bool:
        candidate = line.rstrip(b"\r\n").strip()
        key, separator, _value = candidate.partition(b"=")
        if not separator:
            return False
        key = key.strip()
        if os.name == "nt":
            key = key.upper()
            return key in {candidate_key.upper() for candidate_key in token_keys}
        return key in token_keys

    lines = [line for line in snapshot.body.splitlines(keepends=True) if not is_token_line(line)]
    body = b"".join(lines)
    newline = b"\r\n" if b"\r\n" in snapshot.body else b"\n"
    if body and not body.endswith((b"\r", b"\n")):
        body += newline
    return body + token_prefix + safe_token + newline


def _rotate_token_restore_locked(
    dotenv_path: str,
    snapshot: _RotateTokenDotenvSnapshot,
) -> None:
    """Durably restore the exact pre-transaction dotenv bytes or absence."""

    if snapshot.existed:
        atomic_write_private_bytes(dotenv_path, snapshot.body)
        if os.name != "nt" and snapshot.mode is not None:
            os.chmod(dotenv_path, snapshot.mode)
        return
    if os.path.lexists(dotenv_path):
        reject_symlink(dotenv_path)
        delete_file_durable(dotenv_path)


def _rotate_token_atomic_write(dotenv_path: str, new_token: str) -> None:
    with locked_file_update(dotenv_path):
        _rotate_token_atomic_write_locked(dotenv_path, new_token)


def _rotate_token_atomic_write_locked(dotenv_path: str, new_token: str) -> None:
    """Rewrite the dotenv file with the new token, preserving every
    unrelated byte. Atomic and durable; mode 0o600.

    Uses the canonical key consumed by internal/gateway/firstboot.go while
    preserving the existing file's unrelated byte shape.
    """
    snapshot = _rotate_token_snapshot_locked(dotenv_path)
    atomic_write_private_bytes(dotenv_path, _rotate_token_render(snapshot, new_token))


def _restore_rotate_token_environment(snapshot: dict[str, str | None]) -> None:
    for name, value in snapshot.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _rotate_token_snapshot_value(snapshot: _RotateTokenDotenvSnapshot, name: str) -> str:
    """Return one named dotenv value without materializing unrelated entries."""

    expected = name.encode("ascii")
    value = b""
    for raw_line in snapshot.body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(b"#"):
            continue
        key, separator, candidate = line.partition(b"=")
        if not separator:
            continue
        key = key.strip()
        matches = key.upper() == expected if os.name == "nt" else key == expected
        if not matches:
            continue
        value = candidate.strip()
        if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {b'"', b"'"}:
            value = value[1:-1]
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise click.ClickException("Gateway dotenv token is not valid UTF-8; refusing token rotation.") from exc


def _rotate_token_previous_value(app: AppContext, snapshot: _RotateTokenDotenvSnapshot) -> str:
    """Resolve A using the daemon's dotenv-before-process precedence."""

    for name in (_GATEWAY_TOKEN_ENV, _LEGACY_GATEWAY_TOKEN_ENV):
        value = _rotate_token_snapshot_value(snapshot, name).strip()
        if value:
            return value
    for name in (_GATEWAY_TOKEN_ENV, _LEGACY_GATEWAY_TOKEN_ENV):
        value = str(os.environ.get(name, "") or "").strip()
        if value:
            return value
    return str(getattr(app.cfg.gateway, "token", "") or "").strip()


def _rotate_token_child_environment(data_dir: str, config_file: str, token: str) -> dict[str, str]:
    """Build the bounded lifecycle environment from individually named inputs."""

    child_env: dict[str, str] = {}
    for name in _TOKEN_ROTATION_CHILD_ENV_ALLOWLIST:
        value = os.environ.get(name)
        if value is not None:
            child_env[name] = value
    normalized_data_dir = os.path.abspath(data_dir)
    normalized_config_file = os.path.abspath(config_file)
    child_env[_DEFENSECLAW_HOME_ENV] = normalized_data_dir
    child_env[_DEFENSECLAW_DATA_DIR_ENV] = normalized_data_dir
    child_env[CONFIG_PATH_ENV] = normalized_config_file
    child_env[_GATEWAY_TOKEN_ENV] = token
    return child_env


@dataclass(frozen=True)
class _RotateTokenConnectorPolicy:
    name: str
    mode: str
    hook_fail_mode: str
    enabled: bool


def _rotate_token_connector_state(cfg: Any) -> str:
    """Serialize the complete configured connector posture for A/B verification."""

    if hasattr(cfg, "active_connectors"):
        configured = cfg.active_connectors()
    else:
        configured = [(getattr(getattr(cfg, "guardrail", None), "connector", "") or "").strip()]
    guardrail = getattr(cfg, "guardrail", None)
    policies: dict[str, _RotateTokenConnectorPolicy] = {}
    for raw in configured:
        name = normalize_connector(raw)
        if not name:
            continue
        if name in policies:
            continue

        mode_resolver = getattr(guardrail, "effective_mode", None)
        mode = (
            str(mode_resolver(name) or "").strip().lower()
            if callable(mode_resolver)
            else str(getattr(guardrail, "mode", "") or "observe").strip().lower()
        )
        fail_mode_resolver = getattr(guardrail, "effective_hook_fail_mode", None)
        if callable(fail_mode_resolver):
            hook_fail_mode = str(fail_mode_resolver(name) or "").strip().lower()
        else:
            configured_fail_mode = str(getattr(guardrail, "hook_fail_mode", "") or "closed").strip().lower()
            hook_fail_mode = configured_fail_mode if mode == "action" else "open"
        enabled_resolver = getattr(guardrail, "effective_enabled", None)
        enabled = bool(enabled_resolver(name)) if callable(enabled_resolver) else True

        if mode not in {"observe", "action"} or hook_fail_mode not in {"open", "closed"}:
            raise click.ClickException("Configured connector posture is invalid; refusing token rotation.")
        policies[name] = _RotateTokenConnectorPolicy(name, mode, hook_fail_mode, enabled)

    payload = {
        "version": 1,
        "connectors": [
            {
                "name": policy.name,
                "mode": policy.mode,
                "hook_fail_mode": policy.hook_fail_mode,
                "enabled": policy.enabled,
            }
            for policy in sorted(policies.values(), key=lambda policy: policy.name)
        ],
    }
    return _json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _run_rotate_token_lifecycle(
    data_dir: str,
    action: str,
    *,
    token: str,
    config_file: str,
    connector_state: str | None = None,
    cleanup: bool = False,
) -> None:
    """Run one bounded lifecycle phase without placing a token on argv."""

    if action not in {"start", "stop"}:
        raise ValueError("unsupported token-rotation lifecycle action")
    if cleanup and action != "stop":
        raise ValueError("token-rotation cleanup is only valid for stop")
    executable = _gateway_lifecycle_executable()
    if not executable:
        raise click.ClickException("Gateway lifecycle executable was not found.")
    command = [executable, action, _TOKEN_ROTATION_TRANSACTION_FLAG]
    if cleanup:
        command.append(_TOKEN_ROTATION_CLEANUP_FLAG)
    if action == "start":
        if not connector_state:
            raise ValueError("token-rotation start requires the authoritative connector state")
        command.extend([_TOKEN_ROTATION_CONNECTOR_STATE_FLAG, connector_state])
    elif connector_state is not None:
        raise ValueError("token-rotation connector state is only valid for start")
    child_env = _rotate_token_child_environment(data_dir, config_file, token)
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=child_env,
            timeout=_TOKEN_ROTATION_LIFECYCLE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise click.ClickException(f"Gateway {action} timed out during the token-rotation transaction.") from exc
    except OSError as exc:
        raise click.ClickException(
            f"Gateway {action} could not be executed during the token-rotation transaction."
        ) from exc
    if result.returncode != 0:
        # The child output is deliberately not replayed: lifecycle diagnostics
        # are not a trusted secret-redaction boundary.
        raise click.ClickException(f"Gateway {action} failed during the token-rotation transaction.")

    try:
        ctx = click.get_current_context(silent=True)
    except RuntimeError:
        ctx = None
    if ctx is not None:
        ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True


def _rotate_token_transaction(
    app: AppContext,
    dotenv_path: str,
    new_token: str,
    audit_details: str,
    *,
    recover_previous_runtime: bool = True,
) -> None:
    """Commit token B only between verified stop(A) and start(B).

    Normal operator-initiated rotation restores ready gateway A if B cannot
    activate. Doctor passes ``recover_previous_runtime=False`` when A's token
    was already exposed: the exact files are still restored for operator
    recovery, but the compromised runtime is deliberately left stopped.
    """

    data_dir = os.path.abspath(app.cfg.data_dir or os.path.dirname(dotenv_path))
    config_file = os.path.abspath(str(config_path_for_data_dir(data_dir)))
    environment_before = {_GATEWAY_TOKEN_ENV: os.environ.get(_GATEWAY_TOKEN_ENV)}

    # PR #444 later centralizes daemon config loading. Integration must retain
    # this on-disk A/B boundary: stop loads config+dotenv A, while start reloads
    # config+dotenv B under the explicit data directory. Do not reuse a
    # post-commit loader result for the authenticated stop phase.
    with locked_config_yaml(config_file), locked_file_update(dotenv_path):
        config_snapshot, config_mode = _snapshot_regular_file(config_file, what="gateway config")
        authoritative_cfg = load_config(data_dir=data_dir)
        current_config, current_mode = _snapshot_regular_file(config_file, what="gateway config")
        if current_config != config_snapshot or current_mode != config_mode:
            raise click.ClickException("Gateway configuration changed while token rotation was taking its snapshot.")
        connector_state = _rotate_token_connector_state(authoritative_cfg)
        snapshot = _rotate_token_snapshot_locked(dotenv_path)
        old_token = _rotate_token_previous_value(app, snapshot)
        pid_file = os.path.join(data_dir, "gateway.pid")
        was_running = _is_pid_alive(pid_file)
        old_stopped = False
        mutation_attempted = False
        try:
            try:
                _run_rotate_token_lifecycle(data_dir, "stop", token=old_token, config_file=config_file)
            except BaseException as stop_error:
                # The bounded child may fail after it has completed shutdown
                # (for example while verifying listener release). If A's
                # authenticated PID disappeared, restore and readiness-check A
                # before returning without ever committing B.
                if was_running and not _is_pid_alive(pid_file) and recover_previous_runtime:
                    try:
                        _run_rotate_token_lifecycle(
                            data_dir,
                            "start",
                            token=old_token,
                            config_file=config_file,
                            connector_state=connector_state,
                        )
                    except BaseException:
                        raise click.ClickException(
                            "Token rotation stopped gateway A before the transaction could commit; "
                            "gateway A did not return to verified readiness."
                        ) from stop_error
                raise
            old_stopped = True

            mutation_attempted = True
            atomic_write_private_bytes(dotenv_path, _rotate_token_render(snapshot, new_token))
            os.environ[_GATEWAY_TOKEN_ENV] = new_token

            _run_rotate_token_lifecycle(
                data_dir,
                "start",
                token=new_token,
                config_file=config_file,
                connector_state=connector_state,
            )
            current_config, current_mode = _snapshot_regular_file(config_file, what="gateway config")
            if current_config != config_snapshot or current_mode != config_mode:
                raise click.ClickException("Gateway configuration changed during token rotation.")
            _log_setup_action(
                app,
                ACTION_SETUP_GATEWAY,
                audit_details,
                allow_offline=False,
            )
        except BaseException as primary_error:
            if not old_stopped:
                raise

            if mutation_attempted:
                try:
                    # Reconcile a READY replacement (including a watchdog-start
                    # failure) while B is still the durable authentication state.
                    _run_rotate_token_lifecycle(
                        data_dir,
                        "stop",
                        token=new_token,
                        config_file=config_file,
                        cleanup=True,
                    )
                except BaseException:
                    raise click.ClickException(
                        "Token rotation failed and the replacement gateway could not be "
                        "safely stopped; token B was preserved on disk."
                    ) from primary_error

            try:
                _rotate_token_restore_locked(dotenv_path, snapshot)
            except BaseException:
                raise click.ClickException(
                    "Token rotation failed and the exact prior dotenv snapshot could not "
                    "be restored; the gateway remains stopped."
                ) from primary_error

            try:
                current_config, current_mode = _snapshot_regular_file(config_file, what="gateway config")
                if current_config != config_snapshot or current_mode != config_mode:
                    _restore_regular_file_snapshot(
                        config_file,
                        config_snapshot,
                        config_mode,
                        what="gateway config",
                    )
            except BaseException:
                raise click.ClickException(
                    "Token rotation failed and the exact prior gateway configuration could not be restored; "
                    "the gateway remains stopped."
                ) from primary_error

            _restore_rotate_token_environment(environment_before)
            if was_running and recover_previous_runtime:
                try:
                    _run_rotate_token_lifecycle(
                        data_dir,
                        "start",
                        token=old_token,
                        config_file=config_file,
                        connector_state=connector_state,
                    )
                except BaseException:
                    raise click.ClickException(
                        "Token rotation failed; the exact prior dotenv snapshot was restored, "
                        "but gateway A did not return to verified readiness."
                    ) from primary_error
            raise
        finally:
            _restore_rotate_token_environment(environment_before)


@setup.command("rotate-token")
@click.option(
    "--connector",
    default=None,
    help="Optional presentation hint (the token is shared, so ALL active connectors are refreshed).",
)
@click.option(
    "--no-restart",
    is_flag=True,
    help="Deprecated unsafe mode; retained only to return a fail-closed migration error.",
)
@click.option(
    "--yes",
    is_flag=True,
    help="Skip the confirmation prompt and rotate immediately.",
)
@pass_ctx
def rotate_token_cmd(app: AppContext, connector: str | None, no_restart: bool, yes: bool) -> None:
    """Rotate the DEFENSECLAW_GATEWAY_TOKEN.

    Generates a new 32-byte CSPRNG hex token, verifies and stops gateway A
    with token/config A, durably commits ~/.defenseclaw/.env B, then starts
    and verifies gateway B. Any post-stop failure restores the exact dotenv
    snapshot and the prior ready generation.

    The token is a single shared secret baked into every connector's hook
    scripts, so rotation is inherently global: refreshing only one
    connector would leave the others authenticating with the now-invalid
    old token. On a multi-connector install all active connectors are
    refreshed in one restart.

    Plan B5 / S0.5.
    """
    import secrets

    dotenv_path = _rotate_token_dotenv_path(app)
    if no_restart:
        raise click.ClickException(
            "--no-restart is not safe for token rotation; the daemon must cross the verified A/B lifecycle boundary."
        )
    token_env = str(getattr(app.cfg.gateway, "token_env", "") or "").strip()
    canonical_token_env = (
        token_env.casefold() == _GATEWAY_TOKEN_ENV.casefold() if os.name == "nt" else token_env == _GATEWAY_TOKEN_ENV
    )
    if token_env and not canonical_token_env:
        raise click.ClickException(
            "Token rotation requires gateway.token_env to be unset or DEFENSECLAW_GATEWAY_TOKEN; "
            "an externally managed token environment cannot be durably rotated here."
        )

    # ``active_connectors`` is the authoritative configured roster.  The
    # command-line connector is only a restart presentation hint: treating it
    # as configuration could refresh an inactive connector while leaving the
    # real hook token stale.  Older config facades without the roster API may
    # fall back to their singular configured connector, but an explicitly
    # empty roster remains empty.
    if hasattr(app.cfg, "active_connectors"):
        configured = app.cfg.active_connectors()
    else:
        configured = [(getattr(app.cfg.guardrail, "connector", "") or "").strip()]
    actives: list[str] = []
    for raw in configured:
        active = normalize_connector(raw)
        if active and active not in actives:
            actives.append(active)

    requested_hint = normalize_connector(connector)
    if requested_hint and requested_hint not in actives:
        click.echo(f"  Ignoring inactive connector restart hint {connector!r}.")

    if not yes:
        scope = ", ".join(actives) if actives else "no active connector"
        click.confirm(
            f"This will rotate DEFENSECLAW_GATEWAY_TOKEN in {dotenv_path}\n"
            f"and restart the gateway so every active connector ({scope}) re-bakes\n"
            "the new token into its hook scripts. Continue?",
            abort=True,
        )

    new_token = secrets.token_hex(32)
    audit_details = f"action=rotate-token active_connectors={len(actives)} restart=true"
    target_summary = ", ".join(actives) if actives else "no active connectors"
    click.echo(f"  {ux.dim('Rotating gateway token for')} {target_summary}…")
    _rotate_token_transaction(app, dotenv_path, new_token, audit_details)

    ux.ok(f"Rotated DEFENSECLAW_GATEWAY_TOKEN in {dotenv_path} (mode 0o600); gateway B is verified ready.")
    if actives:
        ux.ok(f"Hook scripts refreshed for {len(actives)} active connector(s).")
    else:
        ux.subhead("active connector roster: none")
    click.echo()
    ux.subhead("Next step: restart each agent so it picks up the new token in its")
    ux.subhead("inspect / hook subprocess invocations.")


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
    host,
    port,
    api_port,
    token,
    ssm_param,
    ssm_region,
    ssm_profile,
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

        ux.section("Verifying gateway connectivity")
        r = _DoctorResult()
        _check_openclaw_gateway(app.cfg, r)
        _check_sidecar(app.cfg, r)
        click.echo()
        if r.failed:
            click.echo("  Tip: fix the issues above, then run 'defenseclaw doctor' to re-check.")
            click.echo()

    if app.logger:
        mode = "remote" if (remote or gw.resolved_token()) else "local"
        app.logger.log_action(ACTION_SETUP_GATEWAY, "config", f"mode={mode} host={gw.host} port={gw.port}")


def _interactive_gateway_local(gw, openclaw_config_file: str, data_dir: str) -> None:
    click.echo()
    ux.section("Gateway Configuration (local)")
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
    ux.section("Gateway Configuration (remote)")
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
        "aws",
        "ssm",
        "get-parameter",
        "--name",
        param,
        "--with-decryption",
        "--query",
        "Parameter.Value",
        "--output",
        "text",
        "--region",
        region,
    ]
    if profile:
        cmd.extend(["--profile", profile])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_DEFENSE_GATEWAY_LIFECYCLE_TIMEOUT_SECONDS,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


# ---------------------------------------------------------------------------
# Connector metadata (mirrors internal/gateway/connector/*.go)
# ---------------------------------------------------------------------------

_CONNECTOR_NAMES_FALLBACK = [
    "openclaw",
    "zeptoclaw",
    "claudecode",
    "codex",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
    "amp",
    "omnigent",
]


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
        return platform_support.supported_connectors(_CONNECTOR_NAMES_FALLBACK)
    try:
        url = f"http://{host}:{port}/v1/connectors"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = _json.loads(resp.read())
            names = [c.get("name") or c.get("id") for c in data.get("connectors", [])]
            resolved = [n for n in names if n] or list(_CONNECTOR_NAMES_FALLBACK)
            return platform_support.supported_connectors(resolved)
    except Exception:
        return platform_support.supported_connectors(_CONNECTOR_NAMES_FALLBACK)


_CONNECTOR_NAMES = platform_support.supported_connectors(_CONNECTOR_NAMES_FALLBACK)
_HILT_MIN_SEVERITIES = ["HIGH", "MEDIUM", "LOW", "CRITICAL"]


class _PlatformConnectorChoice(click.Choice):
    """Hide unsupported choices while returning their reason on explicit use."""

    def convert(
        self,
        value: Any,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> Any:
        if isinstance(value, str):
            connector = normalize_connector(value)
            if connector in _CONNECTOR_NAMES_FALLBACK:
                support = platform_support.connector_platform_support(connector)
                if not support.available:
                    self.fail(
                        f"connector {connector!r} is {support.status} on "
                        f"{platform_support.host_os()}: {support.reason}",
                        param,
                        ctx,
                    )
        return super().convert(value, param, ctx)


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
        "description": "native owned hook matrix + OTLP env",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "codex": {
        "label": "Codex",
        "description": "env var + hook script + response-scan",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "hermes": {
        "label": "Hermes",
        "description": "config.yaml hooks (JSON block; fail-open) + MCP/skills/plugin inventory",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "cursor": {
        "label": "Cursor",
        "description": "user hooks with event-scoped deny + bounded local inventory",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "windsurf": {
        "label": "Devin Desktop — legacy Cascade",
        "description": "legacy Cascade-only hooks + bounded local customization discovery",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "geminicli": {
        "label": "Gemini CLI",
        "description": (
            "enterprise/Google Cloud/paid API-key settings.json hooks + "
            "native OTLP + extensions"
        ),
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "copilot": {
        "label": "GitHub Copilot CLI",
        "description": "~/.copilot/hooks command hooks by default; optional .github/hooks workspace override",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "openhands": {
        "label": "OpenHands",
        "description": "~/.openhands/hooks.json command hooks by default; optional repo-local override",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "antigravity": {
        "label": "Antigravity",
        "description": (
            "five lifecycle hooks in ~/.gemini/config/hooks.json; only "
            "PreToolUse has documented native ask and deny responses"
        ),
        "tool_mode": "pre-execution",
        "subprocess_policy": "none",
    },
    "opencode": {
        "label": "OpenCode",
        "description": ("auto-loaded JS bridge plugin (~/.config/opencode/plugins); tool.execute.before blocking"),
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "amp": {
        "label": "Amp",
        "description": "system TypeScript policy plugin with synchronous tool.call allow/confirm/block verdicts",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
    "omnigent": {
        "label": "OmniGent",
        "description": "custom Python policy bridge with ALLOW/ASK/DENY and optional native OTLP",
        "tool_mode": "both",
        "subprocess_policy": "none",
    },
}


def _connector_presentation_label(connector: str) -> str:
    """Return the connector label with an explicit preview marker."""
    label = _CONNECTOR_META.get(connector, {}).get("label", connector)
    if platform_support.connector_preview_on_os(connector):
        return f"{label} (preview)"
    return label


def _ensure_connector_available(connector: str) -> None:
    """Reject an unsupported host/connector pair with its recorded reason."""
    support = platform_support.connector_platform_support(connector)
    if not support.available:
        raise click.ClickException(
            f"connector {connector!r} is {support.status} on {platform_support.host_os()}: {support.reason}"
        )


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
        "Optional CodeGuard native plugin only when explicitly installed",
        "~/.defenseclaw/hooks/",
    ),
    "codex": (
        "~/.codex/config.toml hooks / features.hooks / hook trust state",
        "~/.codex/config.toml otel / notify",
        "Optional CodeGuard native skill only when explicitly installed",
        "~/.defenseclaw/hooks/ (including owner-only scoped OTLP credential) and notify bridge files",
    ),
    "hermes": (
        (
            "HERMES_HOME/config.yaml hooks (defaults to "
            "%LOCALAPPDATA%\\hermes\\config.yaml on Windows and "
            "~/.hermes/config.yaml elsewhere)"
        ),
        "HERMES_HOME/config.yaml MCP entries when configured explicitly",
        "HERMES_HOME/skills and HERMES_HOME/plugins discovery/install surfaces",
        "DefenseClaw's platform-native hook runtime and connector-scoped token files",
    ),
    "cursor": (
        "~/.cursor/hooks.json hooks",
        "<workspace>/.cursor/mcp.json MCP entries when configured explicitly",
        (
            "Recursive project/user .cursor/.agents skills plus documented "
            ".claude/.codex compatibility roots"
        ),
        "<workspace>/.cursor/rules/**/*.mdc and root/nested AGENTS.md",
        (
            "Existing ~/.cursor/plugins/local plugins and user/project "
            ".cursor/.claude/.codex agents are inventoried read-only"
        ),
        (
            "~/.defenseclaw/hooks/cursor-hook.ps1 on Windows; "
            "~/.defenseclaw/hooks/cursor-hook.sh on non-Windows"
        ),
    ),
    "windsurf": (
        "Legacy Cascade only: ~/.codeium/windsurf/hooks.json hooks",
        "Bound-user MCP plus non-enterprise Cascade rules/skills are discovered read-only",
        "Devin Local/default-agent, cloud, ACP, and managed/ProgramData layers remain unsupported",
    ),
    "geminicli": (
        "~/.gemini/settings.json hooks (continuing enterprise/Google Cloud/paid API-key product only)",
        "~/.gemini/settings.json native OTLP telemetry and MCP entries",
        "<workspace>/.gemini/skills, extensions, and agents install surfaces",
        "~/.defenseclaw/hooks/geminicli-hook.sh (supported non-Windows hosts only)",
    ),
    "copilot": (
        "~/.copilot/hooks/defenseclaw.json hooks by default",
        "<workspace>/.github/hooks/defenseclaw.json hooks only when --workspace is provided",
        "~/.copilot/mcp-config.json MCP entries; optional workspace .github/mcp.json with --workspace",
        "~/.copilot/skills and ~/.copilot/agents install surfaces; optional workspace surfaces with --workspace",
        "Native OTLP env vars are documented for the process env; shell rc files are not mutated",
        "~/.defenseclaw/hooks/copilot-hook.sh",
    ),
    "openhands": (
        "~/.openhands/hooks.json hooks by default",
        "<workspace>/.openhands/hooks.json hooks only when --workspace is provided",
        "~/.openhands/mcp.json MCP entries when configured explicitly",
        (
            "~/.agents/skills install surface and ~/.openhands/cache/skills/"
            "public-skills/skills discovery by default; workspace .agents/skills "
            "only when --workspace is provided"
        ),
        "~/.defenseclaw/hooks/openhands-hook.sh",
    ),
    "antigravity": (
        (
            "~/.gemini/config/hooks.json — five DefenseClaw-owned registrations "
            "using Antigravity's documented direct-list and matcher-group shapes; "
            "the host separately discovers <workspace>/.agents/hooks.json, so "
            "DefenseClaw owns only the global registration"
        ),
        "~/.defenseclaw/hooks/antigravity-hook.sh",
    ),
    "opencode": (
        (
            "~/.config/opencode/plugins/defenseclaw.js — DefenseClaw bridge "
            "plugin auto-loaded by opencode; no opencode.json edit and no "
            "shell-hook config patch"
        ),
    ),
    "amp": (
        (
            "~/.config/amp/plugins/defenseclaw.ts — owner-only system "
            "policy plugin loaded by Amp on macOS, Linux, and native Windows"
        ),
        (
            "~/.config/amp/settings.json or settings.jsonc, "
            "<workspace>/.amp/settings.json or settings.jsonc, "
            "and OS enterprise managed-settings.json are discovery-only"
        ),
        (
            "Amp-native amp.permissions, amp.guardedFiles.allowlist, "
            "amp.dangerouslyAllowAll, and amp.mcpPermissions are reported but never mutated"
        ),
        (
            "AGENTS.md guidance and .agents/checks / global checks are "
            "discovered read-only; DefenseClaw does not rewrite them"
        ),
        "Amp MCP registrations are discovered read-only; manage them with `amp mcp add`",
    ),
    "omnigent": (
        "OmniGent's effective config.yaml policy_modules and server-wide policies",
        "~/.defenseclaw/hooks/defenseclaw_omnigent_policy.py",
        "OmniGent Python environment defenseclaw_omnigent.pth import-path file",
        "Optional native OTLP uses documented process environment variables; shell startup files are not modified",
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
    surfaces = _CONNECTOR_CHANGE_SURFACES.get(connector, ())
    if connector == "windsurf":
        hook_surface = (
            "~/.defenseclaw/hooks/windsurf-hook.ps1 on Windows"
            if platform_support.host_os() == "windows"
            else "~/.defenseclaw/hooks/windsurf-hook.sh on non-Windows"
        )
        surfaces = (*surfaces, hook_surface)
    for surface in surfaces:
        click.echo(f"    - {surface}")
    click.echo(
        "  A hash-checked backup is stored before edits; teardown restores or surgically removes only "
        "DefenseClaw-owned entries."
    )


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


def _detect_installed_connectors() -> list[str]:
    """Return verified installed applications in discovery precedence order.

    A connector config file is configuration evidence, not installation
    evidence.  Reuse the shared discovery model so setup, quickstart, and
    ``agent discover`` cannot disagree about that distinction.
    """
    # Setup/quickstart must reflect applications installed since the last
    # inventory cache was written, so always perform a fresh shared scan.
    disc = agent_discovery.discover_agents(use_cache=False)
    order = getattr(agent_discovery, "DISCOVERY_PRECEDENCE", ()) or tuple(disc.agents)
    found = [name for name in order if name in disc.agents and disc.agents[name].installed]
    return platform_support.supported_connectors(found)


def _detect_connector(data_dir: str | None = None) -> str | None:
    """Guess the active agent framework, preferring the install-time hint.

    Resolution order:
      1. ``<data_dir>/picked_connector`` (written by ``scripts/install.sh
         --connector ...``) — the operator's explicit choice at install
         time.
      2. Shared verified application discovery — the highest-priority
         installed agent (see ``_detect_installed_connectors``).

    Returns ``None`` when neither source is conclusive so the caller
    can fall back to ``"openclaw"``.
    """
    picked = _read_picked_connector(data_dir)
    if picked:
        return picked
    installed = _detect_installed_connectors()
    return installed[0] if installed else None


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
        label = _connector_presentation_label(name)
        click.echo(f"    {i}. {label:<22s} — {meta['description']}{marker}")
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
    support = platform_support.connector_platform_support(name)
    click.echo(f"    Connector:         {_connector_presentation_label(name)} ({name})")
    # Keep the status visible even for stable connectors when this detail view
    # is explicitly requested; it makes preview classification auditable.
    click.echo(f"    Platform support:  {support.status} — {support.reason}")
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
        click.echo("      Tool calls are scanned in LLM responses only (response-scan mode).")
        click.echo("      DefenseClaw can block the response but cannot prevent individual")
        click.echo("      tool execution if the response has already been delivered.")


def _connector_not_detected_message(label: str) -> str:
    """SU-09: the one standard 'connector not detected locally' message.

    Both the hook-connector aliases and the proxy (openclaw/zeptoclaw)
    ``setup guardrail`` path run their setup-time install check through
    ``_check_connector_version_supported_for_setup``, so routing the message
    through this single helper makes it literally one standard string across
    both connector classes (decision: unify). The *operational* "openclaw CLI
    not found" surface during a gateway restart is deliberately left distinct:
    a proxy connector genuinely needs a running CLI/gateway to restart, which a
    hook connector does not — that is a different failure than "the agent isn't
    installed".
    """
    return f"{label}: connector was not detected locally; setup will write DefenseClaw config anyway."


def _connector_contract_upgrade_guidance(
    connector: str,
    label: str,
    normalized_version: str = "",
) -> str:
    """Give range-aware remediation without calling every mismatch an upgrade."""

    contracts = HOOK_CONTRACTS.get(normalize_connector(connector), ())
    if len(contracts) != 1:
        return f"Use a {label} version covered by a DefenseClaw hook contract, then rerun setup."

    contract = contracts[0]
    if contract.exact_agent_versions:
        requirement = "one of " + ", ".join(contract.exact_agent_versions)
    elif contract.min_agent_version and contract.max_agent_version:
        requirement = f">={contract.min_agent_version} and <{contract.max_agent_version}"
    elif contract.min_agent_version:
        requirement = f">={contract.min_agent_version}"
    elif contract.max_agent_version:
        requirement = f"<{contract.max_agent_version}"
    else:
        requirement = "an explicitly supported version"
    if normalized_version and not contract.exact_agent_versions:
        if contract.min_agent_version and compare_agent_versions(
            normalized_version,
            contract.min_agent_version,
        ) < 0:
            return (
                f"Upgrade {label}; installed version {normalized_version} is older than the validated "
                f"minimum. {contract.contract_id} requires {requirement}. Then rerun setup."
            )
        if contract.max_agent_version and compare_agent_versions(
            normalized_version,
            contract.max_agent_version,
        ) >= 0:
            return (
                f"{label} {normalized_version} is newer than DefenseClaw's validated range "
                f"({requirement}). Use a validated version, or update DefenseClaw when a matching "
                "hook contract is available; then rerun setup."
            )
    return (
        f"{label} {normalized_version or 'version'} is outside the validated hook contract; "
        f"{contract.contract_id} requires {requirement}. Use a covered version, then rerun setup."
    )


def _check_connector_version_supported_for_setup(
    connector: str,
    *,
    mode: str = "observe",
    emit: bool = True,
    data_dir: str | os.PathLike[str] | None = None,
    _allow_prompt: bool = True,
    _trusted_prompt_cache: dict[str, bool] | None = None,
) -> bool:
    """Verify the selected connector's installed version before setup.

    Runtime enforcement happens in the Go gateway too, but setup should tell
    the operator before it writes config and restarts services. Unknown hook
    contracts are fatal in action mode unless the explicit exploratory
    override used by the gateway is set.

    ``_allow_prompt`` gates the interactive "trust this directory" remediation.
    It defaults to ``True`` so direct CLI use is unchanged, but callers that
    must never block on stdin — the TUI, or this function's own re-entry after
    trusting a prefix — pass ``False`` to force the non-interactive path.
    ``_trusted_prompt_cache`` is a flow-local map keyed by trusted directory so
    batch setup can avoid asking the same yes/no question repeatedly.
    """
    connector = normalize_connector(connector)
    label = _CONNECTOR_META.get(connector, {}).get("label", connector or "connector")
    action_mode = (mode or "").strip().lower() == "action"
    allow_drift = os.environ.get("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") == "1"
    try:
        disc = agent_discovery.discover_agents(
            use_cache=False,
            refresh=True,
            data_dir=data_dir,
            # Native Windows OmniGent/OpenCode/Amp setup immediately records a protected,
            # connector-scoped executable selection below.  Its admission scan
            # therefore does not need to republish the process-wide discovery
            # cache.  Leaving that cache untouched prevents an unrelated
            # connector whose CLI is temporarily undiscoverable from losing
            # already-sealed version and contract status when the gateway
            # restarts every active connector.
            persist_cache=not (
                connector in {"omnigent", "opencode", "amp"}
                and platform_support.host_os() == "windows"
            ),
        )
        signal = disc.agents.get(connector)
    except Exception as exc:
        compatibility = resolve_connector_contract(connector, "")
        if action_mode and compatibility.status != STATUS_NOT_GATED and not allow_drift:
            if emit:
                ux.err(f"{label}: could not refresh local version discovery ({exc}); refusing action-mode hook setup.")
                ux.subhead("Set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing.")
            return False
        if emit:
            ux.warn(f"{label}: could not refresh local version discovery ({exc}); setup will continue.")
        return True

    raw_version = ""
    installed = False
    probe_error = ""
    if signal is not None:
        raw_version = signal.version or ""
        installed = bool(signal.installed)
        probe_error = signal.error or ""

    compatibility = resolve_connector_contract(connector, raw_version)
    version_display = raw_version or "(not probed)"
    contract = compatibility.contract.contract_id if compatibility.contract else "none"

    if not installed:
        if action_mode and compatibility.status != STATUS_NOT_GATED and not allow_drift:
            if emit:
                ux.err(f"{label}: connector was not detected locally; refusing action-mode hook setup.")
                ux.subhead("Install the connector locally, or use observe mode until it is available.")
            return False
        if emit:
            ux.warn(_connector_not_detected_message(label))
        return True

    if compatibility.status == STATUS_KNOWN:
        if emit:
            ux.ok(f"{label}: version {version_display} is supported by {contract}.")
        return True

    if compatibility.status == STATUS_NOT_GATED:
        if emit:
            ux.ok(f"{label}: version {version_display}; proxy/chat connector has no hook contract gate.")
        return True

    if compatibility.status == STATUS_UNVERSIONED:
        detail = f"{label}: version not available"
        if probe_error:
            detail += f" ({probe_error})"
        detail += f"; using default hook contract {contract}."
        # SU-08: the untrusted-binary-prefix remediation prompt used to be
        # nested inside the action-mode branch, so an OBSERVE-mode setup with an
        # untrusted binary path only got a bare warning and no way to fix it.
        # Detect the untrusted-prefix case and offer the same "add to trusted
        # prefixes?" prompt in BOTH modes. Only the *consequence* of declining
        # differs: action mode refuses (the hook contract can't be verified),
        # observe mode warns and continues.
        is_untrusted_path = bool(
            probe_error == agent_discovery.UNTRUSTED_PREFIX_ERROR and signal and signal.binary_path
        )
        interactive = _allow_prompt and sys.stdin.isatty() and sys.stdout.isatty()
        resolved_bin = ""
        parent = ""
        if is_untrusted_path:
            resolved_bin = os.path.realpath(signal.binary_path)
            parent = os.path.dirname(resolved_bin)
        already_asked = bool(
            is_untrusted_path and _trusted_prompt_cache is not None and parent in _trusted_prompt_cache
        )
        if already_asked:
            interactive = False
        if emit and is_untrusted_path and interactive:
            ux.warn(detail)
            ux.subhead(f"  Binary resolves to: {resolved_bin}")
            ux.subhead(f"  Directory '{parent}' is not in the trusted prefix list.")
            ux.subhead(
                "  Trusting a directory lets DefenseClaw execute any binary placed "
                "there during discovery — only trust locations you control."
            )
            if click.confirm(f"  Add '{parent}' to trusted binary prefixes?", default=False):
                _add_trusted_bin_prefix(parent, data_dir or os.path.expanduser("~/.defenseclaw"))
                if _trusted_prompt_cache is not None:
                    _trusted_prompt_cache[parent] = True
                ux.subhead(f"  Trusted '{parent}' (persisted to ~/.defenseclaw/.env); re-checking…")
                ux.subhead(
                    "  Note: if this path is version-specific it may need re-trusting "
                    "after an upgrade — `defenseclaw setup trusted-paths add <dir>`."
                )
                # Re-run the FULL gate (now non-interactive) so the
                # version -> hook-contract check still applies. Trusting the
                # path only lets us READ the version; it must not be treated
                # as version approval. Suppressing the prompt on re-entry
                # also prevents an infinite loop when trusting the directory
                # cannot help (e.g. a world-writable parent the per-file
                # guard still rejects).
                return _check_connector_version_supported_for_setup(
                    connector,
                    mode=mode,
                    emit=emit,
                    data_dir=data_dir,
                    _allow_prompt=False,
                    _trusted_prompt_cache=_trusted_prompt_cache,
                )
            if _trusted_prompt_cache is not None:
                _trusted_prompt_cache[parent] = False
            # Declined: fall through to the mode-specific handling below.

        if action_mode and not allow_drift:
            if emit:
                if not (is_untrusted_path and interactive):
                    ux.err(
                        detail + " Refusing action-mode hook setup because the installed "
                        "connector version could not be verified."
                    )
                if is_untrusted_path:
                    _emit_untrusted_prefix_setup_hints(resolved_bin, parent)
                ux.subhead("Set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing.")
            return False

        # Observe mode (or drift override): warn and continue. When the
        # untrusted-prefix prompt above already ran interactively we've shown
        # the warning, so only append the persistent trusted-paths hint; the
        # non-prompt path still emits the generic warning.
        if emit:
            if not (is_untrusted_path and interactive):
                ux.warn(detail)
            if is_untrusted_path:
                _emit_untrusted_prefix_setup_hints(resolved_bin, parent)
        return True

    detected_state = (
        "detected-but-unsupported-version"
        if compatibility.normalized_version
        else "detected-but-unrecognized-version"
    )
    detail = (
        f"{label}: {detected_state}; installed version {version_display} is not covered by a "
        f"DefenseClaw hook contract ({compatibility.reason})."
    )
    if probe_error:
        detail += f" Probe detail: {probe_error}."
    upgrade_guidance = _connector_contract_upgrade_guidance(
        connector,
        label,
        compatibility.normalized_version,
    )
    strict_unknown = connector == "opencode"
    if compatibility.status == STATUS_UNKNOWN and not allow_drift and (action_mode or strict_unknown):
        if emit:
            ux.err(detail)
            ux.subhead(upgrade_guidance)
            if strict_unknown:
                ux.subhead(
                    "OpenCode requires a bounded validated plugin contract in both observe and action mode; "
                    "refusing setup before activation."
                )
            else:
                ux.subhead("Refusing action-mode connector setup before activation.")
            ux.subhead("Set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing.")
        return False
    if emit:
        if allow_drift:
            ux.warn(detail + " Continuing because the explicit drift override is set.")
        else:
            ux.warn(detail + " Continuing in observe mode under the connector's established warning policy.")
        ux.subhead(upgrade_guidance)
    return True


def _windows_opencode_requires_exact_selection(connector: str) -> bool:
    """Return whether generic discovery is forbidden as setup authority."""

    return normalize_connector(connector) == "opencode" and platform_support.host_os() == "windows"


def _record_windows_setup_agent_selections(
    data_dir: str | os.PathLike[str] | None,
    connectors: list[str] | tuple[str, ...],
    *,
    _prior_snapshot: _SetupConfigSnapshot | None = None,
) -> _VerifiedSetupAgentSelections | None:
    """Refresh protected executable authority for native runtime inspection."""

    if platform_support.host_os() != "windows":
        return None
    from defenseclaw.agent_selection import (
        record_setup_agent_selections,
        setup_agent_selection_connectors,
    )

    selected = setup_agent_selection_connectors(connectors)
    if not selected:
        return None

    target_dir = data_dir or os.path.expanduser("~/.defenseclaw")
    try:
        selections, selection_errors = record_setup_agent_selections(target_dir, selected)
    except OSError as exc:
        raise click.ClickException(f"could not protect explicit agent executable selection: {exc}") from exc

    for connector in selected:
        if connector not in selections and connector not in selection_errors:
            selection_errors[connector] = "selection was not recorded"
    if selection_errors:
        details = "; ".join(f"{name}: {detail}" for name, detail in sorted(selection_errors.items()))
        raise click.ClickException(
            f"cannot configure native hooks without a freshly verified selected agent executable ({details})"
        )
    try:
        return _validate_setup_agent_selection_receipt(
            target_dir,
            selected,
            selections,
            prior_generation=(_prior_snapshot.agent_selection_generation if _prior_snapshot is not None else None),
        )
    except OSError as exc:
        raise click.ClickException(
            f"could not bind selected agent executables to the protected receipt: {exc}"
        ) from exc


def _guardrail_setup_check_targets(app: AppContext, gc, explicit_connector: str | None) -> list[str]:
    """Connectors whose binaries should be verified before guardrail setup."""
    targets: list[str] = []

    def _add(raw: str | None) -> None:
        if not raw:
            return
        try:
            connector = normalize_connector(raw)
        except Exception:  # noqa: BLE001 - defensive against unmodeled test stubs.
            connector = str(raw).strip().lower()
        if connector and connector not in targets:
            targets.append(connector)

    if explicit_connector:
        _add(explicit_connector)
        return targets

    try:
        for connector in app.cfg.active_connectors():
            _add(connector)
    except Exception:  # noqa: BLE001 - SimpleNamespace tests may omit the method.
        pass

    if not targets:
        _add(getattr(gc, "connector", "") or "openclaw")
    return targets


def _check_guardrail_setup_connector_versions(
    app: AppContext,
    gc,
    *,
    explicit_connector: str | None,
    allow_prompt: bool,
    _prior_snapshot: _SetupConfigSnapshot | None = None,
    _protected_selection: _VerifiedSetupAgentSelections | None = None,
    _transaction_targets: tuple[str, ...] | None = None,
) -> bool:
    """Verify every connector affected by a guardrail setup run."""
    trusted_prompt_cache: dict[str, bool] | None = {} if allow_prompt else None
    targets = (
        list(_transaction_targets)
        if _transaction_targets is not None
        else _guardrail_setup_check_targets(app, gc, explicit_connector)
    )
    setup_snapshot = _prior_snapshot or _capture_setup_config_snapshot(app.cfg)
    exact_windows_opencode = any(_windows_opencode_requires_exact_selection(name) for name in targets)

    for connector in targets:
        if _windows_opencode_requires_exact_selection(connector):
            continue
        mode = gc.effective_mode(connector) if hasattr(gc, "effective_mode") else (getattr(gc, "mode", "") or "observe")
        version_check_kwargs = {
            "mode": mode or "observe",
            "data_dir": getattr(app.cfg, "data_dir", None),
            "_allow_prompt": allow_prompt,
        }
        if trusted_prompt_cache is not None:
            version_check_kwargs["_trusted_prompt_cache"] = trusted_prompt_cache
        if not _check_connector_version_supported_for_setup(connector, **version_check_kwargs):
            if (mode or "").strip().lower() == "action":
                _downgrade_guardrail_setup_action_connector(gc, connector)
                continue
            _restore_setup_config_snapshot(app, setup_snapshot)
            return False
    if exact_windows_opencode:
        try:
            if _protected_selection is None:
                raise OSError("exact OpenCode selection was not recorded")
            from defenseclaw.agent_selection import setup_agent_selection_connectors

            if _protected_selection.connectors != setup_agent_selection_connectors(tuple(targets)):
                raise OSError("exact OpenCode selection does not cover this guardrail transaction")
            _revalidate_setup_agent_selections(
                app.cfg.data_dir,
                _protected_selection,
                transaction_snapshot=setup_snapshot,
            )
        except OSError as exc:
            try:
                _restore_setup_config_snapshot(app, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve proof and rollback failures.
                raise click.ClickException(
                    f"guardrail executable selection proof was invalid ({exc}); "
                    f"prior state restoration failed: {rollback_exc}"
                ) from exc
            raise click.ClickException(f"guardrail executable selection changed before mutation: {exc}") from exc
    else:
        _record_windows_setup_agent_selections(
            getattr(app.cfg, "data_dir", None),
            tuple(targets),
            _prior_snapshot=setup_snapshot,
        )
    # Version validation can refuse a requested action mode and persist an
    # observe fallback. Reconcile the hook-lane judge gate after every target
    # has reached its final mode so a refused connector cannot remain judged
    # when execute_guardrail_setup() saves the configuration below.
    _prune_judge_gate_to_action_scope(gc, targets)
    return True


def _downgrade_guardrail_setup_action_connector(gc, connector: str) -> None:
    """Persist an observe fallback when guardrail setup refuses action mode."""
    label = _CONNECTOR_META.get(connector, {}).get("label", connector or "connector")
    ux.warn(f"{label}: requested action mode was refused; configuring observe mode instead.")

    connectors = getattr(gc, "connectors", None)
    if connectors:
        key = connector
        if key not in connectors:
            wanted = normalize_connector(connector)
            for existing_key in connectors:
                if normalize_connector(str(existing_key)) == wanted:
                    key = existing_key
                    break
        if key not in connectors:
            connectors[key] = PerConnectorGuardrailConfig()
        connectors[key].mode = "observe"
        return

    gc.mode = "observe"


def _hilt_support_note(connector: str) -> str:
    """Return the operator-facing HILT support note for a connector."""
    if connector == "openclaw":
        return "OpenClaw supports DefenseClaw approval prompts for tool actions."
    if connector == "claudecode":
        return "Claude Code supports native PreToolUse ask prompts."
    if connector == "codex":
        return "Codex has no native ask surface here; confirm verdicts are downgraded with raw_action preserved."
    if connector == "zeptoclaw":
        return "ZeptoClaw has no native ask surface; confirm verdicts are downgraded with raw_action preserved."
    if connector == "copilot":
        return "Copilot CLI supports native ask on documented preToolUse hooks."
    if connector == "cursor":
        return (
            "Cursor setup does not enable native human approval; confirm verdicts "
            "remain attributed alerts."
        )
    if connector == "antigravity":
        return "Antigravity documents native ask only for PreToolUse."
    if connector == "omnigent":
        return (
            "OmniGent parks request, tool_call, and llm_request policy phases for native ASK approval; "
            "post-phase confirm findings are audited and continue without an approval pause."
        )
    if connector in {"hermes", "windsurf", "geminicli", "openhands", "opencode"}:
        return (
            "This connector can block supported hook events but has no native human approval surface; "
            "confirm falls back explicitly."
        )
    return "Support depends on the connector surface."


def _configure_hilt_interactive(gc, *, action_connectors: list[str] | None = None) -> None:
    """Prompt for human approval settings from the guardrail advanced section."""
    ux.section("Human Approval (HILT)")
    if action_connectors is not None:
        if not action_connectors:
            ux.subhead("Human approval is action-mode only.")
            ux.subhead("No connector is currently in action mode, so approvals are inactive.")
            return
        ux.subhead("Applies to action-mode connector(s): " + ", ".join(action_connectors))
        connector = action_connectors[0] if len(action_connectors) == 1 else (gc.connector or "openclaw")
    elif (gc.mode or "observe").lower() != "action":
        ux.subhead("Human approval is action-mode only.")
        ux.subhead("Current mode is observe, so approvals are inactive and no prompts will appear.")
        return
    else:
        connector = gc.connector or "openclaw"
    ux.subhead(_hilt_support_note(connector))
    ux.subhead("CRITICAL findings still block. HILT can confirm risky HIGH findings first.")
    enabled = click.confirm("  Human approval for risky actions?", default=gc.hilt.enabled)
    gc.hilt.enabled = enabled
    if not enabled:
        gc.hilt.min_severity = gc.hilt.min_severity or "HIGH"
        return

    default_min = (gc.hilt.min_severity or "HIGH").upper()
    if default_min not in _HILT_MIN_SEVERITIES:
        default_min = "HIGH"
    gc.hilt.min_severity = click.prompt(
        "  Approval minimum severity",
        type=click.Choice(_HILT_MIN_SEVERITIES, case_sensitive=False),
        default=default_min,
    ).upper()


def _resolve_rule_pack_dir(
    app: AppContext,
    *,
    rule_pack: str | None,
    rule_pack_dir: str | None,
) -> str | None:
    """Resolve a rule-pack selection to a concrete directory path.

    ``--rule-pack`` names a bundled preset (default/strict/permissive),
    resolved under ``<policy_root>/guardrail/<preset>``. ``--rule-pack-dir``
    (R1) points at an arbitrary directory verbatim, giving the CLI parity
    with the TUI's free-text ``rule_pack_dir`` field. The two are mutually
    exclusive — naming a single pack two different ways in one invocation is
    exactly the one-input-two-meanings ambiguity R3 exists to remove, so we
    reject it loudly rather than silently picking a winner.

    Returns:
      * ``None`` — neither flag supplied; the caller leaves the existing
        ``rule_pack_dir`` untouched.
      * ``""`` — ``--rule-pack-dir ""`` was passed explicitly; clears the
        override back to the inherited/global default (three-state parity
        with the YAML semantics the gateway loader honors).
      * an absolute path — the resolved preset or operator-supplied dir.
    """
    if rule_pack is not None and rule_pack_dir is not None:
        raise click.UsageError(
            "--rule-pack and --rule-pack-dir are mutually exclusive: pass a "
            "built-in preset name OR a custom directory path, not both."
        )
    if rule_pack is not None:
        policy_root = app.cfg.policy_dir or os.path.join(app.cfg.data_dir, "policies")
        return os.path.join(policy_root, "guardrail", rule_pack)
    if rule_pack_dir is not None:
        raw = rule_pack_dir.strip()
        # Empty string is an explicit "clear the override"; a real path is
        # anchored to an absolute location so the gateway's LoadRulePack
        # reads exactly where the operator pointed regardless of the
        # sidecar's working directory at boot.
        if not raw:
            return ""
        resolved = os.path.abspath(os.path.expanduser(raw))
        # R5: validate the pack dir on set. Setup is a local authoring command;
        # saving a path that does not exist makes the summary look successful
        # while the gateway cannot load the intended rules at boot.
        if not os.path.isdir(resolved):
            raise click.UsageError(
                f"--rule-pack-dir {resolved!r} does not exist or is not a directory. "
                "Create the directory first, or use --rule-pack default|strict|permissive."
            )
        return resolved
    return None


def _apply_rule_pack_selection(gc, pack_dir: str, *, connector: str | None) -> bool:
    """Write *pack_dir* with per-connector scoping (R3).

    When *connector* already owns an override block in ``gc.connectors``, the
    pack is written there and peers keep their current rule pack. Without an
    explicit connector, this is a global/all-connectors write: update
    ``gc.rule_pack_dir`` and clear every per-connector rule-pack override so
    all active connectors inherit the same pack. Returns True when the write
    was per-connector.
    """
    if connector and getattr(gc, "connectors", None) and connector in gc.connectors:
        gc.connectors[connector].rule_pack_dir = pack_dir
        return True
    gc.rule_pack_dir = pack_dir
    for block in (getattr(gc, "connectors", None) or {}).values():
        block.rule_pack_dir = ""
    return False


def _apply_guardrail_extra_options(
    app: AppContext,
    gc,
    *,
    rule_pack: str | None,
    rule_pack_dir: str | None = None,
    connector: str | None = None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
) -> None:
    """Apply guardrail options shared by the CLI and TUI non-interactive wizard.

    *connector* (when supplied by the caller) scopes the rule-pack write
    per-connector if that connector owns an override block, else global — the
    R3 consistency fix so ``setup guardrail --connector X`` matches ``setup X``.
    """

    pack_dir = _resolve_rule_pack_dir(app, rule_pack=rule_pack, rule_pack_dir=rule_pack_dir)
    if pack_dir is not None:
        _apply_rule_pack_selection(gc, pack_dir, connector=connector)
    per_connector = bool(connector and getattr(gc, "connectors", None) and connector in gc.connectors)
    _apply_hilt_setup(
        gc,
        connector=connector or "",
        per_connector=per_connector,
        hilt=human_approval,
        hilt_min_severity=hilt_min_severity,
    )
    if not per_connector and not gc.hilt.min_severity:
        gc.hilt.min_severity = "HIGH"


def _resolve_judge_hook_gate(
    value: str | None,
    *,
    judge_just_enabled: bool,
    current: list[str],
) -> list[str] | None:
    """Resolve ``--judge-hook-connectors`` into a new ``judge.hook_connectors`` gate (B2).

    The hook-lane judge is tunable per connector via
    ``guardrail.judge.hook_connectors``. Guardrail-level setup can still opt
    every hook connector into judge review; direct connector setup defaults to
    the connector being configured. This flag remains the explicit
    non-interactive / advanced surface for widening or narrowing that gate.

    Accepted values:
      * ``all`` / ``*``  → ``["*"]`` (the all-hook-connectors sentinel)
      * ``none`` / ``""``→ ``[]`` (judge proxy lane only)
      * a comma-separated list of hook-enforced connector names

    Returns the new gate list, or ``None`` to leave the existing gate
    untouched. When the flag is omitted and the judge is being turned on for the
    first time this run with no gate yet, default to ALL active hook connectors
    (``["*"]``) — the agreed product default (tui.md §10.2) so enabling the
    judge never silently no-ops on the hook lane. A deliberate empty gate on a
    re-run (judge already enabled) is preserved, not re-armed.
    """
    if value is not None:
        low = value.strip().lower()
        if low in ("all", "*"):
            return ["*"]
        if low in ("", "none"):
            return []
        names: list[str] = []
        for token in value.split(","):
            token = token.strip()
            if not token:
                continue
            norm = normalize_connector(token)
            if norm not in _HOOK_ENFORCED_CONNECTORS:
                raise click.UsageError(
                    f"--judge-hook-connectors: {token!r} is not a hook-enforced "
                    f"connector. Choose from {sorted(_HOOK_ENFORCED_CONNECTORS)}, "
                    "or pass 'all' / 'none'."
                )
            if norm not in names:
                names.append(norm)
        return names
    if judge_just_enabled and not current:
        return ["*"]
    return None


# ---------------------------------------------------------------------------
# setup guardrail
# ---------------------------------------------------------------------------


@setup.command("guardrail")
@click.option(
    "--disable",
    is_flag=True,
    help="Disable guardrail and restore connector config where applicable.",
)
# ``--connector`` is the canonical name (matches scripts/install.sh and
# /v1/connectors). ``--agent`` is kept as an alias for backward
# compatibility with existing scripts and docs. Both bind to the same
# ``agent_name`` parameter; supplying both flags will simply use the
# last one parsed by Click, which is consistent with Click's standard
# behavior for aliased options.
@click.option(
    "--connector",
    "--agent",
    "agent_name",
    type=_PlatformConnectorChoice(_CONNECTOR_NAMES, case_sensitive=False),
    default=None,
    help=(
        "Agent framework connector. Alias: --agent. Defaults to "
        "<data_dir>/picked_connector when set by the installer, "
        "else filesystem auto-detection, else openclaw."
    ),
)
@click.option("--mode", "guard_mode", type=click.Choice(["observe", "action"]), default=None, help="Guardrail mode")
@click.option(
    "--scanner-mode",
    type=click.Choice(["local", "remote", "both"]),
    default=None,
    help="Scanner mode (local patterns, remote Cisco API, or both)",
)
@click.option("--cisco-endpoint", default=None, help="Cisco AI Defense API endpoint")
@click.option("--cisco-api-key-env", default=None, help="Env var name holding Cisco AI Defense API key")
@click.option("--cisco-timeout-ms", type=int, default=None, help="Cisco AI Defense timeout (ms)")
@click.option("--port", "guard_port", type=int, default=None, help="Guardrail proxy port")
@click.option("--block-message", default=None, help="Custom message shown when a request is blocked (empty = default)")
@click.option(
    "--detection-strategy",
    type=click.Choice(["regex_only", "regex_judge", "judge_first"]),
    default=None,
    help="Detection strategy (regex_only, regex_judge, judge_first)",
)
# J3: per-direction detection-strategy overrides. The base --detection-strategy
# only sets the global field; these write the existing per-direction slots
# (guardrail.detection_strategy_{prompt,completion,tool_call}) so an operator
# can opt the judge into the tool-output / tool-call lanes. OFF by default
# (opt-in) — omitting a flag leaves that direction inheriting the base
# strategy. CLI surface only; the Go lane wiring is Round-2 fu/judge-go.
@click.option(
    "--detection-strategy-prompt",
    type=click.Choice(["regex_only", "regex_judge", "judge_first"]),
    default=None,
    help="Per-direction detection strategy for the prompt lane (opt-in; default inherits --detection-strategy).",
)
@click.option(
    "--detection-strategy-completion",
    type=click.Choice(["regex_only", "regex_judge", "judge_first"]),
    default=None,
    help=(
        "Per-direction detection strategy for the tool-output/completion lane "
        "(opt-in; OFF by default — judging tool output adds an LLM round-trip "
        "per tool call). Go wiring lands in Round-2 fu/judge-go."
    ),
)
@click.option(
    "--detection-strategy-tool-call",
    type=click.Choice(["regex_only", "regex_judge", "judge_first"]),
    default=None,
    help=(
        "Per-direction detection strategy for the tool-call lane (opt-in; OFF "
        "by default). Go wiring lands in Round-2 fu/judge-go."
    ),
)
@click.option(
    "--rule-pack",
    type=click.Choice(["default", "strict", "permissive"]),
    default=None,
    help="Guardrail rule-pack profile",
)
@click.option(
    "--rule-pack-dir",
    default=None,
    help=(
        "Custom rule-pack DIRECTORY (free-text path) — CLI parity with the "
        "TUI's free-text field. Use instead of --rule-pack to point at a pack "
        "outside the built-in default/strict/permissive presets. Scoped "
        "per-connector when --connector names a multi-install peer, else "
        'global. Mutually exclusive with --rule-pack; pass "" to clear.'
    ),
)
@click.option("--judge-model", default=None, help="LLM judge model (e.g. anthropic/claude-sonnet-4-20250514)")
@click.option("--judge-api-base", default=None, help="LLM judge API base URL (e.g. Bifrost URL)")
@click.option("--judge-api-key-env", default=None, help="Env var name for judge API key")
@click.option(
    "--judge-provider",
    default=None,
    help=("Judge LLM provider (e.g. anthropic, bedrock, vertex_ai). Persisted to guardrail.judge.llm.provider."),
)
@click.option(
    "--judge-region",
    default=None,
    help="Judge regional provider region (Bedrock/Vertex). Persisted to guardrail.judge.llm.region.",
)
@click.option(
    "--judge-instance-name",
    default=None,
    help="Custom-provider instance for the judge. Persisted to guardrail.judge.llm.instance_name.",
)
@click.option(
    "--judge-hook-connectors",
    default=None,
    help=(
        "Hook-lane judge gate (guardrail.judge.hook_connectors). The judge "
        "always covers the proxy lane; hook connectors are opt-in. Pass 'all' "
        "(or '*'), 'none', or a comma-separated list of hook-enforced "
        "connectors (e.g. hermes,codex). When omitted and the judge is being "
        "enabled for the first time, defaults to all active hook connectors."
    ),
)
@click.option(
    "--llm-role",
    type=click.Choice(["judge_only", "judge_and_agent"]),
    default=None,
    help=(
        "How the LLM is used by this connector. 'judge_only' (hook-based "
        "connectors like Codex/Claude Code) configures only the guardrail "
        "judge. 'judge_and_agent' (proxy-backed connectors like OpenClaw/"
        "ZeptoClaw) configures both judge and the agent's upstream LLM."
    ),
)
@click.option(
    "--inherit-from",
    "judge_inherit_from",
    type=click.Choice(["", "guardrail", "scanners.skill", "scanners.mcp", "scanners.plugin"]),
    default=None,
    help=(
        "Copy resolved provider/model/api_key_env from a sibling LLM "
        "block onto guardrail.judge.llm before applying flags."
    ),
)
@click.option(
    "--inherit-llm/--no-inherit-llm",
    "judge_inherit_llm",
    default=None,
    help=(
        "Shortcut for --inherit-from guardrail. Copies the connector's "
        "agent-side LLM into guardrail.judge.llm so the judge reuses the "
        "same model/key."
    ),
)
@click.option(
    "--judge-auth-mode",
    default=None,
    help=(
        "Generic judge auth-mode. Maps to --judge-bedrock-auth-mode / "
        "--judge-azure-auth-mode / --judge-vertex-auth-mode depending on "
        "--judge-provider."
    ),
)
@click.option("--judge-bedrock-region", default=None, help="AWS region for the Bedrock judge (e.g. us-east-1).")
@click.option(
    "--judge-bedrock-auth-mode",
    type=click.Choice(["api_key", "iam_credentials", "profile", "instance_role"]),
    default=None,
    help="Bedrock auth strategy for the judge.",
)
@click.option(
    "--judge-bedrock-access-key-env", default=None, help="Env var holding AWS access key ID for the Bedrock judge."
)
@click.option(
    "--judge-bedrock-secret-key-env", default=None, help="Env var holding AWS secret access key for the Bedrock judge."
)
@click.option(
    "--judge-bedrock-session-token-env", default=None, help="Env var holding AWS session token for the Bedrock judge."
)
@click.option(
    "--judge-bedrock-profile-name", default=None, help="AWS profile name when judge-bedrock-auth-mode=profile."
)
@click.option(
    "--judge-bedrock-inference-profile",
    default=None,
    help="Bedrock inference-profile prefix for the judge (e.g. 'us.').",
)
@click.option(
    "--judge-bedrock-deployment",
    "judge_bedrock_deployment_aliases",
    multiple=True,
    help="Judge Bedrock model alias formatted ``alias=model-id`` (repeatable).",
)
@click.option("--judge-vertex-project-id", default=None, help="GCP project ID for the Vertex AI judge.")
@click.option("--judge-vertex-region", default=None, help="GCP region/location for the Vertex AI judge.")
@click.option(
    "--judge-vertex-auth-mode",
    type=click.Choice(["service_account", "adc", "workload_identity"]),
    default=None,
    help="Vertex auth strategy for the judge.",
)
@click.option(
    "--judge-vertex-service-account-json-env",
    default=None,
    help="Env var holding the path to the Vertex service-account JSON (judge).",
)
@click.option(
    "--judge-azure-endpoint",
    default=None,
    help="Azure OpenAI endpoint for the judge (e.g. https://name.openai.azure.com).",
)
@click.option(
    "--judge-azure-api-version", default=None, help="Azure OpenAI api-version for the judge (e.g. 2024-10-21)."
)
@click.option(
    "--judge-azure-auth-mode",
    type=click.Choice(["api_key", "managed_identity"]),
    default=None,
    help="Azure auth strategy for the judge.",
)
@click.option(
    "--judge-azure-deployment-alias",
    "judge_azure_deployment_aliases",
    multiple=True,
    help="Judge Azure deployment alias formatted ``model=deployment`` (repeatable).",
)
@click.option(
    "--judge-tls-ca-cert-file",
    default=None,
    type=click.Path(exists=False, dir_okay=False),
    help="PEM CA bundle for self-signed judge endpoints (inline-stored on guardrail.judge.llm.tls.ca_cert_pem).",
)
@click.option(
    "--judge-insecure-skip-verify",
    is_flag=True,
    default=False,
    help="Disable TLS verification for the judge endpoint (lab use only).",
)
@click.option(
    "--human-approval/--no-human-approval",
    default=None,
    help="Enable or disable human approval (HILT) for risky actions",
)
@click.option(
    "--hilt-min-severity",
    type=click.Choice(_HILT_MIN_SEVERITIES, case_sensitive=False),
    default=None,
    help="Minimum severity that asks for human approval",
)
@click.option(
    "--workspace",
    "--workspace-dir",
    "workspace_dir",
    default=None,
    help="Opt into workspace-scoped connector config. Defaults to global/user config.",
)
@click.option(
    "--restart/--no-restart", default=True, help="Restart gateway and the active connector after setup (default: on)"
)
@click.option("--verify/--no-verify", default=True, help="Run connectivity checks after setup (default: on)")
@click.option(
    "--non-interactive",
    "--accept-defaults",
    "--yes",
    "non_interactive",
    is_flag=True,
    help="Use flags instead of prompts (aliases: --accept-defaults, --yes)",
)
@pass_ctx
def setup_guardrail(
    app: AppContext,
    disable: bool,
    agent_name: str | None,
    guard_mode,
    guard_port,
    scanner_mode,
    cisco_endpoint,
    cisco_api_key_env,
    cisco_timeout_ms,
    block_message,
    detection_strategy,
    detection_strategy_prompt: str | None,
    detection_strategy_completion: str | None,
    detection_strategy_tool_call: str | None,
    rule_pack,
    rule_pack_dir,
    judge_model,
    judge_api_base,
    judge_api_key_env,
    judge_provider: str | None,
    judge_region: str | None,
    judge_instance_name: str | None,
    judge_hook_connectors: str | None,
    llm_role: str | None,
    judge_inherit_from: str | None,
    judge_inherit_llm: bool | None,
    judge_auth_mode: str | None,
    judge_bedrock_region: str | None,
    judge_bedrock_auth_mode: str | None,
    judge_bedrock_access_key_env: str | None,
    judge_bedrock_secret_key_env: str | None,
    judge_bedrock_session_token_env: str | None,
    judge_bedrock_profile_name: str | None,
    judge_bedrock_inference_profile: str | None,
    judge_bedrock_deployment_aliases: tuple[str, ...],
    judge_vertex_project_id: str | None,
    judge_vertex_region: str | None,
    judge_vertex_auth_mode: str | None,
    judge_vertex_service_account_json_env: str | None,
    judge_azure_endpoint: str | None,
    judge_azure_api_version: str | None,
    judge_azure_auth_mode: str | None,
    judge_azure_deployment_aliases: tuple[str, ...],
    judge_tls_ca_cert_file: str | None,
    judge_insecure_skip_verify: bool,
    human_approval,
    hilt_min_severity,
    workspace_dir: str | None,
    restart: bool,
    verify: bool,
    non_interactive: bool,
) -> None:
    """Configure the LLM guardrail (routes LLM traffic through the Go proxy for inspection).

    Routes all LLM traffic through the built-in Go guardrail proxy.
    Every prompt and response is inspected for prompt injection, secrets,
    PII, and data exfiltration patterns.

    Use --connector (alias: --agent) to select the agent framework
    connector. The connector
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
    explicit_connector = normalize_connector(agent_name) if agent_name else None

    if disable:
        # Always restart on disable — leaving the proxy running defeats the
        # purpose of disabling. The fetch interceptor also needs OpenClaw
        # to restart (which happens automatically when openclaw.json changes).
        _disable_guardrail(app, gc, restart=True)
        return

    # Validate explicit operator input before mutating the in-memory config.
    # Stored/picked fallback values are checked after resolution below.
    if explicit_connector:
        _ensure_connector_available(explicit_connector)

    try:
        setup_snapshot = _capture_setup_config_snapshot(app.cfg, capture_runtime=_windows_runtime_rollback(restart))
    except OSError as exc:
        raise click.ClickException(f"cannot establish guardrail setup rollback point: {exc}") from exc

    protected_selection: _VerifiedSetupAgentSelections | None = None
    selection_attempted = False
    transaction_targets: tuple[str, ...] | None = None
    pending_guardrail_secrets: list[_PendingGuardrailSecret] = []
    guardrail_secret_transaction: _GuardrailSecretTransaction | None = None

    def preselect_guardrail_targets(targets: list[str] | tuple[str, ...]) -> None:
        """Select exact OpenCode authority once, before guardrail mutation."""

        nonlocal protected_selection, selection_attempted, transaction_targets
        normalized_targets = tuple(dict.fromkeys(normalize_connector(name) for name in targets if name))
        if not any(_windows_opencode_requires_exact_selection(name) for name in normalized_targets):
            return
        if transaction_targets is not None and transaction_targets != normalized_targets:
            raise click.ClickException("guardrail transaction targets changed after selection")
        transaction_targets = normalized_targets
        if selection_attempted:
            raise click.ClickException("guardrail executable selection was attempted more than once")
        selection_attempted = True
        try:
            protected_selection = _record_windows_setup_agent_selections(
                getattr(app.cfg, "data_dir", None),
                normalized_targets,
                _prior_snapshot=setup_snapshot,
            )
            if protected_selection is None or protected_selection.record_for("opencode") is None:
                raise click.ClickException("native-Windows OpenCode guardrail setup has no concrete exact selection")
        except Exception as exc:
            rollback_errors: list[str] = []
            for label, restore in (
                ("agent_selection.json", _restore_setup_agent_selection_snapshot),
                ("hook_contract_lock.json", _restore_setup_hook_contract_lock_snapshot),
            ):
                try:
                    restore(app.cfg, setup_snapshot)
                except Exception as rollback_exc:  # noqa: BLE001 — restore independent authority files.
                    rollback_errors.append(f"{label}: {rollback_exc}")
            if rollback_errors:
                raise click.ClickException(
                    f"guardrail executable selection failed ({exc}); "
                    f"authority rollback was incomplete: {'; '.join(rollback_errors)}"
                ) from exc
            raise

    def restore_precommit_guardrail_selection() -> None:
        """Restore transaction-owned exact authority after an interactive no-op."""

        if protected_selection is None:
            return
        rollback_errors: list[str] = []
        for label, restore in (
            (
                "in-memory config",
                lambda: _restore_setup_config_in_memory(app, setup_snapshot),
            ),
            (
                "agent_selection.json",
                lambda: _restore_setup_agent_selection_snapshot(app.cfg, setup_snapshot),
            ),
            (
                "hook_contract_lock.json",
                lambda: _restore_setup_hook_contract_lock_snapshot(app.cfg, setup_snapshot),
            ),
        ):
            try:
                restore()
            except Exception as exc:  # noqa: BLE001 — restore independent transaction state.
                rollback_errors.append(f"{label}: {exc}")
        if rollback_errors:
            raise click.ClickException(
                "guardrail cancellation authority rollback was incomplete: " + "; ".join(rollback_errors)
            )

    def restore_guardrail_secret_publication() -> _GuardrailSecretRollbackStatus:
        """Restore a published judge secret and release its rollback snapshot."""

        nonlocal guardrail_secret_transaction
        if guardrail_secret_transaction is None:
            return _guardrail_secret_rollback_status()
        transaction = guardrail_secret_transaction
        try:
            status = _restore_guardrail_secret_transaction(transaction)
        except BaseException:
            transaction.clear()
            status = _guardrail_secret_rollback_status("secret-rollback-error")
        guardrail_secret_transaction = None
        return status

    def restore_guardrail_setup_after_secret_publication() -> _GuardrailSecretRollbackStatus:
        """Restore desired setup state and independently restore secret custody."""

        status_codes: list[str] = []
        try:
            _restore_setup_config_snapshot(app, setup_snapshot)
        except BaseException:  # Secret restoration must still run.
            status_codes.append("setup-rollback-error")
        status_codes.extend(restore_guardrail_secret_publication().codes)
        return _guardrail_secret_rollback_status(*status_codes)

    aid = app.cfg.cisco_ai_defense

    if non_interactive:
        # B2: snapshot the judge gate state BEFORE the judge config below can
        # flip ``gc.judge.enabled`` on, so the hook-gate default only fires when
        # this run actually turns the judge on (not on every re-run).
        judge_enabled_by_this_run = False
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
        target_connector = explicit_connector or ""
        if explicit_connector:
            target_connector = explicit_connector
        elif not gc.connector or gc.connector == "openclaw":
            picked = _read_picked_connector(getattr(app.cfg, "data_dir", None))
            if picked:
                target_connector = normalize_connector(picked)
            else:
                target_connector = gc.connector
        else:
            target_connector = gc.connector
        target_connector = target_connector or gc.connector
        if target_connector:
            _ensure_connector_available(normalize_connector(target_connector))
            configured_connectors = getattr(gc, "connectors", None)
            if (
                explicit_connector
                or not configured_connectors
                or not any(_windows_opencode_requires_exact_selection(name) for name in configured_connectors)
            ):
                target_connectors = (target_connector,)
            else:
                target_connectors = tuple(_guardrail_setup_check_targets(app, gc, None))
            preselect_guardrail_targets(target_connectors)

        if explicit_connector:
            if not (getattr(gc, "connectors", None) and target_connector in gc.connectors):
                gc.connector = target_connector
        elif not gc.connector or gc.connector == "openclaw":
            if target_connector:
                gc.connector = target_connector
        per_connector_target = bool(
            explicit_connector
            and target_connector
            and getattr(gc, "connectors", None)
            and target_connector in gc.connectors
        )
        if guard_mode and not explicit_connector:
            mode_targets = _guardrail_setup_check_targets(app, gc, None)
            gc.mode = guard_mode
            if getattr(gc, "connectors", None) and mode_targets:
                _write_per_connector_modes(
                    gc,
                    {connector: guard_mode for connector in mode_targets},
                )
        elif per_connector_target:
            if guard_mode:
                gc.connectors[target_connector].mode = guard_mode
            elif not gc.mode:
                gc.mode = "observe"
        else:
            gc.mode = guard_mode or gc.mode or "observe"
        gc.scanner_mode = scanner_mode or gc.scanner_mode or "local"
        if cisco_endpoint is not None:
            aid.endpoint = cisco_endpoint
        if cisco_api_key_env is not None:
            aid.api_key_env = cisco_api_key_env
        if cisco_timeout_ms is not None:
            aid.timeout_ms = cisco_timeout_ms
        gc.port = guard_port or gc.port or 4000
        if block_message is not None and per_connector_target:
            gc.connectors[target_connector].block_message = block_message
        elif block_message is not None:
            gc.block_message = block_message
            block_message_targets = (
                _guardrail_setup_check_targets(app, gc, None) if getattr(gc, "connectors", None) else []
            )
            for connector in block_message_targets:
                entry = gc.connectors.get(connector)
                if entry is None:
                    entry = PerConnectorGuardrailConfig()
                    gc.connectors[connector] = entry
                entry.block_message = block_message
        if detection_strategy is not None:
            gc.detection_strategy = detection_strategy
        _apply_guardrail_extra_options(
            app,
            gc,
            rule_pack=rule_pack,
            rule_pack_dir=rule_pack_dir,
            connector=explicit_connector,
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
        )
        # Optional: inherit a sibling LLM block onto guardrail.judge.llm
        # before applying per-judge flags so non-empty operator overrides
        # always win on top.
        effective_inherit_from = judge_inherit_from
        if judge_inherit_llm and not effective_inherit_from:
            # --inherit-llm is a friendlier alias for --inherit-from guardrail.
            effective_inherit_from = "guardrail"
        if effective_inherit_from:
            _apply_llm_inherit(app.cfg, inherit_from=effective_inherit_from, target_path="guardrail.judge")
        if judge_model is not None:
            gc.judge.model = judge_model
            gc.judge.llm.model = judge_model
            gc.judge.enabled = True
            judge_enabled_by_this_run = True
        if judge_api_base is not None:
            gc.judge.api_base = judge_api_base
            gc.judge.llm.base_url = judge_api_base
        if judge_api_key_env is not None:
            gc.judge.api_key_env = judge_api_key_env
            gc.judge.llm.api_key_env = judge_api_key_env
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
        if judge_provider is not None:
            gc.judge.llm.provider = judge_provider.strip().lower()
        if judge_region is not None:
            gc.judge.llm.region = judge_region.strip()
        if judge_instance_name is not None:
            gc.judge.llm.instance_name = judge_instance_name.strip()

        # Generic --judge-auth-mode → provider-typed alias.
        effective_jbed_auth = judge_bedrock_auth_mode
        effective_jver_auth = judge_vertex_auth_mode
        effective_jaz_auth = judge_azure_auth_mode
        if judge_auth_mode is not None:
            jprov = (judge_provider or gc.judge.llm.provider or "").strip().lower()
            if jprov == "bedrock" and effective_jbed_auth is None:
                effective_jbed_auth = judge_auth_mode
            elif jprov in ("azure", "azure_openai") and effective_jaz_auth is None:
                effective_jaz_auth = judge_auth_mode
            elif jprov in ("vertex_ai", "vertex", "gemini") and effective_jver_auth is None:
                effective_jver_auth = judge_auth_mode

        _apply_llm_provider_typed_flags(
            gc.judge.llm,
            bedrock_region=judge_bedrock_region,
            bedrock_auth_mode=effective_jbed_auth,
            bedrock_access_key_env=judge_bedrock_access_key_env,
            bedrock_secret_key_env=judge_bedrock_secret_key_env,
            bedrock_session_token_env=judge_bedrock_session_token_env,
            bedrock_profile_name=judge_bedrock_profile_name,
            bedrock_inference_profile=judge_bedrock_inference_profile,
            bedrock_deployment_aliases=judge_bedrock_deployment_aliases,
            vertex_project_id=judge_vertex_project_id,
            vertex_region=judge_vertex_region,
            vertex_auth_mode=effective_jver_auth,
            vertex_service_account_json_env=judge_vertex_service_account_json_env,
            azure_endpoint=judge_azure_endpoint,
            azure_api_version=judge_azure_api_version,
            azure_auth_mode=effective_jaz_auth,
            azure_deployment_aliases=judge_azure_deployment_aliases,
            tls_ca_cert_file=judge_tls_ca_cert_file,
            insecure_skip_verify=judge_insecure_skip_verify,
        )

        if llm_role is not None:
            gc.llm_role = llm_role
        elif not gc.llm_role:
            # Default the role based on the connector class so saved
            # configs declare the intent even when the operator didn't
            # supply --llm-role explicitly.
            gc.llm_role = (
                "judge_and_agent"
                if (target_connector or gc.connector or "openclaw") in _PROXY_BACKED_CONNECTORS
                else "judge_only"
            )
        if detection_strategy is not None:
            if _strategy_uses_judge(detection_strategy):
                gc.judge.enabled = True
                judge_enabled_by_this_run = True
            elif detection_strategy == "regex_only":
                gc.judge.enabled = False
        if judge_hook_connectors is not None:
            hook_gate_value = judge_hook_connectors.strip().lower()
            if hook_gate_value in ("", "none"):
                gc.judge.enabled = False
                gc.detection_strategy = "regex_only"
                gc.detection_strategy_completion = "regex_only"
            else:
                gc.judge.enabled = True
                judge_enabled_by_this_run = True
                if not gc.detection_strategy or gc.detection_strategy == "regex_only":
                    gc.detection_strategy = "regex_judge"
        gc.enabled = True

        # Apply sensible strategy defaults when judge is enabled
        if gc.judge.enabled:
            if not gc.detection_strategy or gc.detection_strategy == "regex_only":
                gc.detection_strategy = "regex_judge"
            if not getattr(gc, "detection_strategy_completion", None):
                gc.detection_strategy_completion = "regex_only"

        # J3: explicit per-direction strategy overrides win over auto-seeded
        # defaults. A regex_only completion flag remains the operator's opt-out
        # from tool-output judge coverage.
        if detection_strategy_prompt is not None:
            gc.detection_strategy_prompt = detection_strategy_prompt
        if detection_strategy_completion is not None:
            gc.detection_strategy_completion = detection_strategy_completion
        if detection_strategy_tool_call is not None:
            gc.detection_strategy_tool_call = detection_strategy_tool_call

        # B2: hook-lane judge gate. Honor an explicit --judge-hook-connectors,
        # else default to ALL active hook connectors when the judge is turned on
        # for the first time (tui.md §10.2), so a non-interactive / TUI-driven
        # judge setup never leaves the hook lane silently un-judged.
        new_gate = _resolve_judge_hook_gate(
            judge_hook_connectors,
            judge_just_enabled=(
                gc.judge.enabled and judge_enabled_by_this_run and not list(gc.judge.hook_connectors or [])
            ),
            current=list(gc.judge.hook_connectors or []),
        )
        if new_gate is not None:
            gc.judge.hook_connectors = new_gate

        if gc.judge.enabled and list(gc.judge.hook_connectors or []) and detection_strategy_completion is None:
            _default_hook_judge_completion_strategy(gc)

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
        secret_collection_failure_code: str | None = None
        try:
            interactive_completed = _interactive_guardrail_setup(
                app,
                gc,
                agent_name=agent_name,
                _pre_mutation_selection=preselect_guardrail_targets,
                _pending_secrets=pending_guardrail_secrets,
            )
            if not interactive_completed:
                _clear_pending_guardrail_secrets(pending_guardrail_secrets)
                restore_precommit_guardrail_selection()
                click.echo("  Guardrail not enabled. Run again without declining to configure.")
                return
            _apply_guardrail_extra_options(
                app,
                gc,
                rule_pack=rule_pack,
                rule_pack_dir=rule_pack_dir,
                connector=explicit_connector,
                human_approval=human_approval,
                hilt_min_severity=hilt_min_severity,
            )
        except click.Abort:
            secret_was_collected = bool(pending_guardrail_secrets)
            _clear_pending_guardrail_secrets(pending_guardrail_secrets)
            selection_rollback_failed = False
            try:
                restore_precommit_guardrail_selection()
            except BaseException:
                selection_rollback_failed = True
            if not secret_was_collected:
                if selection_rollback_failed:
                    raise click.ClickException(
                        "guardrail setup was aborted; prior selection authority restoration failed"
                    ) from None
                raise
            secret_collection_failure_code = (
                "collection-aborted-rollback-incomplete" if selection_rollback_failed else "collection-aborted-restored"
            )
        except BaseException:
            if not pending_guardrail_secrets:
                raise
            _clear_pending_guardrail_secrets(pending_guardrail_secrets)
            selection_rollback_failed = False
            try:
                restore_precommit_guardrail_selection()
            except BaseException:
                selection_rollback_failed = True
            secret_collection_failure_code = (
                "collection-failed-rollback-incomplete" if selection_rollback_failed else "collection-failed-restored"
            )
        if secret_collection_failure_code is not None:
            raise _GuardrailSecretFailure(secret_collection_failure_code) from None

    secret_publication_expected = bool(pending_guardrail_secrets)
    secret_publication_failed = False
    secret_publication_rollback_incomplete = False
    try:
        guardrail_secret_transaction = _publish_pending_guardrail_secrets(
            pending_guardrail_secrets,
            app.cfg.data_dir,
        )
    except _GuardrailSecretFailure as publication_failure:
        if not secret_publication_expected:
            raise
        secret_publication_rollback_incomplete = publication_failure.code == "publication-failed-rollback-incomplete"
        secret_publication_failed = True
    except BaseException:
        if not secret_publication_expected:
            raise
        secret_publication_failed = True
    if secret_publication_failed:
        setup_rollback_failed = False
        try:
            _restore_setup_config_snapshot(app, setup_snapshot)
        except BaseException:
            setup_rollback_failed = True
        if setup_rollback_failed and secret_publication_rollback_incomplete:
            failure_code = "publication-failed-setup-and-secret-rollback-incomplete"
        elif secret_publication_rollback_incomplete:
            failure_code = "publication-failed-secret-rollback-incomplete"
        elif setup_rollback_failed:
            failure_code = "publication-failed-setup-rollback-incomplete"
        else:
            failure_code = "publication-failed-setup-restored"
        raise _GuardrailSecretFailure(failure_code) from None

    if not gc.enabled:
        if guardrail_secret_transaction is not None:
            rollback_status = restore_guardrail_setup_after_secret_publication()
            if not rollback_status.complete:
                raise _GuardrailSecretFailure("not-enabled-rollback-incomplete") from None
        click.echo("  Guardrail not enabled. Run again without declining to configure.")
        return

    validation_failed_with_secret = False
    try:
        versions_supported = _check_guardrail_setup_connector_versions(
            app,
            gc,
            explicit_connector=(target_connector if non_interactive else explicit_connector),
            allow_prompt=not non_interactive,
            _prior_snapshot=setup_snapshot,
            _protected_selection=protected_selection,
            _transaction_targets=transaction_targets,
        )
    except BaseException:
        if guardrail_secret_transaction is None:
            raise
        validation_failed_with_secret = True
    if validation_failed_with_secret:
        rollback_status = restore_guardrail_setup_after_secret_publication()
        failure_code = (
            "validation-failed-restored" if rollback_status.complete else "validation-failed-rollback-incomplete"
        )
        raise _GuardrailSecretFailure(failure_code) from None
    if not versions_supported:
        rollback_status = restore_guardrail_secret_publication()
        if not rollback_status.complete:
            raise _GuardrailSecretFailure("validation-refused-rollback-incomplete") from None
        return

    setup_failed_with_secret = False
    try:
        ok, warnings = execute_guardrail_setup(app, save_config=True, workspace_dir=workspace_dir)
    except BaseException as exc:
        if guardrail_secret_transaction is not None:
            setup_failed_with_secret = True
        else:
            try:
                _restore_setup_config_snapshot(app, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve the original setup failure.
                raise click.ClickException(
                    f"guardrail setup failed ({exc}); prior state restoration failed: {rollback_exc}"
                ) from exc
            raise
    if setup_failed_with_secret:
        rollback_status = restore_guardrail_setup_after_secret_publication()
        failure_code = "setup-failed-restored" if rollback_status.complete else "setup-failed-rollback-incomplete"
        raise _GuardrailSecretFailure(failure_code) from None
    if not ok:
        rollback_status = restore_guardrail_setup_after_secret_publication()
        if not rollback_status.complete:
            raise _GuardrailSecretFailure("setup-refused-rollback-incomplete") from None
        return
    if any(warning.startswith("Config not saved") for warning in warnings):
        rollback_status = restore_guardrail_setup_after_secret_publication()
        if not rollback_status.complete:
            raise _GuardrailSecretFailure("config-save-rollback-incomplete") from None
        return

    aid = app.cfg.cisco_ai_defense

    # --- Summary ---
    click.echo()
    connector_label = _CONNECTOR_META.get(gc.connector or "openclaw", {}).get("label", gc.connector)
    _actives = list(app.cfg.active_connectors()) if hasattr(app.cfg, "active_connectors") else []
    _multi = len(_actives) > 1
    scope_val = (
        f"workspace ({app.cfg.claw.workspace_dir})"
        if getattr(app.cfg.claw, "workspace_dir", "")
        else "global user config"
    )
    if _multi:
        # All connectors are peers. Show each connector's *effective*
        # per-connector policy (override > global) instead of collapsing
        # the summary to the singular guardrail.connector. The genuinely
        # global fields (port/model/scanner/judge/redaction) are listed
        # once below since they apply to every connector.
        rows = [
            ("guardrail.connectors", ", ".join(_actives)),
            ("scope", scope_val),
        ]
        for c in _actives:
            hilt_c = gc.effective_hilt(c)
            # Empty rule-pack dir = the built-in default pack — render it the
            # same way `guardrail status` does (basename, or "default").
            _rp = gc.effective_rule_pack_dir(c)
            rp_label = os.path.basename(_rp.rstrip("/")) if _rp.strip() else "default"
            rows.append((f"  [{c}] mode", gc.effective_mode(c)))
            rows.append((f"  [{c}] rule_pack", rp_label))
            rows.append((f"  [{c}] hook_fail_mode", gc.effective_hook_fail_mode(c) or "open"))
            rows.append(
                (
                    f"  [{c}] hilt",
                    f"{str(bool(hilt_c.enabled)).lower()} (min {hilt_c.min_severity or 'HIGH'})",
                )
            )
        rows += [
            ("guardrail.port", str(gc.port)),
            ("guardrail.model", gc.model),
            ("guardrail.model_name", gc.model_name),
            ("guardrail.api_key_env", gc.api_key_env),
            ("guardrail.detection_strategy", gc.detection_strategy),
        ]
        if gc.api_base:
            rows.append(("guardrail.api_base", gc.api_base[:60] + "..." if len(gc.api_base) > 60 else gc.api_base))
    else:
        rows = [
            ("guardrail.connector", f"{connector_label} ({gc.connector})"),
            ("scope", scope_val),
            ("guardrail.mode", gc.mode),
            ("guardrail.port", str(gc.port)),
            ("guardrail.model", gc.model),
            ("guardrail.model_name", gc.model_name),
            ("guardrail.api_key_env", gc.api_key_env),
            ("guardrail.detection_strategy", gc.detection_strategy),
            ("guardrail.rule_pack_dir", gc.rule_pack_dir),
        ]
        if gc.api_base:
            rows.append(("guardrail.api_base", gc.api_base[:60] + "..." if len(gc.api_base) > 60 else gc.api_base))
        if gc.block_message:
            truncated = gc.block_message[:60] + "..." if len(gc.block_message) > 60 else gc.block_message
            rows.append(("guardrail.block_message", truncated))
        rows.append(("guardrail.hook_fail_mode", gc.hook_fail_mode or "open"))
        rows.append(("guardrail.hilt.enabled", str(bool(gc.hilt.enabled)).lower()))
        rows.append(("guardrail.hilt.min_severity", gc.hilt.min_severity or "HIGH"))
    if gc.judge.enabled:
        rows.append(("guardrail.judge.enabled", "true"))
        rows.append(("guardrail.judge.model", gc.judge.model))
        if gc.judge.api_base:
            judge_api_base = gc.judge.api_base
            if len(judge_api_base) > 60:
                judge_api_base = judge_api_base[:60] + "..."
            rows.append(("guardrail.judge.api_base", judge_api_base))
        rows.append(("guardrail.judge.api_key_env", gc.judge.api_key_env))
        hook_gate = gc.judge.hook_connectors or []
        rows.append(
            (
                "guardrail.judge.hook_connectors",
                "all" if hook_gate == ["*"] else (", ".join(hook_gate) if hook_gate else "(none — hook lane off)"),
            )
        )
        if gc.judge.fallbacks:
            rows.append(("guardrail.judge.fallbacks", ", ".join(gc.judge.fallbacks)))
    if gc.scanner_mode in ("remote", "both"):
        rows.append(("cisco_ai_defense.endpoint", aid.endpoint))
        rows.append(("cisco_ai_defense.api_key_env", aid.api_key_env))
        rows.append(("cisco_ai_defense.timeout_ms", str(aid.timeout_ms)))
    # Colored two-column rendering. ``ux.kv`` aligns and dims the
    # key while keeping the value in the default fg so it pops out.
    # Empty/missing values render as a dim em-dash so the row still
    # tracks the column instead of looking truncated.
    for key, val in rows:
        ux.kv(key, val)
    click.echo()

    if warnings:
        ux.section("Warnings", divider_char="─")
        for w in warnings:
            ux.warn(w)
        click.echo()

    if restart:
        readiness_failed_with_secret = False
        try:
            _restart_services(
                app.cfg.data_dir,
                app.cfg.gateway.host,
                app.cfg.gateway.port,
                connector=gc.connector or "openclaw",
                connectors=app.cfg.active_connectors(),
            )
        except BaseException as exc:
            if guardrail_secret_transaction is None:
                _rollback_failed_connector_application(app, setup_snapshot, exc)
            readiness_failed_with_secret = True
        if readiness_failed_with_secret:
            secret_rollback_status = restore_guardrail_secret_publication()
            safe_cause = _GuardrailSecretFailure("readiness-failed")
            unexpected_rollback_failure = False
            try:
                _rollback_failed_connector_application(
                    app,
                    setup_snapshot,
                    safe_cause,
                    _secret_safe=True,
                    _secret_rollback_complete=secret_rollback_status.complete,
                )
            except _GuardrailSecretFailure:
                raise
            except BaseException:
                unexpected_rollback_failure = True
            if unexpected_rollback_failure:
                raise _GuardrailSecretFailure("readiness-rollback-error") from None
    else:
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True
        click.echo("  Next steps:")
        click.echo("    Restart the defenseclaw sidecar for changes to take effect:")
        click.echo("       defenseclaw-gateway restart")
        click.echo()

    click.echo("  To disable and revert:")
    click.echo("    defenseclaw setup guardrail --disable")
    click.echo()

    _log_setup_action(
        app,
        ACTION_SETUP_GUARDRAIL,
        f"mode={gc.mode} scanner_mode={gc.scanner_mode} port={gc.port} model={gc.model} hilt={bool(gc.hilt.enabled)!s}",
        allow_offline=not restart,
    )
    if guardrail_secret_transaction is not None:
        guardrail_secret_transaction.clear()
    guardrail_secret_transaction = None


# ---------------------------------------------------------------------------
# setup <hook connector>  —  observe-by-default aliases
# ---------------------------------------------------------------------------
#
# These are thin wrappers around the hook-driven setup branch. They
# exist because operators who only want telemetry (no traffic
# interception, no enforcement) currently have to walk through the full
# ``setup guardrail`` wizard, answer "yes" to a single confirm, and
# trust that the wizard does the right thing under the hood. The
# aliases shortcut that by defaulting to observe mode while still
# accepting ``--mode action`` for hook-native blocking:
#
#   defenseclaw setup codex          → observe by default for Codex
#   defenseclaw setup claude-code    → observe by default for Claude Code
#   defenseclaw setup hermes         → observe by default for Hermes
#   defenseclaw setup cursor         → observe by default for Cursor
#   defenseclaw setup windsurf       → observe by default for Windsurf
#   defenseclaw setup geminicli      → observe by default for Gemini CLI
#   defenseclaw setup copilot        → observe by default for GitHub Copilot CLI
#   defenseclaw setup openhands      → observe by default for OpenHands
#   defenseclaw setup antigravity    → observe by default for Antigravity (agy)
#
# Both commands also flip ``claw.mode`` so the rest of the CLI/TUI
# (skill scanner, MCP scanner, plugin scanner, overview panels) reads
# from the matching connector's source-of-truth files (``~/.codex`` or
# ``~/.claude``) instead of OpenClaw's default ``~/.openclaw`` layout.
# Without this flip, ``defenseclaw scan skills`` after ``setup codex``
# would scan ``~/.openclaw/skills`` and miss every Codex skill — a
# foot-gun we explicitly want to close.
#
# Hook connectors have no proxy data path to engage. Observe mode
# records via hooks and native OTel where documented; action mode uses
# the same hook bus to return deny verdicts on policy hits.

# Stable hint filename used by ``defenseclaw setup guardrail`` and
# ``defenseclaw quickstart`` to default the connector picker after a
# fresh install. Mirrors the ``picked_connector`` constant baked into
# scripts/install.sh — keeping these in sync means re-running the
# alias commands here updates the hint just like the installer would.
_PICKED_CONNECTOR_FILENAME = "picked_connector"
_AGENT_SELECTION_FILENAME = "agent_selection.json"
_HOOK_CONTRACT_LOCK_FILENAME = "hook_contract_lock.json"
_AGENT_SELECTION_MAX_BYTES = 64 << 10
_HOOK_CONTRACT_LOCK_MAX_BYTES = 16 << 20
_SETUP_CONFIG_MAX_BYTES = 16 << 20
_ACTIVE_CONNECTOR_STATE_MAX_BYTES = 64 << 10
_SETUP_RUNTIME_ARTIFACT_MAX_BYTES = 16 << 20
_SETUP_RUNTIME_RECEIPT_MAX_FILES = 128
_SETUP_RUNTIME_REGISTRATION_MAX_FILES = 128
_SETUP_RUNTIME_SNAPSHOT_ATTEMPTS = 6
_SETUP_RUNTIME_SNAPSHOT_RETRY_SECONDS = 0.2
_SETUP_ROLLBACK_MAX_FAILURES = 64
_WINDOWS_REPARSE_POINT_ATTRIBUTE = 0x400


def _windows_runtime_rollback(restart: bool) -> bool:
    return restart and platform_support.host_os() == "windows"


_SETUP_SELECTION_PROOF_SEAL = object()


@dataclass(frozen=True)
class _VerifiedSetupAgentSelections:
    """Concrete, receipt-bound executable selections for one transaction."""

    connectors: tuple[str, ...]
    records: tuple[Any, ...]
    receipt_sha256: str
    receipt_generation: tuple[int, int, int, int]
    prior_receipt_generation: tuple[int, int, int, int] | None
    _seal: object = field(repr=False, compare=False)

    def record_for(self, connector: str):
        wanted = normalize_connector(connector)
        return next(
            (record for record in self.records if normalize_connector(record.connector) == wanted),
            None,
        )


def _write_picked_connector_hint(data_dir: str | None, connector: str) -> None:
    """Persist *connector* as the install-time picked-connector hint.

    Writes ``<data_dir>/picked_connector`` with the same private atomic writer
    required when setup later captures it as rollback evidence. Failures are
    non-fatal and surface as a warning —
    a stale hint never blocks setup, it only affects the *default*
    selected by future ``defenseclaw setup guardrail`` invocations.

    The bound on contents is intentional: the file is one short word
    (one of ``_CONNECTOR_NAMES_FALLBACK``) and ``_read_picked_connector``
    rejects anything outside the host's supported connector names, so even a
    corrupted write can never escalate to remote code paths. Valid aliases
    remain persistable when tests or a cross-platform installer deliberately
    configure a connector that is filtered from the current host's menu.
    """
    if not data_dir:
        return
    if connector not in _CONNECTOR_NAMES_FALLBACK:
        return
    try:
        os.makedirs(data_dir, exist_ok=True)
        path = os.path.join(data_dir, _PICKED_CONNECTOR_FILENAME)
        atomic_write_private_bytes(path, (connector + "\n").encode("utf-8"))
    except OSError as exc:
        click.echo(
            f"  ⚠ Failed to update picked_connector hint: {exc}",
            err=True,
        )


@dataclass(frozen=True)
class _SetupConfigSnapshot:
    """Exact rollback point for desired config and setup authority receipts."""

    config: Any
    config_existed: bool
    config_bytes: bytes
    config_generation: tuple[int, int, int, int] | None
    picked_connector_existed: bool
    picked_connector_bytes: bytes
    picked_connector_generation: tuple[int, int, int, int] | None
    agent_selection_existed: bool
    agent_selection_bytes: bytes
    agent_selection_generation: tuple[int, int, int, int] | None
    hook_contract_lock_existed: bool
    hook_contract_lock_bytes: bytes
    hook_contract_lock_generation: tuple[int, int, int, int] | None
    applied_runtime: _SetupAppliedRuntimeEvidence | None


@dataclass(frozen=True)
class _SetupRegistrationLocationEvidence:
    connector: str
    role: str
    identity: str
    fingerprint: str
    path: str = field(repr=False)


@dataclass(frozen=True)
class _SetupAppliedRuntimeEvidence:
    lifecycle: str
    generation: str | None
    invariants: tuple[tuple[str, str, str, str], ...]
    registration_locations: tuple[_SetupRegistrationLocationEvidence, ...] = ()


def _capture_protected_setup_file(
    path: str,
    maximum: int,
    label: str,
) -> tuple[bool, bytes, tuple[int, int, int, int] | None]:
    """Read one bounded private regular file without following path redirects."""

    try:
        fd = open_regular_file_no_follow(path)
    except FileNotFoundError:
        return False, b"", None
    except OSError:
        raise OSError(f"{label} rollback source is unavailable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"{label} rollback source is not a regular file")
        if info.st_size > maximum:
            raise OSError(f"{label} rollback source is unexpectedly large")
        if os.name == "nt":
            acl_error = windows_acl_write_error(path)
            if acl_error is not None:
                raise OSError(f"{label} rollback source is not protected")
        else:
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise OSError(f"{label} rollback source is not owned by the current user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise OSError(f"{label} rollback source is not private")
        body = bytearray()
        while len(body) <= maximum:
            chunk = os.read(fd, min(64 << 10, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if len(body) > maximum:
            raise OSError(f"{label} rollback source grew while reading")
        after = os.fstat(fd)
        if after.st_size != len(body) or not os.path.samestat(info, after):
            raise OSError(f"{label} rollback source changed while reading")
        try:
            path_after = os.stat(path, follow_symlinks=False)
        except OSError:
            raise OSError(f"{label} rollback source path is unavailable") from None
        if not stat.S_ISREG(path_after.st_mode) or not os.path.samestat(info, path_after):
            raise OSError(f"{label} rollback source path changed while reading")
        generation = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        return True, bytes(body), generation
    finally:
        os.close(fd)


def _setup_runtime_digest(value: Any) -> str:
    body = _json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _setup_runtime_ref(value: object) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:12]


def _setup_runtime_subject(name: object) -> str:
    raw = str(name).strip()
    normalized = normalize_connector(raw) if raw else ""
    if normalized in _CONNECTOR_NAMES_FALLBACK:
        return normalized
    return f"id-{_setup_runtime_ref(raw)}"


def _capture_setup_runtime_location(path: object, role: str) -> tuple[str, str, str]:
    raw = os.fspath(path) if isinstance(path, (str, os.PathLike)) else ""
    if not raw or not os.path.isabs(raw) or "\x00" in raw:
        raise OSError(f"{role} evidence {_setup_runtime_ref(raw)} has an invalid identity")
    normalized = os.path.normcase(os.path.normpath(os.path.abspath(raw)))
    identity = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()
    try:
        existed, body, _generation = _capture_protected_setup_file(
            normalized,
            _SETUP_RUNTIME_ARTIFACT_MAX_BYTES,
            role,
        )
    except Exception:
        raise OSError(f"{role} evidence {identity[:12]} is unavailable") from None
    if not existed:
        return normalized, identity, "missing"
    return normalized, identity, f"present:{len(body)}:{hashlib.sha256(body).hexdigest()}"


def _capture_setup_runtime_file(path: object, role: str) -> tuple[str, str]:
    _normalized, identity, fingerprint = _capture_setup_runtime_location(path, role)
    return identity[:12], fingerprint


def _capture_setup_receipt_fingerprint(data_dir: str, connector: str) -> str:
    subject = _setup_runtime_subject(connector)
    if connector not in _CONNECTOR_NAMES_FALLBACK:
        raise OSError(f"connector {subject}: receipt ownership is unavailable")
    root = os.path.join(data_dir, "connector_backups", connector)
    try:
        info = os.lstat(root)
    except FileNotFoundError:
        return "missing"
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT_ATTRIBUTE:
        raise OSError(f"connector {subject}: receipt root is unsafe")
    try:
        with os.scandir(root) as iterator:
            entries = sorted(iterator, key=lambda item: os.path.normcase(item.name))
    except OSError:
        raise OSError(f"connector {subject}: receipts are unavailable") from None
    if len(entries) > _SETUP_RUNTIME_RECEIPT_MAX_FILES:
        raise OSError(f"connector {subject}: receipt set exceeds the bounded limit")
    fingerprints: dict[str, str] = {}
    for entry in entries:
        reference, fingerprint = _capture_setup_runtime_file(entry.path, "owned receipt")
        fingerprints[reference] = fingerprint
    return f"present:{_setup_runtime_digest(fingerprints)}"


def _capture_setup_registration_locations(
    connector: str,
    lock_entry: dict[str, Any],
    *,
    remaining: int = _SETUP_RUNTIME_REGISTRATION_MAX_FILES,
) -> tuple[_SetupRegistrationLocationEvidence, ...]:
    locations = lock_entry.get("locations", {})
    subject = _setup_runtime_subject(connector)
    if not isinstance(locations, dict):
        raise OSError(f"connector {subject}: registration locations are malformed")
    requested: list[tuple[str, object]] = []
    for field_name, role in (
        ("hook_config_paths", "hook registration"),
        ("hook_script_paths", "hook runtime"),
        ("telemetry_config_paths", "telemetry registration"),
    ):
        paths = locations.get(field_name, [])
        if not isinstance(paths, list):
            raise OSError(f"connector {subject}: {role} set is malformed")
        for path in paths:
            requested.append((role, path))
    if len(requested) > remaining:
        raise OSError(f"connector {subject}: registration set exceeds the bounded limit")

    evidence: dict[tuple[str, str, str], _SetupRegistrationLocationEvidence] = {}
    for role, path in requested:
        normalized, identity, fingerprint = _capture_setup_runtime_location(path, role)
        key = (subject, role, identity)
        current = _SetupRegistrationLocationEvidence(
            connector=subject,
            role=role,
            identity=identity,
            fingerprint=fingerprint,
            path=normalized,
        )
        if key in evidence:
            raise OSError(f"connector {subject}: registration identity is duplicated")
        evidence[key] = current
    return tuple(evidence[key] for key in sorted(evidence))


def _setup_registration_fingerprint(locations: tuple[_SetupRegistrationLocationEvidence, ...]) -> str:
    mapped = _setup_registration_location_map(locations)
    return _setup_runtime_digest(
        {
            f"{connector}:{role}:{identity}": location.fingerprint
            for (connector, role, identity), location in mapped.items()
        }
    )


def _setup_registration_location_key(
    location: _SetupRegistrationLocationEvidence,
) -> tuple[str, str, str]:
    if (
        location.role not in {"hook registration", "hook runtime", "telemetry registration"}
        or len(location.identity) != 64
        or any(character not in "0123456789abcdef" for character in location.identity)
    ):
        raise OSError("registration location evidence has an invalid identity")
    return location.connector, location.role, location.identity


def _setup_registration_location_map(
    locations: tuple[_SetupRegistrationLocationEvidence, ...],
) -> dict[tuple[str, str, str], _SetupRegistrationLocationEvidence]:
    mapped: dict[tuple[str, str, str], _SetupRegistrationLocationEvidence] = {}
    fingerprints: dict[str, str] = {}
    paths: dict[str, str] = {}
    for location in locations:
        key = _setup_registration_location_key(location)
        if key in mapped:
            raise OSError("registration location evidence contains a duplicate full identity")
        prior_fingerprint = fingerprints.get(location.identity)
        if prior_fingerprint is not None and prior_fingerprint != location.fingerprint:
            raise OSError("registration location evidence contains conflicting full identities")
        prior_path = paths.get(location.identity)
        if prior_path is not None and prior_path != location.path:
            raise OSError("registration location evidence contains conflicting exact paths")
        fingerprints[location.identity] = location.fingerprint
        paths[location.identity] = location.path
        mapped[key] = location
    return mapped


def _decode_setup_hook_contract_lock(body: bytes) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    try:
        document = _json.loads(body)
    except (UnicodeDecodeError, ValueError):
        raise OSError("hook contract evidence is malformed") from None
    if not isinstance(document, dict):
        raise OSError("hook contract evidence has an unsupported schema")
    version = document.get("version")
    raw_entries = document.get("connectors")
    if type(version) is not int or not 1 <= version <= 2 or not isinstance(raw_entries, dict):
        raise OSError("hook contract evidence has an unsupported schema")
    entries: dict[str, dict[str, Any]] = {}
    for raw_name, raw_entry in raw_entries.items():
        if not isinstance(raw_name, str) or not raw_name.strip() or not isinstance(raw_entry, dict):
            raise OSError("hook contract connector evidence is malformed")
        name = normalize_connector(raw_name)
        if not name or name in entries:
            raise OSError(f"connector {_setup_runtime_subject(name)}: hook contract identity is duplicated")
        entries[name] = raw_entry
    return document, entries


def _capture_setup_lock_registration_locations_once(cfg) -> tuple[_SetupRegistrationLocationEvidence, ...]:
    lock_path = os.path.join(os.path.abspath(os.fspath(cfg.data_dir)), _HOOK_CONTRACT_LOCK_FILENAME)
    existed, body, generation = _capture_protected_setup_file(
        lock_path,
        _HOOK_CONTRACT_LOCK_MAX_BYTES,
        "hook contract lock",
    )
    if not existed:
        existed_after, _body_after, _generation_after = _capture_protected_setup_file(
            lock_path,
            _HOOK_CONTRACT_LOCK_MAX_BYTES,
            "hook contract lock",
        )
        if existed_after:
            raise OSError("hook contract changed while registration evidence was captured")
        return ()
    _document, entries = _decode_setup_hook_contract_lock(body)
    locations: list[_SetupRegistrationLocationEvidence] = []
    for name in sorted(entries):
        captured = _capture_setup_registration_locations(
            name,
            entries[name],
            remaining=_SETUP_RUNTIME_REGISTRATION_MAX_FILES - len(locations),
        )
        locations.extend(captured)
    existed_after, body_after, generation_after = _capture_protected_setup_file(
        lock_path,
        _HOOK_CONTRACT_LOCK_MAX_BYTES,
        "hook contract lock",
    )
    if not existed_after or generation_after != generation or body_after != body:
        raise OSError("hook contract changed while registration evidence was captured")
    return tuple(sorted(locations, key=lambda item: (item.connector, item.role, item.identity)))


def _capture_failed_setup_registration_locations(cfg) -> tuple[_SetupRegistrationLocationEvidence, ...]:
    previous: tuple[_SetupRegistrationLocationEvidence, ...] | None = None
    last_error: Exception | None = None
    for _attempt in range(_SETUP_RUNTIME_SNAPSHOT_ATTEMPTS):
        try:
            current = _capture_setup_lock_registration_locations_once(cfg)
        except Exception as exc:  # noqa: BLE001 - retry a bounded failed-publication race.
            previous = None
            last_error = exc
            continue
        if previous == current:
            return current
        previous = current
    reference = _setup_runtime_ref(type(last_error).__name__) if last_error is not None else "unstable"
    raise OSError(f"failed-generation registration evidence did not stabilize [{reference}]") from None


def _capture_setup_gateway_boundary(cfg) -> tuple[str, dict[str, Any] | None, str | None]:
    from defenseclaw.commands.cmd_doctor import _trusted_gateway_listener
    from defenseclaw.commands.cmd_status import _fetch_runtime_bound_health
    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    trust = _trusted_gateway_listener(cfg, platform_name="win32")
    if trust.code in {"missing", "missing_process"}:
        return "stopped", None, None
    if not trust.trusted:
        raise OSError(f"gateway lifecycle evidence is unavailable [{_setup_runtime_ref(trust.code)}]")
    try:
        client = OrchestratorClient(
            host=gateway_api_client_host(cfg),
            port=int(cfg.gateway.api_port),
            token=cfg.gateway.resolved_token(),
        )
        health = _fetch_runtime_bound_health(client, cfg)
    except Exception:
        health = None
    generation = health.get("started_at") if isinstance(health, dict) else None
    if (
        not isinstance(generation, str)
        or not generation.strip()
        or len(generation) > 256
        or any(character in generation for character in "\x00\r\n")
    ):
        raise OSError("authenticated gateway generation evidence is unavailable")
    return "running", health, generation.strip()


def _capture_setup_watchdog_fingerprint(cfg) -> str:
    from defenseclaw.commands.cmd_doctor import _inspect_windows_watchdog_runtime
    from defenseclaw.doctor_gateway import GatewayEvidence

    evidence = GatewayEvidence(platform_name="win32")
    posture, _detail, _health = _inspect_windows_watchdog_runtime(cfg, evidence)
    if posture in {"foreign", "uninspectable", "unowned", "unsafe"}:
        raise OSError(f"watchdog custody evidence is unavailable [{_setup_runtime_ref(posture)}]")
    # The inspection above fail-closes every contradictory custody posture.
    # Safe lifecycle postures are not durable rollback identity: during hosted
    # teardown the same owned watchdog can move through running, stale/invalid,
    # and stopped while its atomically published files are retired. Binding
    # that liveness hint prevents two otherwise identical snapshots from ever
    # converging. The gateway boundary and durable connector publications below
    # remain authoritative for rollback comparison.
    return _setup_runtime_digest(
        {
            "enabled": str(bool(getattr(getattr(cfg.gateway, "watchdog", None), "enabled", True))).lower(),
        }
    )


def _capture_setup_applied_runtime_once(
    cfg,
    required_registration_locations: tuple[_SetupRegistrationLocationEvidence, ...] = (),
) -> _SetupAppliedRuntimeEvidence:
    from defenseclaw.commands.cmd_status import _fetch_health_connectors

    lifecycle, health, generation = _capture_setup_gateway_boundary(cfg)
    invariants: dict[tuple[str, str, str], str] = {}

    def put(key: tuple[str, str, str], value: object) -> None:
        normalized = str(value)
        if key in invariants and invariants[key] != normalized:
            raise OSError(f"{key[0]} {_setup_runtime_subject(key[1])}: duplicate evidence")
        invariants[key] = normalized

    data_dir = os.path.abspath(os.fspath(cfg.data_dir))
    active_existed, active_body, _active_generation = _capture_protected_setup_file(
        os.path.join(data_dir, "active_connector.json"),
        _ACTIVE_CONNECTOR_STATE_MAX_BYTES,
        "active connector state",
    )
    active: set[str] = set()
    inactive: set[str] = set()
    put(("runtime", "gateway", "active-state-presence"), "present" if active_existed else "missing")
    if active_existed:
        try:
            active_document = _json.loads(active_body)
        except (UnicodeDecodeError, ValueError):
            raise OSError("active connector evidence is malformed") from None
        runtime_sets = _connector_runtime_state_sets(active_document)
        if runtime_sets is None:
            raise OSError("active connector evidence has an unsupported schema")
        active, raw_inactive = runtime_sets
        inactive = raw_inactive or set()
        version = active_document.get("version") if isinstance(active_document, dict) else None
        put(("runtime", "gateway", "active-state-version"), version)

    lock_existed, lock_body, _lock_generation = _capture_protected_setup_file(
        os.path.join(data_dir, _HOOK_CONTRACT_LOCK_FILENAME),
        _HOOK_CONTRACT_LOCK_MAX_BYTES,
        "hook contract lock",
    )
    put(("runtime", "gateway", "lock-presence"), "present" if lock_existed else "missing")
    lock_entries: dict[str, dict[str, Any]] = {}
    if lock_existed:
        lock_document, lock_entries = _decode_setup_hook_contract_lock(lock_body)
        version = lock_document.get("version")
        shared_digests = lock_document.get("shared_hook_script_digests", {})
        if not isinstance(shared_digests, dict):
            raise OSError("hook contract shared digest evidence is malformed")
        put(("runtime", "gateway", "lock-version"), version)
        put(("runtime", "gateway", "shared-lock-digests"), _setup_runtime_digest(shared_digests))
        for name, raw_entry in lock_entries.items():
            subject = _setup_runtime_subject(name)
            stable_entry = copy.deepcopy(raw_entry)
            stable_entry.pop("updated_at", None)
            put(("connector", subject, "lock-identity"), _setup_runtime_digest(stable_entry))
            fail_mode = raw_entry.get("hook_fail_mode")
            posture = raw_entry.get("registration_posture")
            mode = posture.get("guardrail_mode") if isinstance(posture, dict) else None
            put(("connector", subject, "hook-fail-mode"), fail_mode)
            put(("connector", subject, "guardrail-mode"), mode)
        expected_hook_connectors = active & _HOOK_ENFORCED_CONNECTORS
        lock_covers = _hook_contract_lock_covers(lock_document, expected_hook_connectors, inactive)
        put(("runtime", "gateway", "lock-covers-active-roster"), str(lock_covers).lower())
        publications = _validated_hook_contract_lock_publications(lock_document, expected_hook_connectors)
        for name in sorted(expected_hook_connectors):
            put(
                ("connector", _setup_runtime_subject(name), "lock-publication-presence"),
                "present" if name in publications else "missing",
            )

    health_connectors = _fetch_health_connectors(health=health)
    health_records: dict[str, dict[str, str]] = {}
    for raw_name, record in health_connectors.items():
        name = normalize_connector(raw_name)
        subject = _setup_runtime_subject(name)
        if not name or name in health_records or not isinstance(record, dict):
            raise OSError(f"connector {subject}: authenticated health identity is malformed")
        health_records[name] = {
            attribute: value if isinstance(value := record.get(attribute), str) and value else "missing"
            for attribute in ("state", "source", "tool_inspection_mode", "subprocess_policy")
        }
    health_modes: dict[str, str] = {}
    if isinstance(health, dict):
        subsystem_states = {}
        for subsystem in ("gateway", "guardrail", "watcher"):
            subsystem_record = health.get(subsystem)
            state = subsystem_record.get("state") if isinstance(subsystem_record, dict) else None
            subsystem_states[subsystem] = state if isinstance(state, str) and state else "missing"
        put(("runtime", "gateway", "health"), _setup_runtime_digest(subsystem_states))
        guardrail = health.get("guardrail")
        details = guardrail.get("details") if isinstance(guardrail, dict) else None
        raw_modes = details.get("connector_modes") if isinstance(details, dict) else None
        if raw_modes is not None:
            if not isinstance(raw_modes, dict):
                raise OSError("authenticated connector mode evidence is malformed")
            for raw_name, raw_mode in raw_modes.items():
                name = normalize_connector(raw_name) if isinstance(raw_name, str) else ""
                subject = _setup_runtime_subject(raw_name)
                if not name or name in health_modes or not isinstance(raw_mode, str):
                    raise OSError(f"connector {subject}: authenticated mode evidence is malformed")
                health_modes[name] = raw_mode

    configured_names = {normalize_connector(name) for name in cfg.active_connectors() if name}
    connector_names = configured_names | active | inactive | set(lock_entries) | set(health_records) | set(health_modes)
    registration_locations: list[_SetupRegistrationLocationEvidence] = []
    for name in sorted(connector_names):
        subject = _setup_runtime_subject(name)
        if name in active:
            put(("connector", subject, "roster-active"), "present")
        if name in inactive:
            put(("connector", subject, "roster-inactive"), "present")
        put(("connector", subject, "health-presence"), "present" if name in health_records else "missing")
        put(
            ("connector", subject, "health-identity"),
            _setup_runtime_digest(health_records[name]) if name in health_records else "missing",
        )
        put(("connector", subject, "health-guardrail-mode"), health_modes.get(name, "missing"))
        put(
            ("connector", subject, "lock-entry-presence"),
            "present" if name in lock_entries else "missing",
        )
        put(
            ("connector", subject, "owned-receipts"),
            _capture_setup_receipt_fingerprint(data_dir, name),
        )
        entry = lock_entries.get(name)
        captured_locations = ()
        if entry is not None:
            captured_locations = _capture_setup_registration_locations(
                name,
                entry,
                remaining=_SETUP_RUNTIME_REGISTRATION_MAX_FILES - len(registration_locations),
            )
            registration_locations.extend(captured_locations)
        put(
            ("connector", subject, "registrations"),
            _setup_registration_fingerprint(captured_locations) if entry is not None else "missing",
        )

    registration_map = _setup_registration_location_map(tuple(registration_locations))
    by_identity = {location.identity: location for location in registration_map.values()}
    for required in required_registration_locations:
        key = _setup_registration_location_key(required)
        current = registration_map.get(key)
        if current is not None:
            if current.path != required.path:
                raise OSError("registration location evidence has a conflicting exact path")
            continue
        if len(registration_map) >= _SETUP_RUNTIME_REGISTRATION_MAX_FILES:
            raise OSError("registration location union exceeds the bounded limit")
        identity_match = by_identity.get(required.identity)
        if identity_match is not None:
            if identity_match.path != required.path:
                raise OSError("registration location evidence has a conflicting exact path")
            current = _SetupRegistrationLocationEvidence(
                connector=required.connector,
                role=required.role,
                identity=required.identity,
                fingerprint=identity_match.fingerprint,
                path=required.path,
            )
        else:
            normalized, identity, fingerprint = _capture_setup_runtime_location(required.path, required.role)
            if identity != required.identity:
                raise OSError("registration location evidence changed exact identity")
            current = _SetupRegistrationLocationEvidence(
                connector=required.connector,
                role=required.role,
                identity=identity,
                fingerprint=fingerprint,
                path=normalized,
            )
        registration_map[key] = current
        by_identity[current.identity] = current
    normalized_locations = tuple(registration_map[key] for key in sorted(registration_map))
    _setup_registration_location_map(normalized_locations)

    put(("watchdog", "runtime", "custody-health"), _capture_setup_watchdog_fingerprint(cfg))
    end_lifecycle, _end_health, end_generation = _capture_setup_gateway_boundary(cfg)
    if (lifecycle, generation) != (end_lifecycle, end_generation):
        raise OSError("gateway generation changed while applied runtime evidence was captured")
    normalized = tuple((*key, value) for key, value in sorted(invariants.items()))
    return _SetupAppliedRuntimeEvidence(
        lifecycle=lifecycle,
        generation=generation,
        invariants=normalized,
        registration_locations=normalized_locations,
    )


def _capture_setup_applied_runtime(
    cfg,
    required_registration_locations: tuple[_SetupRegistrationLocationEvidence, ...] = (),
) -> _SetupAppliedRuntimeEvidence:
    previous: _SetupAppliedRuntimeEvidence | None = None
    last_error: Exception | None = None
    last_error_site: str | None = None
    last_difference: str | None = None
    for attempt in range(_SETUP_RUNTIME_SNAPSHOT_ATTEMPTS):
        try:
            current = _capture_setup_applied_runtime_once(cfg, required_registration_locations)
        except Exception as exc:  # noqa: BLE001 - retry one bounded evidence race.
            # An unavailable read is not contradictory runtime evidence. Keep
            # the last complete, internally generation-fenced sample so a
            # later equal complete sample can establish the rollback point.
            # A later different sample still replaces it below, and the
            # bounded loop still fails closed without two equal successes.
            last_error = exc
            last_error_site = _setup_runtime_error_site(exc)
        else:
            if previous == current:
                return current
            if previous is not None:
                last_difference = _setup_applied_runtime_difference(previous, current)
            previous = current
        if attempt + 1 < _SETUP_RUNTIME_SNAPSHOT_ATTEMPTS:
            time.sleep(_SETUP_RUNTIME_SNAPSHOT_RETRY_SECONDS)
    if last_difference is not None:
        reference = f"diff={last_difference}"
    elif last_error is not None:
        error_ref = _setup_runtime_ref(type(last_error).__name__)
        reference = f"site={last_error_site};error={error_ref}" if last_error_site else error_ref
    else:
        reference = "unstable"
    raise OSError(f"applied runtime evidence did not stabilize [{reference}]") from None


def _setup_runtime_error_site(exc: Exception) -> str | None:
    """Return the deepest local capture site without exposing exception data."""
    site: str | None = None
    traceback = exc.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        function = frame.f_code.co_name
        if frame.f_globals.get("__name__") == __name__ and function != "_capture_setup_applied_runtime":
            site = f"{function}:{traceback.tb_lineno}"
        traceback = traceback.tb_next
    return site


def _setup_applied_runtime_difference(
    previous: _SetupAppliedRuntimeEvidence,
    current: _SetupAppliedRuntimeEvidence,
) -> str:
    """Name the first changed evidence field without exposing its value."""
    if previous.lifecycle != current.lifecycle:
        return "lifecycle"
    if previous.generation != current.generation:
        return "generation"
    previous_invariants = {item[:3]: item[3] for item in previous.invariants}
    current_invariants = {item[:3]: item[3] for item in current.invariants}
    for key in sorted(previous_invariants.keys() | current_invariants.keys()):
        if previous_invariants.get(key) != current_invariants.get(key):
            return ".".join(key)
    if previous.registration_locations != current.registration_locations:
        return "registration-locations"
    return "unknown"


def _capture_setup_desired_snapshot_once(cfg) -> _SetupConfigSnapshot:
    data_dir = getattr(cfg, "data_dir", None)
    config_existed = False
    config_body = b""
    config_generation = None
    if data_dir:
        config_existed, config_body, config_generation = _capture_protected_setup_file(
            os.path.abspath(os.fspath(config_path_for_data_dir(data_dir))),
            _SETUP_CONFIG_MAX_BYTES,
            "config.yaml",
        )
    existed = False
    body = b""
    picked_generation = None
    if data_dir:
        existed, body, picked_generation = _capture_protected_setup_file(
            os.path.join(os.path.abspath(os.fspath(data_dir)), _PICKED_CONNECTOR_FILENAME),
            4096,
            "picked_connector",
        )
    selection_existed = False
    selection_body = b""
    selection_generation = None
    lock_existed = False
    lock_body = b""
    lock_generation = None
    if data_dir:
        selection_existed, selection_body, selection_generation = _capture_protected_setup_file(
            os.path.join(os.path.abspath(os.fspath(data_dir)), _AGENT_SELECTION_FILENAME),
            _AGENT_SELECTION_MAX_BYTES,
            "agent_selection.json",
        )
        lock_existed, lock_body, lock_generation = _capture_protected_setup_file(
            os.path.join(os.path.abspath(os.fspath(data_dir)), _HOOK_CONTRACT_LOCK_FILENAME),
            _HOOK_CONTRACT_LOCK_MAX_BYTES,
            "hook_contract_lock.json",
        )
    return _SetupConfigSnapshot(
        config=copy.deepcopy(cfg),
        config_existed=config_existed,
        config_bytes=config_body,
        config_generation=config_generation,
        picked_connector_existed=existed,
        picked_connector_bytes=body,
        picked_connector_generation=picked_generation,
        agent_selection_existed=selection_existed,
        agent_selection_bytes=selection_body,
        agent_selection_generation=selection_generation,
        hook_contract_lock_existed=lock_existed,
        hook_contract_lock_bytes=lock_body,
        hook_contract_lock_generation=lock_generation,
        applied_runtime=None,
    )


def _setup_snapshot_authority_fence(snapshot: _SetupConfigSnapshot) -> tuple[Any, ...]:
    return (
        snapshot.config_existed,
        snapshot.config_generation,
        hashlib.sha256(snapshot.config_bytes).digest(),
        snapshot.picked_connector_existed,
        snapshot.picked_connector_generation,
        hashlib.sha256(snapshot.picked_connector_bytes).digest(),
        snapshot.agent_selection_existed,
        snapshot.agent_selection_generation,
        hashlib.sha256(snapshot.agent_selection_bytes).digest(),
        snapshot.hook_contract_lock_existed,
        snapshot.hook_contract_lock_generation,
        hashlib.sha256(snapshot.hook_contract_lock_bytes).digest(),
    )


def _capture_setup_config_snapshot(
    cfg,
    *,
    capture_runtime: bool = False,
) -> _SetupConfigSnapshot:
    if not capture_runtime:
        return _capture_setup_desired_snapshot_once(cfg)
    for _attempt in range(_SETUP_RUNTIME_SNAPSHOT_ATTEMPTS):
        before = _capture_setup_desired_snapshot_once(cfg)
        runtime = _capture_setup_applied_runtime(cfg)
        after = _capture_setup_desired_snapshot_once(cfg)
        if _setup_snapshot_authority_fence(before) == _setup_snapshot_authority_fence(after):
            return replace(after, applied_runtime=runtime)
    raise OSError("setup rollback authority changed while runtime evidence was captured")


def _restore_setup_config_snapshot(app: AppContext, snapshot: _SetupConfigSnapshot) -> None:
    """Atomically republish prior desired config, hint, and authority receipt."""

    cfg = _restore_setup_config_in_memory(app, snapshot)
    restore_errors: list[str] = []
    try:
        _restore_setup_config_file_snapshot(cfg, snapshot)
    except Exception as exc:  # noqa: BLE001 — still restore independent protected receipts.
        restore_errors.append(f"config [{_setup_runtime_ref(type(exc).__name__)}]")
    try:
        _sync_guardrail_hilt_to_opa(cfg.policy_dir, cfg.guardrail)
    except Exception as exc:  # noqa: BLE001 — receipt restoration must still run.
        restore_errors.append(f"HILT policy [{_setup_runtime_ref(type(exc).__name__)}]")

    if cfg.data_dir:
        hint_path = os.path.join(cfg.data_dir, _PICKED_CONNECTOR_FILENAME)
        try:
            if snapshot.picked_connector_existed:
                atomic_write_private_bytes(hint_path, snapshot.picked_connector_bytes)
            elif os.path.lexists(hint_path):
                delete_file_durable(hint_path)
        except Exception as exc:  # noqa: BLE001 — continue to the authority receipt.
            restore_errors.append(f"picked_connector [{_setup_runtime_ref(type(exc).__name__)}]")
        try:
            _restore_setup_agent_selection_snapshot(cfg, snapshot)
        except Exception as exc:  # noqa: BLE001 — report exact protected-receipt failure.
            restore_errors.append(f"agent_selection.json [{_setup_runtime_ref(type(exc).__name__)}]")
        try:
            _restore_setup_hook_contract_lock_snapshot(cfg, snapshot)
        except Exception as exc:  # noqa: BLE001 — report exact sealed-authority failure.
            restore_errors.append(f"hook_contract_lock.json [{_setup_runtime_ref(type(exc).__name__)}]")
    if restore_errors:
        raise OSError("setup rollback was incomplete: " + "; ".join(restore_errors))


def _restore_setup_config_file_snapshot(cfg, snapshot: _SetupConfigSnapshot) -> None:
    """Restore exact pre-setup YAML without the modeled-delta save path.

    ``Config.save()`` applies only values that differ from the object's loaded
    v8 baseline. The restored object and its baseline both describe the prior
    generation, while the file still describes the failed requested generation;
    another modeled save would therefore see no delta and preserve the failed
    file. Republish the captured bytes before asking the gateway to re-apply
    and verify the prior runtime generation.
    """

    if not cfg.data_dir:
        return
    config_path = os.path.abspath(os.fspath(config_path_for_data_dir(cfg.data_dir)))
    with locked_config_yaml(config_path):
        if snapshot.config_existed:
            atomic_write_private_bytes(config_path, snapshot.config_bytes)
        elif os.path.lexists(config_path):
            delete_file_durable(config_path)


def _restore_setup_agent_selection_snapshot(cfg, snapshot: _SetupConfigSnapshot) -> None:
    """Restore exact pre-setup executable authority without rewriting config."""

    if not cfg.data_dir:
        return
    selection_path = os.path.join(
        os.path.abspath(os.fspath(cfg.data_dir)),
        _AGENT_SELECTION_FILENAME,
    )
    if snapshot.agent_selection_existed:
        atomic_write_private_bytes(selection_path, snapshot.agent_selection_bytes)
    elif os.path.lexists(selection_path):
        delete_file_durable(selection_path)


def _restore_setup_hook_contract_lock_snapshot(cfg, snapshot: _SetupConfigSnapshot) -> None:
    """Restore exact pre-setup sealed executable authority."""

    if not cfg.data_dir:
        return
    lock_path = os.path.join(
        os.path.abspath(os.fspath(cfg.data_dir)),
        _HOOK_CONTRACT_LOCK_FILENAME,
    )
    if snapshot.hook_contract_lock_existed:
        atomic_write_private_bytes(lock_path, snapshot.hook_contract_lock_bytes)
    elif os.path.lexists(lock_path):
        delete_file_durable(lock_path)


def _parse_setup_selection_time(raw: Any, label: str) -> datetime:
    if not isinstance(raw, str) or not raw.strip():
        raise OSError(f"agent_selection.json has no valid {label}")
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise OSError(f"agent_selection.json has invalid {label}") from exc
    if parsed.tzinfo is None:
        raise OSError(f"agent_selection.json {label} is not timezone-bound")
    return parsed.astimezone(timezone.utc)


def _validate_setup_agent_selection_receipt(
    data_dir: str | os.PathLike[str],
    connectors: tuple[str, ...],
    records: dict[str, Any],
    *,
    expected_receipt_sha256: str | None = None,
    expected_generation: tuple[int, int, int, int] | None = None,
    prior_generation: tuple[int, int, int, int] | None = None,
) -> _VerifiedSetupAgentSelections:
    """Bind concrete selection records to the current fresh protected receipt."""

    from defenseclaw.agent_selection import (
        SELECTION_LIFETIME,
        SetupAgentSelection,
        setup_agent_selection_connectors,
    )

    expected = setup_agent_selection_connectors(connectors)
    if not expected:
        raise OSError("no protected executable selections were requested")
    if set(records) != set(expected) or any(not isinstance(record, SetupAgentSelection) for record in records.values()):
        raise OSError("selection records do not cover the complete protected connector roster")

    receipt_path = os.path.join(
        os.path.abspath(os.fspath(data_dir)),
        _AGENT_SELECTION_FILENAME,
    )
    existed, body, generation = _capture_protected_setup_file(
        receipt_path,
        _AGENT_SELECTION_MAX_BYTES,
        "agent_selection.json",
    )
    if not existed or generation is None:
        raise OSError("fresh agent_selection.json is missing")
    if expected_generation is not None and generation != expected_generation:
        raise OSError("agent_selection.json generation changed after protected selection")
    if prior_generation is not None and generation == prior_generation:
        raise OSError("agent_selection.json was not freshly published for this transaction")

    digest = hashlib.sha256(body).hexdigest()
    if expected_receipt_sha256 is not None and digest != expected_receipt_sha256:
        raise OSError("agent_selection.json bytes changed after protected selection")
    try:
        payload = _json.loads(body)
    except (UnicodeDecodeError, ValueError) as exc:
        raise OSError("agent_selection.json is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise OSError("agent_selection.json has an unsupported schema")
    entries = payload.get("selections")
    if payload.get("schema_version") != 1 or not isinstance(entries, dict):
        raise OSError("agent_selection.json has an unsupported schema")
    if set(entries) != set(expected):
        raise OSError("agent_selection.json does not contain the complete protected connector roster")

    updated_at = _parse_setup_selection_time(payload.get("updated_at"), "updated_at")
    now = datetime.now(timezone.utc)
    if updated_at > now or now - updated_at > SELECTION_LIFETIME:
        raise OSError("agent_selection.json is not fresh for this transaction")

    ordered_records: list[SetupAgentSelection] = []
    for connector in expected:
        record = records[connector]
        entry = entries.get(connector)
        if not isinstance(entry, dict):
            raise OSError(f"agent_selection.json has no record for {connector}")
        selected_at = _parse_setup_selection_time(entry.get("selected_at"), f"{connector}.selected_at")
        expires_at = _parse_setup_selection_time(entry.get("expires_at"), f"{connector}.expires_at")
        if selected_at != updated_at or expires_at - selected_at != SELECTION_LIFETIME:
            raise OSError(f"agent_selection.json has invalid freshness bounds for {connector}")
        if expires_at <= now or selected_at > now:
            raise OSError(f"agent_selection.json record for {connector} is stale or future-dated")
        expected_fields = {
            "connector": record.connector,
            "source": "setup-selected",
            "executable": record.executable,
            "raw_version": record.raw_version,
            "normalized_version": record.normalized_version,
            "sha256": record.sha256,
        }
        if any(entry.get(key) != value for key, value in expected_fields.items()):
            raise OSError(f"agent_selection.json does not match the selected {connector} executable")
        ordered_records.append(record)

    return _VerifiedSetupAgentSelections(
        connectors=expected,
        records=tuple(ordered_records),
        receipt_sha256=digest,
        receipt_generation=generation,
        prior_receipt_generation=prior_generation,
        _seal=_SETUP_SELECTION_PROOF_SEAL,
    )


def _revalidate_setup_agent_selections(
    data_dir: str | os.PathLike[str],
    verified: _VerifiedSetupAgentSelections,
    *,
    transaction_snapshot: _SetupConfigSnapshot | None = None,
) -> _VerifiedSetupAgentSelections:
    """Re-read and validate a transaction-owned selection result before mutation."""

    if not isinstance(verified, _VerifiedSetupAgentSelections) or verified._seal is not _SETUP_SELECTION_PROOF_SEAL:
        raise OSError("protected executable selection proof was not created by this transaction")
    if (
        transaction_snapshot is not None
        and verified.prior_receipt_generation != transaction_snapshot.agent_selection_generation
    ):
        raise OSError("protected executable selection proof belongs to a different setup transaction")
    records = {record.connector: record for record in verified.records}
    return _validate_setup_agent_selection_receipt(
        data_dir,
        verified.connectors,
        records,
        expected_receipt_sha256=verified.receipt_sha256,
        expected_generation=verified.receipt_generation,
    )


def _verify_restored_setup_persistence(
    cfg,
    snapshot: _SetupConfigSnapshot,
    *,
    include_lock: bool,
) -> list[str]:
    data_dir = getattr(cfg, "data_dir", None)
    if not data_dir:
        return ["desired authority data directory is unavailable"]
    root = os.path.abspath(os.fspath(data_dir))
    checks: list[tuple[str, str, int, bool, bytes]] = [
        (
            "config.yaml",
            os.path.abspath(os.fspath(config_path_for_data_dir(root))),
            _SETUP_CONFIG_MAX_BYTES,
            snapshot.config_existed,
            snapshot.config_bytes,
        ),
        (
            "picked_connector",
            os.path.join(root, _PICKED_CONNECTOR_FILENAME),
            4096,
            snapshot.picked_connector_existed,
            snapshot.picked_connector_bytes,
        ),
        (
            "agent_selection.json",
            os.path.join(root, _AGENT_SELECTION_FILENAME),
            _AGENT_SELECTION_MAX_BYTES,
            snapshot.agent_selection_existed,
            snapshot.agent_selection_bytes,
        ),
    ]
    if include_lock:
        checks.append(
            (
                "hook_contract_lock.json",
                os.path.join(root, _HOOK_CONTRACT_LOCK_FILENAME),
                _HOOK_CONTRACT_LOCK_MAX_BYTES,
                snapshot.hook_contract_lock_existed,
                snapshot.hook_contract_lock_bytes,
            )
        )

    failures: list[str] = []
    for label, path, maximum, expected_existed, expected_body in checks:
        try:
            existed, body, _generation = _capture_protected_setup_file(path, maximum, label)
        except Exception as exc:  # noqa: BLE001 - continue every independent check.
            failures.append(f"{label} verification unavailable [{_setup_runtime_ref(type(exc).__name__)}]")
            continue
        if (existed, body) != (expected_existed, expected_body):
            failures.append(f"{label} differs from the rollback point")
    return failures


def _setup_runtime_manifest_mismatches(
    expected: _SetupAppliedRuntimeEvidence,
    actual: _SetupAppliedRuntimeEvidence,
    *,
    failed_location_keys: set[tuple[str, str, str]] | None = None,
) -> list[str]:
    failures: list[str] = []
    omitted = False

    def add(message: str) -> bool:
        nonlocal omitted
        if len(failures) >= _SETUP_ROLLBACK_MAX_FAILURES:
            omitted = True
            return False
        failures.append(message)
        return True

    if expected.lifecycle != actual.lifecycle:
        add(f"gateway lifecycle changed ({expected.lifecycle} -> {actual.lifecycle})")
    if expected.generation is None:
        if actual.generation is not None:
            add("gateway generation was unexpectedly present")
    elif actual.generation is None:
        add("prior running gateway generation is missing")
    elif actual.generation == expected.generation:
        add("restored gateway generation did not advance")

    expected_map = {(scope, subject, attribute): value for scope, subject, attribute, value in expected.invariants}
    actual_map = {(scope, subject, attribute): value for scope, subject, attribute, value in actual.invariants}
    keys = sorted(set(expected_map) | set(actual_map))
    for scope, subject, attribute in keys:
        label = attribute.replace("-", " ")
        if scope == "connector":
            prefix = f"connector {subject}: "
        elif scope == "watchdog":
            prefix = "watchdog: "
        else:
            prefix = f"runtime {subject}: "
        key = (scope, subject, attribute)
        if key not in actual_map:
            add(prefix + label + " is missing")
        elif key not in expected_map:
            add(prefix + "unexpected " + label + " is present")
        elif expected_map[key] != actual_map[key]:
            add(prefix + label + " changed")

    try:
        expected_locations = _setup_registration_location_map(expected.registration_locations)
        actual_locations = _setup_registration_location_map(actual.registration_locations)
    except Exception as exc:  # noqa: BLE001 - malformed evidence must fail closed without details.
        add(f"registration location evidence is inconsistent [{_setup_runtime_ref(type(exc).__name__)}]")
    else:
        for key in sorted(set(expected_locations) | set(actual_locations)):
            connector, role, identity = key
            display_role = f"failed {role}" if key in (failed_location_keys or set()) else role
            label = f"connector {connector}: {display_role} {identity[:12]}"
            if key not in actual_locations:
                add(label + " is missing")
            elif key not in expected_locations:
                add(label + " is unexpectedly present")
            elif expected_locations[key].fingerprint != actual_locations[key].fingerprint:
                add(label + " changed")
    if omitted:
        failures[-1] = "additional runtime mismatches were omitted at the bounded reporting limit"
    return failures


def _expected_setup_registration_locations(
    snapshot: _SetupConfigSnapshot,
    failed_locations: tuple[_SetupRegistrationLocationEvidence, ...],
) -> tuple[_SetupRegistrationLocationEvidence, ...]:
    expected = snapshot.applied_runtime
    if expected is None:
        return ()
    prior = _setup_registration_location_map(expected.registration_locations)
    failed = _setup_registration_location_map(failed_locations)
    if len(prior) > _SETUP_RUNTIME_REGISTRATION_MAX_FILES:
        raise OSError("registration location union exceeds the bounded limit")
    prior_by_identity = {location.identity: location for location in prior.values()}
    union = dict(prior)
    for key, location in failed.items():
        prior_location = prior_by_identity.get(location.identity)
        fingerprint = prior_location.fingerprint if prior_location is not None else "missing"
        current = union.get(key)
        if current is not None:
            if current.path != location.path or current.fingerprint != fingerprint:
                raise OSError("registration location union contains conflicting exact authority")
            continue
        if prior_location is not None and prior_location.path != location.path:
            raise OSError("registration location union contains conflicting exact authority")
        if len(union) >= _SETUP_RUNTIME_REGISTRATION_MAX_FILES:
            raise OSError("registration location union exceeds the bounded limit")
        union[key] = _SetupRegistrationLocationEvidence(
            connector=location.connector,
            role=location.role,
            identity=location.identity,
            fingerprint=fingerprint,
            path=location.path,
        )
    normalized = tuple(union[key] for key in sorted(union))
    _setup_registration_location_map(normalized)
    return normalized


def _verify_restored_setup_runtime(
    cfg,
    snapshot: _SetupConfigSnapshot,
    failed_locations: tuple[_SetupRegistrationLocationEvidence, ...] = (),
) -> list[str]:
    expected = snapshot.applied_runtime
    if expected is None:
        return []
    try:
        expected_locations = _expected_setup_registration_locations(snapshot, failed_locations)
        actual = _capture_setup_applied_runtime(cfg, failed_locations)
    except Exception as exc:  # noqa: BLE001 - persistence verification still completed.
        return [f"applied runtime verification unavailable [{_setup_runtime_ref(type(exc).__name__)}]"]
    return _setup_runtime_manifest_mismatches(
        replace(expected, registration_locations=expected_locations),
        actual,
        failed_location_keys={_setup_registration_location_key(item) for item in failed_locations},
    )


def _restore_prior_setup_lifecycle(app: AppContext, snapshot: _SetupConfigSnapshot) -> None:
    expected = snapshot.applied_runtime
    if expected is None:
        return
    if expected.lifecycle == "running":
        _restart_restored_connector_runtime(app)
        return

    from defenseclaw.commands.cmd_doctor import _trusted_gateway_listener

    # A failed start has already let the gateway publish connector-owned host
    # registrations, receipts, active-roster state, and watchdog custody. A
    # plain stop cannot undo those writes. Reboot once under the already
    # restored and verified desired authority so the existing gateway
    # teardown/reconciliation transaction removes the failed generation, then
    # return the lifecycle to its proven stopped state. No untrusted path or
    # wildcard cleanup is introduced: the gateway consumes only the restored
    # config plus the protected failed-generation roster/lock evidence.
    restart_error: Exception | None = None
    try:
        _restart_restored_connector_runtime(app)
    except Exception as exc:  # Cleanup must run even when readiness fails after process start.
        restart_error = exc

    cleanup_error: OSError | None = None
    try:
        trust = _trusted_gateway_listener(app.cfg, platform_name="win32")
    except Exception as exc:  # noqa: BLE001 - bounded below; preserve restart failure as cause.
        cleanup_error = OSError(
            f"restored gateway cleanup inspection failed [{_setup_runtime_ref(type(exc).__name__)}]"
        )
    else:
        if trust.trusted:
            try:
                stopped = _stop_defense_gateway_native(app.cfg.data_dir)
            except Exception as exc:  # noqa: BLE001 - bounded below; preserve restart failure as cause.
                cleanup_error = OSError(f"reconciled gateway cleanup failed [{_setup_runtime_ref(type(exc).__name__)}]")
            else:
                if not stopped:
                    cleanup_error = OSError("reconciled gateway created by the failed setup did not stop")
        elif restart_error is None or trust.code not in {"missing", "missing_process"}:
            cleanup_error = OSError(f"restored gateway cleanup is unavailable [{_setup_runtime_ref(trust.code)}]")

    if restart_error is not None:
        if cleanup_error is not None:
            raise OSError(
                "restored gateway restart failed "
                f"[{_setup_runtime_ref(type(restart_error).__name__)}]; cleanup incomplete: {cleanup_error}"
            ) from restart_error
        raise restart_error
    if cleanup_error is not None:
        raise cleanup_error


def _restore_setup_config_in_memory(app: AppContext, snapshot: _SetupConfigSnapshot):
    cfg = app.cfg
    cfg.__dict__.clear()
    cfg.__dict__.update(copy.deepcopy(snapshot.config.__dict__))
    return cfg


def _restart_restored_connector_runtime(app: AppContext) -> None:
    cfg = app.cfg
    restored = list(cfg.active_connectors()) if hasattr(cfg, "active_connectors") else []
    primary = normalize_connector(cfg.active_connector()) if hasattr(cfg, "active_connector") else "openclaw"
    _restart_services(
        cfg.data_dir,
        cfg.gateway.host,
        cfg.gateway.port,
        connector=primary or "openclaw",
        connectors=restored,
        wait_for_connector_ready=bool({normalize_connector(name) for name in restored} & _HOOK_ENFORCED_CONNECTORS),
        start_if_stopped=True,
    )


def _rollback_failed_connector_application(
    app: AppContext,
    snapshot: _SetupConfigSnapshot,
    cause: BaseException,
    *,
    _secret_safe: bool = False,
    _secret_rollback_complete: bool = True,
) -> None:
    """Restore, reconcile, and verify every feasible rollback phase."""

    exact_runtime = snapshot.applied_runtime is not None
    rollback_errors: list[str] = []
    secret_rollback_failed = False
    failed_registration_locations: tuple[_SetupRegistrationLocationEvidence, ...] | None = None
    if exact_runtime:
        try:
            failed_registration_locations = _capture_failed_setup_registration_locations(app.cfg)
        except BaseException as exc:  # Capture must precede restoration of the failed lock.
            if not isinstance(exc, Exception) and not _secret_safe:
                raise
            rollback_errors.append(
                f"failed-generation registration evidence unavailable [{_setup_runtime_ref(type(exc).__name__)}]"
            )
    restore_complete = True
    try:
        _restore_setup_config_snapshot(app, snapshot)
    except BaseException as exc:  # Preserve the original non-secret readiness failure too.
        if _secret_safe:
            secret_rollback_failed = True
        elif not isinstance(exc, Exception):
            raise
        restore_complete = False
        if not _secret_safe:
            detail = (
                f"restore prior desired authority [{_setup_runtime_ref(type(exc).__name__)}]"
                if exact_runtime
                else f"restore prior desired config: {exc}"
            )
            rollback_errors.append(detail)

    pre_verification_complete = True
    pre_reconcile_failures: list[str] = []
    if exact_runtime:
        try:
            pre_reconcile_failures = _verify_restored_setup_persistence(app.cfg, snapshot, include_lock=True)
        except BaseException as exc:  # Continue to every other independently feasible phase.
            if not isinstance(exc, Exception) and not _secret_safe:
                raise
            pre_verification_complete = False
            pre_reconcile_failures.append(
                f"pre-reconciliation persistence verification unavailable [{_setup_runtime_ref(type(exc).__name__)}]"
            )
    rollback_errors.extend(pre_reconcile_failures)
    authority_safe = restore_complete and pre_verification_complete and not pre_reconcile_failures
    if authority_safe:
        try:
            if exact_runtime:
                _restore_prior_setup_lifecycle(app, snapshot)
            else:
                _restart_restored_connector_runtime(app)
        except BaseException as exc:  # Report both non-secret transaction failures.
            if _secret_safe:
                secret_rollback_failed = True
            elif not isinstance(exc, Exception):
                raise
            if not _secret_safe:
                detail = (
                    f"restore prior gateway lifecycle [{_setup_runtime_ref(type(exc).__name__)}]"
                    if exact_runtime
                    else f"re-apply prior connector runtime: {exc}"
                )
                rollback_errors.append(detail)
    elif exact_runtime:
        rollback_errors.append("runtime reconciliation was skipped because restored authority was not exact")

    if exact_runtime:
        final_registration_locations = failed_registration_locations or ()
        verification_checks: list[tuple[str, Any]] = [
            (
                "post-reconciliation persistence",
                lambda: _verify_restored_setup_persistence(app.cfg, snapshot, include_lock=False),
            ),
            (
                "applied runtime",
                lambda: _verify_restored_setup_runtime(app.cfg, snapshot, final_registration_locations),
            ),
        ]
        for label, check in verification_checks:
            try:
                rollback_errors.extend(check())
            except BaseException as exc:  # Continue every independent verification.
                if not isinstance(exc, Exception) and not _secret_safe:
                    raise
                rollback_errors.append(f"{label} verification unavailable [{_setup_runtime_ref(type(exc).__name__)}]")
    if len(rollback_errors) > _SETUP_ROLLBACK_MAX_FAILURES:
        rollback_errors = rollback_errors[: _SETUP_ROLLBACK_MAX_FAILURES - 1]
        rollback_errors.append("additional rollback failures were omitted at the bounded reporting limit")

    if _secret_safe:
        failure_code = (
            "readiness-failed-rollback-incomplete"
            if secret_rollback_failed or rollback_errors or not _secret_rollback_complete
            else "readiness-failed-restored"
        )
        raise _GuardrailSecretFailure(failure_code) from None

    cause_text = f"[ref {_setup_runtime_ref(type(cause).__name__)}]" if exact_runtime else f"({cause})"
    outcome = (
        "rollback was incomplete: " + "; ".join(rollback_errors)
        if rollback_errors
        else "restored the prior connector configuration and runtime"
    )
    failure = click.ClickException(f"connector setup did not converge {cause_text}; {outcome}")
    if exact_runtime:
        raise failure from None
    raise failure from cause


def _resolve_connector_workspace(workspace_dir: str | None) -> str:
    raw = (workspace_dir or "").strip()
    if not raw:
        return ""
    workspace = os.path.abspath(os.path.expanduser(raw))
    try:
        return str(Path(workspace).resolve(strict=False))
    except OSError:
        return workspace


def _configure_connector_workspace(cfg, workspace_dir: str | None = None) -> str:
    """Persist an explicit workspace, or clear it for global/user scope."""
    workspace = _resolve_connector_workspace(workspace_dir)
    try:
        cfg.claw.workspace_dir = workspace
    except AttributeError:
        pass
    return workspace


def _configured_connector_set(gc) -> list[str]:
    """Return the connectors already configured, in stable sorted order.

    Prefers the multi-connector ``guardrail.connectors`` map keys when
    populated; otherwise falls back to the singular ``guardrail.connector``
    field. Empty when nothing is configured yet.
    """
    connectors = getattr(gc, "connectors", None)
    if connectors:
        return sorted(name for name in connectors if (name or "").strip())
    single = (getattr(gc, "connector", "") or "").strip()
    return [single] if single else []


def _prompt_checkbox_selection(
    options: list[str],
    *,
    default_selected: list[str],
    title: str,
    empty_ok: bool,
) -> list[str]:
    return terminal_checkbox.prompt_checkbox_selection(
        options,
        default_selected=default_selected,
        title=title,
        empty_ok=empty_ok,
        redraw=_supports_terminal_redraw(),
        getchar=click.getchar,
    )


def _prompt_add_replace_cancel(connector: str, others: list[str]) -> str | None:
    """Three-choice interactive prompt for the additive-setup decision (WU7 D1).

    Returns ``"add"``, ``"replace"``, or ``None`` (cancel).
    """
    others_label = ", ".join(others)
    click.echo()
    click.echo(f"  DefenseClaw is already configured for: {others_label}")
    click.echo(f"  You are setting up: {connector}")
    click.echo("    [a] Add     — run it alongside the existing connector(s) (multi-connector)")
    click.echo("    [r] Replace — switch to only this connector")
    click.echo("    [c] Cancel  — make no changes")
    choice = click.prompt(
        "  Choose",
        type=click.Choice(["a", "r", "c"], case_sensitive=False),
        default="a",
        show_default=True,
    ).lower()
    return {"a": "add", "r": "replace", "c": None}[choice]


def _write_connector_identity(cfg, connector: str, write_mode: str) -> None:
    """Persist the active-connector identity honoring the WU7 write mode.

    ``replace`` (default, legacy behavior): this connector becomes the sole
    active connector — the ``guardrail.connectors`` map is cleared and the
    singular ``guardrail.connector`` / ``claw.mode`` fields are pinned to it.

    ``add`` (WU7 D2=A): merge this connector into ``guardrail.connectors``
    alongside the existing one(s). On the first add the existing singular
    connector is seeded into the map so BOTH are represented. The singular
    ``guardrail.connector`` and ``claw.mode`` fields are kept pointing at the
    primary (sorted-first) connector so backward-compat readers — older Go
    binaries and the Python single-connector paths — keep working.
    """
    gc = cfg.guardrail
    if write_mode == "add":
        if not getattr(gc, "connectors", None):
            gc.connectors = {}
        existing_single = (getattr(gc, "connector", "") or "").strip()
        # Only seed a HOOK-enforced predecessor into the multi map — a
        # proxy-backed connector cannot be a multi-connector peer (D4=A).
        if (
            existing_single
            and existing_single != connector
            and existing_single in _HOOK_ENFORCED_CONNECTORS
            and existing_single not in gc.connectors
        ):
            gc.connectors[existing_single] = PerConnectorGuardrailConfig(
                mode=gc.effective_mode(existing_single),
                hook_fail_mode=gc.effective_hook_fail_mode(existing_single),
            )
        if connector not in gc.connectors:
            gc.connectors[connector] = PerConnectorGuardrailConfig()
        primary = sorted(gc.connectors)[0]
        gc.connector = primary
        cfg.claw.mode = primary
    else:  # replace
        gc.connectors = {}
        gc.connector = connector
        cfg.claw.mode = connector


def _apply_hilt_setup(
    gc,
    *,
    connector: str,
    per_connector: bool,
    hilt: bool | None,
    hilt_min_severity: str | None,
) -> None:
    """Write the HILT (human-approval) override for *connector* (B3/E4d).

    When *per_connector* the override lands on the connector's own
    ``PerConnectorGuardrailConfig.hilt`` block (which fully replaces the
    global block for that connector — see ``GuardrailConfig.effective_hilt``);
    otherwise it edits the shared global ``gc.hilt``. ``hilt`` toggles
    enablement; ``hilt_min_severity`` updates the threshold. A min-severity
    given without an explicit enable updates the threshold in place without
    flipping enablement. Both ``None`` is a no-op (preserve existing).
    """
    if hilt is None and hilt_min_severity is None:
        return

    def _target() -> HILTConfig:
        if per_connector:
            block = gc.connectors[connector].hilt or HILTConfig()
            gc.connectors[connector].hilt = block
            return block
        return gc.hilt

    block = _target()
    if hilt is not None:
        block.enabled = bool(hilt)
    if hilt_min_severity is not None:
        block.min_severity = str(hilt_min_severity).upper()
    elif not block.min_severity:
        block.min_severity = "HIGH"


def _apply_judge_enablement(
    gc,
    *,
    connector: str,
    enable_judge: bool | None,
    judge_hook_connectors: str | None,
) -> None:
    """Wire setup-time LLM-judge enablement for *connector* (SU-07/B3).

    ``enable_judge=True`` turns the judge on globally, bumps the strategy off
    ``regex_only`` so it actually runs, and defaults the hook-lane gate
    (``judge.hook_connectors``) to this connector. An explicit
    ``judge_hook_connectors`` spec is still honored for scripted advanced
    setup.
    ``enable_judge=False`` opts *connector* out of a concrete gate (leaving the
    global ``judge.enabled`` alone — peers may still use it). ``None`` is a
    no-op unless an explicit gate spec was passed.
    """
    if enable_judge is None and judge_hook_connectors is None:
        return

    if enable_judge:
        was_enabled = bool(gc.judge.enabled)
        gc.judge.enabled = True
        if not gc.detection_strategy or gc.detection_strategy == "regex_only":
            gc.detection_strategy = "regex_judge"
        _default_hook_judge_completion_strategy(gc)
        if judge_hook_connectors is None:
            current = list(gc.judge.hook_connectors or []) if was_enabled else []
            if current == ["*"]:
                new_gate = current
            else:
                new_gate = list(current)
                if connector not in new_gate:
                    new_gate.append(connector)
        else:
            new_gate = _resolve_judge_hook_gate(
                judge_hook_connectors,
                judge_just_enabled=not was_enabled,
                current=list(gc.judge.hook_connectors or []),
            )
        if new_gate is not None:
            gc.judge.hook_connectors = new_gate
        return

    if judge_hook_connectors is not None:
        new_gate = _resolve_judge_hook_gate(
            judge_hook_connectors,
            judge_just_enabled=False,
            current=list(gc.judge.hook_connectors or []),
        )
        if new_gate is not None:
            gc.judge.hook_connectors = new_gate

    if enable_judge is False:
        # Explicit opt-out: drop this connector from a concrete gate. A "*"
        # sentinel is left intact (expanding-then-subtracting "all" is the
        # ambiguous case `guardrail judge remove` deliberately rejects, J6).
        gate = list(gc.judge.hook_connectors or [])
        if gate != ["*"] and connector in gate:
            gate.remove(connector)
            gc.judge.hook_connectors = gate


def _apply_hook_connector_setup(
    app: AppContext,
    *,
    connector: str,
    mode: str = "observe",
    restart: bool,
    allow_offline_audit: bool = False,
    workspace_dir: str | None = None,
    write_mode: str = "replace",
    rule_pack: str | None = None,
    rule_pack_dir: str | None = None,
    block_message: str | None = None,
    fail_mode: str | None = None,
    hilt: bool | None = None,
    hilt_min_severity: str | None = None,
    enable_judge: bool | None = None,
    judge_hook_connectors: str | None = None,
    allow_trusted_path_prompt: bool = True,
    trusted_prompt_cache: dict[str, bool] | None = None,
    _downgrade_refused_action: bool = False,
    _version_preflighted: bool = False,
    _protected_selection: _VerifiedSetupAgentSelections | None = None,
    _selection_transaction_snapshot: _SetupConfigSnapshot | None = None,
) -> bool:
    """Pin DefenseClaw to *connector* in hook-driven mode.

    Idempotent: running twice with the same arguments yields the same
    on-disk state. The function:

      1. Sets ``guardrail.connector`` and ``claw.mode`` to *connector*
         so the active-connector resolver
         (``Config.active_connector``) returns *connector* even if a
         future ``guardrail.enabled = false`` toggle is applied.
      2. Sets ``gc.enabled=True`` and ``gc.mode`` to the operator's
         choice (``observe`` or ``action``). Both modes are supported
         end-to-end via the hook surface: ``observe`` only records,
         ``action`` returns a deny verdict from the connector's
         pre-tool hook so the agent blocks the tool call inside its
         own permission flow.
         The LLM data path is direct-to-upstream in both cases — no
         proxy listener binds for hook-enforced connectors.
      3. Defaults scanner mode, detection strategy, AI-discovery
         flags, etc., to sensible-for-hook-only values that keep the
         YAML loadable.
      4. Persists config.yaml and writes the
         ``<data_dir>/picked_connector`` hint.
      5. When ``restart`` is true, bounces the gateway so its
         ``Connector.Setup()`` wires hooks + native OTel exporter +
         (codex only) the notify bridge against the running sidecar.

    Returns True on success, False on any persistence error.
    """
    # Canonicalize the connector name at the boundary so the
    # guardrail.connectors key and the singular guardrail.connector / claw.mode
    # mirror are always the registry name (e.g. "claude-code" -> "claudecode").
    # Without this a caller passing an alias could write a second map entry that
    # collides with the canonical one — which GuardrailConfig.Validate now
    # rejects at load, so an un-normalized write would brick config loading.
    connector = normalize_connector(connector)
    if connector not in _HOOK_ENFORCED_CONNECTORS:
        click.echo(
            f"  ✗ hook-driven setup is only supported for {sorted(_HOOK_ENFORCED_CONNECTORS)} (got {connector!r})",
            err=True,
        )
        return False

    # Normalize mode at the boundary. Anything other than the literal
    # ``action`` sentinel is downgraded to ``observe`` because failing-
    # safe on a typo is strictly less surprising than enforcing on one.
    desired_mode = (mode or "").strip().lower()
    if desired_mode not in ("observe", "action"):
        desired_mode = "observe"

    exact_windows_opencode = _windows_opencode_requires_exact_selection(connector)
    # Preserve the predecessor's ordering for every non-OpenCode connector:
    # generic version admission still precedes rule-pack validation and the
    # setup snapshot. Only native-Windows OpenCode takes the exact-selection
    # branch below.
    if not _version_preflighted and not exact_windows_opencode:
        version_check_kwargs = {
            "mode": desired_mode,
            "data_dir": getattr(app.cfg, "data_dir", None),
            "_allow_prompt": allow_trusted_path_prompt,
        }
        if trusted_prompt_cache is not None:
            version_check_kwargs["_trusted_prompt_cache"] = trusted_prompt_cache
        if not _check_connector_version_supported_for_setup(connector, **version_check_kwargs):
            # Every non-OpenCode hook contract deliberately permits observe
            # when action admission is refused (missing, unversioned, or
            # outside the validated range).  Reusing that decision avoids a
            # second discovery/probe whose answer can drift within the same
            # setup transaction.  OpenCode is the strict exception: unknown
            # versions are refused in both modes and never reach this fallback.
            if desired_mode == "action" and _downgrade_refused_action and connector != "opencode":
                label = _CONNECTOR_META.get(connector, {}).get("label", connector)
                ux.warn(f"{label}: requested action mode was refused; configuring observe mode instead.")
                desired_mode = "observe"
            else:
                return False

    cfg = app.cfg
    gc = cfg.guardrail
    pack_dir = _resolve_rule_pack_dir(app, rule_pack=rule_pack, rule_pack_dir=rule_pack_dir)
    try:
        setup_snapshot = _capture_setup_config_snapshot(app.cfg, capture_runtime=_windows_runtime_rollback(restart))
    except OSError as exc:
        click.echo(f"  ✗ Cannot establish connector setup rollback point: {exc}", err=True)
        return False

    verified = _protected_selection
    selection_roster = (connector,)
    if write_mode == "add":
        # A protected selection receipt is transaction-scoped and replacing
        # it removes entries that are not named by the new receipt.  Carry the
        # complete additive roster so a sequence of ``--no-restart`` setup
        # calls cannot erase an earlier peer's still-unpublished executable
        # authority before the gateway gets its first chance to seal it in the
        # contract lock.
        selection_roster = tuple(
            dict.fromkeys(
                (
                    *(normalize_connector(name) for name in cfg.active_connectors() if name),
                    connector,
                )
            )
        )
    if (
        isinstance(verified, _VerifiedSetupAgentSelections)
        and verified._seal is _SETUP_SELECTION_PROOF_SEAL
        and connector in verified.connectors
    ):
        from defenseclaw.agent_selection import setup_agent_selection_connectors

        if verified.connectors == setup_agent_selection_connectors(selection_roster):
            selection_roster = verified.connectors
        else:
            verified = None
    if verified is not None:
        try:
            verified = _revalidate_setup_agent_selections(
                cfg.data_dir,
                verified,
                transaction_snapshot=_selection_transaction_snapshot or setup_snapshot,
            )
        except OSError:
            verified = None
    if verified is None or verified.record_for(connector) is None:
        try:
            verified = _record_windows_setup_agent_selections(
                getattr(app.cfg, "data_dir", None),
                selection_roster,
                _prior_snapshot=setup_snapshot,
            )
        except Exception as exc:
            try:
                _restore_setup_agent_selection_snapshot(app.cfg, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve both authority failures.
                raise click.ClickException(
                    f"connector {connector!r} executable selection failed ({exc}); "
                    f"agent_selection.json rollback was incomplete: {rollback_exc}"
                ) from exc
            raise
    if exact_windows_opencode and (verified is None or verified.record_for(connector) is None):
        raise click.ClickException("native-Windows OpenCode setup has no concrete receipt-bound exact SST selection")

    workspace = _configure_connector_workspace(cfg, workspace_dir)
    # WU7: honor the resolved write mode — "replace" pins this as the sole
    # connector (legacy behavior); "add" merges it into guardrail.connectors
    # alongside the existing one(s) while keeping the singular field as a
    # backward-compatible primary mirror.
    _write_connector_identity(cfg, connector, write_mode)
    # Per-connector rule pack (parity with single-connector --rule-pack).
    # Each connector scans against its own EffectiveRulePackDir at boot, so
    # this lets one connector run strict while a peer runs permissive.
    #
    #   * multi (write_mode == "add"): the pack is written to THIS
    #     connector's per-connector override block, so peers keep their own
    #     pack (or inherit the global default). The existing connector that
    #     gets seeded into the map on the first add keeps an empty block and
    #     therefore inherits the global pack — unchanged.
    #   * sole connector (replace / first-ever single): there is no
    #     per-connector block, so it sets the global rule_pack_dir exactly
    #     like `setup guardrail --rule-pack` does for a single-connector
    #     install. "Set this connector's pack" thus means the same thing in
    #     both shapes.
    #
    # R1: --rule-pack-dir accepts a free-text directory verbatim (parity with
    # the TUI's free-text field); ``pack_dir`` was resolved above. The scoping
    # branch below is unchanged.
    if pack_dir is not None:
        # Operator-facing label: the preset name, the dir path, or an explicit
        # "(cleared)" when --rule-pack-dir "" reset the override.
        pack_label = rule_pack if rule_pack is not None else (pack_dir or "(cleared — inherits global)")
        if write_mode == "add" and connector in gc.connectors:
            gc.connectors[connector].rule_pack_dir = pack_dir
            click.echo(f"  ✓ {connector} rule pack: {pack_label} (per-connector override)")
        else:
            gc.rule_pack_dir = pack_dir
            click.echo(f"  ✓ rule pack: {pack_label} (global)")
    gc.enabled = True
    # SU-01/G1: write the guardrail mode PER-CONNECTOR when this connector owns
    # an override block (the multi/add shape), so flipping one connector to
    # action no longer silently switches every peer via the shared global
    # field. Mirrors the per-connector rule-pack scoping just above and the
    # per-connector write `init` already does (cmd_init.py). The sole-connector
    # / replace shape (no map entry) keeps writing the global gc.mode, which
    # effective_mode() resolves as the inherited default — so single-connector
    # installs are unchanged and an existing global mode is still honored.
    per_connector = write_mode == "add" and connector in gc.connectors
    if per_connector:
        gc.connectors[connector].mode = desired_mode
    else:
        gc.mode = desired_mode

    # B3 / E4d: per-connector guardrail write-surface. The TUI B4 editor and
    # `setup <connector> --block-message/--fail-mode/--human-approval/...`
    # need every per-connector guardrail field writable from the setup path,
    # not just mode + rule-pack. Each field lands on this connector's override
    # block in the multi/add shape (so peers keep their own value) and on the
    # shared global field for a sole-connector install — mirroring the
    # mode/rule-pack scoping above. Readers resolve via gc.effective_*(connector),
    # which falls back to the global field, so single-connector installs stay
    # byte-identical and an unset field never disturbs a peer. Every write is
    # guarded by `is not None`, so omitting the flag leaves the value untouched
    # (SU-02/J1 preserve-don't-clobber).
    if block_message is not None:
        if per_connector:
            gc.connectors[connector].block_message = block_message
        else:
            gc.block_message = block_message
    if fail_mode is not None or connector == "cursor":
        normalized_fail = "closed" if str(fail_mode).strip().lower() == "closed" else "open"
        if connector == "cursor":
            mode_fail = "closed" if desired_mode == "action" else "open"
            if fail_mode is not None and normalized_fail != mode_fail:
                click.echo(
                    f"  ⚠ Cursor {desired_mode} mode pins hook failures={mode_fail}; "
                    f"ignoring --fail-mode {normalized_fail}."
                )
            normalized_fail = mode_fail
        if per_connector:
            gc.connectors[connector].hook_fail_mode = normalized_fail
        else:
            gc.hook_fail_mode = normalized_fail
    if connector == "cursor":
        if hilt:
            click.echo("  ⚠ Cursor native human approval is not implemented; disabling it for this connector.")
        hilt = False
    _apply_hilt_setup(
        gc,
        connector=connector,
        per_connector=per_connector,
        hilt=hilt,
        hilt_min_severity=hilt_min_severity,
    )
    # SU-07 / B3: setup-time LLM-judge enablement. Flips the global
    # gc.judge.enabled switch, opts this connector into hook-lane coverage,
    # and bumps the strategy off regex_only so the judge actually runs. Full
    # judge LLM config (model/key) stays the job of `setup guardrail` /
    # `setup llm`; this only wires setup-time enablement. Default
    # (enable_judge is None) leaves judge state alone.
    _apply_judge_enablement(
        gc,
        connector=connector,
        enable_judge=enable_judge,
        judge_hook_connectors=judge_hook_connectors,
    )
    # Judge eligibility follows the connector's final enforcement mode. Do
    # this before cfg.save(): action validation may have fallen back to a
    # second observe-mode setup call, and pruning only after that save leaves
    # a stale gate on disk that the restarted gateway immediately reloads.
    _prune_judge_gate_to_action_scope(gc, [connector])

    gc.scanner_mode = "local"
    gc.port = gc.port or 4000
    # SU-02/J1/J2: preserve the operator's detection strategy + judge state
    # across re-runs. setup used to unconditionally re-pin detection_strategy =
    # "regex_only" and force gc.judge.enabled = False on EVERY invocation,
    # silently undoing a prior `guardrail judge add` / `setup guardrail` the
    # next time the operator re-ran `setup <connector>` for any reason. Only
    # seed the per-direction completion strategy when unset; never clobber an
    # existing non-regex_only strategy or an enabled judge. The dataclass
    # default (regex_judge) now survives a hook setup, aligning with the
    # documented default (ND-1).
    if not gc.detection_strategy:
        gc.detection_strategy = "regex_only"
    if not gc.detection_strategy_completion:
        gc.detection_strategy_completion = "regex_only"
    cfg.ai_discovery.enabled = True
    cfg.ai_discovery.mode = cfg.ai_discovery.mode or "enhanced"
    cfg.ai_discovery.include_shell_history = True
    cfg.ai_discovery.include_package_manifests = True
    cfg.ai_discovery.include_env_var_names = True
    cfg.ai_discovery.include_network_domains = True

    try:
        cfg.save()
        click.echo("  ✓ Config saved to ~/.defenseclaw/config.yaml")
    except OSError as exc:
        try:
            _restore_setup_config_snapshot(app, setup_snapshot)
        except Exception as rollback_exc:  # noqa: BLE001 — no authority receipt may be stranded.
            raise click.ClickException(
                f"connector {connector!r} config save failed ({exc}); rollback was incomplete: {rollback_exc}"
            ) from exc
        click.echo(f"  ✗ Failed to save config: {exc}", err=True)
        return False

    try:
        _sync_guardrail_hilt_to_opa(cfg.policy_dir, gc)
        _write_picked_connector_hint(getattr(cfg, "data_dir", None), connector)
    except Exception as exc:  # noqa: BLE001 — no post-save side effect may strand desired state.
        try:
            _restore_setup_config_snapshot(app, setup_snapshot)
        except Exception as rollback_exc:  # noqa: BLE001 — preserve both transaction failures.
            raise click.ClickException(
                f"connector {connector!r} setup failed after saving desired config ({exc}); "
                f"prior desired state restoration failed: {rollback_exc}"
            ) from exc
        click.echo(
            f"  ✗ Connector setup failed after saving desired config: {exc}; "
            "restored the prior desired connector state",
            err=True,
        )
        return False
    _actives = list(cfg.active_connectors()) if hasattr(cfg, "active_connectors") else [connector]
    if len(_actives) > 1:
        click.echo(
            f"  ✓ Desired roster staged for {connector!r} — "
            f"{len(_actives)} connectors selected: {', '.join(_actives)}"
        )
    else:
        click.echo(f"  ✓ Desired connector {connector!r} staged")
    if workspace:
        click.echo(f"  ✓ Workspace root pinned to {workspace}")
    else:
        click.echo("  ✓ Scope: global user config (no workspace pinned)")
    # Hook connector setup should describe mode in connector terms. The first
    # connector may still be represented through legacy global fields on disk,
    # but presenting that as guardrail.mode nudges users toward unsafe global
    # edits on multi-connector installs.
    click.echo(f"  ✓ {connector} mode={desired_mode}")
    if connector == "cursor":
        effective_fail_mode = "closed" if desired_mode == "action" else "open"
        click.echo(
            f"  ✓ cursor hook failures={effective_fail_mode} "
            f"(failClosed={'true' if desired_mode == 'action' else 'false'})"
        )
        click.echo(
            "  ℹ Cursor runs all matching hooks and merges Enterprise > Team > Project > User; "
            "DefenseClaw cannot safely detect an actual higher-priority conflict, so none is inferred"
        )

    if restart:
        click.echo()
        click.echo("  Restarting gateway to wire connector runtime and telemetry...")
        try:
            _restart_services(
                cfg.data_dir,
                cfg.gateway.host,
                cfg.gateway.port,
                connector=connector,
                connectors=_actives,
                wait_for_connector_ready=True,
            )
        except Exception as exc:  # noqa: BLE001 — readiness failure triggers transaction rollback.
            _rollback_failed_connector_application(app, setup_snapshot, exc)
        if connector == "hermes":
            click.echo("  ✓ Hermes on-disk hook registration staged")
            ux.warn(
                "Hermes callbacks are not live-verified: reload or restart every running "
                "Hermes CLI, TUI, gateway, desktop, and service host before relying on registration changes."
            )
        elif connector == "omnigent":
            click.echo("  ✓ OmniGent on-disk policy registration staged")
            ux.warn(
                "OmniGent 0.7.0 does not expose a loaded policy generation/module/config identity. "
                "Reload or restart every running OmniGent server; action/fail-closed enforcement "
                "remains unverified until then."
            )
        else:
            click.echo(f"  ✓ {_CONNECTOR_META[connector]['label']} connector setup complete")
    else:
        click.echo(
            "  ℹ Connector desired state is staged offline; it is not active until the gateway "
            "publishes matching registration and lock evidence."
        )

    _log_setup_action(
        app,
        ACTION_SETUP_HOOK_CONNECTOR,
        f"connector={connector} mode={desired_mode} surface=hook",
        allow_offline=allow_offline_audit,
    )

    return True


# Backwards-compat alias for any out-of-tree callers; new code must
# use ``_apply_hook_connector_setup`` directly. Forces observe mode
# so the legacy contract is preserved bit-for-bit.
def _apply_connector_observability_only(
    app: AppContext,
    *,
    connector: str,
    restart: bool,
) -> bool:
    return _apply_hook_connector_setup(
        app,
        connector=connector,
        mode="observe",
        restart=restart,
        allow_offline_audit=not restart,
        workspace_dir=None,
    )


def _print_connector_observability_banner(connector: str, *, mode: str = "observe") -> None:
    setup_slug = "claude-code" if connector == "claudecode" else connector
    label = _CONNECTOR_META[connector]["label"]
    click.echo()
    click.echo(f"  DefenseClaw — {label} {mode} setup")
    click.echo("  ─────────────────────────────────────────────────────────")
    click.echo()
    if connector == "amp":
        click.echo("  This installs DefenseClaw as Amp's system TypeScript policy")
        click.echo("  plugin. No proxy is inserted in the LLM data path; Amp")
        if mode == "action":
            click.echo("  waits for synchronous tool.call allow, confirm, or reject")
            click.echo("  verdicts before the requested tool can execute.")
        else:
            click.echo("  tool activity is recorded but never blocked.")
    elif connector == "omnigent":
        click.echo("  This wires OmniGent into DefenseClaw through its custom")
        click.echo("  Python policy API. No proxy is inserted in the LLM data")
        if mode == "action":
            click.echo("  path; supported policy phases return ALLOW, ASK, or DENY")
            click.echo("  directly through OmniGent's native approval flow.")
        else:
            click.echo("  path; policy activity is recorded but never blocked.")
    else:
        click.echo(f"  This wires {label} into DefenseClaw via the agent's")
        click.echo("  native hook bus. No proxy is inserted in the LLM data")
        if connector == "hermes" and mode == "action":
            click.echo("  path; valid synchronous pre_tool_call JSON can deny tools,")
            click.echo("  while pre_verify JSON can continue verification. Failures")
            click.echo("  remain open, exit status is not enforcement, and there is no ask.")
        elif connector == "antigravity" and mode == "action":
            click.echo("  path; only synchronous PreToolUse JSON can ask or deny.")
            click.echo("  Other lifecycle outputs are non-blocking, and nonzero")
            click.echo("  hook exit status is not an enforcement interface.")
        elif connector == "cursor" and mode == "action":
            click.echo("  path; supported pre-action events return Cursor's native deny")
            click.echo("  response with failClosed=true. Native human approval is not enabled.")
        elif mode == "action":
            click.echo("  path; supported actions flagged by policy are blocked")
            click.echo("  by the connector's native lifecycle verdict.")
        else:
            click.echo("  path; activity is recorded but never blocked.")
    click.echo()
    click.echo("  Telemetry channels:")
    if connector == "amp":
        click.echo("    • Plugin API — session/agent/tool lifecycle → /api/v1/amp/hook")
        click.echo(
            "    • Enforcement — synchronous tool.call execution gate "
            "+ model-bound tool.result output gate"
        )
        click.echo(
            "    • Agent360 / Galileo — correlated session, turn, tool, outcome, "
            "decision, audit, log, metric, and trace views"
        )
    elif connector == "omnigent":
        click.echo("    • Policy API — six request/tool/model phases → /api/v1/omnigent/hook")
    elif connector == "hermes":
        click.echo("    • Hooks      — 23 classified v0.19 events → /api/v1/hermes/hook")
    elif connector == "antigravity":
        click.echo("    • Hooks      — five bound lifecycle events → /api/v1/antigravity/hook")
        click.echo("                   only PreToolUse carries documented ask/deny output")
    else:
        click.echo(f"    • Hooks      — tool calls, prompt-submit, agent stop → /api/v1/{connector}/hook")
    native_otel_connectors = {"codex", "claudecode", "geminicli", "omnigent"}
    if connector in native_otel_connectors:
        if connector == "omnigent":
            click.echo(
                "    • Native OTel — optional; inactive until OTEL_* variables are exported for the OmniGent process"
            )
        elif connector == "codex":
            click.echo(
                "    • Native OTel — logs, metrics, and traces → scoped bearer + source header on /v1/<signal>"
            )
        else:
            click.echo("    • Native OTel — documented agent telemetry → /v1/logs, /v1/metrics, and/or /v1/traces")
    if connector == "codex":
        click.echo("    • Notify     — agent-turn-complete events → /api/v1/codex/notify")
    if connector == "amp":
        click.echo("    • Headless   — use `amp -x ... --plugin-ready-timeout 30` for complete lifecycle telemetry")
    click.echo()
    if mode == "observe":
        click.echo("  To later turn enforcement on:")
        click.echo(f"    defenseclaw setup {setup_slug} --mode action")
    else:
        click.echo("  To revert to observe-only:")
        click.echo(f"    defenseclaw setup {setup_slug} --mode observe")
    click.echo()
    _print_connector_mutation_notice(connector)
    click.echo()


def _print_connector_next_steps(connector: str, *, os_name: str | None = None) -> None:
    """Print native commands for inspecting one connector's activity."""

    if os_name is None:
        os_name = os.name

    click.echo("  Next steps:")
    click.echo("    • Verify gateway picked up the new connector: defenseclaw-gateway status")
    click.echo("    • Optionally launch the bundled local stack: defenseclaw setup local-observability up")
    if connector == "hermes":
        click.echo(
            "    • Reload/restart every running Hermes CLI, TUI, gateway, desktop, and service host; "
            "DefenseClaw does not manage Hermes PortableGit terminal behavior"
        )
    elif connector == "omnigent":
        click.echo(
            "    • Reload/restart every running OmniGent server; OmniGent 0.7.0 does not expose "
            "loaded policy generation/module/config identity for live verification"
        )
    if os_name == "nt":
        click.echo("    • Watch decisions live: defenseclaw tui")
        click.echo(f"    • Recent alerts for this connector: defenseclaw alerts --limit 25 --connector {connector}")
        return

    click.echo("    • Watch decisions live: defenseclaw tui  (Logs and Alerts read canonical SQLite history)")
    click.echo(
        f"    • Recent alerts as a table: defenseclaw alerts --limit 25  "
        f"(filter to this connector with: jq 'select(.connector == \"{connector}\")')"
    )


def _print_observability_summary(
    connector: str,
    cfg=None,
    *,
    mode: str = "observe",
    os_name: str | None = None,
) -> None:
    """One-screen summary surfaced after a successful alias run."""
    label = _CONNECTOR_META[connector]["label"]
    setup_slug = "claude-code" if connector == "claudecode" else connector
    if connector == "amp":
        enforcement_label = (
            "enabled (synchronous policy plugin)"
            if mode == "action"
            else "disabled (observe-only)"
        )
    elif connector == "omnigent":
        enforcement_label = (
            "configured (custom policy API; live policy generation unverified)"
            if mode == "action"
            else "configured (observe-only; live policy generation unverified)"
        )
    elif connector == "hermes":
        enforcement_label = (
            "pre_tool deny; pre_verify continue; failures open; no ask"
            if mode == "action"
            else "disabled (observe-only)"
        )
    elif connector == "cursor":
        enforcement_label = (
            "enabled (user-hook native deny; failClosed=true; no native ask)"
            if mode == "action"
            else "disabled (observe-only; failClosed=false)"
        )
    else:
        enforcement_label = "enabled (hook-driven)" if mode == "action" else "disabled (observe-only)"

    # Multi-connector awareness: a singular legacy mirror row + a global
    # "setup guardrail --disable" revert line both read as if this one
    # connector IS the whole install. When more than one connector is
    # configured, show the full roster (all connectors are peers) and point
    # revert / mode guidance at the per-connector commands. Single-connector
    # output still uses connector-specific wording rather than exposing
    # claw.mode.
    actives: list[str] = []
    if cfg is not None and hasattr(cfg, "active_connectors"):
        try:
            actives = list(cfg.active_connectors())
        except Exception:  # noqa: BLE001 — fall back to single-connector view.
            actives = []
    multi = len(actives) > 1

    click.echo()
    click.echo("  Summary")
    click.echo("  ───────")
    if multi:
        mode_row = ("connectors", ", ".join(actives))
    else:
        mode_row = ("active connector", connector)
    rows = [
        ("connector", f"{label} ({connector})"),
        mode_row,
        (
            "scope",
            (
                f"workspace ({getattr(getattr(cfg, 'claw', None), 'workspace_dir', '')})"
                if cfg and getattr(getattr(cfg, "claw", None), "workspace_dir", "")
                else "global user config"
            ),
        ),
        ("guardrail.enabled", "true"),
        (f"{connector} mode", mode),
        ("enforcement", enforcement_label),
        ("ai_discovery", f"enabled ({cfg.ai_discovery.mode})" if cfg else "enabled"),
    ]
    if connector == "omnigent":
        rows.extend(
            [
                ("native OTel", "optional; inactive until OTEL_* is exported for OmniGent"),
                ("running OmniGent hosts", "unverified; reload/restart required"),
                (
                    "validation evidence",
                    "on-disk registration only; loaded policy identity unavailable in OmniGent 0.7.0",
                ),
            ]
        )
    elif connector == "hermes":
        rows.extend(
            [
                ("hook failure posture", "upstream fail-open"),
                ("native ask/approve", "unsupported"),
                ("native OTel", "unsupported; hook-derived audit only"),
                ("running Hermes hosts", "unverified; reload/restart required"),
                ("validation evidence", "not recorded; live=false"),
            ]
        )
    elif connector == "cursor":
        rows.extend(
            [
                ("native human approval", "unsupported"),
                ("priority conflict check", "unavailable; none inferred"),
                ("validation evidence", "not recorded; live=false"),
            ]
        )
    for k, v in rows:
        click.echo(f"    {k + ':':<22s} {v}")
    click.echo()
    print_redaction_status_hint(cfg)
    click.echo()
    _print_connector_next_steps(connector, os_name=os_name)
    if multi:
        click.echo(f"    • Change this connector's mode: defenseclaw setup {setup_slug} --mode observe|action")
    click.echo()
    if multi:
        click.echo(f"  This install now has {len(actives)} connectors: {', '.join(actives)}.")
        click.echo("  To revert just this connector (the others keep running):")
        click.echo(f"    defenseclaw setup remove {setup_slug}")
        click.echo("  Or keep it configured but stop enforcing it:")
        click.echo(f"    defenseclaw guardrail disable --connector {connector}")
    else:
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
        click.echo("  ✓ Local observability stack already reachable on :3000 (skipping `up`)")
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


def _is_interactive() -> bool:
    """True when both stdin and stdout are TTYs.

    The interactive setup prompts (SU-06 mode, SU-07 judge, SU-08 trusted
    prefix, SU-11 picker) gate on this so a piped / non-interactive invocation
    — including the whole CLI test suite — never blocks on stdin and stays
    byte-for-byte unchanged. ``--yes`` is a separate, explicit opt-out checked
    alongside this.
    """
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (ValueError, OSError):  # pragma: no cover - closed std streams
        return False


def _prompt_connector_mode(connector: str, *, default_mode: str) -> str:
    """SU-06: interactive observe/action prompt for a hook connector.

    Returns the chosen mode. *default_mode* (from ``--mode``, normally
    ``observe``) seeds the default so passing ``--mode action`` pre-selects
    action while still letting the operator confirm or change it.
    """
    ux.section(f"Enforcement mode for {_CONNECTOR_META[connector]['label']}")
    click.echo(
        "    " + ux.bold("[1] observe") + " — scan and report findings, never block " + ux.dim("(recommended to start)")
    )
    click.echo(
        "    "
        + ux.bold("[2] action ")
        + " — scan and block/confirm when policy requires "
        + ux.dim("(PreToolUse deny)")
    )
    mode_default = "2" if default_mode == "action" else "1"
    choice = click.prompt(
        "  Select mode",
        type=click.Choice(["1", "2"]),
        default=mode_default,
    )
    return "action" if choice == "2" else "observe"


def _prompt_enable_judge(connector: str, gc) -> bool:
    """SU-07: interactive setup-time LLM judge prompt.

    Returns True when the operator opts in. Default reflects whether the judge
    already covers this connector (so re-running setup with Enter preserves
    state). The full judge LLM config stays the job of ``setup guardrail`` /
    ``setup llm``; this only offers setup-time enablement.
    """
    gate = list(gc.judge.hook_connectors or [])
    already = bool(gc.judge.enabled) and (gate == ["*"] or connector in gate)
    ux.section("Optional LLM judge")
    ux.subhead(f"Rule/regex scanning is already enabled for {_CONNECTOR_META[connector]['label']}.")
    ux.subhead("The judge adds semantic injection/PII/exfil detection on top of those rules.")
    ux.subhead("Judged hook calls add latency (up to the hook timeout) and LLM cost.")
    ux.subhead("These LLM settings are shared by all connectors with judge enabled.")
    ux.subhead(
        "This only enables judge scanning; configure provider/model/key with "
        "`defenseclaw setup guardrail` or `defenseclaw setup llm`."
    )
    return click.confirm(
        "  Add LLM judge on top of rule scanning?",
        default=already,
    )


def _setup_observability_alias(
    app: AppContext,
    *,
    connector: str,
    yes: bool,
    restart: bool,
    with_local_stack: bool,
    mode: str = "observe",
    workspace_dir: str | None = None,
    replace: bool = False,
    rule_pack: str | None = None,
    rule_pack_dir: str | None = None,
    block_message: str | None = None,
    fail_mode: str | None = None,
    human_approval: bool | None = None,
    hilt_min_severity: str | None = None,
    enable_judge: bool | None = None,
    judge_hook_connectors: str | None = None,
) -> None:
    """Shared body for hook-based connector setup aliases.

    Splitting this out (rather than calling each Click command from
    the other) keeps the wiring linear: each Click command parses its
    own flags, then defers to this helper for the actual work.

    *mode* defaults to ``observe`` (the safe one-line setup the alias
    was designed for). Pass ``action`` to provision hook-driven
    enforcement: the connector's pre-tool hook returns a deny
    verdict on policy hits and the agent blocks inside its own
    permission flow. The LLM
    data path is direct-to-upstream in either mode.
    """
    if connector not in _HOOK_ENFORCED_CONNECTORS:
        raise click.ClickException(f"unsupported connector for hook alias: {connector!r}")
    _ensure_connector_available(connector)
    if connector == "hermes":
        unsupported = connector_paths.hermes_profile_unsupported_reason()
        if unsupported:
            raise click.ClickException(f"{unsupported}; no changes made")

    # Antigravity documents global customization at
    # ~/.gemini/config/hooks.json and workspace customization at
    # <workspace>/.agents/hooks.json. The host discovers both, so Setup owns
    # only the global file and rejects --workspace to avoid duplicate
    # DefenseClaw registrations.
    if connector == "antigravity" and (workspace_dir or "").strip():
        raise click.ClickException(
            "antigravity setup does not support --workspace: Antigravity "
            "discovers both ~/.gemini/config/hooks.json and "
            "<workspace>/.agents/hooks.json, so DefenseClaw owns only the "
            "global file to avoid duplicate registrations. "
            "Re-run without --workspace."
        )

    normalized_mode = "action" if (mode or "").strip().lower() == "action" else "observe"
    interactive = not yes and _is_interactive()

    # SU-06: interactive observe/action prompt. Asked before the banner so the
    # banner + the "configure now?" confirm reflect the chosen mode. Only runs
    # on a real TTY without --yes; a piped run keeps the flag default. The
    # prompt is per-connector-meaningful here (this alias configures exactly one
    # connector), unlike the global `setup guardrail` wizard which skips it on
    # multi-connector installs.
    if interactive:
        normalized_mode = _prompt_connector_mode(connector, default_mode=normalized_mode)

    _print_connector_observability_banner(connector, mode=normalized_mode)
    if connector == "hermes" and (fail_mode or "").strip().lower() == "closed":
        ux.warn(
            "Hermes remains upstream fail-open. --fail-mode closed is recorded only as policy "
            "provenance; timeout, nonzero, malformed, authentication, and transport failures continue."
        )

    # WU7: resolve add-vs-replace. Only HOOK-ENFORCED peers count as valid
    # multi-connector neighbors (D4=A) — proxy-backed connectors
    # (openclaw/zeptoclaw) bind the proxy and cannot coexist, so an existing
    # proxy connector is treated as "no additive peer" and this stays the
    # legacy confirm-then-replace flow byte-for-byte. When another HOOK
    # connector is configured this becomes the multi-connector decision point.
    gc = app.cfg.guardrail
    existing_others = [c for c in _configured_connector_set(gc) if c != connector and c in _HOOK_ENFORCED_CONNECTORS]
    if not existing_others:
        if not yes:
            verb = "enforcement" if normalized_mode == "action" else "observability"
            if not click.confirm(
                f"  Configure DefenseClaw for {_CONNECTOR_META[connector]['label']} {verb} now?",
                default=True,
            ):
                click.echo("  Aborted — no changes made.")
                return
        # Preserve an existing per-connector override block on re-run;
        # otherwise pin as the sole connector.
        if getattr(gc, "connectors", None) and connector in gc.connectors:
            write_mode = "add"
        else:
            write_mode = "replace"
    elif replace:
        # --replace with other connectors configured: confirm the
        # destructive switch unless running non-interactively.
        if not yes and not click.confirm(
            f"  Replace {', '.join(existing_others)} with {connector}? This removes the other connector(s).",
            default=False,
        ):
            click.echo("  Aborted — no changes made.")
            return
        write_mode = "replace"
    elif yes:
        # WU7 D3=A: the non-interactive default is ADD (backward-incompatible
        # — previously --yes overwrote). Use --replace to overwrite.
        write_mode = "add"
    else:
        write_mode = _prompt_add_replace_cancel(connector, existing_others)
        if write_mode is None:
            click.echo("  Aborted — no changes made.")
            return

    # SU-07: judge-enable prompt. Asked after the operator commits to
    # proceeding (write_mode resolved, not cancelled). Only when the operator
    # didn't already decide via --enable-judge/--no-enable-judge. On yes,
    # _apply_hook_connector_setup flips the judge on for this connector and
    # bumps the strategy off regex_only.
    if interactive and normalized_mode == "action" and enable_judge is None and _prompt_enable_judge(connector, gc):
        enable_judge = True

    trusted_prompt_cache: dict[str, bool] | None = {} if interactive else None
    ok = _apply_hook_connector_setup(
        app,
        connector=connector,
        mode=normalized_mode,
        restart=restart,
        allow_offline_audit=not restart,
        workspace_dir=workspace_dir,
        write_mode=write_mode,
        rule_pack=rule_pack,
        rule_pack_dir=rule_pack_dir,
        block_message=block_message,
        fail_mode=fail_mode,
        hilt=human_approval,
        hilt_min_severity=hilt_min_severity,
        enable_judge=enable_judge,
        judge_hook_connectors=judge_hook_connectors,
        allow_trusted_path_prompt=interactive,
        trusted_prompt_cache=trusted_prompt_cache,
        _downgrade_refused_action=True,
    )
    if not ok:
        raise click.ClickException(f"failed to configure {connector} (mode={normalized_mode}) — see errors above")
    normalized_mode = app.cfg.guardrail.effective_mode(connector)

    if interactive:
        _prune_judge_gate_to_action_scope(app.cfg.guardrail, [connector])

    if interactive and enable_judge and normalized_mode == "action":
        configure_model = click.confirm(
            "  Configure LLM judge provider/model/API settings now?",
            default=_judge_llm_needs_configuration(app),
        )
        if configure_model:
            _prompt_judge_model_config(app, app.cfg.guardrail)
            try:
                app.cfg.save()
                click.echo("  ✓ Judge LLM config saved to ~/.defenseclaw/config.yaml")
            except OSError as exc:
                raise click.ClickException(f"failed to save judge LLM config: {exc}") from exc

    if not restart:
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True

    _maybe_bring_up_local_stack(app, auto=with_local_stack)
    _print_observability_summary(connector, app.cfg, mode=normalized_mode)


def _run_setup_picker(app: AppContext) -> list[str]:
    """SU-11: interactive multi-connector picker for bare ``setup``.

    Lists every supported hook connector with detected/configured tags,
    pre-selects the already-active set (or detected applications on a fresh
    install), and returns the operator's chosen active set (batch mode/judge
    pickers happen later in
    ``_dispatch_bare_setup``). Returns an empty list when the operator selects
    nothing. Only called on an interactive TTY (the caller falls back to help
    on a non-interactive stream).
    """
    candidates = platform_support.supported_connectors(sorted(_HOOK_ENFORCED_CONNECTORS))
    detected = {c for c in _detect_installed_connectors() if c in _HOOK_ENFORCED_CONNECTORS}
    configured = {c for c in _configured_connector_set(app.cfg.guardrail) if c in _HOOK_ENFORCED_CONNECTORS}
    # Once a connector set exists, it is the source of truth for defaults:
    # discovering another installed application must not silently activate it.
    # First-time setup still preselects detected applications for convenience.
    preselect = configured if configured else detected

    display_by_connector: dict[str, str] = {}
    for c in candidates:
        tags = []
        if c in detected:
            tags.append("detected")
        if c in configured:
            tags.append("configured")
        suffix = f"  {ux.dim('(' + ', '.join(tags) + ')')}" if tags else ""
        display_by_connector[c] = f"{_connector_presentation_label(c)}{suffix}"
    connector_by_display = {label: c for c, label in display_by_connector.items()}

    ux.section("Select active connectors")
    if configured:
        ux.subhead("Active connectors are pre-selected. Detected inactive connectors remain unchecked.")
    else:
        ux.subhead("No connectors are active yet. Detected connectors are pre-selected for initial setup.")
    ux.subhead("Unchecked connectors will not remain active after this setup run.")
    selected = _prompt_checkbox_selection(
        [display_by_connector[c] for c in candidates],
        default_selected=[display_by_connector[c] for c in candidates if c in preselect],
        title="Use Space to choose active connectors.",
        empty_ok=True,
    )
    return [connector_by_display[label] for label in selected]


def _connector_display_options(connectors: list[str]) -> tuple[list[str], dict[str, str], dict[str, str]]:
    """Return checkbox labels plus connector/display lookup maps."""
    display_by_connector = {c: _connector_presentation_label(c) for c in connectors}
    connector_by_display = {label: c for c, label in display_by_connector.items()}
    return [display_by_connector[c] for c in connectors], display_by_connector, connector_by_display


def _prompt_batch_connector_modes(connectors: list[str], gc, *, default_mode: str | None) -> dict[str, str]:
    """Ask once which selected connectors should use action mode."""
    options, display_by_connector, connector_by_display = _connector_display_options(connectors)
    default_action = [
        display_by_connector[c]
        for c in connectors
        if (
            (default_mode or "").strip().lower() == "action"
            or (hasattr(gc, "effective_mode") and gc.effective_mode(c) == "action")
        )
    ]
    ux.section("Action enforcement")
    ux.subhead("Rule/regex scanning applies to every selected connector.")
    ux.subhead("Checked connectors run in action mode and can block.")
    ux.subhead("Unchecked connectors stay in observe mode and only report findings.")
    selected = _prompt_checkbox_selection(
        options,
        default_selected=default_action,
        title="Select connector(s) for action enforcement.",
        empty_ok=True,
    )
    action_connectors = {connector_by_display[label] for label in selected}
    return {c: ("action" if c in action_connectors else "observe") for c in connectors}


def _write_per_connector_modes(gc, connector_modes: dict[str, str]) -> bool:
    """Persist per-connector observe/action choices and report whether any changed."""
    if not connector_modes:
        return False
    if not getattr(gc, "connectors", None):
        gc.connectors = {}

    changed = False
    for connector, mode in connector_modes.items():
        current = (
            gc.effective_mode(connector) if hasattr(gc, "effective_mode") else (getattr(gc, "mode", "") or "observe")
        )
        normalized = "action" if str(mode).strip().lower() == "action" else "observe"
        if connector not in gc.connectors:
            gc.connectors[connector] = PerConnectorGuardrailConfig()
        gc.connectors[connector].mode = normalized
        changed = changed or normalized != current
    return changed


def _existing_connector_override(gc, connector: str):
    """Return an existing per-connector override matching *connector*, if any."""
    wanted = normalize_connector(connector)
    for key, pc in (getattr(gc, "connectors", None) or {}).items():
        try:
            normalized_key = normalize_connector(str(key))
        except Exception:  # noqa: BLE001 - defensive for hand-written configs.
            normalized_key = str(key).strip().lower()
        if normalized_key == wanted:
            return pc
    return None


def _reconcile_batch_active_connectors(cfg, connectors: list[str]) -> list[str]:
    """Make bare setup's active connector map exactly match the selected set."""
    selected: list[str] = []
    for raw in connectors:
        name = normalize_connector(raw)
        if name not in selected:
            selected.append(name)
    if not selected:
        return []

    gc = cfg.guardrail
    before = {normalize_connector(str(c)) for c in (getattr(gc, "connectors", None) or {}) if str(c).strip()}
    if not before:
        current = (getattr(gc, "connector", "") or getattr(cfg.claw, "mode", "") or "").strip()
        if current:
            before.add(normalize_connector(current))

    gc.connectors = {
        name: (_existing_connector_override(gc, name) or PerConnectorGuardrailConfig()) for name in selected
    }
    primary = sorted(selected)[0]
    gc.connector = primary
    cfg.claw.mode = primary

    gate = list(gc.judge.hook_connectors or [])
    if gate != ["*"]:
        selected_set = set(selected)
        gc.judge.hook_connectors = [
            normalize_connector(c) for c in gate if c and normalize_connector(c) in selected_set
        ]

    removed = sorted(before - set(selected))
    if removed:
        click.echo("  " + ux.dim("Inactive connectors removed from this setup: " + ", ".join(removed)))
    return removed


def _strategy_uses_judge(strategy: str) -> bool:
    return (strategy or "").strip().lower() in {"regex_judge", "judge_first"}


def _default_hook_judge_completion_strategy(gc) -> None:
    """Default opted-in hook connectors to judge-capable tool-output scans."""
    current = (getattr(gc, "detection_strategy_completion", "") or "").strip().lower()
    if current in ("", "regex_only"):
        gc.detection_strategy_completion = "regex_judge"


def _prompt_batch_scan_strategy(gc) -> str:
    """Ask once how hook calls should be scanned for a batch setup."""
    ux.section("Scan strategy")
    ux.subhead("Choose the detection strategy for all configured hook connectors.")
    ux.subhead("Judge strategies use your configured LLM judge; this setup can ask for model settings next.")
    ux.subhead(
        "You can also configure provider/model/key later with `defenseclaw setup guardrail` or `defenseclaw setup llm`."
    )
    click.echo("    " + ux.bold("[1] regex only") + "   — rules and regex scanning, no LLM judge calls")
    click.echo("    " + ux.bold("[2] regex + judge") + " — rules first, then LLM judge review")
    click.echo("    " + ux.bold("[3] judge first") + "  — LLM judge first, with regex fallback")
    current = (getattr(gc, "detection_strategy", "") or "regex_only").strip().lower()
    default = {"regex_only": "1", "regex_judge": "2", "judge_first": "3"}.get(current, "1")
    choice = click.prompt(
        "  Select scan strategy",
        type=click.Choice(["1", "2", "3"]),
        default=default,
    )
    return {"1": "regex_only", "2": "regex_judge", "3": "judge_first"}[choice]


def _set_hook_judge_coverage_all(gc) -> None:
    gc.judge.hook_connectors = ["*"]
    click.echo("  " + ux.dim("Hook judge coverage: all configured hook connectors"))


def _default_batch_judge_labels(
    connectors: list[str],
    gc,
    display_by_connector: dict[str, str],
) -> list[str]:
    if not bool(getattr(gc.judge, "enabled", False)):
        return []
    gate = list(getattr(gc.judge, "hook_connectors", []) or [])
    if gate == ["*"]:
        selected = set(connectors)
    else:
        selected = {c for c in connectors if c in gate}
    return [display_by_connector[c] for c in connectors if c in selected]


def _merge_batch_judge_selection(
    gc,
    connectors: list[str],
    selected_connectors: set[str],
    *,
    preserve_outside_targets: bool = False,
) -> list[str]:
    """Apply a judge checkbox selection without exposing strategy jargon."""
    targets = {normalize_connector(c) for c in connectors if c}
    selected = {normalize_connector(c) for c in selected_connectors if c}
    if preserve_outside_targets:
        current_gate = [
            normalize_connector(str(c)) for c in (getattr(gc.judge, "hook_connectors", []) or []) if str(c).strip()
        ]
        if "*" in current_gate:
            removed_targets = targets - selected
            if removed_targets:
                configured_hook_connectors = {
                    normalize_connector(c)
                    for c in _configured_connector_set(gc)
                    if normalize_connector(c) in _HOOK_ENFORCED_CONNECTORS
                }
                new_gate = sorted(configured_hook_connectors - removed_targets)
            else:
                new_gate = ["*"]
        else:
            preserved = {c for c in current_gate if c not in targets}
            new_gate = sorted(preserved | {c for c in selected if c in targets})
    else:
        # Bare setup is scoped to the connectors selected at the top of the flow.
        # Do not carry previously configured, unselected connectors into the judge
        # gate; otherwise the checkbox summary can name connectors the operator
        # deliberately left out of this setup run.
        new_gate = sorted(c for c in selected if c in targets)
    gc.judge.hook_connectors = new_gate
    if new_gate:
        gc.judge.enabled = True
        if not gc.detection_strategy or gc.detection_strategy == "regex_only":
            gc.detection_strategy = "regex_judge"
        _default_hook_judge_completion_strategy(gc)
        _apply_judge_runtime_defaults(gc)
        click.echo("  " + ux.dim(f"Hook judge connectors: {', '.join(new_gate)}"))
    else:
        gc.judge.enabled = False
        gc.detection_strategy = "regex_only"
        gc.detection_strategy_completion = "regex_only"
        click.echo("  " + ux.dim("LLM judge: off (rule/regex scanning only)"))
    return new_gate


def _prune_judge_gate_to_action_scope(gc, connectors: list[str]) -> list[str]:
    """Remove observe-mode connectors in this interactive setup scope from judge."""
    targets = {normalize_connector(c) for c in connectors if c and normalize_connector(c) in _HOOK_ENFORCED_CONNECTORS}
    if not targets:
        return list(getattr(gc.judge, "hook_connectors", []) or [])

    action_targets = {
        c
        for c in targets
        if (gc.effective_mode(c) if hasattr(gc, "effective_mode") else getattr(gc, "mode", "observe")) == "action"
    }
    current_gate = [
        normalize_connector(str(c)) for c in (getattr(gc.judge, "hook_connectors", []) or []) if str(c).strip()
    ]
    if not current_gate:
        return []

    if current_gate == ["*"]:
        # Nothing in this setup scope needs removing. Keep the wildcard rather
        # than needlessly narrowing "all" to today's configured connector
        # list, which would stop future action-mode connectors inheriting it.
        if action_targets == targets:
            return current_gate
        configured_hook_connectors = {
            normalize_connector(c)
            for c in _configured_connector_set(gc)
            if normalize_connector(c) in _HOOK_ENFORCED_CONNECTORS
        }
        new_gate = sorted((configured_hook_connectors - targets) | action_targets)
    else:
        new_gate = sorted(c for c in current_gate if c not in targets or c in action_targets)

    gc.judge.hook_connectors = new_gate
    if not new_gate:
        gc.judge.enabled = False
        gc.detection_strategy = "regex_only"
        gc.detection_strategy_completion = "regex_only"
    return new_gate


def _prompt_batch_judge_connectors(connectors: list[str], gc) -> set[str]:
    """Ask once which selected action connectors should add LLM judge review."""
    options, display_by_connector, connector_by_display = _connector_display_options(connectors)
    ux.section("Optional LLM judge")
    ux.subhead("Rule/regex scanning is enabled by default for every active connector selected above.")
    ux.subhead("Only action-mode connectors can add LLM judge review in this setup flow.")
    ux.subhead("These LLM settings are shared by all connectors with judge enabled.")
    selected = _prompt_checkbox_selection(
        options,
        default_selected=_default_batch_judge_labels(connectors, gc, display_by_connector),
        title="Select action connector(s) that should use the LLM judge.",
        empty_ok=True,
    )
    selected_connectors = {connector_by_display[label] for label in selected}
    _merge_batch_judge_selection(gc, connectors, selected_connectors)
    return selected_connectors


def _prompt_guardrail_judge_enablement(
    gc,
    judge_targets: list[str],
    *,
    preserve_outside_targets: bool = False,
) -> set[str]:
    """Interactive ``setup guardrail`` judge prompt without scan-strategy jargon."""
    if judge_targets:
        options, display_by_connector, connector_by_display = _connector_display_options(judge_targets)
        ux.subhead("Rule/regex scanning is already enabled for every active connector.")
        ux.subhead("Only action-mode connectors can add LLM judge review in this setup flow.")
        ux.subhead("These LLM settings are shared by all connectors with judge enabled.")
        selected = _prompt_checkbox_selection(
            options,
            default_selected=_default_batch_judge_labels(judge_targets, gc, display_by_connector),
            title="Select action connector(s) for LLM judge.",
            empty_ok=True,
        )
        selected_connectors = {connector_by_display[label] for label in selected}
        _merge_batch_judge_selection(
            gc,
            judge_targets,
            selected_connectors,
            preserve_outside_targets=preserve_outside_targets,
        )
        return selected_connectors

    enabled = click.confirm(
        "  Add LLM judge on top of rule scanning?",
        default=bool(gc.judge.enabled),
    )
    if enabled:
        gc.judge.enabled = True
        if not gc.detection_strategy or gc.detection_strategy == "regex_only":
            gc.detection_strategy = "regex_judge"
        _apply_judge_runtime_defaults(gc)
    else:
        gc.judge.enabled = False
        gc.detection_strategy = "regex_only"
        gc.detection_strategy_completion = "regex_only"
    return set()


def _prompt_batch_trusted_prefixes(
    app: AppContext,
    connector_modes: dict[str, str],
) -> dict[str, bool]:
    """Prompt once per untrusted binary directory before batch judge prompts."""
    cache: dict[str, bool] = {}
    if not connector_modes:
        return cache

    try:
        disc = agent_discovery.discover_agents(
            use_cache=False,
            refresh=True,
            data_dir=getattr(app.cfg, "data_dir", None),
        )
    except Exception as exc:  # noqa: BLE001 - final per-connector validation reports details.
        ux.warn(f"Could not refresh local connector discovery before setup ({exc}); continuing.")
        return cache

    for connector in connector_modes:
        if _windows_opencode_requires_exact_selection(connector):
            continue
        signal = disc.agents.get(connector)
        if (
            signal is None
            or not bool(getattr(signal, "installed", False))
            or getattr(signal, "error", "") != agent_discovery.UNTRUSTED_PREFIX_ERROR
            or not getattr(signal, "binary_path", "")
        ):
            continue
        resolved_bin = os.path.realpath(signal.binary_path)
        parent = os.path.dirname(resolved_bin)
        if parent in cache:
            continue

        label = _CONNECTOR_META.get(connector, {}).get("label", connector)
        ux.warn(f"{label}: binary path is outside DefenseClaw's trusted prefixes.")
        ux.subhead(f"  Binary resolves to: {resolved_bin}")
        ux.subhead(f"  Directory '{parent}' is not in the trusted prefix list.")
        ux.subhead(
            "  Trusting a directory lets DefenseClaw execute any binary placed "
            "there during discovery — only trust locations you control."
        )
        if click.confirm(f"  Add '{parent}' to trusted binary prefixes?", default=False):
            _add_trusted_bin_prefix(parent, getattr(app.cfg, "data_dir", None) or os.path.expanduser("~/.defenseclaw"))
            cache[parent] = True
            ux.subhead(f"  Trusted '{parent}' (persisted to ~/.defenseclaw/.env).")
        else:
            cache[parent] = False
    return cache


def _judge_llm_needs_configuration(app: AppContext) -> bool:
    try:
        resolved = app.cfg.resolve_llm("guardrail.judge")
        return not (bool(resolved.model) and bool(resolved.resolved_api_key()))
    except Exception:  # noqa: BLE001 — prompt conservatively if resolution fails.
        return True


def _apply_setup_batch(
    ctx: click.Context,
    app: AppContext,
    connectors: list[str],
    *,
    mode: str,
    restart: bool,
    prompt_per_connector: bool,
    connector_modes: dict[str, str] | None = None,
    allow_trusted_path_prompt: bool = True,
    trusted_prompt_cache: dict[str, bool] | None = None,
    _prior_snapshot: _SetupConfigSnapshot | None = None,
    _protected_selection: _VerifiedSetupAgentSelections | None = None,
) -> None:
    """Configure each connector in *connectors* as a multi-connector batch (SU-11).

    Each connector is written with the additive (``add``) shape so they all
    land in ``guardrail.connectors`` as peers, with per-connector mode
    overrides. The gateway is bounced once at the end via the
    group's auto-restart result callback (suppressed for ``--no-restart``)
    rather than per connector.
    """
    default_mode = "action" if (mode or "").strip().lower() == "action" else "observe"
    setup_snapshot = _prior_snapshot or _capture_setup_config_snapshot(
        app.cfg,
        capture_runtime=_windows_runtime_rollback(restart),
    )

    resolved_connector_modes = {
        connector_name: (connector_modes or {}).get(connector_name, default_mode)
        for connector_name in connectors
    }

    # Exact protected selection is the first compatibility authority in the
    # batch. Windows OpenCode must succeed here before generic discovery can
    # prompt for or persist any unrelated trusted prefix.
    exact_windows_opencode = any(_windows_opencode_requires_exact_selection(name) for name in connectors)
    protected_selection = _protected_selection
    if protected_selection is not None:
        try:
            protected_selection = _revalidate_setup_agent_selections(
                app.cfg.data_dir,
                protected_selection,
                transaction_snapshot=setup_snapshot,
            )
        except OSError:
            protected_selection = None
    if exact_windows_opencode and (protected_selection is None or protected_selection.record_for("opencode") is None):
        try:
            protected_selection = _record_windows_setup_agent_selections(
                getattr(app.cfg, "data_dir", None),
                tuple(connectors),
                _prior_snapshot=setup_snapshot,
            )
        except Exception as exc:
            _restore_setup_config_in_memory(app, setup_snapshot)
            try:
                _restore_setup_agent_selection_snapshot(app.cfg, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve both authority failures.
                raise click.ClickException(
                    f"batch executable selection failed ({exc}); "
                    f"agent_selection.json rollback was incomplete: {rollback_exc}"
                ) from exc
            raise

    if allow_trusted_path_prompt and exact_windows_opencode:
        try:
            trusted_prompt_cache = _prompt_batch_trusted_prefixes(app, resolved_connector_modes)
        except Exception as exc:
            try:
                _restore_setup_config_snapshot(app, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve both transaction failures.
                raise click.ClickException(
                    f"batch setup prompt failed ({exc}); rollback was incomplete: {rollback_exc}"
                ) from exc
            raise

    # Resolve every contract before replacing the desired roster. A selected
    # connector that cannot be set up must leave the exact prior roster intact,
    # rather than becoming desired state that the gateway can never apply.
    for connector_name in connectors:
        connector_mode = resolved_connector_modes[connector_name]
        if _windows_opencode_requires_exact_selection(connector_name):
            continue
        preflight_kwargs = {
            "mode": connector_mode,
            "emit": True,
            "data_dir": getattr(app.cfg, "data_dir", None),
            "_allow_prompt": False,
        }
        if trusted_prompt_cache is not None:
            preflight_kwargs["_trusted_prompt_cache"] = trusted_prompt_cache
        if not _check_connector_version_supported_for_setup(connector_name, **preflight_kwargs):
            if (connector_mode or "").strip().lower() == "action" and connector_name != "opencode":
                label = _CONNECTOR_META.get(connector_name, {}).get("label", connector_name)
                ux.warn(f"{label}: requested action mode was refused; configuring observe mode instead.")
                resolved_connector_modes[connector_name] = "observe"
                continue
            _restore_setup_config_snapshot(app, setup_snapshot)
            raise click.ClickException(
                f"connector {connector_name!r} did not pass setup preflight; prior roster was not changed"
            )

    if protected_selection is not None:
        try:
            protected_selection = _revalidate_setup_agent_selections(
                app.cfg.data_dir,
                protected_selection,
                transaction_snapshot=setup_snapshot,
            )
        except OSError:
            protected_selection = None
    if protected_selection is None:
        try:
            protected_selection = _record_windows_setup_agent_selections(
                getattr(app.cfg, "data_dir", None),
                tuple(connectors),
                _prior_snapshot=setup_snapshot,
            )
        except Exception as exc:
            try:
                _restore_setup_agent_selection_snapshot(app.cfg, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve both authority failures.
                raise click.ClickException(
                    f"batch executable selection failed ({exc}); "
                    f"agent_selection.json rollback was incomplete: {rollback_exc}"
                ) from exc
            raise

    _reconcile_batch_active_connectors(app.cfg, connectors)
    gc = app.cfg.guardrail
    click.echo()
    click.echo(f"  Configuring {len(connectors)} connector(s): {', '.join(connectors)}")

    applied: list[str] = []
    if allow_trusted_path_prompt:
        trusted_prompt_cache = trusted_prompt_cache if trusted_prompt_cache is not None else {}
    else:
        trusted_prompt_cache = None
    for c in connectors:
        connector_mode = resolved_connector_modes[c]
        enable_judge: bool | None = None
        if prompt_per_connector:
            connector_mode = _prompt_connector_mode(c, default_mode=connector_mode)
            if _prompt_enable_judge(c, gc):
                enable_judge = True
        try:
            ok = _apply_hook_connector_setup(
                app,
                connector=c,
                mode=connector_mode,
                restart=False,
                allow_offline_audit=not restart,
                write_mode="add",
                enable_judge=enable_judge,
                judge_hook_connectors=None,
                allow_trusted_path_prompt=allow_trusted_path_prompt,
                trusted_prompt_cache=trusted_prompt_cache,
                _downgrade_refused_action=True,
                _version_preflighted=True,
                _protected_selection=protected_selection,
                _selection_transaction_snapshot=setup_snapshot,
            )
        except Exception as exc:
            try:
                _restore_setup_config_snapshot(app, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve both transaction failures.
                raise click.ClickException(
                    f"connector {c!r} setup failed ({exc}); batch rollback was incomplete: {rollback_exc}"
                ) from exc
            raise
        if ok:
            applied.append(c)
        else:
            try:
                _restore_setup_config_snapshot(app, setup_snapshot)
            except Exception as exc:  # noqa: BLE001 — surface rollback failure with setup refusal.
                raise click.ClickException(
                    f"connector {c!r} setup failed and prior desired roster restoration failed: {exc}"
                ) from exc
            raise click.ClickException(
                f"connector {c!r} setup failed; restored the prior desired connector roster"
            )

    if not applied:
        raise click.ClickException("no connectors were configured — see errors above")

    click.echo()
    click.echo(f"  ✓ Staged desired config for {len(applied)} connector(s): {', '.join(applied)}")

    # Restart handling: the bare batch owns one narrow result-callback marker.
    # Its default restart must start or restart the gateway and verify every
    # selected target, even when the gateway was stopped or the config bytes
    # were already current. Unrelated setup subcommands never set this marker.
    if restart:
        ctx.meta[_SETUP_BATCH_ROLLBACK_KEY] = setup_snapshot
        ctx.meta[_SETUP_BATCH_READINESS_KEY] = tuple(
            sorted({normalize_connector(name) for name in connectors if name})
        )
    else:
        ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True
        click.echo("  --no-restart: config updated; restart defenseclaw-gateway to wire the connector hooks.")


def _dispatch_bare_setup(
    ctx: click.Context,
    app: AppContext | None,
    *,
    connectors: list[str],
    detected: bool,
    all_connectors: bool,
    mode: str,
    restart: bool,
    yes: bool,
) -> None:
    """Resolve and apply the bare-``setup`` target set (SU-11, Hybrid C).

    Scripting flags (``-c/--connector``, ``--detected``, ``--all``) select the
    batch non-interactively; with no flags and a TTY this launches the
    interactive picker. With no flags on a non-interactive stream it falls back
    to printing the group help — preserving the pre-SU-11 bare-``setup``
    behavior in CI / pipelines so nothing hangs on stdin.
    """
    if app is None or getattr(app, "cfg", None) is None:
        click.echo(ctx.get_help())
        return

    targets: list[str] = []

    def _add(raw: str) -> None:
        c = normalize_connector(raw)
        if c not in _HOOK_ENFORCED_CONNECTORS:
            raise click.UsageError(
                f"{raw!r} is not a hook-enforced connector. Choose from "
                f"{sorted(_HOOK_ENFORCED_CONNECTORS)}. (OpenClaw/ZeptoClaw use "
                "`defenseclaw setup openclaw` — they cannot be batch peers.)"
            )
        support = platform_support.connector_platform_support(c)
        if not support.available:
            raise click.UsageError(
                f"connector {c!r} is {support.status} on {platform_support.host_os()}: {support.reason}"
            )
        if c not in targets:
            targets.append(c)

    for raw in connectors:
        _add(raw)
    if detected:
        for c in _detect_installed_connectors():
            if c in _HOOK_ENFORCED_CONNECTORS and platform_support.connector_supported_on_os(c):
                _add(c)
    if all_connectors:
        for c in platform_support.supported_connectors(sorted(_HOOK_ENFORCED_CONNECTORS)):
            _add(c)

    if not targets:
        if not _is_interactive():
            # No scripting flags and no TTY: keep the historical behavior of
            # bare `setup` (print help) rather than blocking on a picker prompt.
            click.echo(ctx.get_help())
            return
        targets = _run_setup_picker(app)
        if not targets:
            click.echo("  Aborted — no connectors selected.")
            return

    setup_snapshot = _capture_setup_config_snapshot(app.cfg, capture_runtime=_windows_runtime_rollback(restart))
    exact_windows_opencode = any(_windows_opencode_requires_exact_selection(name) for name in targets)
    protected_selection: _VerifiedSetupAgentSelections | None = None
    if exact_windows_opencode:
        try:
            protected_selection = _record_windows_setup_agent_selections(
                getattr(app.cfg, "data_dir", None),
                tuple(targets),
                _prior_snapshot=setup_snapshot,
            )
        except Exception as exc:
            _restore_setup_config_in_memory(app, setup_snapshot)
            try:
                _restore_setup_agent_selection_snapshot(app.cfg, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve both authority failures.
                raise click.ClickException(
                    f"batch executable selection failed ({exc}); "
                    f"agent_selection.json rollback was incomplete: {rollback_exc}"
                ) from exc
            raise

    prompt_batch = (not yes) and _is_interactive()
    connector_modes: dict[str, str] | None = None
    judge_connectors: set[str] | None = None
    trusted_prompt_cache: dict[str, bool] | None = None
    if prompt_batch:
        try:
            gc = app.cfg.guardrail
            connector_modes = _prompt_batch_connector_modes(targets, gc, default_mode=mode)
            if exact_windows_opencode:
                # Trusted-path remediation runs inside _apply_setup_batch only
                # after this exact protected selection has succeeded.
                trusted_prompt_cache = {}
            else:
                trusted_prompt_cache = _prompt_batch_trusted_prefixes(app, connector_modes)
            judge_targets = [
                c for c in targets if (connector_modes.get(c, "observe") or "").strip().lower() == "action"
            ]
            if judge_targets:
                judge_connectors = _prompt_batch_judge_connectors(judge_targets, gc)
            else:
                judge_connectors = set()
                click.echo("  " + ux.dim("LLM judge: skipped because no selected connector is in action mode."))
            if judge_connectors:
                configure_model = click.confirm(
                    "  Configure LLM judge provider/model/API settings now?",
                    default=_judge_llm_needs_configuration(app),
                )
                if configure_model:
                    _prompt_judge_model_config(app, gc)
        except Exception as exc:
            if not exact_windows_opencode:
                raise
            try:
                _restore_setup_config_snapshot(app, setup_snapshot)
            except Exception as rollback_exc:  # noqa: BLE001 — preserve both transaction failures.
                raise click.ClickException(
                    f"batch setup prompt failed ({exc}); rollback was incomplete: {rollback_exc}"
                ) from exc
            raise

    _apply_setup_batch(
        ctx,
        app,
        targets,
        mode=mode,
        restart=restart,
        prompt_per_connector=False,
        connector_modes=connector_modes,
        allow_trusted_path_prompt=prompt_batch,
        trusted_prompt_cache=trusted_prompt_cache,
        _prior_snapshot=setup_snapshot,
        _protected_selection=protected_selection,
    )
    if prompt_batch:
        _prune_judge_gate_to_action_scope(app.cfg.guardrail, targets)


def _hook_guardrail_options(fn):
    """SU-10 parity: per-connector guardrail options for hook setup commands.

    The hook factory historically exposed only mode/workspace/rule-pack, while
    the proxy factory (``_make_guardrail_connector_setup_command``) exposed
    judge/HILT/block-message. That fork is *why* judge/HILT/block-message were
    unreachable on hook connectors (SU-06/07/08/10). These options close the
    gap and, because every field writes per-connector (B3/E4d via
    ``_apply_hook_connector_setup``), they make the per-connector guardrail
    write-surface the TUI B4 editor consumes reachable from the CLI too.

    Applied as a shared decorator (rather than copied across codex,
    claude-code, and the factory) so the surface stays consistent by
    construction. All default to ``None`` → omitting the flag leaves the field
    untouched (judge stays OFF by default; SU-02/J1 preserve-don't-clobber).
    """
    opts = [
        click.option(
            "--enable-judge/--no-enable-judge",
            "enable_judge",
            default=None,
            help=(
                "Enable LLM judge scanning for this connector and bump "
                "the detection strategy off regex_only. --no-enable-judge "
                "opts this connector out of a concrete hook-lane gate while "
                "leaving the global judge switch alone. Configure the judge "
                "model via `setup guardrail` / `setup llm`."
            ),
        ),
        click.option(
            "--judge-hook-connectors",
            default=None,
            help=(
                "Hook-lane judge gate to write (guardrail.judge.hook_connectors): "
                "'all'/'*', 'none', or a comma list of hook connectors. When "
                "--enable-judge is given without this, defaults to this connector."
            ),
        ),
        click.option(
            "--human-approval/--no-human-approval",
            "human_approval",
            default=None,
            help="Enable or disable human approval (HILT) for this connector (action mode).",
        ),
        click.option(
            "--hilt-min-severity",
            type=click.Choice(_HILT_MIN_SEVERITIES, case_sensitive=False),
            default=None,
            help="Minimum severity that asks for human approval for this connector.",
        ),
        click.option(
            "--block-message",
            default=None,
            help="Custom block message for THIS connector (empty = inherit the global/default).",
        ),
        click.option(
            "--fail-mode",
            type=click.Choice(["open", "closed"], case_sensitive=False),
            default=None,
            help=(
                "Per-connector hook fail mode: how the hook behaves when the "
                "gateway answers with an error. 'open' allows + logs "
                "(recommended); 'closed' blocks."
            ),
        ),
    ]
    for opt in reversed(opts):
        fn = opt(fn)
    return fn


@setup.command(
    "codex",
    epilog=(
        "Hook connectors enforce via the agent's PreToolUse deny verdict (no "
        "LLM proxy). The judge/HILT/block-message options here write "
        "per-connector overrides; openclaw/zeptoclaw use the proxy backend "
        "(`setup openclaw --help`) and additionally expose proxy/scanner "
        "options that do not apply to hook connectors."
    ),
)
@click.option(
    "--yes",
    "-y",
    "yes",
    is_flag=True,
    help="Skip the confirmation prompt (non-interactive).",
)
@click.option(
    "--restart/--no-restart",
    default=True,
    show_default=True,
    help=(
        "Restart defenseclaw-gateway after applying changes "
        "(needed so the connector's hook scripts + OTel block are wired)."
    ),
)
@click.option(
    "--with-local-stack/--no-local-stack",
    default=False,
    show_default=True,
    help=(
        "Also bring up the bundled Prom/Loki/Tempo/Grafana stack via "
        "`defenseclaw setup local-observability up` once config is saved."
    ),
)
@click.option(
    "--mode",
    type=click.Choice(["observe", "action"], case_sensitive=False),
    default="observe",
    show_default=True,
    help=(
        "Hook policy mode. observe records only; action returns a deny "
        "verdict from PreToolUse on policy hits so Codex blocks the "
        "tool call inside its own permission flow. No proxy is involved "
        "in either mode."
    ),
)
@click.option(
    "--workspace",
    "--workspace-dir",
    "workspace_dir",
    default=None,
    help="Opt into workspace-scoped config for this setup. Defaults to global/user config.",
)
@click.option(
    "--replace",
    is_flag=True,
    help=(
        "Replace the currently configured connector(s) with this one instead "
        "of adding alongside them. When other connectors are configured the "
        "default (and the --yes default) is to ADD; pass --replace to switch."
    ),
)
@click.option(
    "--rule-pack",
    type=click.Choice(["default", "strict", "permissive"]),
    default=None,
    help=(
        "Rule-pack profile for THIS connector. In a multi-connector install "
        "this writes a per-connector override so Codex can run a different "
        "pack than its peers (each connector scans against its own pack at "
        "boot); when Codex is the only connector it sets the global pack, "
        "matching `setup guardrail --rule-pack`. Omit to leave unchanged "
        "(inherits the global pack)."
    ),
)
@click.option(
    "--rule-pack-dir",
    default=None,
    help=(
        "Custom rule-pack DIRECTORY for THIS connector (free-text path; CLI "
        "parity with the TUI). Use instead of --rule-pack to point at a pack "
        "outside the built-in presets; same per-connector scoping. Mutually "
        'exclusive with --rule-pack; pass "" to clear an override.'
    ),
)
@_hook_guardrail_options
@pass_ctx
def setup_codex(
    app: AppContext,
    yes: bool,
    restart: bool,
    with_local_stack: bool,
    mode: str,
    workspace_dir: str | None,
    replace: bool,
    rule_pack: str | None,
    rule_pack_dir: str | None,
    enable_judge: bool | None,
    judge_hook_connectors: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
    block_message: str | None,
    fail_mode: str | None,
) -> None:
    """Configure DefenseClaw for Codex via the hook bus.

    Alias for the hook-driven path of ``setup guardrail`` with
    ``--connector codex``. Configures Codex in the hook connector set
    so inventory follows Codex's current ``.agents`` asset layouts and
    user/project ``.codex/config.toml`` layers.

    Wires three telemetry channels at gateway boot:

    \b
      • Hooks   — version-selected lifecycle contract: six events on
                  0.124-0.128, eight on 0.129-0.132, ten on
                  0.133-0.144, and eleven from 0.145 (with SessionEnd
                  advisory-only)
      • OTel    — native Codex logs, metrics, and traces using a
                  connector-scoped bearer and X-DefenseClaw-Source
                  header on the loopback /v1/<signal> routes
      • Notify  — agent-turn-complete webhooks via the bundled
                  native notification bridge

    Default mode is ``observe`` (record only). Pass ``--mode action``
    to provision hook-driven enforcement: the PreToolUse hook returns
    a deny verdict on policy hits and Codex blocks via its permission
    flow. No proxy listener binds in either mode — Codex talks
    directly to its native upstream.
    """
    _setup_observability_alias(
        app,
        connector="codex",
        yes=yes,
        restart=restart,
        with_local_stack=with_local_stack,
        mode=mode,
        workspace_dir=workspace_dir,
        replace=replace,
        rule_pack=rule_pack,
        rule_pack_dir=rule_pack_dir,
        block_message=block_message,
        fail_mode=fail_mode,
        human_approval=human_approval,
        hilt_min_severity=hilt_min_severity,
        enable_judge=enable_judge,
        judge_hook_connectors=judge_hook_connectors,
    )


@setup.command(
    "claude-code",
    epilog=(
        "Hook connectors enforce via the agent's PreToolUse deny verdict (no "
        "LLM proxy). The judge/HILT/block-message options here write "
        "per-connector overrides; openclaw/zeptoclaw use the proxy backend "
        "(`setup openclaw --help`) and additionally expose proxy/scanner "
        "options that do not apply to hook connectors."
    ),
)
@click.option(
    "--yes",
    "-y",
    "yes",
    is_flag=True,
    help="Skip the confirmation prompt (non-interactive).",
)
@click.option(
    "--restart/--no-restart",
    default=True,
    show_default=True,
    help=(
        "Restart defenseclaw-gateway after applying changes "
        "(needed so the connector's hook scripts + OTel env vars are wired)."
    ),
)
@click.option(
    "--with-local-stack/--no-local-stack",
    default=False,
    show_default=True,
    help=(
        "Also bring up the bundled Prom/Loki/Tempo/Grafana stack via "
        "`defenseclaw setup local-observability up` once config is saved."
    ),
)
@click.option(
    "--mode",
    type=click.Choice(["observe", "action"], case_sensitive=False),
    default="observe",
    show_default=True,
    help=(
        "Hook policy mode. observe records only; action returns a deny "
        "verdict from PreToolUse on policy hits so Claude Code blocks "
        "the tool call inside its own permission flow. No proxy is "
        "involved in either mode."
    ),
)
@click.option(
    "--workspace",
    "--workspace-dir",
    "workspace_dir",
    default=None,
    help="Opt into workspace-scoped config for this setup. Defaults to global/user config.",
)
@click.option(
    "--replace",
    is_flag=True,
    help=(
        "Replace the currently configured connector(s) with this one instead "
        "of adding alongside them. When other connectors are configured the "
        "default (and the --yes default) is to ADD; pass --replace to switch."
    ),
)
@click.option(
    "--rule-pack",
    type=click.Choice(["default", "strict", "permissive"]),
    default=None,
    help=(
        "Rule-pack profile for THIS connector. In a multi-connector install "
        "this writes a per-connector override so Claude Code can run a "
        "different pack than its peers (each connector scans against its own "
        "pack at boot); when it is the only connector it sets the global "
        "pack, matching `setup guardrail --rule-pack`. Omit to leave "
        "unchanged (inherits the global pack)."
    ),
)
@click.option(
    "--rule-pack-dir",
    default=None,
    help=(
        "Custom rule-pack DIRECTORY for THIS connector (free-text path; CLI "
        "parity with the TUI). Use instead of --rule-pack to point at a pack "
        "outside the built-in presets; same per-connector scoping. Mutually "
        'exclusive with --rule-pack; pass "" to clear an override.'
    ),
)
@_hook_guardrail_options
@pass_ctx
def setup_claude_code(
    app: AppContext,
    yes: bool,
    restart: bool,
    with_local_stack: bool,
    mode: str,
    workspace_dir: str | None,
    replace: bool,
    rule_pack: str | None,
    rule_pack_dir: str | None,
    enable_judge: bool | None,
    judge_hook_connectors: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
    block_message: str | None,
    fail_mode: str | None,
) -> None:
    """Configure DefenseClaw for Claude Code via the hook bus.

    Alias for the hook-driven path of ``setup guardrail`` with
    ``--connector claudecode``. Configures Claude Code in the hook
    connector set so the TUI, skill scanner, MCP scanner, and plugin
    scanner read from ``~/.claude/`` for Claude-scoped surfaces.

    Wires two telemetry channels at gateway boot:

    \b
      • Hooks — the exact version-selected Claude Code contract: 28
                events for >=2.1.154,<2.1.219 or 29 events for
                >=2.1.219, including observational DirectoryAdded
      • OTel  — native Claude Code OTel exporter (env-driven) pointing
                at the gateway's /v1/logs and /v1/metrics

    Default mode is ``observe`` (record only). Pass ``--mode action``
    to provision hook-driven enforcement: the PreToolUse hook returns
    a deny verdict on policy hits and Claude Code blocks via its
    native permission flow (including HITL when ``--human-approval``
    is on). No proxy listener binds in either mode — Claude Code
    talks directly to its native upstream.
    """
    _setup_observability_alias(
        app,
        connector="claudecode",
        yes=yes,
        restart=restart,
        with_local_stack=with_local_stack,
        mode=mode,
        workspace_dir=workspace_dir,
        replace=replace,
        rule_pack=rule_pack,
        rule_pack_dir=rule_pack_dir,
        block_message=block_message,
        fail_mode=fail_mode,
        human_approval=human_approval,
        hilt_min_severity=hilt_min_severity,
        enable_judge=enable_judge,
        judge_hook_connectors=judge_hook_connectors,
    )


def _remove_connector(
    app: AppContext,
    *,
    connector: str,
    restart: bool,
    force: bool,
    yes: bool,
) -> bool:
    """Remove *connector* from the configured set (WU8, inverse of setup-add).

    Mutation shape mirrors ``_write_connector_identity`` so the two stay
    symmetric:

      * Removing one of several connectors drops it from
        ``guardrail.connectors`` and repoints the singular
        ``guardrail.connector`` / ``claw.mode`` mirror at the new primary
        (sorted-first remaining). The final map entry remains authoritative
        so connector-specific policy is not discarded when one peer remains.
      * Removing the LAST connector is gated (WU8 D2=A): refused unless
        ``--force``, which fully unconfigures enforcement (clears the map
        and the singular mirror). ``defenseclaw uninstall`` remains the
        path for taking DefenseClaw off the machine entirely.

    Teardown is delegated to the gateway boot loop (WU8 D3=A): once the
    connector is gone from config, restarting defenseclaw-gateway lets the
    set-difference reconciliation (``teardownRemovedConnectors``) remove
    exactly that connector's hooks. No per-connector teardown plumbing is
    added here.

    Returns True on success (including an idempotent known-absent request),
    and False on refusal or persistence error.
    """
    cfg = app.cfg
    gc = cfg.guardrail
    requested = (connector or "").strip()
    if not requested:
        click.echo("  ✗ No connector specified.", err=True)
        return False
    requested_norm = normalize_connector(requested)

    configured = _configured_connector_set(gc)
    # Match against canonical aliases so operators can type `Codex`,
    # `claude-code`, or `open-hands` interchangeably.
    match = next((c for c in configured if normalize_connector(c) == requested_norm), None)
    if match is None:
        if requested_norm in _CONNECTOR_META:
            click.echo(f"  ✓ Connector {requested_norm!r} is already absent; no changes made.")
            return True
        configured_label = ", ".join(configured) if configured else "(none configured)"
        click.echo(
            f"  ✗ {requested!r} is not a configured connector. Configured: {configured_label}",
            err=True,
        )
        return False

    remaining = [c for c in configured if c != match]

    # WU8 D2=A — last-connector gate.
    if not remaining:
        if not force:
            click.echo(
                f"  ✗ Refusing to remove the last connector ({match!r}) — the gateway would enforce nothing.",
                err=True,
            )
            click.echo(
                "    Pass --force to fully unconfigure enforcement (DefenseClaw stays installed),",
                err=True,
            )
            click.echo(
                "    or run `defenseclaw uninstall` to remove DefenseClaw entirely.",
                err=True,
            )
            return False
        if not yes and not click.confirm(
            f"Remove the last connector {match!r} and fully unconfigure enforcement?",
            default=False,
        ):
            # Operator-initiated cancel is a clean no-op (exit 0), matching
            # the setup-add cancel path — not an error.
            click.echo("  Aborted; no changes made.")
            return True
    elif not yes and not click.confirm(f"Remove connector {match!r}?", default=True):
        click.echo("  Aborted; no changes made.")
        return True

    setup_snapshot: _SetupConfigSnapshot | None = None
    runtime_rollback = _windows_runtime_rollback(restart)
    if runtime_rollback:
        try:
            setup_snapshot = _capture_setup_config_snapshot(cfg, capture_runtime=True)
        except OSError as exc:
            click.echo(
                f"  ✗ Cannot establish connector removal rollback point [ref {_setup_runtime_ref(type(exc).__name__)}]",
                err=True,
            )
            return False

    # Drop from the multi-connector map (case-insensitive key match).
    if getattr(gc, "connectors", None):
        for key in [k for k in gc.connectors if k.lower() == match.lower()]:
            del gc.connectors[key]

    if not remaining:
        # Fully unconfigured: no connector enforces anything.
        gc.connectors = {}
        gc.connector = ""
        cfg.claw.mode = ""
    elif len(remaining) == 1:
        # Keep the surviving map entry authoritative. Collapsing to the
        # singular mirror here would silently discard per-connector policy.
        gc.connector = remaining[0]
        cfg.claw.mode = remaining[0]
    else:
        # Still multi: keep the map, repoint the primary mirror.
        primary = sorted(remaining)[0]
        gc.connector = primary
        cfg.claw.mode = primary

    try:
        cfg.save()
    except OSError as exc:
        if setup_snapshot is not None:
            _rollback_failed_connector_application(app, setup_snapshot, exc)
        click.echo(f"  ✗ Failed to save config [ref {_setup_runtime_ref(type(exc).__name__)}]", err=True)
        return False

    click.echo(f"  ✓ Removed connector {match!r}")
    if remaining:
        click.echo(f"  ✓ Remaining connector(s): {', '.join(sorted(remaining))}")
    else:
        click.echo("  ✓ No connectors configured — DefenseClaw enforces nothing until you run `setup` again.")

    if restart:
        click.echo()
        click.echo("  Restarting gateway so the removed connector's hooks are torn down…")
        # The set-difference teardown (WU6b) runs at gateway boot and is
        # connector-agnostic, so a plain defense-gateway bounce is the
        # precise primitive here. _restart_defense_gateway also marks the
        # restart as handled so the group result callback won't bounce
        # again.
        if not runtime_rollback:
            _restart_defense_gateway(cfg.data_dir)
        else:
            try:
                if not _restart_defense_gateway(cfg.data_dir):
                    raise OSError("gateway restart failed during connector removal")
            except Exception as exc:  # noqa: BLE001 - removal shares the Setup transaction boundary.
                if setup_snapshot is None:
                    raise click.ClickException("connector removal restart failed without rollback authority") from None
                _rollback_failed_connector_application(app, setup_snapshot, exc)
    else:
        # Suppress the group's auto-restart result callback so --no-restart
        # is honored; warn that teardown is deferred until the next boot.
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True
        click.echo()
        click.echo(
            "  --no-restart: config updated, but the removed connector's hooks are "
            "still installed until you restart defenseclaw-gateway."
        )

    remaining_label = ",".join(sorted(remaining)) if remaining else "(none)"
    _log_setup_action(
        app,
        ACTION_SETUP_HOOK_CONNECTOR,
        f"connector={match} action=remove remaining={remaining_label}",
        allow_offline=not restart,
    )

    return True


@setup.command("remove")
@click.argument("connector")
@click.option(
    "--restart/--no-restart",
    default=True,
    show_default=True,
    help=(
        "Restart defenseclaw-gateway after removing the connector so its "
        "hooks are torn down via boot-time reconciliation."
    ),
)
@click.option(
    "--force",
    is_flag=True,
    help=(
        "Allow removing the LAST remaining connector, fully unconfiguring "
        "DefenseClaw enforcement (it stays installed). Use `defenseclaw "
        "uninstall` to remove DefenseClaw entirely."
    ),
)
@click.option(
    "--yes",
    "-y",
    "yes",
    is_flag=True,
    help="Skip the confirmation prompt (non-interactive).",
)
@pass_ctx
def setup_remove(
    app: AppContext,
    connector: str,
    restart: bool,
    force: bool,
    yes: bool,
) -> None:
    """Remove a connector from the configured set.

    The inverse of ``defenseclaw setup <connector>``: drops CONNECTOR from
    ``guardrail.connectors`` and, after a restart, lets the gateway tear
    down its hooks via set-difference reconciliation.

    Removing the last remaining connector is refused unless ``--force`` is
    given (which fully unconfigures enforcement). To take DefenseClaw off
    the machine entirely, use ``defenseclaw uninstall``.
    """
    if not _remove_connector(
        app,
        connector=connector,
        restart=restart,
        force=force,
        yes=yes,
    ):
        raise click.ClickException(f"failed to remove connector {connector!r} — see errors above")


def _make_observability_setup_command(connector: str) -> click.Command:
    """Create a ``defenseclaw setup <connector>`` hook-driven alias."""
    label = _CONNECTOR_META[connector]["label"]
    surface_name = (
        "synchronous policy plugin"
        if connector == "amp"
        else ("custom policy API" if connector == "omnigent" else "agent lifecycle hooks")
    )
    platform = platform_support.connector_platform_support(connector)
    platform_note = (
        ""
        if platform.status == platform_support.SUPPORTED
        else (f"\n\nPlatform status on {platform_support.host_os()}: {platform.status} — {platform.reason}")
    )
    product_note = (
        "\n\nGemini CLI scope: continuing enterprise, Google Cloud, and paid "
        "API-key access only. Consumer/free/Google AI Pro/Ultra service ended "
        "on June 18, 2026; this setup does not restore that access."
        if connector == "geminicli"
        else (
            "\n\nCursor scope: DefenseClaw owns only the user hook. Enterprise, Team, "
            "and Project hooks have higher precedence. DefenseClaw cannot safely detect "
            "an actual higher-priority conflict, so none is inferred. Action uses the "
            "documented event-native deny response; native human approval is unsupported."
            if connector == "cursor"
            else ""
        )
    )
    short_help = (
        "Configure continuing paid/enterprise Gemini CLI hooks."
        if connector == "geminicli"
        else f"Configure DefenseClaw for {label}."
    )
    if platform.status != platform_support.SUPPORTED:
        short_help = f"{label}: {platform.status} on {platform_support.host_os()}."

    @click.command(
        connector,
        help=(
            f"Configure DefenseClaw for {label} via its {surface_name}.\n\n"
            "Configures this connector in the hook connector set so CLI/TUI "
            "scanners read that agent's documented local surfaces. Default "
            "mode is observe. Action may enable agent-native blocking/approval verdicts with "
            "--mode action on supported events. No proxy is involved in either mode."
            f"{product_note}"
            f"{platform_note}"
        ),
        short_help=short_help,
        epilog=(
            "Hook and policy connectors enforce through agent-native lifecycle "
            "verdicts (no LLM proxy). The judge/HILT/block-message options here write "
            "per-connector overrides; openclaw/zeptoclaw use the proxy backend "
            "(`setup openclaw --help`) and additionally expose proxy/scanner "
            "options that do not apply to hook connectors."
        ),
    )
    @click.option(
        "--yes",
        "-y",
        "yes",
        is_flag=True,
        help="Skip the confirmation prompt (non-interactive).",
    )
    @click.option(
        "--restart/--no-restart",
        default=True,
        show_default=True,
        help=(
            "Restart defenseclaw-gateway after applying changes "
            "(needed so the connector's runtime artifacts and telemetry are wired)."
        ),
    )
    @click.option(
        "--with-local-stack/--no-local-stack",
        default=False,
        show_default=True,
        help=(
            "Also bring up the bundled Prom/Loki/Tempo/Grafana stack via "
            "`defenseclaw setup local-observability up` once config is saved."
        ),
    )
    @click.option(
        "--mode",
        type=click.Choice(["observe", "action"], case_sensitive=False),
        default="observe",
        show_default=True,
        help=(
            "Lifecycle policy mode. observe records only; action requests the connector's "
            "native blocking or approval verdict on supported events. Cursor action uses "
            "event-native deny and does not enable human approval."
        ),
    )
    @click.option(
        "--workspace",
        "--workspace-dir",
        "workspace_dir",
        default=None,
        help="Opt into workspace-scoped config for this setup. Defaults to global/user config.",
    )
    @click.option(
        "--replace",
        is_flag=True,
        help=(
            "Replace the currently configured connector(s) with this one instead "
            "of adding alongside them. When other connectors are configured the "
            "default (and the --yes default) is to ADD; pass --replace to switch."
        ),
    )
    @click.option(
        "--rule-pack",
        type=click.Choice(["default", "strict", "permissive"]),
        default=None,
        help=(
            f"Rule-pack profile for THIS connector. In a multi-connector "
            f"install this writes a per-connector override so {label} can run "
            "a different pack than its peers (each connector scans against its "
            "own pack at boot); when it is the only connector it sets the "
            "global pack, matching `setup guardrail --rule-pack`. Omit to "
            "leave unchanged (inherits the global pack)."
        ),
    )
    @click.option(
        "--rule-pack-dir",
        default=None,
        help=(
            "Custom rule-pack DIRECTORY for THIS connector (free-text path; "
            "CLI parity with the TUI). Use instead of --rule-pack to point at "
            "a pack outside the built-in presets; same per-connector scoping. "
            'Mutually exclusive with --rule-pack; pass "" to clear an override.'
        ),
    )
    @_hook_guardrail_options
    @pass_ctx
    def _cmd(
        app: AppContext,
        yes: bool,
        restart: bool,
        with_local_stack: bool,
        mode: str,
        workspace_dir: str | None,
        replace: bool,
        rule_pack: str | None,
        rule_pack_dir: str | None,
        enable_judge: bool | None,
        judge_hook_connectors: str | None,
        human_approval: bool | None,
        hilt_min_severity: str | None,
        block_message: str | None,
        fail_mode: str | None,
    ) -> None:
        _setup_observability_alias(
            app,
            connector=connector,
            yes=yes,
            restart=restart,
            with_local_stack=with_local_stack,
            mode=mode,
            workspace_dir=workspace_dir,
            replace=replace,
            rule_pack=rule_pack,
            rule_pack_dir=rule_pack_dir,
            block_message=block_message,
            fail_mode=fail_mode,
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
            enable_judge=enable_judge,
            judge_hook_connectors=judge_hook_connectors,
        )

    _cmd.__name__ = f"setup_{connector}"
    _cmd.__doc__ = (
        f"Configure DefenseClaw for {label} via its {surface_name}.\n\n"
        "Configures this connector in the hook connector set so CLI/TUI "
        "scanners read that agent's documented local surfaces. Default "
        "mode is observe. Action uses agent-native lifecycle verdicts on policy hits; "
        "Cursor does not enable native human approval."
        f"{product_note}"
    )
    return _cmd


for _observability_connector in (
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
    "amp",
    "omnigent",
):
    setup.add_command(_make_observability_setup_command(_observability_connector))


# Two orthogonal facts about a connector — split deliberately so the
# wizard, doctor, and TUI can talk about each independently:
#
#   * _PROXY_BACKED_CONNECTORS — connectors whose enforcement path
#     interposes a local HTTP proxy on the LLM data path (port 4000).
#     openclaw and zeptoclaw bind the proxy listener at gateway boot
#     and route requests through Bifrost.
#
#   * _HOOK_ENFORCED_CONNECTORS — connectors whose enforcement path is
#     the agent's own hook bus (PreToolUse / UserPromptSubmit /
#     PostToolUse). The agent talks directly to its native upstream;
#     DefenseClaw observes via hooks + (where the vendor documents it)
#     native OTLP, and BLOCKS by returning a deny verdict from the
#     PreToolUse hook. ``mode=action`` IS supported on this surface —
#     it's hook-driven blocking, not proxy-driven.
#
# Action mode is supported on both surfaces. The difference is the data-path
# topology and the proxy listener binding decision. The
# observability-only label is reserved for installs where the operator
# explicitly picks mode=observe.
_PROXY_BACKED_CONNECTORS = frozenset({"openclaw", "zeptoclaw"})
_HOOK_ENFORCED_CONNECTORS = frozenset(
    {
        "codex",
        "claudecode",
        "hermes",
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
        "openhands",
        "antigravity",
        "opencode",
        "amp",
        "omnigent",
    }
)

# Legacy alias retained as a backstop for any out-of-tree code that
# imported the old name. New call sites must use one of the two named
# sets above. Slated for deletion once internal docs catch up.
_OBSERVABILITY_ONLY_CONNECTORS = _HOOK_ENFORCED_CONNECTORS

# Kept as separate name for legibility at call sites that mean
# "supports the proxy enforcement surface".
_GUARDRAIL_SUPPORTING_CONNECTORS = _PROXY_BACKED_CONNECTORS


def connector_llm_role(connector: str) -> str:
    """Return the default ``llm_role`` for ``connector``.

    Hook-based connectors (Codex, Claude Code, ...) intercept the
    agent's outbound LLM call via a sidecar hook, so DefenseClaw only
    ever uses an LLM for the judge — ``judge_only``.

    Proxy-backed connectors (OpenClaw, ZeptoClaw) route the agent
    through DefenseClaw's gateway and can therefore either share one
    LLM for judge AND agent or split them. The safer default is
    ``judge_and_agent``; operators who want to keep their agent LLM
    untouched can still pick ``judge_only`` interactively or via
    ``setup guardrail --llm-role judge_only``.

    Unknown connectors fall back to ``judge_only`` to avoid silently
    rerouting their traffic through the proxy.
    """
    if connector in _HOOK_ENFORCED_CONNECTORS:
        return "judge_only"
    if connector in _PROXY_BACKED_CONNECTORS:
        return "judge_and_agent"
    return "judge_only"


def _echo_custom_provider_enforcement(cfg: Any) -> None:
    """Print the honest, per-connector meaning of binding a custom
    provider, keyed on the active connector's LLM traffic mode.

    This closes the UX gap where an operator binds a custom provider
    while guarding a hook connector and believes their agent now runs on
    that model. It does not: on hook connectors a custom provider only
    configures DefenseClaw's judge/aux model; the agent's own model
    calls are never routed through or inspected by DefenseClaw. Only the
    proxy connectors (OpenClaw, ZeptoClaw) enforce it on agent traffic.
    """
    connector = connector_paths.normalize(getattr(cfg.guardrail, "connector", "") or "openclaw")
    if connector in _PROXY_BACKED_CONNECTORS:
        ux.subhead(
            f"Enforced: {connector} routes the agent's model traffic through "
            "DefenseClaw, so this custom provider can serve the agent's "
            "upstream model, the judge, or both.",
        )
    else:
        ux.warn(
            f"Judge/aux only: {connector} is a hook connector, so this custom "
            "provider configures DefenseClaw's judge/aux model only. "
            f"{connector}'s own model calls are NOT routed through or "
            "inspected by DefenseClaw.",
        )


def _setup_guardrail_connector_alias(
    app: AppContext,
    *,
    connector: str,
    yes: bool,
    non_interactive: bool,
    guard_mode: str | None,
    scanner_mode: str | None,
    cisco_endpoint: str | None,
    cisco_api_key_env: str | None,
    cisco_timeout_ms: int | None,
    guard_port: int | None,
    block_message: str | None,
    detection_strategy: str | None,
    rule_pack: str | None,
    rule_pack_dir: str | None,
    judge_model: str | None,
    judge_api_base: str | None,
    judge_api_key_env: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
    restart: bool,
    verify: bool,
) -> None:
    """Run the full guardrail setup backend for a specific connector."""
    if connector not in _GUARDRAIL_SUPPORTING_CONNECTORS:
        raise click.ClickException(f"{connector!r} is not a guardrail-capable connector")
    _ensure_connector_available(connector)

    label = _CONNECTOR_META.get(connector, {}).get("label", connector)
    click.echo()
    click.echo(f"  DefenseClaw — {label} guardrail setup")
    click.echo("  ─────────────────────────────────────────────────────────")
    click.echo()
    click.echo(f"  This pins claw.mode={connector} and guardrail.connector={connector},")
    click.echo("  then runs the same non-interactive backend as `setup guardrail`.")
    click.echo()

    if not (yes or non_interactive):
        if not click.confirm(f"  Configure {label} guardrail now?", default=True):
            click.echo("  Aborted — no changes made.")
            return

    app.cfg.claw.mode = connector
    app.cfg.guardrail.connector = connector
    _write_picked_connector_hint(getattr(app.cfg, "data_dir", None), connector)

    ctx = click.get_current_context()
    ctx.invoke(
        setup_guardrail,
        disable=False,
        agent_name=connector,
        guard_mode=guard_mode,
        guard_port=guard_port,
        scanner_mode=scanner_mode,
        cisco_endpoint=cisco_endpoint,
        cisco_api_key_env=cisco_api_key_env,
        cisco_timeout_ms=cisco_timeout_ms,
        block_message=block_message,
        detection_strategy=detection_strategy,
        rule_pack=rule_pack,
        rule_pack_dir=rule_pack_dir,
        judge_model=judge_model,
        judge_api_base=judge_api_base,
        judge_api_key_env=judge_api_key_env,
        judge_provider=None,
        judge_region=None,
        judge_instance_name=None,
        llm_role=None,
        judge_inherit_from=None,
        judge_inherit_llm=None,
        judge_auth_mode=None,
        judge_bedrock_region=None,
        judge_bedrock_auth_mode=None,
        judge_bedrock_access_key_env=None,
        judge_bedrock_secret_key_env=None,
        judge_bedrock_session_token_env=None,
        judge_bedrock_profile_name=None,
        judge_bedrock_inference_profile=None,
        judge_bedrock_deployment_aliases=(),
        judge_vertex_project_id=None,
        judge_vertex_region=None,
        judge_vertex_auth_mode=None,
        judge_vertex_service_account_json_env=None,
        judge_azure_endpoint=None,
        judge_azure_api_version=None,
        judge_azure_auth_mode=None,
        judge_azure_deployment_aliases=(),
        judge_tls_ca_cert_file=None,
        judge_insecure_skip_verify=False,
        human_approval=human_approval,
        hilt_min_severity=hilt_min_severity,
        restart=restart,
        verify=verify,
        non_interactive=True,
    )


def _make_guardrail_connector_setup_command(connector: str) -> click.Command:
    """Create ``defenseclaw setup openclaw|zeptoclaw`` aliases."""
    label = _CONNECTOR_META[connector]["label"]
    platform = platform_support.connector_platform_support(connector)
    platform_note = (
        ""
        if platform.status == platform_support.SUPPORTED
        else (f"\n\nPlatform status on {platform_support.host_os()}: {platform.status} — {platform.reason}")
    )
    short_help = f"Configure {label} guardrail setup."
    if platform.status != platform_support.SUPPORTED:
        short_help = f"{label}: {platform.status} on {platform_support.host_os()}."

    @click.command(
        connector,
        help=(
            f"Configure DefenseClaw guardrail for {label}.\n\n"
            "Configures the proxy-backed connector selection, then runs the "
            "same backend as `defenseclaw setup guardrail --connector ...`."
            f"{platform_note}"
        ),
        short_help=short_help,
    )
    @click.option("--yes", "-y", "yes", is_flag=True, help="Skip confirmation prompt.")
    @click.option("--non-interactive", "--accept-defaults", is_flag=True, help="Alias for --yes.")
    @click.option(
        "--mode",
        "guard_mode",
        type=click.Choice(["observe", "action"]),
        default=None,
        help="Guardrail mode.",
    )
    @click.option("--scanner-mode", type=click.Choice(["local", "remote", "both"]), default=None, help="Scanner mode.")
    @click.option("--cisco-endpoint", default=None, help="Cisco AI Defense API endpoint.")
    @click.option("--cisco-api-key-env", default=None, help="Env var name holding Cisco AI Defense API key.")
    @click.option("--cisco-timeout-ms", type=int, default=None, help="Cisco AI Defense timeout (ms).")
    @click.option("--port", "guard_port", type=int, default=None, help="Guardrail proxy port.")
    @click.option("--block-message", default=None, help="Custom block message.")
    @click.option(
        "--detection-strategy",
        type=click.Choice(["regex_only", "regex_judge", "judge_first"]),
        default=None,
        help="Detection strategy.",
    )
    @click.option(
        "--rule-pack",
        type=click.Choice(["default", "strict", "permissive"]),
        default=None,
        help="Guardrail rule-pack profile.",
    )
    @click.option(
        "--rule-pack-dir",
        default=None,
        help=(
            "Custom rule-pack directory (free-text path; CLI parity with the "
            'TUI). Mutually exclusive with --rule-pack; pass "" to clear.'
        ),
    )
    @click.option("--judge-model", default=None, help="LLM judge model.")
    @click.option("--judge-api-base", default=None, help="LLM judge API base URL.")
    @click.option("--judge-api-key-env", default=None, help="Env var name for judge API key.")
    @click.option("--human-approval/--no-human-approval", default=None, help="Enable or disable human approval.")
    @click.option(
        "--hilt-min-severity",
        type=click.Choice(_HILT_MIN_SEVERITIES, case_sensitive=False),
        default=None,
        help="Minimum severity that asks for human approval.",
    )
    @click.option("--restart/--no-restart", default=True, show_default=True, help="Restart gateway after setup.")
    @click.option("--verify/--no-verify", default=True, show_default=True, help="Run connectivity checks after setup.")
    @pass_ctx
    def _cmd(
        app: AppContext,
        yes: bool,
        non_interactive: bool,
        guard_mode: str | None,
        scanner_mode: str | None,
        cisco_endpoint: str | None,
        cisco_api_key_env: str | None,
        cisco_timeout_ms: int | None,
        guard_port: int | None,
        block_message: str | None,
        detection_strategy: str | None,
        rule_pack: str | None,
        rule_pack_dir: str | None,
        judge_model: str | None,
        judge_api_base: str | None,
        judge_api_key_env: str | None,
        human_approval: bool | None,
        hilt_min_severity: str | None,
        restart: bool,
        verify: bool,
    ) -> None:
        _setup_guardrail_connector_alias(
            app,
            connector=connector,
            yes=yes,
            non_interactive=non_interactive,
            guard_mode=guard_mode,
            scanner_mode=scanner_mode,
            cisco_endpoint=cisco_endpoint,
            cisco_api_key_env=cisco_api_key_env,
            cisco_timeout_ms=cisco_timeout_ms,
            guard_port=guard_port,
            block_message=block_message,
            detection_strategy=detection_strategy,
            rule_pack=rule_pack,
            rule_pack_dir=rule_pack_dir,
            judge_model=judge_model,
            judge_api_base=judge_api_base,
            judge_api_key_env=judge_api_key_env,
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
            restart=restart,
            verify=verify,
        )

    _cmd.__name__ = f"setup_{connector}"
    return _cmd


for _guardrail_connector in ("openclaw", "zeptoclaw"):
    setup.add_command(_make_guardrail_connector_setup_command(_guardrail_connector))


@setup.command("notifications")
@click.argument(
    "action",
    type=click.Choice(("on", "off", "status"), case_sensitive=False),
    required=False,
)
@click.option(
    "--yes",
    "-y",
    "yes",
    is_flag=True,
    help=(
        "Skip the interactive confirmation prompt and accept the "
        "default answer. Required for non-TTY callers (CI, scripts, "
        "TUI shell-outs); without it the command may hang waiting "
        "on stdin when invoked without an explicit on/off/status "
        "argument."
    ),
)
@click.option(
    "--restart/--no-restart",
    default=True,
    show_default=True,
    help=(
        "Restart defenseclaw-gateway after toggling. The notification "
        "dispatcher is built once at sidecar boot from "
        "``notifications.*`` so a flip without restart leaves the "
        "previous state in effect for the running process. Use "
        "``--no-restart`` only when the sidecar is offline; the "
        "``setup`` group's auto-restart hook will not double-bounce "
        "the gateway because this command marks the restart as "
        "handled."
    ),
)
@pass_ctx
def setup_notifications(
    app: AppContext,
    action: str | None,
    yes: bool,
    restart: bool,
) -> None:
    """Toggle user-session desktop notifications for blocks and HITL approvals.

    \b
    DefenseClaw can surface a desktop notification whenever a hook,
    guardrail verdict, or asset policy blocks a tool call, or when a
    Human-in-the-Loop approval is pending in the chat / TUI. The
    notification is informational only — clicking it does not approve
    or deny anything; the operator still replies in the existing
    chat/CLI surface.
    \b
    With no argument this command is a one-shot Y/n onboarding
    prompt:
    \b
      Show desktop notifications for blocks and approval requests? [Y/n]
    \b
    Use ``on`` / ``off`` to flip ``notifications.enabled`` directly,
    and ``status`` to print the resolved configuration without
    mutating it.
    \b
    Examples:
      defenseclaw setup notifications
      defenseclaw setup notifications on
      defenseclaw setup notifications off --yes
      defenseclaw setup notifications status
    """
    cfg = app.cfg
    nc = cfg.notifications
    current = bool(nc.enabled)
    capability = desktop_notification_capability()

    normalized = action.strip().lower() if action else None

    if normalized == "status":
        ux.section("Notifications state")
        click.echo(f"    {ux.dim('configured (notifications.enabled):')} {'ON' if current else 'OFF'}")
        effective = capability.effective_enabled(current)
        click.echo(f"    {ux.dim('native desktop delivery:')} {'ACTIVE' if effective else 'INACTIVE'}")
        if not capability.supported:
            click.echo(f"    {ux.dim('capability:')} UNSUPPORTED — {capability.unsupported_reason}")
            if current:
                click.echo("    Legacy configured ON is retained, but native desktop delivery is not active.")
            click.echo("    Delivery failures use a labelled terminal fallback; they are never desktop success.")
        click.echo(f"    {ux.dim('block_enforced:')} {'on' if nc.block_enforced else 'off'}")
        click.echo(f"    {ux.dim('block_would_block:')} {'on' if nc.block_would_block else 'off'}")
        click.echo(f"    {ux.dim('hitl_approval:')} {'on' if nc.hitl_approval else 'off'}")
        click.echo(f"    {ux.dim('sources.hook:')} {'on' if nc.sources.hook else 'off'}")
        click.echo(f"    {ux.dim('sources.guardrail:')} {'on' if nc.sources.guardrail else 'off'}")
        click.echo(f"    {ux.dim('sources.asset_policy:')} {'on' if nc.sources.asset_policy else 'off'}")
        click.echo(f"    {ux.dim('dedup_window:')} {nc.dedup_window or '30s'}")
        click.echo(f"    {ux.dim('max_per_minute:')} {nc.max_per_minute}")
        return

    if not capability.supported and normalized != "off":
        raise click.ClickException(capability.unsupported_reason)

    if normalized in ("on", "off"):
        desired = normalized == "on"
    else:
        # No explicit action -> interactive Y/n onboarding prompt.
        # ``--yes`` short-circuits to the prompt's default (True).
        if yes:
            desired = True
        else:
            desired = click.confirm(
                "  Show desktop notifications for blocks and approval requests?",
                default=True,
            )

    if desired == current:
        state = "ON" if current else "OFF"
        click.echo(f"  • Notifications are already {state}; nothing to change.")
        return

    nc.enabled = desired

    try:
        cfg.save()
    except OSError as exc:
        nc.enabled = current
        ux.err(f"Failed to save config: {exc}")
        raise click.ClickException("config save failed") from exc

    ux.ok(f"notifications.enabled set to {desired!s} ({'ON' if desired else 'OFF'})")

    if restart:
        ux.subhead("Restarting gateway so the notification dispatcher picks up the new state...")
        # _restart_defense_gateway sets the per-context "restart
        # already handled" flag, so the setup group's
        # _auto_restart_sidecar_after_setup result callback won't
        # bounce the gateway a second time after this one returns.
        _restart_services(
            cfg.data_dir,
            cfg.gateway.host,
            cfg.gateway.port,
            connector=cfg.active_connector(),
            connectors=cfg.active_connectors(),
        )
    else:
        # Operator opted out of the restart explicitly; suppress the
        # group-level auto-restart hook too so the operator sees one
        # consistent "do it yourself" message instead of the hook
        # contradicting us by bouncing the gateway anyway.
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True
        ux.warn(
            "Skipped restart (--no-restart). The running sidecar still "
            "uses the previous notification state. Restart manually:"
        )
        ux.subhead("   defenseclaw-gateway restart")

    _log_setup_action(
        app,
        ACTION_SETUP_NOTIFICATIONS_TOGGLE,
        f"enabled={desired!s}",
        allow_offline=not restart,
    )


# ``setup notifications`` is already a one-shot command (action is a
# positional argument, not a subgroup) so we can't attach
# ``set <key> <value>`` to it without breaking the existing
# ``defenseclaw setup notifications on`` form. A flat sibling command
# keeps the new surface discoverable (``setup --help`` lists it next
# to ``notifications``) and avoids click's argument-vs-subcommand
# parsing ambiguity.
_NOTIFICATION_SLOTS: dict[str, tuple[str, str]] = {
    # slot name (operator-typed)  ->  (object_path, attr)
    # Categories (event types) live on the NotificationsConfig itself.
    "block_enforced": ("", "block_enforced"),
    "block_would_block": ("", "block_would_block"),
    "hitl_approval": ("", "hitl_approval"),
    # Sources live on the nested NotificationSourceFilter struct.
    "sources.hook": ("sources", "hook"),
    "sources.guardrail": ("sources", "guardrail"),
    "sources.asset_policy": ("sources", "asset_policy"),
    # Friendlier short forms for the source toggles. Keep both so
    # ``--help`` callers and operators copying from ``status`` output
    # land on a working invocation either way.
    "hook": ("sources", "hook"),
    "guardrail": ("sources", "guardrail"),
    "asset_policy": ("sources", "asset_policy"),
}


@setup.command("notifications-set")
@click.argument(
    "slot",
    type=click.Choice(sorted(set(_NOTIFICATION_SLOTS.keys())), case_sensitive=False),
)
@click.argument(
    "value",
    type=click.Choice(("on", "off"), case_sensitive=False),
)
@click.option(
    "--restart/--no-restart",
    default=True,
    show_default=True,
    help=(
        "Restart defenseclaw-gateway after the toggle. The notifier "
        "dispatcher reads its filters at sidecar boot, so a flip "
        "without restart leaves the running process on the previous "
        "filter set."
    ),
)
@pass_ctx
def setup_notifications_set(
    app: AppContext,
    slot: str,
    value: str,
    restart: bool,
) -> None:
    """Toggle a single notifications category or source.

    ``slot`` is one of the dotted paths below; ``value`` is ``on`` or
    ``off``. The master switch (``notifications.enabled``) is left
    alone — use ``defenseclaw setup notifications on/off`` for that.

    \b
    Categories (event types):
      block_enforced       Real blocks (default: on).
      block_would_block    Observe-mode would-block / would-ask toasts (default: off).
      hitl_approval        Human-in-the-loop prompts (default: on).

    \b
    Sources (subsystem of origin):
      sources.hook         Per-tool hooks (claude_code / codex / ...).
      sources.guardrail    Guardrail verdicts.
      sources.asset_policy Skill / MCP allow-list blocks.

    \b
    Examples:
      defenseclaw setup notifications-set sources.hook off
      defenseclaw setup notifications-set hitl_approval on --no-restart
      defenseclaw setup notifications-set guardrail off  # short form
    """
    cfg = app.cfg
    nc = cfg.notifications

    obj_path, attr = _NOTIFICATION_SLOTS[slot.lower()]
    target = nc if not obj_path else getattr(nc, obj_path)
    current = bool(getattr(target, attr))
    desired = value.lower() == "on"

    if current == desired:
        ux.subhead(
            f"notifications.{slot} already {value.lower()}; nothing to change.",
        )
        return

    setattr(target, attr, desired)
    try:
        cfg.save()
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}")
        raise click.ClickException("config save failed") from exc

    ux.ok(f"notifications.{slot} = {value.lower()}")
    if not nc.enabled:
        # The dispatcher checks the master switch first, so flipping a
        # sub-toggle with the master OFF is harmless but invisible —
        # surface that so operators don't think their change had no
        # effect.
        ux.warn(
            "notifications.enabled is OFF — this toggle won't have any "
            "user-visible effect until you run "
            "`defenseclaw setup notifications on`.",
        )

    if restart:
        ux.subhead("Restarting gateway so the dispatcher picks up the new filter…")
        _restart_services(
            cfg.data_dir,
            cfg.gateway.host,
            cfg.gateway.port,
            connector=cfg.active_connector(),
            connectors=cfg.active_connectors(),
        )
    else:
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True
        ux.subhead(
            "Skipped restart (--no-restart). Run `defenseclaw-gateway restart` when ready.",
        )

    _log_setup_action(
        app,
        ACTION_SETUP_NOTIFICATIONS_SET,
        f"slot={slot} value={value.lower()}",
        allow_offline=not restart,
    )


# ``setup registry`` — discoverable shortcut that drops the operator
# straight into the registry wizard. The full ``defenseclaw registry``
# group remains the canonical surface for non-onboarding flows
# (``add`` / ``edit`` / ``sync`` / ...); this wrapper exists so a
# first-time operator working through ``defenseclaw setup --help``
# doesn't have to know that registries live in their own top-level
# group.
@setup.command("registry")
@click.pass_context
def setup_registry(ctx: click.Context) -> None:
    """Register an external skill / MCP catalog (interactive wizard).

    Wraps ``defenseclaw registry wizard`` so first-run operators
    discover the registry feature inside ``defenseclaw setup --help``.
    For non-interactive usage and the full subcommand surface
    (``add`` / ``edit`` / ``sync`` / ``approve`` / ``reject`` /
    ``test`` / ``list`` / ``show`` / ``remove`` / ``require``), use
    the top-level ``defenseclaw registry`` group directly.
    """
    # Lazy import to avoid pulling the registry HTTP / YAML deps into
    # setup commands that don't need them, and to dodge a potential
    # circular import (cmd_registry imports config -> ... -> setup
    # in some lint configurations).
    from defenseclaw.commands.cmd_registry import wizard_cmd

    return ctx.invoke(wizard_cmd)


def execute_guardrail_setup(
    app: AppContext,
    *,
    save_config: bool = True,
    workspace_dir: str | None = None,
) -> tuple[bool, list[str]]:
    """Run guardrail setup steps.

    Returns (success, warnings).  When *save_config* is False the caller
    is responsible for calling ``app.cfg.save()`` (used by ``init`` which
    saves once at the end).

    All connector-specific setup (plugin install, config patching, hook
    scripts, subprocess shims/sandbox) is handled by the Go gateway's
    ``Connector.Setup()`` at sidecar startup. This function only persists
    the Python-side config; config.yaml is the sole runtime source.
    """
    gc = app.cfg.guardrail
    warnings: list[str] = []
    connector_name = gc.connector or "openclaw"
    if connector_name in _CONNECTOR_NAMES:
        app.cfg.claw.mode = connector_name
    workspace = _configure_connector_workspace(app.cfg, workspace_dir)

    click.echo()

    def _tool_display(m: dict) -> str:
        tool_mode = m["tool_mode"]
        return "pre-execution + response-scan" if tool_mode == "both" else tool_mode

    actives = list(app.cfg.active_connectors()) if hasattr(app.cfg, "active_connectors") else [connector_name]
    if len(actives) > 1:
        # All connectors are peers — confirm every one rather than singling
        # out a primary. (claw.mode above is only a back-compat mirror.)
        ux.ok(f"Connectors: {', '.join(actives)}")
        for c in actives:
            m = _CONNECTOR_META.get(c, {})
            if m:
                ux.ok(f"  [{c}] tool inspection: {_tool_display(m)}; subprocess policy: {m['subprocess_policy']}")
            else:
                ux.ok(f"  [{c}] plugin connector")
    else:
        meta = _CONNECTOR_META.get(connector_name, {})
        if meta:
            ux.ok(f"Connector: {meta.get('label', connector_name)} ({connector_name})")
            ux.ok(f"Tool inspection: {_tool_display(meta)}")
            ux.ok(f"Subprocess policy: {meta['subprocess_policy']}")
        else:
            ux.ok(f"Connector: {connector_name} (plugin)")

    ux.ok("Connector setup will run automatically when the gateway starts")
    if workspace:
        ux.ok(f"Workspace root pinned: {workspace}")
    else:
        ux.ok("Scope: global user config (no workspace pinned)")

    # --- Save DefenseClaw config ---
    if save_config:
        try:
            app.cfg.save()
            ux.ok("Config saved to ~/.defenseclaw/config.yaml")
        except OSError as exc:
            ux.err(f"Failed to save config: {exc}")
            warnings.append("Config not saved — settings will be lost on next run")

    # --- Mirror HILT into the OPA Rego data file ---
    # The prompt-side guardrail verdict is computed by Rego, which reads
    # `hilt.enabled` from policies/rego/data.json — NOT from config.yaml.
    # Keeping the wizard's `gc.hilt` in sync with that file is what makes
    # `confirm` actually surface on HIGH-severity prompt findings.
    _sync_guardrail_hilt_to_opa(app.cfg.policy_dir, gc)

    return True, warnings


def _prompt_hook_fail_mode(gc) -> None:
    """Interactive prompt that sets ``gc.hook_fail_mode`` to "open" or
    "closed" based on operator input.

    Centralized so every entry point (initial setup, mode change,
    observability-only flow) emits the same wording and the same
    default-selection rule. The current value drives the default so
    operators who answer the prompt in past invocations don't have
    their explicit choice silently rotated by a subsequent mode flip.
    """
    ux.section("Hook fail mode")
    ux.subhead("How hooks behave when delivery/authentication fails or")
    ux.subhead("the gateway returns 4xx, malformed JSON, or no action.")
    click.echo()
    click.echo(
        "    " + ux.bold("[1] open  ") + " — allow the tool/prompt and log the failure " + ux.dim("(recommended)")
    )
    click.echo("                 " + ux.dim("A misbehaving gateway won't brick your agent."))
    click.echo("    " + ux.bold("[2] closed") + " — block supported events when inspection is unavailable")
    click.echo("                 " + ux.dim("Choose for regulated workflows where every"))
    click.echo("                 " + ux.dim("prompt MUST be inspected."))
    click.echo()
    click.echo(
        "  "
        + ux.dim(
            "Note: DEFENSECLAW_STRICT_AVAILABILITY=1 additionally forces "
            "transport and missing-token failures closed, even when this "
            "choice is open."
        )
    )
    current_fail = (getattr(gc, "hook_fail_mode", "") or "open").lower()
    fail_default = "2" if current_fail == "closed" else "1"
    fail_choice = click.prompt(
        "  Select hook fail mode",
        type=click.Choice(["1", "2"]),
        default=fail_default,
    )
    gc.hook_fail_mode = "open" if fail_choice == "1" else "closed"


def _apply_judge_runtime_defaults(gc) -> None:
    gc.judge.injection = True
    gc.judge.pii = True
    gc.judge.pii_prompt = True
    gc.judge.pii_completion = True
    # Data-exfiltration judge runs alongside injection + PII on every prompt.
    gc.judge.exfil = True
    # Completion-side strategy defaults to regex_only (no judge latency).
    if not getattr(gc, "detection_strategy_completion", None):
        gc.detection_strategy_completion = "regex_only"


def _prompt_judge_model_config(
    app: AppContext,
    gc,
    *,
    _pending_secrets: list[_PendingGuardrailSecret] | None = None,
) -> None:
    """Prompt for judge LLM details using the same model UX across setup flows."""
    ux.subhead("These LLM settings are shared by all connectors with judge enabled.")

    # V5 UX: when the operator has already configured the unified top-level
    # ``llm:`` block, default the judge to INHERIT those values. Empty judge
    # fields fall through ``Config.resolve_llm("guardrail.judge")`` to the
    # top-level block and pick up ``DEFENSECLAW_LLM_KEY`` automatically.
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
        click.echo(f"    api key:     {top_llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV} (inherited)")
        click.echo()
        inherit_unified = click.confirm(
            "  Inherit the unified LLM for the judge?",
            default=True,
        )

    if inherit_unified:
        gc.judge.model = ""
        gc.judge.api_base = ""
        gc.judge.api_key_env = ""
        click.echo(f"  ✓ Judge will use {top_llm.model} via {top_llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV}.")
    else:
        # Pre-fill each prompt from the top-level ``llm:`` block so operators
        # who want to override only have to retype the fields they're changing.
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

        default_key_env = gc.judge.api_key_env or top_llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV
        gc.judge.api_key_env = click.prompt(
            "  API key env var name",
            default=default_key_env,
        )
        env_val = os.environ.get(gc.judge.api_key_env, "")
        if env_val:
            click.echo(f"    Current value: {_mask(env_val)} (set)")
        else:
            click.echo(f"    {gc.judge.api_key_env} is not set in environment")

        # Only prompt for a secret value when the operator picked a custom env
        # var that is not already satisfied by the unified key.
        unified_env = top_llm.api_key_env or DEFENSECLAW_LLM_KEY_ENV
        if gc.judge.api_key_env != unified_env or not env_val:
            _prompt_and_save_secret(
                gc.judge.api_key_env,
                "",
                app.cfg.data_dir,
                _pending_secrets=_pending_secrets,
            )

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

    _apply_judge_runtime_defaults(gc)

    # Share a custom judge key into the v5 top-level LLM block only when that
    # block is otherwise unset, matching the guardrail wizard's existing rule.
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


def _interactive_guardrail_setup(
    app: AppContext,
    gc,
    *,
    agent_name: str | None = None,
    _pre_mutation_selection=None,
    _pending_secrets: list[_PendingGuardrailSecret] | None = None,
) -> bool:
    # Snapshot the entry-point ``gc.enabled`` BEFORE any prompt mutates
    # it. The wizard flips ``gc.enabled = True`` after the operator
    # confirms enabling, which means by the time we reach the fail-mode
    # prompt block below the live value no longer tells us whether we
    # are configuring this guardrail for the first time. Without this
    # snapshot the previous ``not bool(gc.mode)`` heuristic was dead
    # code (mode defaults to "observe", never empty) and a fresh-install
    # operator who accepted the default observe mode would never be
    # asked about hook_fail_mode — directly contradicting the
    # operator-defined fail-mode contract.
    was_initial_setup = not bool(gc.enabled)

    ux.section("LLM Guardrail Setup")
    click.echo()
    click.echo("  " + ux.bold("Scans every LLM prompt and response for:"))
    click.echo("    • " + ux.dim("Prompt injection and jailbreak attempts"))
    click.echo("    • " + ux.dim("Secrets, API keys, and credentials"))
    click.echo("    • " + ux.dim("PII leakage (names, emails, SSNs, credit cards)"))
    click.echo(
        "    • "
        + ux.dim("Data exfiltration: credential-file reads (/etc/passwd, ~/.ssh, ~/.aws), out-of-band channels")
    )
    click.echo()

    # --- Step 0: Connector selection ---
    #
    # The singular "which agent framework?" picker only makes sense at
    # bootstrap (nothing configured yet). Once one or more connectors are
    # active, this command edits PROCESS-GLOBAL guardrail policy (rule
    # pack, HILT, scanner, judge, redaction) that applies to ALL of them,
    # so re-asking a single-connector question is misleading — picking one
    # would only re-point the back-compat primary pointer, not reconfigure
    # the fleet. We therefore run the picker only when nothing is
    # configured AND the operator didn't pass an explicit --connector/
    # --agent override. Connector add/switch stays the job of
    # `setup <connector>`.
    #
    # ``was_initial_setup`` (sampled above, before gc.enabled is flipped)
    # guards the openclaw-default bootstrap: a default "openclaw" with the
    # guardrail never enabled is NOT a real configuration, so the first-
    # ever run still shows the picker.
    configured = _configured_connector_set(gc)
    active_connectors = [] if was_initial_setup else configured
    is_multi = len(active_connectors) >= 2
    if agent_name and agent_name in _CONNECTOR_META:
        if _pre_mutation_selection is not None:
            _pre_mutation_selection((agent_name,))
        gc.connector = agent_name
        click.echo()
        _print_connector_info(gc.connector)
        click.echo()
    elif active_connectors:
        if _pre_mutation_selection is not None:
            _pre_mutation_selection(tuple(active_connectors))
        # Global-policy edit across the existing fleet — skip the picker
        # and leave the current primary pointer untouched.
        names = ", ".join(active_connectors)
        click.echo()
        click.echo(
            "  "
            + ux.dim(f"Editing global guardrail policy for {len(active_connectors)} configured connector(s): {names}.")
        )
        # Only steer toward per-connector mode when there's genuinely more
        # than one connector — a single active connector still gets the
        # (meaningful, unambiguous) observe/action prompt below, so the
        # guidance would otherwise contradict the prompt we're about to show.
        if is_multi:
            click.echo(
                "  "
                + ux.dim(
                    "Per-connector enforcement mode is managed via "
                    "`defenseclaw setup <connector> --mode observe|action`."
                )
            )
        click.echo()
    else:
        selected_connector = _select_connector_interactive(
            gc.connector or "openclaw",
            data_dir=getattr(app.cfg, "data_dir", None),
        )
        if _pre_mutation_selection is not None:
            _pre_mutation_selection((selected_connector,))
        gc.connector = selected_connector
        click.echo()
        _print_connector_info(gc.connector)
        click.echo()

    # Codex and Claude Code are hook-enforced — they go through the
    # same mode-prompt flow as the other hook connectors below. The
    # earlier "observability-only vs. guardrail proxy" fork has been
    # retired with the proxy data path; the only remaining question
    # is observe vs. action, which the standard mode prompt asks.

    model_name = gc.model_name or gc.model or ""
    if model_name:
        click.echo(f"  Detected LLM:  {model_name}")
    proxy_port = gc.port or 4000
    if gc.connector in _HOOK_ENFORCED_CONNECTORS:
        # Reach into ``cfg.gateway`` defensively — the wizard is also
        # exercised by tests against a SimpleNamespace cfg that may
        # not carry the gateway sub-config. Falling back to the
        # canonical default (18970) keeps the message accurate
        # everywhere it is rendered.
        gateway_cfg = getattr(app.cfg, "gateway", None)
        api_port = getattr(gateway_cfg, "api_port", 18970) if gateway_cfg else 18970
        click.echo(
            f"  API port:      {api_port} "
            "(hook endpoint — PreToolUse deny is the enforcement surface; "
            "no LLM proxy binding)"
        )
    else:
        click.echo(f"  Proxy port:    {proxy_port} (traffic rerouted automatically)")
    click.echo()

    if not click.confirm("  Enable guardrail?", default=True):
        gc.enabled = False
        return False

    gc.enabled = True

    if is_multi:
        # Per-connector mode is the source of truth in multi-connector mode;
        # ask once across the active set instead of writing the legacy global
        # gc.mode. When --connector scoped this guardrail run, only that peer is
        # offered here; bare setup guardrail covers the full active set.
        mode_targets = [agent_name] if agent_name and agent_name in active_connectors else list(active_connectors)
        connector_modes = _prompt_batch_connector_modes(
            mode_targets,
            gc,
            default_mode=None,
        )
        mode_changed = _write_per_connector_modes(gc, connector_modes)
    else:
        ux.section("Enforcement mode")
        ux.subhead("Rule/regex scanning applies in both modes.")
        click.echo(
            "    "
            + ux.bold("[1] observe")
            + " — scan and report findings, never block "
            + ux.dim("(recommended to start)")
        )
        click.echo("    " + ux.bold("[2] action ") + " — scan and block/confirm when policy requires")
        current_mode = gc.mode or "observe"
        mode_default = "1" if current_mode == "observe" else "2"
        mode_choice = click.prompt(
            "  Select mode",
            type=click.Choice(["1", "2"]),
            default=mode_default,
        )
        new_mode = "observe" if mode_choice == "1" else "action"
        mode_changed = new_mode != current_mode
        gc.mode = new_mode

    # Hook fail-mode prompt. Asked on initial setup OR when the
    # operator just flipped between observe and action — those are
    # the moments where the operator is actively making policy-
    # posture decisions and most likely to want to revisit the
    # delivery/response fallback. Otherwise we leave the existing value
    # alone (operator can change it later via
    # `defenseclaw guardrail fail-mode <open|closed>`).
    #
    # ``was_initial_setup`` is sampled at the very top of this function
    # (snapshot of ``gc.enabled`` before the wizard flips it true) — we
    # cannot use the live ``gc.mode`` value here because the dataclass
    # default is "observe" rather than empty, which made the previous
    # detection dead code on every realistic fresh install.
    if was_initial_setup or mode_changed:
        _prompt_hook_fail_mode(gc)

    # Human-In-the-Loop (HILT). Hoisted out of the "Configure
    # advanced options?" branch so operators see the question on
    # every guardrail setup that *can* fire approvals — i.e.,
    # action mode. The previous wiring buried HILT under an opt-in
    # "advanced" gate (default N), which meant first-time users
    # who walked through the wizard never got asked unless they
    # already knew HILT existed and discovered it from docs.
    #
    # Skipped when ``gc.mode == "observe"``: HILT only fires in
    # action mode, so prompting in observe mode is just noise that
    # misleads operators about what their answer does. Their
    # previously-saved ``gc.hilt`` block stays intact for the day
    # they later flip to action via this same wizard or via
    # ``defenseclaw setup <connector> --mode action``.
    #
    # ``_configure_hilt_interactive`` itself emits the
    # action-mode-only short-circuit message when called outside
    # action mode — but we deliberately avoid calling it for
    # observe so the wizard stays terse for the (common) observe-
    # mode operator. The verbose "this is action-only" message
    # was useful when the call lived under "Advanced options" and
    # the operator had explicitly opted in; here, asking and
    # immediately printing "never mind" would feel like a bug.
    # HILT (human approval) is process-global but only fires for
    # action-mode connectors. In multi-connector mode the singular
    # gc.mode is just a back-compat default, so gate on whether ANY
    # configured connector resolves to action mode; otherwise fall back
    # to the singular mode for the bootstrap/single-connector path.
    if is_multi:
        hilt_action_connectors = [c for c in active_connectors if (gc.effective_mode(c) or "").strip() == "action"]
        hilt_applicable = bool(hilt_action_connectors)
    else:
        hilt_action_connectors = None
        hilt_applicable = gc.mode == "action"
    if hilt_applicable:
        _configure_hilt_interactive(gc, action_connectors=hilt_action_connectors)

    ux.section("Scanner engine")
    click.echo(
        "    " + ux.bold("[1] local ") + "  — built-in pattern matching, no network calls " + ux.dim("(fastest)")
    )
    click.echo(
        "    "
        + ux.bold("[2] remote")
        + "  — Cisco AI Defense cloud API "
        + ux.dim("(higher accuracy, requires API key)")
    )
    sm_current = gc.scanner_mode or "local"
    if sm_current == "both":
        sm_current = "local"
    sm_default = "1" if sm_current == "local" else "2"
    sm_choice = click.prompt(
        "  Select engine",
        type=click.Choice(["1", "2"]),
        default=sm_default,
    )
    gc.scanner_mode = "local" if sm_choice == "1" else "remote"

    if gc.scanner_mode in ("remote", "both"):
        ux.section("Cisco AI Defense Configuration")
        aid = app.cfg.cisco_ai_defense
        aid.endpoint = click.prompt(
            "  API endpoint",
            default=aid.endpoint,
        )
        cisco_key_env = aid.api_key_env or "CISCO_AI_DEFENSE_API_KEY"
        env_val = os.environ.get(cisco_key_env, "")
        if env_val:
            click.echo(f"  API key env var: {cisco_key_env} ({_mask(env_val)})")
        else:
            click.echo(f"  API key env var: {cisco_key_env} (not set)")
            click.echo(f"    Set it before starting: export {cisco_key_env}=your-key")
        aid.api_key_env = click.prompt(
            "  API key env var name",
            default=cisco_key_env,
        )
        aid.timeout_ms = click.prompt(
            "  Timeout (ms)",
            default=aid.timeout_ms,
            type=int,
        )

    gc.port = proxy_port

    # --- LLM Judge section ---
    #
    # The judge is a gateway-side verification layer that runs on
    # inspectable payloads. Proxy connectors can still opt in here directly;
    # hook connectors only see judge choices for connectors currently in action
    # mode, so the wizard does not imply observe-mode judge enforcement.
    ux.section("Optional LLM judge")
    ux.subhead("Uses an LLM to verify detections and catch novel attacks.")
    ux.subhead("Works with any OpenAI-compatible API (Bifrost, OpenAI, Anthropic, etc.)")
    click.echo()
    click.echo("  " + ux.bold("Three judge kinds run on every prompt when enabled:"))
    click.echo("    • " + ux.dim("injection — overrides / jailbreaks (kind=injection)"))
    click.echo("    • " + ux.dim("pii       — names, emails, SSNs, secrets (kind=pii)"))
    click.echo("    • " + ux.dim("exfil     — credential-file reads & out-of-band channels (kind=exfil)"))
    click.echo("  " + ux.dim("Tool calls additionally run the tool_injection judge."))
    click.echo()

    hook_judge_scope = [
        c for c in (mode_targets if is_multi else [gc.connector or "openclaw"]) if c in _HOOK_ENFORCED_CONNECTORS
    ]
    judge_targets = [
        c for c in hook_judge_scope if (gc.effective_mode(c) if hasattr(gc, "effective_mode") else gc.mode) == "action"
    ]

    if hook_judge_scope and not judge_targets:
        _prune_judge_gate_to_action_scope(gc, hook_judge_scope)
        click.echo("  " + ux.dim("LLM judge: skipped because no selected connector is in action mode."))
    else:
        judge_kwargs = {"preserve_outside_targets": True} if agent_name and is_multi else {}
        _prompt_guardrail_judge_enablement(gc, judge_targets, **judge_kwargs)
    if not getattr(gc, "detection_strategy", None):
        gc.detection_strategy = "regex_only"
    if not getattr(gc, "detection_strategy_completion", None):
        gc.detection_strategy_completion = "regex_only"
    if gc.judge.enabled:
        if not getattr(gc, "detection_strategy_completion", None):
            gc.detection_strategy_completion = "regex_only"

        # Connector-aware LLM role branching.
        #
        # Hook-based connectors (Codex, Claude Code, …) keep their own
        # agent LLM — DefenseClaw only uses an LLM for the judge. Proxy-
        # backed connectors (OpenClaw, ZeptoClaw) can either share one
        # LLM for judge + agent or split them. We surface the decision
        # here so saved configs declare intent rather than relying on
        # implicit defaults.
        default_role = gc.llm_role or connector_llm_role(gc.connector or "")
        if connector_llm_role(gc.connector or "") == "judge_only":
            click.echo(
                "  "
                + ux.dim(
                    "This connector uses its own LLM — DefenseClaw will use the LLM "
                    "you configure here only for the judge."
                )
            )
            gc.llm_role = "judge_only"
        else:
            click.echo("  " + ux.bold("How should DefenseClaw use the LLM?"))
            click.echo(
                "    "
                + ux.bold("[1] Judge only          ")
                + ux.dim("— keep your existing agent LLM, use DefenseClaw only for the judge")
            )
            click.echo(
                "    "
                + ux.bold("[2] Judge AND agent     ")
                + ux.dim("— route the agent's LLM through DefenseClaw too (recommended)")
            )
            role_default = "2" if default_role == "judge_and_agent" else "1"
            role_choice = click.prompt(
                "  Select role",
                type=click.Choice(["1", "2"]),
                default=role_default,
            )
            gc.llm_role = "judge_only" if role_choice == "1" else "judge_and_agent"
            click.echo()

        _apply_judge_runtime_defaults(gc)
        click.echo()
        _prompt_judge_model_config(
            app,
            gc,
            _pending_secrets=_pending_secrets,
        )

    if bool(gc.judge.enabled):
        click.echo()

    if click.confirm("  Configure advanced options?", default=False):
        gc.port = click.prompt("  Guardrail proxy port", default=gc.port, type=int)
        if gc.mode == "action":
            click.echo()
            if gc.block_message:
                preview = gc.block_message[:80] + ("..." if len(gc.block_message) > 80 else "")
                click.echo(f'  Current block message: "{preview}"')
            else:
                click.echo('  Default block message: "I\'m unable to process this request. DefenseClaw detected..."')
            if click.confirm("  Use a custom block message?", default=bool(gc.block_message)):
                gc.block_message = click.prompt("  Block message", default=gc.block_message or "")
            else:
                gc.block_message = ""
        # NOTE: HILT was previously asked here. As of the
        # always-ask-when-action change it lives inline in
        # ``_interactive_guardrail_setup`` right after the hook
        # fail-mode prompt, so we don't double-prompt under
        # advanced. Operators who want to revisit HILT specifically
        # can re-run ``defenseclaw setup guardrail`` (no flag
        # needed) and walk through to the action-mode block.

    return True


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
        app.logger.log_action(ACTION_SETUP_GUARDRAIL, "config", f"disabled connector={connector_name}")


def _sync_guardrail_hilt_to_opa(policy_dir: str, gc) -> None:
    """Mirror ``gc.hilt`` into the OPA Rego data.json the gateway evaluates.

    NOTE (architecture): As of the input.hilt SSOT change, the Go gateway
    now passes ``cfg.Guardrail.HILT`` directly into ``policy.GuardrailInput``
    so the Rego policy reads ``input.hilt.{enabled,min_severity}`` and
    ``config.yaml`` is the single source of truth for the gateway path.
    See ``internal/gateway/guardrail.go`` (``SetHILTConfig`` / ``hiltInput``)
    and ``policies/rego/guardrail.rego`` (``_hilt := input.hilt if {...}
    else := object.get(data.guardrail, "hilt", {})``).

    This helper is now a **fallback** that keeps non-gateway callers
    (direct ``opa eval`` invocations, integration tests that build a
    ``GuardrailInput`` without HILT, third-party tooling) consistent with
    the wizard's view of HILT. The gateway no longer DEPENDS on it for
    correctness, but mirroring the value here costs nothing and avoids
    confusing operators who introspect ``data.json`` directly.

    The HILT toggle has two consumers:

    1. The Go inspector reads ``cfg.Guardrail.HILT`` from ``config.yaml``
       and injects it into the Rego ``input`` (the gateway path — primary).
    2. The Rego ``defenseclaw.guardrail`` policy falls back to
       ``data.guardrail.hilt`` from ``policies/rego/data.json`` when the
       caller does not populate ``input.hilt`` (legacy / test path).

    Operator-facing wizards (``defenseclaw init``, ``defenseclaw setup
    guardrail``) persist (1) via ``config.yaml`` and mirror to (2) via
    this helper as defense-in-depth. The helper is intentionally narrow:
    it ONLY mirrors the ``guardrail.hilt`` block, leaving thresholds,
    patterns, severity_mappings, etc. owned by ``defenseclaw policy
    activate`` (which calls ``_sync_opa_data`` in ``cmd_policy``). That
    keeps the wizard from accidentally clobbering activated-policy state.
    """
    import json

    if gc is None or getattr(gc, "hilt", None) is None:
        return

    data_json = os.path.join(policy_dir, "rego", "data.json")
    if not os.path.isfile(data_json):
        return

    try:
        with open(data_json) as f:
            opa_data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        click.echo(f"  ⚠ Failed to read {data_json}: {exc}")
        return

    desired = {
        "enabled": bool(gc.hilt.enabled),
        "min_severity": (gc.hilt.min_severity or "HIGH").upper(),
    }
    guardrail_block = opa_data.setdefault("guardrail", {})
    if guardrail_block.get("hilt") == desired:
        return

    guardrail_block["hilt"] = desired
    try:
        with open(data_json, "w") as f:
            json.dump(opa_data, f, indent=2)
            f.write("\n")
        click.echo(f"  ✓ HILT synced to OPA: enabled={desired['enabled']} min_severity={desired['min_severity']}")
    except OSError as exc:
        click.echo(f"  ⚠ Failed to write {data_json}: {exc}")


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
    """Check whether the process recorded in ``pid_file`` is alive.

    Delegates to :func:`defenseclaw.process_liveness.pid_file_alive`, which
    probes liveness correctly on every OS. The previous inline
    ``os.kill(pid, 0)`` check reported a live gateway as dead on Windows
    (signal 0 is not a liveness probe there), which made
    ``setup --restart`` no-op against the running daemon.

    This predicate is observation only. A positive result never authenticates
    the recorded process or authorizes lifecycle mutation; control paths must
    independently prove gateway identity and custody.
    """
    from defenseclaw.process_liveness import pid_file_alive

    return pid_file_alive(pid_file)


def _restart_services(
    data_dir: str,
    oc_host: str = "127.0.0.1",
    oc_port: int = 18789,
    connector: str = "openclaw",
    connectors: list[str] | None = None,
    wait_for_connector_ready: bool = False,
    start_if_stopped: bool = True,
) -> None:
    """Restart defenseclaw-gateway and, when OpenClaw is the selected
    connector, restart the OpenClaw gateway too so it picks up the
    freshly-registered defenseclaw plugin. Other connectors manage
    their own processes; defenseclaw-gateway is the only process we
    always need to bounce.

    ``connector`` selects the single connector whose post-restart hint is
    shown (and, for OpenClaw, whether its own gateway is bounced). For a
    GLOBAL change on a multi-connector install (e.g. ``guardrail hilt`` with no
    ``--connector``), pass the full active set as ``connectors`` so the
    hook-bus hint names every affected connector instead of just the primary —
    the gateway restart itself is always global regardless.

    Avarice F-0142/F-0143: a failed gateway restart is fatal. We collect
    every restart failure and raise a ``ClickException`` at the end so the
    setup command exits non-zero (fail closed) instead of reporting
    success while the gateway is down and hooks fail open.

    ``start_if_stopped=False`` preserves the setup result callback's policy
    of never starting a gateway the operator deliberately stopped."""
    ux.section("Restarting services")

    # Names of services whose restart failed; non-empty ⇒ fail the command.
    failed: list[str] = []

    hook_targets = sorted(
        {
            normalize_connector(name)
            for name in ((connectors or []) if connectors else [connector])
            if name and normalize_connector(name) in _HOOK_ENFORCED_CONNECTORS
        }
    )
    connector_state_before = (
        _active_connector_state_marker(data_dir) if wait_for_connector_ready and hook_targets else None
    )
    if wait_for_connector_ready and hook_targets:
        hook_contract_lock_before, hook_contract_publications_before = _hook_contract_lock_progress_baseline(
            data_dir,
            set(hook_targets),
        )
    else:
        hook_contract_lock_before, hook_contract_publications_before = None, {}

    gateway_restarted = (
        _restart_defense_gateway(data_dir)
        if start_if_stopped
        else _restart_defense_gateway(data_dir, start_if_stopped=False)
    )
    if not gateway_restarted:
        failed.append("defenseclaw-gateway")

    connector_registration_verified = False
    connector_runtime_pending_reload = False
    if wait_for_connector_ready and hook_targets and gateway_restarted:
        readiness_label = "DefenseClaw gateway registration" if "omnigent" in hook_targets else "connector runtime"
        click.echo(f"  {readiness_label}: waiting for verified setup...", nl=False)
        readiness = _wait_for_connector_runtime(
            data_dir,
            hook_targets,
            connector_state_before,
            hook_contract_lock_before,
            previous_lock_publications=hook_contract_publications_before,
            require_gateway_health=True,
        )
        diagnostic = ": ".join(
            value
            for value in (
                getattr(readiness, "connector", ""),
                getattr(readiness, "invariant", ""),
                getattr(readiness, "detail", ""),
            )
            if value
        )
        if readiness and getattr(readiness, "invariant", "") == "pending-reload":
            connector_runtime_pending_reload = True
            click.echo(f" !{f' ({diagnostic})' if diagnostic else ''}")
        elif readiness:
            click.echo(" ✓")
            connector_registration_verified = True
        else:
            click.echo(f" ✗{f' ({diagnostic})' if diagnostic else ''}")
            failed.append(f"{readiness_label} readiness")

    # Multi-connector global change: every active hook connector is affected
    # by the gateway bounce, so enumerate them rather than naming the primary.
    hook_multi = [c for c in (connectors or []) if c in _HOOK_ENFORCED_CONNECTORS]
    if connector != "openclaw" and len(hook_multi) > 1:
        names = ", ".join(sorted(hook_multi))
        if "omnigent" in hook_multi:
            registration_state = (
                "DefenseClaw gateway registration is ready"
                if connector_registration_verified
                else "DefenseClaw gateway registration is not verified"
            )
            ux.subhead(
                f"{len(hook_multi)} hook/policy connectors ({names}): {registration_state} "
                "on the sidecar API port; OmniGent loaded policy generation "
                "remains unverified pending reload/restart. No proxy listener — each talks directly "
                "to its native upstream."
            )
        elif connector_runtime_pending_reload:
            ux.subhead(
                f"{len(hook_multi)} hook connectors ({names}): protected registrations are current "
                "on the sidecar API port; Hermes remains live=false/pending-reload until every "
                "affected Hermes host is reloaded or restarted. No proxy listener — each talks "
                "directly to its native upstream."
            )
        else:
            ux.subhead(
                f"{len(hook_multi)} hook connectors ({names}): enforcement via native "
                f"lifecycle surfaces on the sidecar API port. No proxy listener — each talks directly "
                f"to its native upstream."
            )
        click.echo()
        _fail_if_restart_failed(failed)
        return

    if connector == "openclaw":
        if not _restart_openclaw_gateway():
            failed.append("openclaw-gateway")
        _check_openclaw_gateway(oc_host, oc_port)
    elif connector in _PROXY_BACKED_CONNECTORS:
        # OpenClaw is the only proxy-backed connector that owns its own
        # gateway process; others (ZeptoClaw today) get the proxy
        # message without the separate openclaw-gateway restart step.
        ux.subhead(f"{connector} connector: traffic will route through defenseclaw-gateway proxy.")
    elif connector in _HOOK_ENFORCED_CONNECTORS:
        # No proxy listener binds for hook-only connectors — the agent
        # talks directly to its native upstream and DefenseClaw
        # observes/enforces via the hook bus on the sidecar API port.
        if connector == "omnigent":
            registration_state = (
                "DefenseClaw gateway registration is ready"
                if connector_registration_verified
                else "DefenseClaw gateway registration is not verified"
            )
            ux.subhead(
                f"omnigent connector: {registration_state} on the sidecar API port; loaded policy "
                "generation remains unverified pending OmniGent reload/restart. "
                "No proxy listener — omnigent talks directly to its native upstream."
            )
        elif connector == "hermes" and connector_runtime_pending_reload:
            ux.subhead(
                "hermes connector: protected on-disk registration is current on the sidecar API port; "
                "runtime_state=pending-reload and live=false until every affected Hermes host is "
                "reloaded or restarted. No proxy listener — hermes talks directly to its native upstream."
            )
        else:
            surface = "synchronous policy plugin" if connector == "amp" else "hook bus"
            ux.subhead(
                f"{connector} connector: enforcement via {surface} on the sidecar API port. "
                f"No proxy listener — {connector} talks directly to its native upstream."
            )

    click.echo()
    _fail_if_restart_failed(failed)


def _fail_if_restart_failed(failed: list[str]) -> None:
    """Raise a ``ClickException`` (non-zero exit) when any service restart
    failed, so setup fails closed instead of silently reporting success
    against a gateway that never came back up (Avarice F-0142/F-0143)."""
    if not failed:
        return
    raise click.ClickException(
        "gateway restart/readiness failed for: "
        + ", ".join(failed)
        + ". The requested configuration was not verified as applied. Fix the error above "
        "before relying on enforcement."
    )


def _active_connector_state_marker(data_dir: str) -> int | None:
    return _regular_file_marker(os.path.join(data_dir, "active_connector.json"))


def _hook_contract_lock_marker(data_dir: str) -> int | None:
    return _regular_file_marker(os.path.join(data_dir, "hook_contract_lock.json"))


def _regular_file_marker(path: str) -> int | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info.st_mtime_ns


def _read_stable_regular_json(path: str) -> tuple[Any, int]:
    fd: int | None = None
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"{path} is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        opened_info = os.fstat(fd)
        if not stat.S_ISREG(opened_info.st_mode):
            raise OSError(f"opened {path} is not a regular file")
        if not os.path.samestat(info, opened_info):
            raise OSError(f"{path} changed while opening")
        opened_file = os.fdopen(fd, encoding="utf-8")
        fd = None
        with opened_file:
            payload = _json.load(opened_file)
        return payload, opened_info.st_mtime_ns
    finally:
        if fd is not None:
            os.close(fd)


def _hook_contract_lock_covers(
    lock: Any,
    expected: set[str],
    inactive: set[str] | None = None,
) -> bool:
    if not isinstance(lock, dict):
        return False
    version = lock.get("version")
    entries = lock.get("connectors")
    if type(version) is not int or version < 1 or version > 2 or not isinstance(entries, dict):
        return False
    if inactive is None:
        actual = {
            normalize_connector(name)
            for name in entries
            if isinstance(name, str) and name.strip()
        }
        if actual != expected:
            return False
    else:
        actual: set[str] = set()
        for raw_name in entries:
            if not isinstance(raw_name, str) or not raw_name.strip():
                return False
            name = normalize_connector(raw_name)
            if not name or name in actual:
                return False
            actual.add(name)
        if not expected.issubset(actual) or not (actual - expected).issubset(inactive):
            return False
    for name in expected:
        if not _hook_contract_lock_entry_covers(name, entries.get(name)):
            return False
    return True


def _hook_contract_lock_entry_covers(name: str, entry: Any) -> bool:
    return not connector_lock_contract_invariant(name, entry)


def _validated_hook_contract_lock_publications(lock: Any, expected: set[str]) -> dict[str, str]:
    """Return per-connector publication tokens from a structurally valid lock.

    A token is useful only after the corresponding expected entry satisfies the
    same metadata checks as final readiness. The caller compares these opaque
    RFC3339 timestamps with the protected pre-restart snapshot; timestamp text
    never grants readiness by itself.
    """

    if not isinstance(lock, dict):
        return {}
    version = lock.get("version")
    entries = lock.get("connectors")
    if type(version) is not int or version < 1 or version > 2 or not isinstance(entries, dict):
        return {}
    normalized_names: set[str] = set()
    for raw_name in entries:
        if not isinstance(raw_name, str) or not raw_name.strip():
            return {}
        normalized = normalize_connector(raw_name)
        if not normalized or normalized in normalized_names:
            return {}
        normalized_names.add(normalized)
    publications: dict[str, str] = {}
    for name in expected:
        entry = entries.get(name)
        if not _hook_contract_lock_entry_covers(name, entry):
            continue
        updated_at = entry.get("updated_at")
        if (
            isinstance(updated_at, str)
            and updated_at.strip() == updated_at
            and updated_at
            and not any(char in updated_at for char in "\x00\r\n")
        ):
            publications[name] = updated_at
    return publications


def _hook_contract_lock_progress_baseline(
    data_dir: str,
    expected: set[str],
) -> tuple[int | None, dict[str, str]]:
    try:
        lock, marker = _read_stable_regular_json(os.path.join(data_dir, "hook_contract_lock.json"))
    except (OSError, ValueError):
        return None, {}
    return marker, _validated_hook_contract_lock_publications(lock, expected)


def _connector_runtime_state_sets(state: Any) -> tuple[set[str], set[str] | None] | None:
    """Return active and explicitly inactive connectors for readiness.

    Version 3 is the first runtime-state schema with connector-scoped inactive
    tombstones.  Validate that shape strictly before allowing a preserved lock
    entry to remain alongside the active set.  Earlier state schemas retain the
    historical active-only interpretation.
    """

    if not isinstance(state, dict):
        return None
    version = state.get("version")
    if version == 3:
        if type(version) is not int:
            return None
        # Go omits an empty active roster from the v3 JSON document.  That is
        # distinct from an explicitly null/malformed roster and is valid when
        # the document contains only inactive connector tombstones.
        raw_names = state.get("names", [])
        raw_inactive = state.get("inactive_names", [])
        if not isinstance(raw_names, list) or not isinstance(raw_inactive, list):
            return None

        def _validated_names(raw: list[Any]) -> set[str] | None:
            names: set[str] = set()
            for value in raw:
                if not isinstance(value, str) or not value.strip():
                    return None
                name = normalize_connector(value)
                if not name or name in names:
                    return None
                names.add(name)
            return names

        active = _validated_names(raw_names)
        inactive = _validated_names(raw_inactive)
        if active is None or inactive is None or active & inactive:
            return None
        return active, inactive

    raw_names = state.get("names")
    if isinstance(raw_names, list):
        active = {
            normalize_connector(name)
            for name in raw_names
            if isinstance(name, str) and name.strip()
        }
    else:
        name = state.get("name")
        active = {normalize_connector(name)} if isinstance(name, str) and name.strip() else set()
    return active, None


def _connector_runtime_snapshot_ready(
    state: Any,
    state_marker: int,
    lock: Any,
    lock_marker: int,
    *,
    expected: set[str],
    previous_state_marker: int | None,
    previous_lock_marker: int | None,
) -> bool:
    runtime_sets = _connector_runtime_state_sets(state)
    if runtime_sets is None:
        return False
    active, inactive = runtime_sets
    state_fresh = previous_state_marker is None or state_marker != previous_state_marker
    lock_fresh = previous_lock_marker is None or lock_marker != previous_lock_marker
    return bool(
        active == expected
        and state_fresh
        and lock_fresh
        and _hook_contract_lock_covers(lock, expected, inactive)
    )


def _connector_runtime_snapshot_failure(
    state: Any,
    state_marker: int,
    lock: Any,
    lock_marker: int,
    *,
    expected: set[str],
    previous_state_marker: int | None,
    previous_lock_marker: int | None,
) -> _ConnectorRuntimeReadiness:
    runtime_sets = _connector_runtime_state_sets(state)
    if runtime_sets is None:
        return _ConnectorRuntimeReadiness(False, invariant="roster", detail="active connector state is malformed")
    active, inactive = runtime_sets
    if active != expected:
        peer = next(iter(sorted(active ^ expected)), "")
        return _ConnectorRuntimeReadiness(
            False,
            peer,
            "roster",
            f"active={','.join(sorted(active))}; expected={','.join(sorted(expected))}",
        )
    if previous_state_marker is not None and state_marker == previous_state_marker:
        return _ConnectorRuntimeReadiness(False, invariant="freshness", detail="active connector state is stale")
    if previous_lock_marker is not None and lock_marker == previous_lock_marker:
        return _ConnectorRuntimeReadiness(False, invariant="freshness", detail="contract lock is stale")
    entries = lock.get("connectors") if isinstance(lock, dict) else None
    if not isinstance(entries, dict):
        return _ConnectorRuntimeReadiness(False, invariant="contract", detail="contract lock is malformed")
    for name in sorted(expected):
        if invariant := connector_lock_contract_invariant(name, entries.get(name)):
            return _ConnectorRuntimeReadiness(False, name, invariant, f"protected lock {invariant} is invalid")
    extra = {normalize_connector(name) for name in entries if isinstance(name, str)} - expected
    if inactive is None and extra:
        peer = next(iter(sorted(extra)))
        return _ConnectorRuntimeReadiness(False, peer, "roster", "contract lock contains an unexpected connector")
    if inactive is not None and not extra.issubset(inactive):
        peer = next(iter(sorted(extra - inactive)), "")
        return _ConnectorRuntimeReadiness(False, peer, "roster", "contract lock peer is not inactive")
    return _ConnectorRuntimeReadiness(False, invariant="snapshot", detail="runtime snapshot is not ready")


def _read_gateway_health(data_dir: str, *, timeout: float = 1.0) -> dict[str, Any] | None:
    try:
        config_path = config_path_for_data_dir(data_dir)
        if not os.path.isfile(config_path):
            return None
        cfg = load_config(data_dir=data_dir)
        gateway = cfg.gateway
        from defenseclaw.logger import _gateway_api_host

        host = _gateway_api_host(cfg)
        port = int(getattr(gateway, "api_port", 18970) or 18970)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    connection = http.client.HTTPConnection(host, port, timeout=max(0.01, min(timeout, 1.0)))
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        body = response.read(1 << 20)
        if response.status != 200:
            return None
        health = _json.loads(body)
        return health if isinstance(health, dict) else None
    except (OSError, http.client.HTTPException, UnicodeDecodeError, ValueError):
        return None
    finally:
        connection.close()


def _gateway_health_generation(data_dir: str) -> str | None:
    health = _read_gateway_health(data_dir)
    started_at = health.get("started_at") if isinstance(health, dict) else None
    if not isinstance(started_at, str) or not started_at.strip():
        return None
    return started_at.strip()


def _new_gateway_health_is_terminal_failure(data_dir: str, generation: str | None) -> bool:
    """Fail early only for a terminal state from the restarted generation."""

    if not generation:
        return False
    health = _read_gateway_health(data_dir)
    if not isinstance(health, dict) or health.get("started_at") != generation:
        return False
    guardrail = health.get("guardrail")
    state = guardrail.get("state") if isinstance(guardrail, dict) else None
    # ``guardrail`` is initialized as disabled before connector boot begins,
    # so disabled is not terminal for a freshly started generation. Error and
    # stopped cannot converge into a verified connector runtime without a new
    # generation and may fail this wait early.
    return isinstance(state, str) and state.strip().lower() in {"error", "stopped"}


def _wait_for_connector_runtime(
    data_dir: str,
    connectors: list[str],
    previous_state_marker: int | None,
    previous_lock_marker: int | None,
    timeout: float = _CONNECTOR_RUNTIME_READY_TIMEOUT_SECONDS,
    *,
    previous_lock_publications: dict[str, str] | None = None,
    gateway_generation: str | None = None,
    require_gateway_health: bool = False,
) -> _ConnectorRuntimeReadiness:
    ordered = tuple(dict.fromkeys(normalize_connector(name) for name in connectors if name))
    expected = set(ordered)
    if not expected:
        return _ConnectorRuntimeReadiness(True)
    state_path = os.path.join(data_dir, "active_connector.json")
    lock_path = os.path.join(data_dir, "hook_contract_lock.json")
    per_connector_budget = max(0.0, timeout)
    started_at = time.monotonic()
    no_progress_deadline = started_at + per_connector_budget
    absolute_budget = min(
        _CONNECTOR_RUNTIME_READY_ABSOLUTE_CAP_SECONDS,
        per_connector_budget * max(1, len(expected) + 1),
    )
    absolute_deadline = started_at + absolute_budget
    baseline_publications = dict(previous_lock_publications or {})
    observed_fresh_publications: set[str] = set()
    last_failure = _ConnectorRuntimeReadiness(False, invariant="snapshot", detail="runtime files are not ready")

    def gateway_ready(deadline: float) -> tuple[bool, str | None, _ConnectorRuntimeReadiness]:
        nonlocal gateway_generation
        if not require_gateway_health and gateway_generation is None:
            return True, gateway_generation, _ConnectorRuntimeReadiness(True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return (
                False,
                gateway_generation,
                _ConnectorRuntimeReadiness(
                    False,
                    invariant="deadline",
                    detail="readiness deadline expired",
                ),
            )
        health = _read_gateway_health(data_dir, timeout=min(0.2, remaining))
        started_at = health.get("started_at") if isinstance(health, dict) else None
        if not isinstance(started_at, str) or not started_at.strip():
            return (
                False,
                gateway_generation,
                _ConnectorRuntimeReadiness(
                    False,
                    invariant="gateway-health",
                    detail="restarted gateway health is unavailable",
                ),
            )
        started_at = started_at.strip()
        if gateway_generation is None:
            gateway_generation = started_at
        if started_at != gateway_generation:
            return (
                False,
                gateway_generation,
                _ConnectorRuntimeReadiness(
                    False,
                    invariant="gateway-generation",
                    detail="gateway generation changed during readiness",
                ),
            )
        guardrail = health.get("guardrail")
        state = guardrail.get("state") if isinstance(guardrail, dict) else None
        if isinstance(state, str) and state.strip().lower() in {"error", "stopped"}:
            return (
                False,
                gateway_generation,
                _ConnectorRuntimeReadiness(
                    False,
                    invariant="gateway-state",
                    detail=f"restarted gateway guardrail is {state.strip().lower()}",
                ),
            )
        return True, gateway_generation, _ConnectorRuntimeReadiness(True)

    def validate_transaction(deadline: float) -> _ConnectorRuntimeReadiness:
        from defenseclaw.commands.cmd_doctor import connector_setup_readiness

        results: queue.Queue[_ConnectorRuntimeReadiness] = queue.Queue(maxsize=1)
        cancelled = threading.Event()
        current = [ordered[0]]

        def worker() -> None:
            try:
                cfg = load_config(data_dir=data_dir)
                pending_reload: _ConnectorRuntimeReadiness | None = None
                for name in ordered:
                    current[0] = name
                    if cancelled.is_set() or time.monotonic() >= deadline:
                        return
                    readiness = connector_setup_readiness(cfg, name)
                    if cancelled.is_set() or time.monotonic() >= deadline:
                        return
                    if not readiness:
                        failure = _ConnectorRuntimeReadiness(
                            False,
                            readiness.connector,
                            readiness.invariant,
                            readiness.detail,
                        )
                        detail = failure.detail.casefold()
                        if (
                            failure.connector == "hermes"
                            # The exact Windows detail names its protected
                            # executable before the explicit pending-reload
                            # state, so the generic classifier may report
                            # either invariant. The required detail below is
                            # the narrow deferred-state authority.
                            and failure.invariant in {"live-runtime", "executable"}
                            and "running hermes" in detail
                            and "live=false" in detail
                            and ("pending-reload" in detail or "unverified" in detail)
                        ):
                            # Hermes hosts cache callbacks. A fresh protected
                            # lock plus exact on-disk registration is a valid
                            # committed Setup outcome, but it must remain
                            # explicitly non-live until upstream hosts reload.
                            pending_reload = _ConnectorRuntimeReadiness(
                                True,
                                "hermes",
                                "pending-reload",
                                failure.detail,
                            )
                            continue
                        results.put_nowait(failure)
                        return
                if not cancelled.is_set() and time.monotonic() < deadline:
                    results.put_nowait(pending_reload or _ConnectorRuntimeReadiness(True))
            except Exception as exc:  # noqa: BLE001 - worker failures are bounded readiness evidence.
                if not cancelled.is_set() and time.monotonic() < deadline:
                    results.put_nowait(_ConnectorRuntimeReadiness(False, current[0], "validation", type(exc).__name__))

        thread = threading.Thread(target=worker, name="defenseclaw-setup-readiness", daemon=True)
        thread.start()
        remaining = max(0.0, deadline - time.monotonic())
        try:
            return results.get(timeout=remaining)
        except queue.Empty:
            cancelled.set()
            return _ConnectorRuntimeReadiness(
                False,
                current[0],
                "deadline",
                "connector validation exceeded the readiness deadline",
            )

    while True:
        now = time.monotonic()
        if now >= no_progress_deadline or now >= absolute_deadline:
            return last_failure
        if require_gateway_health or gateway_generation is not None:
            health_ok, _, health_failure = gateway_ready(min(no_progress_deadline, absolute_deadline))
            if not health_ok:
                last_failure = health_failure
                if health_failure.invariant == "gateway-state":
                    return health_failure
        try:
            state, state_marker = _read_stable_regular_json(state_path)
            lock, lock_marker = _read_stable_regular_json(lock_path)
        except (OSError, ValueError):
            state = lock = None
        else:
            snapshot_ready = _connector_runtime_snapshot_ready(
                state,
                state_marker,
                lock,
                lock_marker,
                expected=expected,
                previous_state_marker=previous_state_marker,
                previous_lock_marker=previous_lock_marker,
            )
            if not snapshot_ready:
                last_failure = _connector_runtime_snapshot_failure(
                    state,
                    state_marker,
                    lock,
                    lock_marker,
                    expected=expected,
                    previous_state_marker=previous_state_marker,
                    previous_lock_marker=previous_lock_marker,
                )
            if snapshot_ready:
                deadline = min(no_progress_deadline, absolute_deadline)
                health_ok, _, health_failure = gateway_ready(deadline)
                if not health_ok:
                    last_failure = health_failure
                    if health_failure.invariant == "gateway-state":
                        return health_failure
                else:
                    validation = validate_transaction(deadline)
                    if validation:
                        if time.monotonic() >= deadline:
                            return _ConnectorRuntimeReadiness(
                                False,
                                invariant="deadline",
                                detail="validation completed after the readiness deadline",
                            )
                        health_ok, _, health_failure = gateway_ready(deadline)
                        snapshot_still_ready = False
                        if health_ok and time.monotonic() < deadline:
                            snapshot_still_ready = (
                                _regular_file_marker(state_path) == state_marker
                                and _regular_file_marker(lock_path) == lock_marker
                            )
                        if health_ok and snapshot_still_ready and time.monotonic() < deadline:
                            return validation
                        last_failure = (
                            health_failure
                            if not health_ok
                            else _ConnectorRuntimeReadiness(
                                False,
                                invariant="snapshot",
                                detail="runtime files changed during validation",
                            )
                        )
                    else:
                        last_failure = validation
                        if validation.invariant not in {
                            "deadline",
                            "gateway-health",
                            "live-runtime",
                        }:
                            return validation

            lock_fresh = previous_lock_marker is None or lock_marker != previous_lock_marker
            if lock_fresh:
                publications = _validated_hook_contract_lock_publications(lock, expected)
                freshly_published = {
                    name for name, token in publications.items() if token != baseline_publications.get(name)
                }
                new_progress = freshly_published - observed_fresh_publications
                if new_progress:
                    observed_fresh_publications.update(new_progress)
                    progress_at = time.monotonic()
                    no_progress_deadline = min(absolute_deadline, progress_at + per_connector_budget)

        sleep_for = min(0.2, max(0.0, min(no_progress_deadline, absolute_deadline) - time.monotonic()))
        if sleep_for:
            time.sleep(sleep_for)


def _restart_openclaw_gateway() -> bool:
    """Ask OpenClaw to restart its gateway service so the updated
    plugin registration (written by OpenClawConnector.Setup) takes
    effect.

    Returns True when the restart succeeded, False on any failure
    (missing CLI, timeout, or non-zero exit). Avarice F-0143: this used
    to swallow every failure and return ``None`` so the caller could not
    tell the OpenClaw gateway never came back — setup then reported
    success while traffic kept flowing past a down (fail-open) gateway."""
    click.echo("  openclaw-gateway: restarting...", nl=False)
    try:
        result = subprocess.run(
            ["openclaw", "gateway", "restart"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            click.echo(" ✓")
            return True
        click.echo(" ✗")
        err = (result.stderr or result.stdout or "").strip()
        if err:
            for line in err.splitlines()[:3]:
                click.echo(f"    {line}")
        return False
    except FileNotFoundError:
        click.echo(" ✗ (openclaw CLI not found)")
        click.echo("    Install OpenClaw or restart its gateway manually.")
        return False
    except subprocess.TimeoutExpired:
        # OpenClaw owns this lifecycle and exposes no DefenseClaw pid/data-dir
        # state that we can safely reconcile here.  A timeout is therefore a
        # fail-closed restart failure; the native DefenseClaw gateway helper
        # below performs its own identity-aware timeout reconciliation.
        click.echo(" ✗ (timed out)")
        return False


def _gateway_pid_file_identifies_gateway(pid_file: str) -> bool:
    """Confirm the live process recorded in ``pid_file`` is actually the
    DefenseClaw gateway, not a planted/stale PID pointing at an unrelated
    process. Avarice F-0721: ``_is_pid_alive`` only proves *something* with
    that PID is alive, so a spoofed ``gateway.pid`` made the setup restart
    path treat a foreign process as the running gateway and issue
    ``restart``. We additionally verify the process identity (fail closed)
    before trusting the PID file as "our gateway is up"."""
    from defenseclaw.process_liveness import process_is_gateway, read_pid_file

    pid = read_pid_file(pid_file)
    if pid is None:
        return False
    return process_is_gateway(pid)


def _gateway_lifecycle_executable(
    *,
    native: bool = False,
    search_path: str | None = None,
) -> str | None:
    """Resolve one stable executable for a complete gateway lifecycle call.

    A packaged Windows CLI must use the gateway beside its verified embedded
    runtime.  Passing a bare executable name lets Windows search the current
    directory before ``PATH`` and allowed a stale checkout binary to shadow the
    installed service. Doctor also reaches this helper on POSIX, so every
    lifecycle mutation uses one concrete path resolved before subprocess
    execution rather than searching a potentially changed ``PATH`` later.
    """

    from defenseclaw.gateway import (
        GATEWAY_BIN_NAME,
        canonical_install_path,
        packaged_windows_gateway_path,
        packaged_windows_install_root,
    )

    if packaged_windows_install_root():
        # A corroborated package with a missing sibling is broken; fail closed
        # instead of allowing PATH/current-directory executable shadowing.
        return packaged_windows_gateway_path()
    raw_search_path = os.environ.get("PATH", os.defpath) if search_path is None else search_path
    current_directory = os.path.normcase(os.path.realpath(os.curdir))
    search_directories: list[str] = []
    seen_directories: set[str] = set()
    for raw_directory in raw_search_path.split(os.pathsep):
        directory = raw_directory.strip()
        if len(directory) >= 2 and directory.startswith('"') and directory.endswith('"'):
            directory = directory[1:-1]
        if not directory or not os.path.isabs(directory):
            continue
        absolute_directory = os.path.abspath(directory)
        normalized_directory = os.path.normcase(os.path.realpath(absolute_directory))
        if normalized_directory == current_directory or normalized_directory in seen_directories:
            continue
        seen_directories.add(normalized_directory)
        search_directories.append(absolute_directory)
    sanitized_search_path = os.pathsep.join(search_directories)
    # Lifecycle mutations deliberately ignore DEFENSECLAW_GATEWAY_BIN. The
    # config loader accepts credential names from .env, so an attacker who
    # could previously write that file could otherwise plant an executable
    # override and have Doctor run it after merely tightening permissions.
    executable = shutil.which(GATEWAY_BIN_NAME, path=sanitized_search_path)
    if executable:
        # Older Python runtimes on Windows can prepend the current directory
        # even when an explicit PATH is supplied. Accept only a concrete result
        # whose parent was one of the sanitized search directories.
        executable_parent = os.path.normcase(os.path.abspath(os.path.dirname(executable)))
        allowed_parents = {os.path.normcase(directory) for directory in search_directories}
        if not os.path.isabs(executable) or executable_parent not in allowed_parents:
            executable = None
    if not executable:
        canonical = canonical_install_path()
        if os.path.isfile(canonical) and os.access(canonical, os.X_OK):
            executable = canonical
    if not executable:
        return None
    resolved = Path(executable).expanduser().resolve()
    if native and os.name == "nt" and resolved.suffix.lower() != ".exe":
        return None
    return _trusted_gateway_lifecycle_executable(str(resolved))


def _trusted_gateway_lifecycle_executable(executable: str) -> str | None:
    """Return a custody-checked concrete executable for lifecycle mutation."""
    if not executable or not os.path.isabs(executable):
        return None
    resolved = str(Path(executable).resolve())
    if os.name != "nt":
        from defenseclaw.file_permissions import trusted_posix_executable_path

        try:
            return trusted_posix_executable_path(resolved)
        except OSError:
            return None

    from defenseclaw.file_permissions import windows_acl_write_error
    from defenseclaw.gateway import packaged_windows_gateway_path

    packaged = packaged_windows_gateway_path()
    if packaged:
        try:
            if os.path.samefile(resolved, packaged):
                return resolved
        except OSError:
            pass
    for candidate in (resolved, os.path.dirname(resolved)):
        if windows_acl_write_error(candidate) is not None:
            return None
    return resolved


def _restart_defense_gateway(
    data_dir: str,
    *,
    start_if_stopped: bool = True,
    child_env: dict[str, str] | None = None,
    lifecycle_executable: str | None = None,
    lifecycle_executable_requires_running: bool = True,
) -> bool:
    # Mark the current Click context as "restart handled" so the
    # `setup` group's auto-restart result callback doesn't bounce the
    # gateway a second time on its way out. Safe to call outside Click.
    #
    # Returns True when the gateway is up afterwards (started/restarted
    # OK, or deliberately left stopped), False when the start/restart
    # failed. Avarice F-0142: this used to print the error and return
    # ``None``, so callers reported setup success even though the gateway
    # never came back (defaulting hooks to fail-open).
    try:
        ctx = click.get_current_context(silent=True)
    except RuntimeError:
        ctx = None
    if ctx is not None:
        ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True

    if os.name == "nt":
        from defenseclaw.gateway import packaged_windows_install_root

        if packaged_windows_install_root():
            return _restart_defense_gateway_native(
                data_dir,
                start_if_stopped=start_if_stopped,
            )

    pid_file = os.path.join(data_dir, "gateway.pid")
    pid_alive = _is_pid_alive(pid_file)
    # F-0721: only trust a live PID when it actually belongs to the gateway
    # binary. If a PID file points at some live but unverified process, fail
    # closed instead of downgrading to `start`; the Go start path treats a live
    # PID file as already running, which can otherwise report success while the
    # old/stale daemon keeps serving the previous config.
    if pid_alive and not _gateway_pid_file_identifies_gateway(pid_file):
        click.echo("  defenseclaw-gateway: live gateway.pid did not verify as DefenseClaw gateway.")
        click.echo("    Refusing to start/restart; inspect or remove the stale PID file.")
        return False
    was_running = pid_alive
    if not was_running and not start_if_stopped:
        click.echo("  defenseclaw-gateway: not running — skipping restart.")
        click.echo("    Start it with: defenseclaw-gateway start")
        return True

    action = "restarting" if was_running else "starting"
    click.echo(f"  defenseclaw-gateway: {action}...", nl=False)

    if (
        lifecycle_executable
        and lifecycle_executable_requires_running
        and not was_running
    ):
        click.echo(" ✗ (verified running executable is no longer active)")
        return False
    search_path = child_env.get("PATH", os.defpath) if child_env is not None else None
    executable = (
        _trusted_gateway_lifecycle_executable(lifecycle_executable)
        if lifecycle_executable
        else _gateway_lifecycle_executable(search_path=search_path)
    )
    if not executable:
        click.echo(" ✗ (binary not found)")
        click.echo("    Build with: make gateway")
        return False
    if not os.path.isabs(executable) or not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        click.echo(" ✗ (binary is not a verified executable file)")
        return False
    executable = str(Path(executable).resolve())
    cmd = [executable, "restart"] if was_running else [executable, "start"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=child_env,
            timeout=30,
        )
        if result.returncode == 0:
            if _wait_for_defense_gateway_api(data_dir):
                click.echo(" ✓")
                return True
            click.echo(" ✗ (API health timed out)")
            click.echo("    The gateway process started but its sidecar API never became ready.")
            return False
        click.echo(" ✗")
        err = (result.stderr or result.stdout or "").strip()
        if err:
            for line in err.splitlines()[:3]:
                click.echo(f"    {line}")
        return False
    except FileNotFoundError:
        click.echo(" ✗ (binary not found)")
        click.echo("    Build with: make gateway")
        return False
    except subprocess.TimeoutExpired:
        # A freshly installed Windows executable can spend appreciable time in
        # OS trust/AV inspection before the Go launcher creates its detached
        # daemon.  The launcher may therefore cross this outer Python timeout
        # even though the managed gateway reaches READY immediately afterward.
        # Reconcile once through the real authenticated/ownership-aware status
        # command instead of reporting a false failure.  If an initial start
        # is still unhealthy, issue a bounded managed stop so a late detached
        # child cannot outlive the failed setup command.  On restart, preserve
        # the pre-existing generation rather than stopping an otherwise healthy
        # service whose replacement outcome is uncertain.
        status = _gateway_lifecycle_status(executable, child_env=child_env)
        if status:
            click.echo(" ✓ (ready after launcher timeout)")
            return True
        if not was_running:
            _cleanup_timed_out_gateway_start(executable, child_env=child_env)
        click.echo(" ✗ (timed out; final status is not healthy)")
        return False


def _wait_for_defense_gateway_api(
    data_dir: str,
    timeout: float = _GATEWAY_API_READY_TIMEOUT_SECONDS,
) -> bool:
    """Wait until the replacement gateway can admit canonical v8 facts.

    The daemon start command returns after spawning its child, before that
    child necessarily binds the sidecar API. Connector setup also observes an
    ``active_connector.json`` marker written earlier in gateway startup, so
    neither signal proves that the API is ready. Returning from setup during
    that window makes the command's own mandatory v8 audit handoff fail with
    ``connection refused``.

    Require the replacement process's health document to report the API
    subsystem as running. This also covers the platform socket-reclaim retry
    in the Go API server, which may legitimately take up to 30 seconds.
    """
    try:
        cfg = load_config(data_dir=data_dir)
        gateway = cfg.gateway
        from defenseclaw.logger import _gateway_api_host

        host = _gateway_api_host(cfg)
        port = int(getattr(gateway, "api_port", 18970) or 18970)
    except (AttributeError, OSError, TypeError, ValueError):
        return False

    if not 1 <= port <= 65535:
        return False

    bounded_timeout = max(0.0, timeout)
    deadline = time.monotonic() + bounded_timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        probe_timeout = min(1.0, bounded_timeout, remaining)
        if probe_timeout <= 0:
            break
        connection = http.client.HTTPConnection(
            host,
            port,
            # Subtracting a large monotonic timestamp can round a few ulps
            # above the caller's budget. Clamp to that original budget so a
            # single health probe never receives a longer timeout than setup
            # promised, particularly for short test/automation deadlines.
            timeout=probe_timeout,
        )
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            body = response.read(1 << 20)
            if response.status == 200:
                health = _json.loads(body)
                api = health.get("api") if isinstance(health, dict) else None
                state = api.get("state") if isinstance(api, dict) else None
                if isinstance(state, str) and state.strip().lower() == "running":
                    return True
        except (OSError, http.client.HTTPException, UnicodeDecodeError, ValueError):
            pass
        finally:
            connection.close()
        sleep_for = min(0.2, max(0.0, deadline - time.monotonic()))
        if sleep_for:
            time.sleep(sleep_for)
    return False


def _restart_defense_gateway_native(
    data_dir: str,
    *,
    start_if_stopped: bool = True,
) -> bool:
    """Reload the gateway with the bounded native process-tree runner."""

    from defenseclaw.observability.local_stack import (
        CommandRunner,
        CommandTimeoutError,
        LocalStackError,
        native_command_environment,
    )

    try:
        ctx = click.get_current_context(silent=True)
    except RuntimeError:
        ctx = None
    if ctx is not None:
        ctx.meta[_SETUP_RESTART_HANDLED_KEY] = True

    executable = _gateway_lifecycle_executable(native=True)
    if not executable:
        click.echo("  defenseclaw-gateway: native executable not found.")
        return False

    pid_file = os.path.join(data_dir, "gateway.pid")
    pid_alive = _is_pid_alive(pid_file)
    if pid_alive and not _gateway_pid_file_identifies_gateway(pid_file):
        click.echo("  defenseclaw-gateway: live gateway.pid did not verify as DefenseClaw gateway.")
        return False
    was_running = pid_alive
    if not was_running and not start_if_stopped:
        return True

    action = "restart" if was_running else "start"
    runner = CommandRunner()
    click.echo(
        f"  defenseclaw-gateway: {'restarting' if was_running else 'starting'}...",
        nl=False,
    )
    try:
        result = runner.run(
            [executable, action],
            timeout=_DEFENSE_GATEWAY_LIFECYCLE_TIMEOUT_SECONDS,
            env=native_command_environment(),
            allow_breakaway=True,
        )
    except CommandTimeoutError as exc:
        if _wait_for_defense_gateway_api(data_dir):
            click.echo(" ✓ (API ready after launcher timeout)")
            return True
        _echo_native_command_diagnostics(exc.result)
        if not was_running:
            _native_gateway_lifecycle_stop(runner, executable)
        click.echo(" ✗ (timed out; final API state is not healthy)")
        return False
    except LocalStackError as exc:
        click.echo(" ✗")
        click.echo(f"    {exc}")
        return False
    if result.returncode == 0 and _wait_for_defense_gateway_api(data_dir):
        click.echo(" ✓")
        return True
    click.echo(" ✗")
    _echo_native_command_diagnostics(result)
    if result.returncode == 0:
        click.echo("    The lifecycle command returned, but the sidecar API did not reach running state.")
    return False


def _echo_native_command_diagnostics(result: Any) -> None:
    detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    for line in detail.splitlines()[:3]:
        click.echo(f"    {line}")


def _native_gateway_lifecycle_status(runner, executable: str) -> bool:
    from defenseclaw.observability.local_stack import LocalStackError

    try:
        result = runner.run(
            [str(Path(executable).resolve()), "status"],
            timeout=_DEFENSE_GATEWAY_STATUS_TIMEOUT_SECONDS,
        )
    except LocalStackError:
        return False
    return result.returncode == 0


def _native_gateway_lifecycle_stop(runner, executable: str) -> bool:
    from defenseclaw.observability.local_stack import LocalStackError

    try:
        result = runner.run(
            [str(Path(executable).resolve()), "stop"],
            timeout=_DEFENSE_GATEWAY_STOP_TIMEOUT_SECONDS,
        )
    except LocalStackError:
        return False
    return result.returncode == 0


def _stop_defense_gateway_native(data_dir: str) -> bool:
    from defenseclaw.observability.local_stack import CommandRunner

    executable = _gateway_lifecycle_executable(native=True)
    if not executable:
        return False
    if not _native_gateway_lifecycle_stop(CommandRunner(), executable):
        return False
    return not _is_pid_alive(os.path.join(data_dir, "gateway.pid"))


def _gateway_lifecycle_status(
    executable: str,
    *,
    child_env: dict[str, str] | None = None,
) -> bool:
    try:
        result = subprocess.run(
            [executable, "status"],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=child_env,
            timeout=_DEFENSE_GATEWAY_STATUS_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def _cleanup_timed_out_gateway_start(
    executable: str,
    *,
    child_env: dict[str, str] | None = None,
) -> None:
    try:
        subprocess.run(
            [executable, "stop"],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=child_env,
            timeout=_DEFENSE_GATEWAY_STOP_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # The caller already reports failure. The gateway's native PID and
        # identity checks prevent this best-effort cleanup targeting another
        # process.
        return


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
        (``setup llm --show``, etc.). The bare connector batch is the narrow
        exception: its explicit readiness marker always runs the gate.
      * Gateway PID file shows the process is not running — generic setup does
        not auto-start a sidecar an operator deliberately stopped. A bare
        connector batch with restart enabled explicitly requests start plus
        all-target verification; only its ``--no-restart`` form stages offline.
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
    batch_targets_raw = ctx.meta.get(_SETUP_BATCH_READINESS_KEY)
    batch_targets = (
        [normalize_connector(name) for name in batch_targets_raw if isinstance(name, str) and name]
        if isinstance(batch_targets_raw, (list, tuple))
        else []
    )
    if not batch_targets and (cfg_path is None or after is None or before == after):
        return

    data_dir = app.cfg.data_dir
    if batch_targets:
        click.echo("")
        if "omnigent" in batch_targets:
            click.echo("  Starting/restarting defenseclaw-gateway and verifying connector registration…")
        else:
            click.echo("  Starting/restarting defenseclaw-gateway and verifying connector readiness…")
        primary = (
            normalize_connector(app.cfg.active_connector())
            if hasattr(app.cfg, "active_connector") and normalize_connector(app.cfg.active_connector()) in batch_targets
            else batch_targets[0]
        )
        try:
            _restart_services(
                data_dir,
                app.cfg.gateway.host,
                app.cfg.gateway.port,
                connector=primary,
                connectors=batch_targets,
                wait_for_connector_ready=True,
                start_if_stopped=True,
            )
        except Exception as exc:  # noqa: BLE001 — readiness failure rolls the whole batch back.
            snapshot = ctx.meta.get(_SETUP_BATCH_ROLLBACK_KEY)
            if isinstance(snapshot, _SetupConfigSnapshot):
                _rollback_failed_connector_application(app, snapshot, exc)
            raise
        if "omnigent" in batch_targets:
            click.echo(
                f"  ✓ Configured {len(batch_targets)} connector(s); DefenseClaw gateway roster and "
                "hook-contract evidence are ready"
            )
            ux.warn(
                "OmniGent loaded policy generation remains unverified; reload/restart every running "
                "OmniGent server before relying on action/fail-closed enforcement."
            )
        else:
            click.echo(
                f"  ✓ Configured {len(batch_targets)} connector(s); runtime roster and hook-contract evidence are ready"
            )
        return

    pid_file = os.path.join(data_dir, "gateway.pid")
    if not _is_pid_alive(pid_file):
        click.echo("")
        click.echo("  Config updated. Gateway is not running — changes will take effect on next start.")
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
    ux.ok("Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    resolved = gw.resolved_token()
    rows = [
        ("host", gw.host),
        ("port", str(gw.port)),
        ("api_port", str(gw.api_port)),
        ("token", f"via {gw.token_env} (in .env)" if resolved else "(none — local mode)"),
    ]

    for key, val in rows:
        label = (f"gateway.{key}:").ljust(20)
        click.echo(f"    {ux._style(label, fg='bright_black', bold=True)} {val}")
    click.echo()

    if resolved:
        ux.subhead("Start the sidecar with:")
        ux.subhead("  defenseclaw-gateway")
    else:
        ux.subhead("Start the sidecar with:")
        ux.subhead("  defenseclaw-gateway")
        ux.subhead("(local mode — ensure OpenClaw is running on this machine)")
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

_SPLUNK_BRIDGE_ENV_REL = os.path.join("splunk-bridge", "env", ".env")


def _native_windows_local_splunk() -> bool:
    """Select the argument-vector native controller only on Windows."""

    return platform_support.host_os() == "windows"


@click.group("splunk", invoke_without_command=True)
@click.pass_context
@click.option(
    "--o11y",
    "enable_o11y",
    is_flag=True,
    default=False,
    help="Enable Splunk Observability Cloud (OTLP traces + metrics)",
)
@click.option(
    "--logs",
    "enable_logs",
    is_flag=True,
    default=False,
    help="Enable local Splunk via Docker (HEC logs + dashboards, Free mode)",
)
@click.option(
    "--s3-export", is_flag=True, default=False, help="Enable local Splunk and start the optional S3 exporter sidecar"
)
@click.option("--s3-bucket", default=None, help="S3 bucket for --s3-export (or set S3_BUCKET)")
@click.option("--s3-prefix", default=None, help="S3 prefix for --s3-export (default: agentwatch/defenseclaw)")
@click.option("--aws-region", default=None, help="AWS region for --s3-export (default: us-west-2)")
@click.option(
    "--enterprise",
    "enable_enterprise",
    is_flag=True,
    default=False,
    help="Enable remote Splunk Enterprise via HEC endpoint + token",
)
@click.option("--realm", default=None, help="Splunk O11y realm (e.g. us1, us0, eu0)")
@click.option("--access-token", default=None, help="Splunk O11y access token")
@click.option("--hec-endpoint", default=None, help="Remote Splunk Enterprise HEC endpoint")
@click.option("--hec-token", default=None, help="Remote Splunk Enterprise HEC token")
@click.option("--app-name", default=None, help="OTEL service name (default: defenseclaw)")
@click.option(
    "--index",
    "logs_index",
    default=None,
    help=("HEC index for --logs/--enterprise (default: defenseclaw_local for local, defenseclaw for enterprise)"),
)
@click.option("--source", "logs_source", default=None, help="HEC source for --logs/--enterprise (default: defenseclaw)")
@click.option(
    "--sourcetype",
    "logs_sourcetype",
    default=None,
    help="HEC sourcetype for --logs/--enterprise (default: defenseclaw:json for local, _json for enterprise)",
)
@click.option("--traces/--no-traces", "enable_traces", default=None, help="Enable/disable trace export (O11y)")
@click.option("--metrics/--no-metrics", "enable_metrics", default=None, help="Enable/disable metrics export (O11y)")
@click.option(
    "--logs-export/--no-logs-export", "enable_logs_export", default=None, help="Enable/disable logs export (O11y)"
)
@click.option("--disable", is_flag=True, help="Disable Splunk integration(s)")
@click.option(
    "--accept-splunk-license", is_flag=True, help="Acknowledge the Splunk General Terms for local Splunk enablement"
)
@click.option("--skip-test", is_flag=True, help="Skip the live HEC probe after remote Splunk Enterprise setup")
@click.option(
    "--show-credentials",
    is_flag=True,
    help="Show the generated HEC token and runtime-only Splunk bootstrap secret",
)
@click.option(
    "--refresh-bundle/--no-refresh-bundle",
    "refresh_bundle",
    default=True,
    show_default=True,
    help=(
        "Before starting local Splunk, refresh ~/.defenseclaw/splunk-bridge/ "
        "from the wheel/repo bundle so newly-shipped compose, bin, app, and "
        "s3_exporter changes take effect. Operator secrets (env/.env) are "
        "preserved. If the stack is already running, it will be stopped, "
        "refreshed, and restarted automatically."
    ),
)
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
def setup_splunk(
    ctx: click.Context,
    enable_o11y: bool,
    enable_logs: bool,
    s3_export: bool,
    s3_bucket: str | None,
    s3_prefix: str | None,
    aws_region: str | None,
    enable_enterprise: bool,
    realm: str | None,
    access_token: str | None,
    hec_endpoint: str | None,
    hec_token: str | None,
    app_name: str | None,
    logs_index: str | None,
    logs_source: str | None,
    logs_sourcetype: str | None,
    enable_traces: bool | None,
    enable_metrics: bool | None,
    enable_logs_export: bool | None,
    disable: bool,
    accept_splunk_license: bool,
    skip_test: bool,
    show_credentials: bool,
    refresh_bundle: bool,
    non_interactive: bool,
) -> None:
    """Configure Splunk integration for DefenseClaw.

    Three independent pipelines are available:

    \b
      --o11y   Splunk Observability Cloud (traces + metrics via OTLP HTTP)
               No local infrastructure needed. Requires a Splunk access token.
    \b
      --logs   Local Splunk (Docker, HEC logs + dashboards)
               Starts the bundled profile in Splunk Free mode from day 1.
               Requires Docker.
    \b
      --enterprise
               Remote Splunk Enterprise HEC endpoint + token.
               No Docker, local bridge, or Splunk-side automation.
               Sends one best-effort HEC probe unless --skip-test is set.

    Both can run simultaneously. Without flags, runs an interactive wizard.
    """
    if ctx.invoked_subcommand is not None:
        return

    local_route_requested = enable_logs or s3_export or show_credentials or (disable and enable_logs)
    if local_route_requested and not local_shell_stacks_supported():
        raise click.ClickException(LOCAL_SHELL_STACKS_UNSUPPORTED_REASON)

    app = ctx.find_object(AppContext)
    if app is None:
        raise click.ClickException("App context unavailable")

    if show_credentials:
        _show_splunk_credentials(app.cfg.data_dir)
        return

    if disable:
        _disable_splunk(app, enable_o11y, enable_logs, enable_enterprise, non_interactive)
        return

    if s3_export:
        # The S3 exporter ships as a sidecar to the local Splunk
        # docker compose stack — there is no Docker-free S3 path. Emit
        # a one-line notice so operators are not surprised when the
        # Docker pre-flight checks below run.
        if not enable_logs:
            click.echo(
                "  note: --s3-export implies --logs (the S3 exporter is a "
                "sidecar to the local Splunk stack). Running Docker pre-flight "
                "checks…"
            )
        enable_logs = True

    if not enable_o11y and not enable_logs and not enable_enterprise and not non_interactive:
        _interactive_splunk_setup(app, realm, access_token, app_name, skip_test=skip_test)
        return

    if not enable_o11y and not enable_logs and not enable_enterprise and non_interactive:
        click.echo(
            "  error: specify --o11y, --logs, --enterprise, or a combination with --non-interactive",
            err=True,
        )
        raise SystemExit(1)

    did_o11y = False
    did_logs = False
    did_enterprise = False

    def configure_o11y() -> None:
        nonlocal did_o11y
        if not enable_o11y:
            return
        _setup_o11y(
            app,
            realm or "us1",
            access_token,
            app_name or "defenseclaw",
            non_interactive=non_interactive,
            traces=enable_traces,
            metrics=enable_metrics,
            logs_export=enable_logs_export,
        )
        did_o11y = True

    def configure_logs() -> None:
        nonlocal did_logs
        if not enable_logs:
            return
        did_logs = _setup_logs(
            app,
            non_interactive=non_interactive,
            accept_splunk_license=accept_splunk_license,
            index=logs_index,
            source=logs_source,
            sourcetype=logs_sourcetype,
            s3_export=s3_export,
            s3_bucket=s3_bucket,
            s3_prefix=s3_prefix,
            aws_region=aws_region,
            refresh_bundle=refresh_bundle,
        )

    def configure_enterprise() -> None:
        nonlocal did_enterprise
        if not enable_enterprise:
            return
        _setup_enterprise(
            app,
            hec_endpoint=hec_endpoint,
            hec_token=hec_token,
            index=logs_index,
            source=logs_source,
            sourcetype=logs_sourcetype,
            non_interactive=non_interactive,
            skip_test=skip_test,
        )
        did_enterprise = True

    native_combined = _native_windows_local_splunk() and enable_logs and (enable_o11y or enable_enterprise)
    if native_combined:
        # Resolve every interactive/flag prerequisite and prove the entire
        # native Local Splunk environment before the first remote-pipeline
        # config write. Local Splunk runs last so its gateway reload activates
        # the complete combined generation exactly once.
        if enable_o11y:
            resolved_access_token = access_token or os.environ.get("SPLUNK_ACCESS_TOKEN", "")
            if not resolved_access_token and non_interactive:
                click.echo("  error: --access-token required (or set SPLUNK_ACCESS_TOKEN env var)", err=True)
                raise SystemExit(1)
            if not resolved_access_token:
                resolved_access_token = _prompt_splunk_token(None)
            if not resolved_access_token:
                click.echo("  error: access token is required for Splunk O11y", err=True)
                raise SystemExit(1)
            access_token = resolved_access_token
        if enable_enterprise:
            resolved_hec_endpoint = (hec_endpoint or "").strip()
            if not resolved_hec_endpoint and non_interactive:
                click.echo(
                    "  error: --hec-endpoint is required with --enterprise --non-interactive",
                    err=True,
                )
                raise SystemExit(1)
            if not resolved_hec_endpoint:
                resolved_hec_endpoint = click.prompt(
                    "  HEC endpoint",
                    default="https://splunk.example.com:8088/services/collector/event",
                )
            resolved_hec_token = hec_token or os.environ.get("DEFENSECLAW_SPLUNK_HEC_TOKEN", "")
            if not resolved_hec_token and non_interactive:
                click.echo(
                    "  error: --hec-token required (or set DEFENSECLAW_SPLUNK_HEC_TOKEN env var)",
                    err=True,
                )
                raise SystemExit(1)
            if not resolved_hec_token:
                resolved_hec_token = _prompt_splunk_hec_token(None)
            if not resolved_hec_token:
                click.echo("  error: HEC token is required for Splunk Enterprise", err=True)
                raise SystemExit(1)
            hec_endpoint = resolved_hec_endpoint
            hec_token = resolved_hec_token
        if not _ensure_splunk_license_acceptance(
            accept_splunk_license=accept_splunk_license,
            non_interactive=non_interactive,
        ):
            return
        accept_splunk_license = True
        if s3_export and not (s3_bucket or os.environ.get("S3_BUCKET")):
            click.echo("  error: --s3-bucket is required with --s3-export (or set S3_BUCKET)", err=True)
            raise SystemExit(1)
        from defenseclaw.observability.local_splunk import preflight_native_local_splunk_setup
        from defenseclaw.observability.local_stack import LocalStackError

        try:
            preflight_native_local_splunk_setup(
                app.cfg.data_dir,
                license_accepted=True,
                require_s3=s3_export,
            )
        except LocalStackError as exc:
            raise click.ClickException(f"Local Splunk preflight failed: {exc}") from exc

        config_path = str(config_path_for_data_dir(app.cfg.data_dir))
        dotenv_path = os.path.join(app.cfg.data_dir, ".env")
        config_snapshot = _snapshot_regular_file(config_path, what="DefenseClaw config")
        dotenv_snapshot = _snapshot_dotenv(dotenv_path)
        setattr(app, _NATIVE_SPLUNK_CONFIG_SNAPSHOT_ATTR, config_snapshot)
        setattr(app, _NATIVE_SPLUNK_DOTENV_SNAPSHOT_ATTR, dotenv_snapshot)
        try:
            configure_o11y()
            configure_enterprise()
            configure_logs()
        except BaseException as exc:
            rollback_errors: list[str] = []
            try:
                _restore_regular_file_snapshot(
                    config_path,
                    config_snapshot[0],
                    config_snapshot[1],
                    what="DefenseClaw config",
                )
            except Exception as restore_exc:
                rollback_errors.append(f"config restore: {restore_exc}")
            try:
                _restore_dotenv_snapshot(dotenv_path, dotenv_snapshot[0], dotenv_snapshot[1])
            except Exception as restore_exc:
                rollback_errors.append(f"credential restore: {restore_exc}")
            try:
                _reload_cfg_from_data_dir(app)
            except Exception as reload_exc:
                rollback_errors.append(f"config reload after restore: {reload_exc}")
            if rollback_errors:
                raise click.ClickException(
                    "Combined Splunk setup failed and rollback was incomplete: " + "; ".join(rollback_errors)
                ) from exc
            raise
        finally:
            delattr(app, _NATIVE_SPLUNK_CONFIG_SNAPSHOT_ATTR)
            delattr(app, _NATIVE_SPLUNK_DOTENV_SNAPSHOT_ATTR)
    else:
        # Preserve the established macOS/Linux and remote-only sequence.
        configure_o11y()
        configure_logs()
        configure_enterprise()

    if not did_o11y and not did_logs and not did_enterprise:
        return

    # Note: no app.cfg.save() here — the observability writer invoked
    # from _apply_o11y_config / _apply_logs_config already persists to
    # config.yaml atomically. A second cfg.save() would be a no-op
    # round-trip now (Config.save deep-merges over the existing file
    # and preserves unmodelled keys), but it's still
    # wasteful so we skip it to keep this path single-writer.
    click.echo("  Config saved to ~/.defenseclaw/config.yaml")
    click.echo()
    _print_splunk_status(app)
    print_redaction_status_hint(app.cfg)
    click.echo()
    _print_splunk_next_steps(did_o11y, did_logs, did_enterprise)

    if app.logger:
        parts: list[str] = []
        if did_o11y:
            parts.append("o11y=enabled")
        if did_logs:
            parts.append("logs=enabled")
            if s3_export:
                parts.append("s3_export=enabled")
        if did_enterprise:
            parts.append("enterprise=enabled")
        app.logger.log_action(ACTION_SETUP_SPLUNK, "config", " ".join(parts))


# Register `defenseclaw setup splunk dashboards` (Terraform-backed dashboard
# and detector provisioning for Splunk Observability Cloud).
setup.add_command(setup_splunk)
setup_splunk.add_command(splunk_o11y_dashboards)


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------


def _interactive_splunk_setup(
    app: AppContext,
    realm: str | None,
    access_token: str | None,
    app_name: str | None,
    *,
    skip_test: bool = False,
) -> None:
    click.echo()
    click.echo("  Splunk Integration Setup")
    click.echo("  ────────────────────────")
    click.echo()
    click.echo("  DefenseClaw supports three Splunk pipelines. You can enable any combination.")
    click.echo()
    click.echo("  1. Splunk Observability Cloud (O11y)")
    click.echo("     Sends traces + metrics + logs via OTLP HTTP directly to Splunk cloud.")
    click.echo("     No local infrastructure needed. Requires a Splunk O11y access token.")
    click.echo()
    click.echo("  2. Local Splunk (Logs)")
    if local_shell_stacks_supported():
        click.echo("     Spins up a local Splunk container via Docker in Free mode from day 1.")
        click.echo("     Audit events are sent via HEC. Includes pre-built dashboards for DefenseClaw.")
        click.echo("     Requires Docker.")
    else:
        click.echo(f"     {LOCAL_SHELL_STACKS_UNSUPPORTED_REASON}")
    click.echo()
    click.echo("  3. Splunk Enterprise (Remote HEC)")
    click.echo("     Sends audit events to an existing Splunk Enterprise HEC endpoint.")
    click.echo("     Requires only a HEC endpoint and HEC token.")
    click.echo()

    did_o11y = False
    did_logs = False
    did_enterprise = False

    if _native_windows_local_splunk():
        enable_o11y = click.confirm("  Enable Splunk Observability Cloud (traces + metrics)?", default=False)
        enable_logs = local_shell_stacks_supported() and click.confirm(
            "  Enable local Splunk (Docker, HEC logs, Free mode)?", default=False
        )
        enable_enterprise = click.confirm("  Enable remote Splunk Enterprise (HEC)?", default=False)
        combined = enable_logs and (enable_o11y or enable_enterprise)
        config_path = str(config_path_for_data_dir(app.cfg.data_dir))
        dotenv_path = os.path.join(app.cfg.data_dir, ".env")
        config_snapshot = None
        dotenv_snapshot = None
        if combined:
            config_snapshot = _snapshot_regular_file(config_path, what="DefenseClaw config")
            dotenv_snapshot = _snapshot_dotenv(dotenv_path)
            setattr(app, _NATIVE_SPLUNK_CONFIG_SNAPSHOT_ATTR, config_snapshot)
            setattr(app, _NATIVE_SPLUNK_DOTENV_SNAPSHOT_ATTR, dotenv_snapshot)
        try:
            if enable_o11y:
                _interactive_o11y(app, realm, access_token, app_name)
                did_o11y = True
                click.echo()
                _interactive_o11y_dashboards(app)
                click.echo()
            # Native Local Splunk is intentionally last: its transactional
            # gateway reload activates every selected pipeline in one runtime
            # generation, and a failure restores the outer snapshots.
            if enable_enterprise:
                _interactive_enterprise(app, skip_test=skip_test)
                did_enterprise = True
            if enable_logs:
                did_logs = _interactive_logs(app)
        except BaseException as exc:
            rollback_errors: list[str] = []
            if combined and config_snapshot is not None and dotenv_snapshot is not None:
                try:
                    _restore_regular_file_snapshot(
                        config_path,
                        config_snapshot[0],
                        config_snapshot[1],
                        what="DefenseClaw config",
                    )
                    _restore_dotenv_snapshot(dotenv_path, dotenv_snapshot[0], dotenv_snapshot[1])
                    _reload_cfg_from_data_dir(app)
                except Exception as restore_exc:
                    rollback_errors.append(str(restore_exc))
            if rollback_errors:
                raise click.ClickException(
                    "Interactive Splunk setup failed and rollback was incomplete: " + "; ".join(rollback_errors)
                ) from exc
            raise
        finally:
            if combined:
                delattr(app, _NATIVE_SPLUNK_CONFIG_SNAPSHOT_ATTR)
                delattr(app, _NATIVE_SPLUNK_DOTENV_SNAPSHOT_ATTR)
    else:
        # Preserve the established macOS/Linux wizard sequence unchanged.
        if click.confirm("  Enable Splunk Observability Cloud (traces + metrics)?", default=False):
            _interactive_o11y(app, realm, access_token, app_name)
            did_o11y = True
            click.echo()
            _interactive_o11y_dashboards(app)
            click.echo()

        if local_shell_stacks_supported() and click.confirm(
            "  Enable local Splunk (Docker, HEC logs, Free mode)?", default=False
        ):
            did_logs = _interactive_logs(app)

        if click.confirm("  Enable remote Splunk Enterprise (HEC)?", default=False):
            _interactive_enterprise(app, skip_test=skip_test)
            did_enterprise = True

    if not did_o11y and not did_logs and not did_enterprise:
        click.echo()
        click.echo("  No Splunk pipelines enabled. Run again to configure.")
        return

    # The canonical v8 destination writer already persisted config.yaml;
    # avoid a second whole-document Config.save() after the surgical write.
    click.echo()
    click.echo("  Config saved to ~/.defenseclaw/config.yaml")
    click.echo()
    _print_splunk_status(app)
    print_redaction_status_hint(app.cfg)
    click.echo()
    _print_splunk_next_steps(did_o11y, did_logs, did_enterprise)

    if app.logger:
        parts = []
        if did_o11y:
            parts.append("o11y=enabled")
        if did_logs:
            parts.append("logs=enabled")
        if did_enterprise:
            parts.append("enterprise=enabled")
        app.logger.log_action(ACTION_SETUP_SPLUNK, "config", " ".join(parts))


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
        app,
        realm,
        access_token,
        app_name,
        enable_traces=enable_traces,
        enable_metrics=enable_metrics,
        enable_logs=enable_logs,
    )


def _interactive_o11y_dashboards(app: AppContext) -> bool:
    click.echo()
    click.echo("  Splunk O11y Dashboards")
    click.echo("  ──────────────────────")
    click.echo()
    if not click.confirm("  Install Splunk Observability Cloud dashboards now?", default=False):
        return False

    o11y_api_token = click.prompt(
        "  O11y API token (not the ingest token)",
        default="",
        show_default=False,
        hide_input=True,
    )
    if not o11y_api_token:
        click.echo("  error: O11y API token is required to install dashboards", err=True)
        raise SystemExit(1)

    apply_dashboards(
        app,
        api_url=None,
        o11y_api_token=o11y_api_token,
        name_prefix="",
        with_detectors=False,
        enable_detectors=False,
        detector_notifications=(),
        work_dir=None,
        state_path=None,
        terraform_bin="terraform",
        plugin_dir=None,
        skip_init=False,
        skip_validate=False,
        timeout=900,
        yes=True,
    )
    return True


def _prompt_splunk_token(current: str | None) -> str:
    env_val = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
    if current:
        hint = _mask(current)
    elif env_val:
        hint = f"from env: {_mask(env_val)}"
    else:
        hint = "(not set)"

    val = click.prompt(
        f"  O11y ingest access token [{hint}]",
        default="",
        show_default=False,
        hide_input=True,
    )
    if val:
        return val
    return current or env_val


def _prompt_splunk_hec_token(current: str | None) -> str:
    env_val = os.environ.get("DEFENSECLAW_SPLUNK_HEC_TOKEN", "")
    if current:
        hint = _mask(current)
    elif env_val:
        hint = f"from env: {_mask(env_val)}"
    else:
        hint = "(not set)"

    val = click.prompt(f"  HEC token [{hint}]", default="", show_default=False, hide_input=True)
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

    if not _native_windows_local_splunk():
        ok, _reason = _preflight_docker()
        if not ok:
            return False

    index = click.prompt("  Index name", default="defenseclaw_local")
    source = click.prompt("  Source", default="defenseclaw")
    sourcetype = click.prompt("  Sourcetype", default="defenseclaw:json")

    _apply_logs_config(app, index=index, source=source, sourcetype=sourcetype, bootstrap_bridge=True)
    return True


def _interactive_enterprise(app: AppContext, *, skip_test: bool = False) -> None:
    click.echo()
    click.echo("  Splunk Enterprise")
    click.echo("  ─────────────────")
    click.echo()

    endpoint = click.prompt(
        "  HEC endpoint",
        default="https://splunk.example.com:8088/services/collector/event",
    )
    token = _prompt_splunk_hec_token(None)
    if not token:
        click.echo("  error: HEC token is required for Splunk Enterprise", err=True)
        raise SystemExit(1)
    index = click.prompt("  Index name", default="defenseclaw")
    source = click.prompt("  Source", default="defenseclaw")
    sourcetype = click.prompt("  Sourcetype", default="_json")

    sink_name = _apply_enterprise_config(
        app,
        endpoint=endpoint,
        token=token,
        index=index,
        source=source,
        sourcetype=sourcetype,
    )
    click.echo("  Splunk Enterprise configured (HEC)")
    _maybe_probe_enterprise_hec(app, sink_name, skip_test=skip_test)


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
        app,
        realm,
        token,
        app_name,
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
    s3_export: bool = False,
    s3_bucket: str | None = None,
    s3_prefix: str | None = None,
    aws_region: str | None = None,
    refresh_bundle: bool = True,
) -> bool:
    if not _ensure_splunk_license_acceptance(
        accept_splunk_license=accept_splunk_license,
        non_interactive=non_interactive,
    ):
        return False

    ok, reason = (True, "") if _native_windows_local_splunk() else _preflight_docker()
    if not ok:
        if non_interactive:
            # Map the pre-flight reason code to a one-line, accurate
            # error so the operator does not have to re-read the
            # checklist above. Historically this branch always said
            # "Docker is required for --logs", which was misleading
            # when the actual failure was a busy port.
            detail = {
                "docker_not_installed": "Docker is not installed",
                "docker_daemon_not_running": "Docker daemon is not running",
            }.get(reason)
            if detail is None and reason.startswith("port_") and reason.endswith("_in_use"):
                # reason looks like "port_8000_in_use"
                port = reason.split("_", 2)[1]
                detail = f"port {port} is already in use — free it (or stop the existing Splunk instance) and re-run"
            if detail is None:
                detail = "pre-flight checks failed (see messages above)"
            click.echo(f"  error: {detail}", err=True)
            raise SystemExit(1)
        return False

    if s3_export and not (s3_bucket or os.environ.get("S3_BUCKET")):
        click.echo("  error: --s3-bucket is required with --s3-export (or set S3_BUCKET)", err=True)
        raise SystemExit(1)

    _apply_logs_config(
        app,
        index=index or "defenseclaw_local",
        source=source or "defenseclaw",
        sourcetype=sourcetype or "defenseclaw:json",
        bootstrap_bridge=True,
        s3_export=s3_export,
        s3_bucket=s3_bucket,
        s3_prefix=s3_prefix,
        aws_region=aws_region,
        refresh_bundle=refresh_bundle,
    )
    click.echo("  Local Splunk configured (Free mode from day 1)")
    return True


def _setup_enterprise(
    app: AppContext,
    *,
    hec_endpoint: str | None,
    hec_token: str | None,
    index: str | None = None,
    source: str | None = None,
    sourcetype: str | None = None,
    non_interactive: bool,
    skip_test: bool = False,
) -> None:
    endpoint = (hec_endpoint or "").strip()
    if not endpoint:
        if non_interactive:
            click.echo(
                "  error: --hec-endpoint is required with --enterprise --non-interactive",
                err=True,
            )
            raise SystemExit(1)
        endpoint = click.prompt(
            "  HEC endpoint",
            default="https://splunk.example.com:8088/services/collector/event",
        )

    token = hec_token or os.environ.get("DEFENSECLAW_SPLUNK_HEC_TOKEN", "")
    if not token and non_interactive:
        click.echo(
            "  error: --hec-token required (or set DEFENSECLAW_SPLUNK_HEC_TOKEN env var)",
            err=True,
        )
        raise SystemExit(1)
    if not token:
        token = _prompt_splunk_hec_token(None)
    if not token:
        click.echo("  error: HEC token is required for Splunk Enterprise", err=True)
        raise SystemExit(1)

    sink_name = _apply_enterprise_config(
        app,
        endpoint=endpoint,
        token=token,
        index=index or "defenseclaw",
        source=source or "defenseclaw",
        sourcetype=sourcetype or "_json",
    )
    click.echo("  Splunk Enterprise configured (HEC)")
    _maybe_probe_enterprise_hec(app, sink_name, skip_test=skip_test)


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


def _apply_v8_observability_preset(
    app: AppContext,
    preset_id: str,
    inputs: dict[str, str],
    *,
    name: str | None = None,
    signals: tuple[str, ...] | None = None,
    secret_value: str | None = None,
    secret_env_name: str | None = None,
) -> str:
    """Write one setup alias through the canonical v8 destination writer."""

    from defenseclaw.commands.cmd_setup_observability import (
        _add_v8_destination,
        _require_v8_operator_status,
    )
    from defenseclaw.observability import resolve_preset
    from defenseclaw.observability.v8_presets import destination_name, resolve_inputs

    _require_v8_operator_status(app.cfg.data_dir)
    preset = resolve_preset(preset_id)
    if secret_env_name:
        # Local Splunk owns a generated token that must remain independent
        # from the operator-provided remote Enterprise token.
        preset = replace(preset, token_env=secret_env_name)
    resolved = resolve_inputs(preset, inputs)
    resolved_name = destination_name(preset, name, resolved)
    _add_v8_destination(
        app.cfg.data_dir,
        preset,
        resolved,
        name=resolved_name,
        enabled=True,
        signals=signals,
        token_value=secret_value,
        target=None,
        dry_run=False,
    )
    return resolved_name


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
    """Keep ``setup splunk --o11y`` as a v8 destination preset alias."""

    signals = tuple(
        s
        for s, on in (
            ("traces", enable_traces),
            ("metrics", enable_metrics),
            ("logs", enable_logs),
        )
        if on
    )
    _apply_v8_observability_preset(
        app,
        "splunk-o11y",
        {"realm": realm},
        name=app_name,
        signals=signals or ("traces",),
        secret_value=access_token or None,
    )
    # OTEL_SERVICE_NAME stays a sibling env var: the OTel SDK env takes
    # precedence over resource.attributes.service.name, so this keeps the
    # effective service name even if the user later edits the YAML.
    _save_secret_to_dotenv("OTEL_SERVICE_NAME", app_name, app.cfg.data_dir)
    # Reload the non-observability Config view after the canonical v8 write.
    # Pin the reload to app.cfg.data_dir (not the default ~/.defenseclaw) so
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
    s3_export: bool = False,
    s3_bucket: str | None = None,
    s3_prefix: str | None = None,
    aws_region: str | None = None,
    refresh_bundle: bool = True,
) -> None:
    """Configure the local Splunk bridge as a canonical HEC destination."""
    if bootstrap_bridge and _native_windows_local_splunk():
        _apply_native_windows_logs_config(
            app,
            index=index,
            source=source,
            sourcetype=sourcetype,
            s3_export=s3_export,
            s3_bucket=s3_bucket,
            s3_prefix=s3_prefix,
            aws_region=aws_region,
            refresh_bundle=refresh_bundle,
        )
        return

    contract: dict[str, str] | None = None
    if bootstrap_bridge:
        contract = _bootstrap_bridge(
            app.cfg.data_dir,
            s3_export=s3_export,
            s3_bucket=s3_bucket,
            s3_prefix=s3_prefix,
            aws_region=aws_region,
            refresh_bundle=refresh_bundle,
        )
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

    _apply_v8_observability_preset(
        app,
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
        secret_value=hec_token or None,
    )
    _reload_cfg_from_data_dir(app)


def _apply_native_windows_logs_config(
    app: AppContext,
    *,
    index: str,
    source: str,
    sourcetype: str,
    s3_export: bool,
    s3_bucket: str | None,
    s3_prefix: str | None,
    aws_region: str | None,
    refresh_bundle: bool,
) -> None:
    """Commit native Local Splunk, its sink, and gateway as one transaction."""

    from defenseclaw.observability.local_splunk import (
        LOCAL_TOKEN_ENV,
        NativeSplunkSetupTransaction,
        start_native_local_splunk,
    )
    from defenseclaw.observability.local_stack import LocalStackError

    config_path = str(config_path_for_data_dir(app.cfg.data_dir))
    dotenv_path = os.path.join(app.cfg.data_dir, ".env")
    config_snapshot = getattr(app, _NATIVE_SPLUNK_CONFIG_SNAPSHOT_ATTR, None)
    if config_snapshot is None:
        config_snapshot = _snapshot_regular_file(config_path, what="DefenseClaw config")
    dotenv_snapshot = getattr(app, _NATIVE_SPLUNK_DOTENV_SNAPSHOT_ATTR, None)
    if dotenv_snapshot is None:
        dotenv_snapshot = _snapshot_dotenv(dotenv_path)
    prior_token_present = LOCAL_TOKEN_ENV in os.environ
    prior_token = os.environ.get(LOCAL_TOKEN_ENV)
    pid_file = os.path.join(app.cfg.data_dir, "gateway.pid")
    gateway_was_running = _is_pid_alive(pid_file) and _gateway_pid_file_identifies_gateway(pid_file)
    transaction: NativeSplunkSetupTransaction | None = None
    contract = None
    config_mutated = False
    click.echo("  Pre-flight checks:")
    try:
        transaction = start_native_local_splunk(
            app.cfg.data_dir,
            license_accepted=True,
            index=index,
            source=source,
            sourcetype=sourcetype,
            s3_export=s3_export,
            s3_bucket=s3_bucket,
            s3_prefix=s3_prefix,
            aws_region=aws_region,
            refresh_bundle=refresh_bundle,
        )
        contract = transaction.contract
        click.echo("    Docker Desktop, Compose v2, Linux containers, assets, and ports... ok")

        # Readiness is complete before the first DefenseClaw configuration
        # byte or root dotenv secret is changed.
        config_mutated = True
        _apply_v8_observability_preset(
            app,
            "splunk-hec",
            {
                "host": "127.0.0.1",
                "port": "8088",
                "endpoint": contract.hec_url,
                "index": contract.index,
                "source": contract.source,
                "sourcetype": contract.sourcetype,
                "verify_tls": "false",
            },
            name="local-splunk",
            secret_value=contract.hec_token,
            secret_env_name=LOCAL_TOKEN_ENV,
        )
        _reload_cfg_from_data_dir(app)

        if not _restart_defense_gateway_native(app.cfg.data_dir, start_if_stopped=True):
            raise LocalStackError("DefenseClaw gateway reload failed after Local Splunk configuration")
        transaction.controller.emit_product_telemetry("integration_configured")
        transaction.commit()
    except BaseException as exc:
        # Restore config and the shared dotenv before restoring the prior
        # gateway generation so it can never observe the failed sink.
        rollback_errors: list[str] = []
        if config_mutated:
            try:
                _restore_regular_file_snapshot(
                    config_path,
                    config_snapshot[0],
                    config_snapshot[1],
                    what="DefenseClaw config",
                )
            except Exception as restore_exc:
                rollback_errors.append(f"config restore: {restore_exc}")
            try:
                _restore_dotenv_snapshot(dotenv_path, dotenv_snapshot[0], dotenv_snapshot[1])
            except Exception as restore_exc:
                rollback_errors.append(f"credential restore: {restore_exc}")
            if prior_token_present and prior_token is not None:
                os.environ[LOCAL_TOKEN_ENV] = prior_token
            else:
                os.environ.pop(LOCAL_TOKEN_ENV, None)
        if transaction is not None:
            try:
                transaction.rollback()
            except Exception as rollback_exc:
                rollback_errors.append(f"stack restore: {rollback_exc}")
        if config_mutated:
            try:
                _reload_cfg_from_data_dir(app)
            except Exception as reload_exc:
                rollback_errors.append(f"config reload after restore: {reload_exc}")
            if gateway_was_running:
                if not _restart_defense_gateway_native(app.cfg.data_dir, start_if_stopped=True):
                    rollback_errors.append("prior gateway generation did not restart")
            elif _is_pid_alive(pid_file) and _gateway_pid_file_identifies_gateway(pid_file):
                if not _stop_defense_gateway_native(app.cfg.data_dir):
                    rollback_errors.append("gateway created by the failed attempt did not stop")
        if rollback_errors:
            raise click.ClickException(
                "Local Splunk setup failed and rollback was incomplete: " + "; ".join(rollback_errors)
            ) from exc
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(exc, click.ClickException):
            raise
        raise click.ClickException(f"Local Splunk setup failed: {exc}") from exc

    click.echo("  Local Splunk is ready")
    click.echo(f"    Web UI: {contract.splunk_web_url}")
    click.echo("    License: Free")
    click.echo("    Web authentication: disabled in Splunk Free mode")
    click.echo("    HEC: ready (token stored securely)")


def _apply_enterprise_config(
    app: AppContext,
    *,
    endpoint: str,
    token: str,
    index: str,
    source: str,
    sourcetype: str,
) -> str:
    """Configure a remote Splunk Enterprise HEC sink.

    This is intentionally config-only: no Docker preflight, local bridge
    bootstrap, Splunk license prompt, or Splunk-side token/index creation.
    """
    try:
        name = _apply_v8_observability_preset(
            app,
            "splunk-enterprise",
            {
                "endpoint": endpoint,
                "index": index,
                "source": source,
                "sourcetype": sourcetype,
            },
            secret_value=token or None,
        )
    except ValueError as exc:
        click.echo(f"  error: {exc}", err=True)
        raise SystemExit(2) from exc
    _reload_cfg_from_data_dir(app)
    return name


def _maybe_probe_enterprise_hec(
    app: AppContext,
    sink_name: str,
    *,
    skip_test: bool,
) -> None:
    if skip_test:
        click.echo("  Live HEC probe skipped.")
        return

    from defenseclaw.commands.cmd_setup_observability import _test_v8_destination

    click.echo("  Live HEC probe:")
    try:
        _test_v8_destination(app.cfg.data_dir, sink_name, 10.0, write_probe=False)
    except click.ClickException as exc:
        click.echo(f"    warning: {exc}")


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


def _refresh_and_maybe_restart_splunk_bridge(
    data_dir: str,
    *,
    env_file: str | None = None,
) -> RefreshResult:
    """Refresh the seeded Splunk bridge, stopping any running stack first.

    Sequence (all best-effort — refresh failures don't abort the parent
    setup flow because the operator can still run with a stale bundle):

    1. Detect a running ``defenseclaw-splunk-local`` compose project.
    2. If running and a bridge binary exists, invoke ``bridge down``
       to release the compose project (named volumes survive, so user
       data is preserved across the bounce).
    3. Refresh ``~/.defenseclaw/splunk-bridge/`` from the bundle. The
       refresh preserves operator secrets (``env/.env``) and the
       generated app tarball (``splunk/build/``).
    4. The caller then runs ``bridge up`` so the freshly refreshed
       bundle (compose, bin, s3_exporter Dockerfile, app source) is
       what materializes the next stack.

    Surface every step inline so an operator sees exactly what
    happened and never has to wonder why a previously-running stack
    came back up on a different image.
    """
    was_running = is_compose_project_running(SPLUNK_COMPOSE_PROJECT)
    stopped = False
    if was_running:
        click.echo(f"  {ux.dim('→')} Stopping running local Splunk stack to refresh bundle...")
        bridge = _resolve_bridge_bin(data_dir)
        if bridge:
            try:
                down_args = [bridge, "down"]
                if env_file:
                    down_args.extend(["--env-file", env_file])
                subprocess.run(
                    down_args,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                stopped = True
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
                click.echo(f"    warning: could not stop stack: {exc}")
        else:
            click.echo(
                "    warning: bridge binary missing — cannot stop stack cleanly. Run 'defenseclaw init' to seed."
            )

    result = refresh_splunk_bridge(data_dir)
    result.was_running = was_running
    result.stopped = stopped

    if result.skipped_reason:
        click.echo(f"  {ux.dim('→')} Bundle refresh skipped: {result.skipped_reason}")
        return result
    if result.errors:
        for err in result.errors[:3]:
            click.echo(f"  warning: refresh: {err}")
    if result.refreshed:
        count = len(result.refreshed_paths)
        preserved_count = len(result.preserved_paths)
        click.echo(
            f"  {ux.bold('Bundle refreshed:')} ~/.defenseclaw/splunk-bridge/ "
            f"({count} file{'s' if count != 1 else ''} updated, "
            f"{preserved_count} preserved)"
        )
    else:
        click.echo(f"  {ux.dim('→')} Bundle refresh: no changes (seeded copy already matches bundle)")
    return result


def _bootstrap_bridge(
    data_dir: str,
    *,
    s3_export: bool = False,
    s3_bucket: str | None = None,
    s3_prefix: str | None = None,
    aws_region: str | None = None,
    refresh_bundle: bool = True,
) -> dict[str, str] | None:
    """Start the local Splunk bridge and return the connection contract.

    When ``refresh_bundle=True`` (the default) we sync
    ``~/.defenseclaw/splunk-bridge/`` from the wheel/repo bundle before
    invoking ``up`` so newly-shipped compose, bin, app, and
    ``s3_exporter/`` changes take effect without requiring the operator
    to ``rm -rf`` the seeded copy. If a docker-compose project for the
    Splunk stack is already running we stop it first (Docker named
    volumes survive ``down``, so user data is preserved) so the new
    bundle is what gets brought back up.
    """
    env_file = _ensure_private_splunk_bridge_env(data_dir)
    if refresh_bundle:
        _refresh_and_maybe_restart_splunk_bridge(data_dir, env_file=env_file)

    bridge = _resolve_bridge_bin(data_dir)
    if not bridge:
        click.echo("  Splunk bridge runtime not found.")
        click.echo("  Run 'defenseclaw init' to seed it, or install from source.")
        return None

    click.echo("  Starting local Splunk (this takes ~2 minutes)...")
    env = None
    if s3_export:
        env = os.environ.copy()
        env["S3_EXPORT_ENABLED"] = "true"
        if s3_bucket:
            env["S3_BUCKET"] = s3_bucket
        if s3_prefix:
            env["S3_PREFIX"] = s3_prefix
        if aws_region:
            env["AWS_REGION"] = aws_region
    # Hoist `result` out of the try so the exception handlers below can
    # surface the bridge's stdout/stderr tails. Without this, a malformed
    # or empty JSON contract was reported only as the bare json module
    # exception ("Expecting value: line 1 column 1 (char 0)"), forcing
    # operators to re-run the bridge by hand to see what actually failed.
    result: subprocess.CompletedProcess[str] | None = None
    try:
        run_kwargs = {"capture_output": True, "text": True, "timeout": 300}
        if env is not None:
            run_kwargs["env"] = env
        result = subprocess.run(
            [bridge, "up", "--env-file", env_file, "--output", "json"],
            **run_kwargs,
        )
        if result.returncode != 0:
            click.echo(f"  Bridge startup failed (exit {result.returncode})")
            _echo_bridge_output_tail(result)
            return None

        stdout = (result.stdout or "").strip()
        if not stdout:
            click.echo(
                "  Bridge startup error: bridge exited 0 but produced no JSON "
                "contract on stdout (expected from `splunk-claw-bridge up "
                "--output json`)"
            )
            _echo_bridge_output_tail(result)
            return None
        contract = _json.loads(stdout)
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
    except _json.JSONDecodeError as exc:
        click.echo(f"  Bridge startup error: malformed JSON contract ({exc})")
        if result is not None:
            _echo_bridge_output_tail(result)
        return None
    except OSError as exc:
        click.echo(f"  Bridge startup error: {exc}")
        if result is not None:
            _echo_bridge_output_tail(result)
        return None


def _ensure_private_splunk_bridge_env(data_dir: str) -> str:
    """Create the private bridge env file used by the local Splunk stack.

    The bridge intentionally refuses to fall back to the checked-in
    ``.env.example`` because it contains public placeholders. The CLI
    setup path is responsible for creating an operator-owned copy with
    fresh local credentials, then passing it explicitly to the bridge.
    Existing files are preserved.
    """
    env_file = os.path.join(data_dir, _SPLUNK_BRIDGE_ENV_REL)
    reject_symlink(env_file, what="Splunk bridge env file")
    if os.path.isfile(env_file):
        _chmod_private_best_effort(env_file)
        return env_file

    example = _load_splunk_bridge_example_env(data_dir)
    if not example.get("SPLUNK_IMAGE"):
        raise click.ClickException("Splunk bridge env template is missing SPLUNK_IMAGE")

    env_dir = os.path.dirname(env_file)
    os.makedirs(env_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(env_dir, 0o700)
    except OSError:
        pass

    hec_token = str(uuid.uuid4())
    entries = dict(example)
    entries.update(
        {
            "SPLUNK_START_ARGS": "--accept-license",
            "SPLUNK_LICENSE_URI": "Free",
            "SPLUNK_GENERAL_TERMS": "--accept-sgt-current-at-splunk-com",
            "SPLUNK_PASSWORD": f"DefenseClawLocal-{secrets.token_hex(16)}!",
            "SPLUNK_HEC_TOKEN": hec_token,
            "DEFENSECLAW_HEC_URL": entries.get(
                "DEFENSECLAW_HEC_URL",
                "https://127.0.0.1:8088/services/collector/event",
            ),
            "DEFENSECLAW_HEC_TOKEN": hec_token,
            "DEFENSECLAW_INDEX": entries.get("DEFENSECLAW_INDEX", "defenseclaw_local"),
            "DEFENSECLAW_SOURCETYPE": entries.get("DEFENSECLAW_SOURCETYPE", "defenseclaw:json"),
            "DEFENSECLAW_SOURCE": entries.get("DEFENSECLAW_SOURCE", "defenseclaw"),
            "DEFENSECLAW_INTEGRATION_ENABLED": "true",
        }
    )
    _write_dotenv(env_file, entries)
    return env_file


def _load_splunk_bridge_example_env(data_dir: str) -> dict[str, str]:
    candidates = (
        os.path.join(data_dir, "splunk-bridge", "env", ".env.example"),
        str(bundled_splunk_bridge_dir() / "env" / ".env.example"),
    )
    for path in candidates:
        if os.path.isfile(path):
            return _load_dotenv(path)
    return {}


def _chmod_private_best_effort(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _echo_bridge_output_tail(
    result: subprocess.CompletedProcess[str],
    *,
    max_lines: int = 10,
) -> None:
    """Print the last ``max_lines`` of the bridge's stdout / stderr.

    Used by the failure paths in :func:`_bootstrap_bridge` so an
    operator can tell *why* the bridge failed without re-running it by
    hand. Both streams are emitted under labelled headers when present;
    streams that are empty (or whitespace-only) are skipped silently.
    """
    for label, raw in (
        ("Last bridge stdout", result.stdout),
        ("Last bridge stderr", result.stderr),
    ):
        text = (raw or "").strip()
        if not text:
            continue
        lines = text.splitlines()[-max_lines:]
        click.echo(f"  {label}:")
        for line in lines:
            click.echo(f"    {line}")


# ---------------------------------------------------------------------------
# Docker pre-flight
# ---------------------------------------------------------------------------


def _preflight_docker() -> tuple[bool, str]:
    """Check Docker prerequisites for the local Splunk stack.

    Returns ``(ok, reason)``. ``reason`` is an empty string on success
    and a short, machine-readable failure code on failure
    (``"docker_not_installed"``, ``"docker_daemon_not_running"``,
    ``"port_<n>_in_use"``). Callers surface ``reason`` verbatim in
    non-interactive error output so operators can tell *which* check
    failed without having to re-read the human-readable lines printed
    above (those lines remain the primary signal in interactive mode).
    """
    click.echo("  Pre-flight checks:")
    docker = shutil.which("docker")
    if not docker:
        click.echo("    Docker installed... NOT FOUND")
        click.echo("    Install Docker: https://docs.docker.com/get-docker/")
        return False, "docker_not_installed"
    click.echo("    Docker installed... ok")

    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            click.echo("    Docker daemon running... NOT RUNNING")
            click.echo("    Start Docker and try again.")
            return False, "docker_daemon_not_running"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        click.echo("    Docker daemon running... NOT RUNNING")
        return False, "docker_daemon_not_running"
    click.echo("    Docker daemon running... ok")

    for port, label in [(8000, "Splunk Web"), (8088, "HEC")]:
        if _port_in_use(port):
            click.echo(f"    Port {port} ({label})... IN USE")
            click.echo(f"    Free port {port} or stop the existing Splunk instance.")
            return False, f"port_{port}_in_use"
        click.echo(f"    Port {port} ({label})... available")

    return True, ""


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


# ---------------------------------------------------------------------------
# Disable
# ---------------------------------------------------------------------------


def _is_local_splunk_destination(dest) -> bool:
    return _is_local_hec_endpoint(str(getattr(dest, "endpoint", "") or ""))


def _is_owned_native_local_splunk_destination(dest) -> bool:
    """Return whether *dest* is the exact enabled sink owned by native setup."""

    return (
        getattr(dest, "name", "") == "local-splunk"
        and getattr(dest, "kind", "") == "splunk_hec"
        and bool(getattr(dest, "enabled", False))
        and _is_local_splunk_destination(dest)
    )


def _splunk_o11y_realm(endpoint: str) -> str:
    """Return the realm for a canonical Splunk O11y ingest endpoint."""

    parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
    host = (parsed.hostname or "").lower()
    prefix = "ingest."
    suffix = ".observability.splunkcloud.com"
    if not host.startswith(prefix) or not host.endswith(suffix):
        return ""
    realm = host[len(prefix) : -len(suffix)]
    return realm if realm and "." not in realm else ""


def _is_local_hec_endpoint(endpoint: str) -> bool:
    parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
    host = (parsed.hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1")


def _disable_splunk(
    app: AppContext,
    o11y_only: bool,
    logs_only: bool,
    enterprise_only: bool,
    non_interactive: bool,
) -> None:
    if logs_only and not local_shell_stacks_supported():
        raise click.ClickException(LOCAL_SHELL_STACKS_UNSUPPORTED_REASON)
    disable_both = not o11y_only and not logs_only and not enterprise_only
    manage_local = local_shell_stacks_supported()

    click.echo()
    click.echo("  Disabling Splunk integration...")

    native_controller = None
    native_was_running = False
    native_s3_export = False
    native_s3_overrides: dict[str, str] = {}
    native_windows = _native_windows_local_splunk()
    native_disable_requested = native_windows and manage_local and (disable_both or logs_only)
    config_snapshot: tuple[bytes | None, int | None] | None = None
    config_path = str(config_path_for_data_dir(app.cfg.data_dir))

    from defenseclaw.commands.cmd_setup_observability import (
        _require_v8_operator_status,
        _set_v8_destination_enabled,
    )

    dests = _require_v8_operator_status(app.cfg.data_dir).destinations
    managed_assets_path = os.path.join(app.cfg.data_dir, "splunk-bridge")
    native_disable = native_disable_requested and (
        any(_is_owned_native_local_splunk_destination(destination) for destination in dests)
        or os.path.lexists(managed_assets_path)
    )
    if native_disable:
        # Prove Docker, assets, volumes, ports, and exact Compose ownership
        # before either configuration or runtime changes.
        from defenseclaw.observability.local_splunk import prepare_native_local_splunk_stop
        from defenseclaw.observability.local_stack import LocalStackError

        try:
            native_controller, native_was_running = prepare_native_local_splunk_stop(app.cfg.data_dir)
            if native_controller is not None and native_was_running:
                native_s3_export, native_s3_overrides = native_controller.s3_runtime_state()
        except LocalStackError as exc:
            raise click.ClickException(f"could not validate owned Local Splunk stack: {exc}") from exc
        config_snapshot = _snapshot_regular_file(config_path, what="DefenseClaw config")

    try:
        if disable_both or o11y_only:
            for destination in dests:
                if destination.kind != "otlp" or not _splunk_o11y_realm(destination.endpoint):
                    continue
                try:
                    _set_v8_destination_enabled(app.cfg.data_dir, destination.name, False, "")
                except click.ClickException:
                    pass
            click.echo("    Splunk O11y (OTLP): disabled")

        if disable_both or logs_only or enterprise_only:
            disabled_local = False
            disabled_enterprise = False
            for destination in dests:
                if destination.kind != "splunk_hec" or not destination.enabled:
                    continue
                is_local = _is_local_splunk_destination(destination)
                if is_local and not manage_local:
                    continue
                if is_local and _native_windows_local_splunk() and getattr(destination, "name", "") != "local-splunk":
                    # Loopback alone is not ownership. Native disable manages
                    # only the exact sink created by this controller.
                    continue
                if not disable_both:
                    if logs_only and not is_local:
                        continue
                    if enterprise_only and is_local:
                        continue
                try:
                    _set_v8_destination_enabled(app.cfg.data_dir, destination.name, False, "")
                    if is_local:
                        disabled_local = True
                    else:
                        disabled_enterprise = True
                except click.ClickException:
                    continue
            if (disable_both or logs_only) and manage_local:
                suffix = "" if disabled_local else " (no active local sinks found)"
                click.echo(f"    Local Splunk (HEC): disabled{suffix}")
            if disable_both or enterprise_only:
                suffix = "" if disabled_enterprise else " (no active Enterprise sinks found)"
                click.echo(f"    Splunk Enterprise (HEC): disabled{suffix}")

        _reload_cfg_from_data_dir(app)
        if native_disable:
            if native_controller is not None and native_was_running:
                native_controller.down()
        elif (disable_both or logs_only) and manage_local and not native_windows:
            _stop_bridge(app.cfg.data_dir)
    except BaseException as exc:
        rollback_errors: list[str] = []
        if config_snapshot is not None:
            try:
                _restore_regular_file_snapshot(
                    config_path,
                    config_snapshot[0],
                    config_snapshot[1],
                    what="DefenseClaw config",
                )
                _reload_cfg_from_data_dir(app)
            except Exception as restore_exc:
                rollback_errors.append(f"config restore: {restore_exc}")
        if native_controller is not None and native_was_running:
            try:
                native_controller.up(
                    s3_export=native_s3_export,
                    overrides=native_s3_overrides,
                    emit_startup_telemetry=False,
                )
            except Exception as restart_exc:
                rollback_errors.append(f"stack restore: {restart_exc}")
        if rollback_errors:
            raise click.ClickException(
                "Splunk disable failed and rollback was incomplete: " + "; ".join(rollback_errors)
            ) from exc
        if isinstance(exc, (KeyboardInterrupt, SystemExit, click.ClickException)):
            raise
        raise click.ClickException(f"Splunk disable failed: {exc}") from exc

    click.echo("  Config saved")
    click.echo()

    if app.logger:
        parts = []
        if disable_both or o11y_only:
            parts.append("o11y=disabled")
        if disable_both or logs_only:
            parts.append("logs=disabled")
        if disable_both or enterprise_only:
            parts.append("enterprise=disabled")
        app.logger.log_action(ACTION_SETUP_SPLUNK, "config", " ".join(parts))


def _stop_bridge(data_dir: str) -> None:
    if not local_shell_stacks_supported():
        return
    if _native_windows_local_splunk():
        from defenseclaw.observability.local_splunk import stop_native_local_splunk
        from defenseclaw.observability.local_stack import LocalStackError

        try:
            stopped = stop_native_local_splunk(data_dir)
        except LocalStackError as exc:
            raise click.ClickException(f"could not stop owned Local Splunk stack: {exc}") from exc
        if stopped:
            click.echo("    Local Splunk container stopped (volumes preserved)")
        else:
            click.echo("    Local Splunk container was not running (volumes preserved)")
        return
    bridge = _resolve_bridge_bin(data_dir)
    if not bridge:
        return
    try:
        subprocess.run(
            [bridge, "down"],
            capture_output=True,
            text=True,
            timeout=60,
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
    with locked_file_update(dotenv_path):
        snapshot = _rotate_token_snapshot_locked(dotenv_path)
        _save_secrets_to_dotenv_locked(
            dotenv_path,
            snapshot,
            ((key, value),),
        )
    os.environ[key] = value


# ---------------------------------------------------------------------------
# Status display
# ---------------------------------------------------------------------------


def _print_splunk_status(app: AppContext) -> None:
    """Print Splunk integrations from the canonical v8 effective plan."""

    from defenseclaw.commands.cmd_setup_observability import _require_v8_operator_status

    destinations = _require_v8_operator_status(app.cfg.data_dir).destinations
    o11y_destinations = [
        destination
        for destination in destinations
        if destination.kind == "otlp" and _splunk_o11y_realm(destination.endpoint)
    ]
    hec_destinations = [destination for destination in destinations if destination.kind == "splunk_hec"]
    any_route_enabled = any(destination.enabled for destination in (*o11y_destinations, *hec_destinations))

    for destination in o11y_destinations:
        suffix = f" [{destination.name}]" if len(o11y_destinations) > 1 else ""
        click.echo(f"  Splunk Observability Cloud (OTLP){suffix}:")
        click.echo(f"    Status:      {'enabled' if destination.enabled else 'disabled'}")
        click.echo(f"    Destination: {destination.name}")
        click.echo(f"    Realm:       {_splunk_o11y_realm(destination.endpoint)}")
        click.echo(f"    Endpoint:    {destination.endpoint}")
        signals = ", ".join(destination.selected_signals) or "none"
        click.echo(f"    Signals:     {signals}")
        buckets = ", ".join(destination.buckets) or "none"
        click.echo(f"    Buckets:     {buckets}")
        click.echo(f"    Redaction:   {destination.redaction_label}")
        dotenv_path = os.path.join(app.cfg.data_dir, ".env")
        dotenv = _load_dotenv(dotenv_path)
        svc = dotenv.get("OTEL_SERVICE_NAME", os.environ.get("OTEL_SERVICE_NAME", "defenseclaw"))
        click.echo(f"    Service:     {svc}")
        click.echo()

    for destination in hec_destinations:
        hec_label = "Local Splunk (HEC)" if _is_local_hec_endpoint(destination.endpoint) else "Splunk Enterprise (HEC)"
        suffix = f" [{destination.name}]" if len(hec_destinations) > 1 else ""
        click.echo(f"  {hec_label}{suffix}:")
        click.echo(f"    Status:      {'enabled' if destination.enabled else 'disabled'}")
        click.echo(f"    Destination: {destination.name}")
        click.echo(f"    HEC:         {destination.endpoint}")
        buckets = ", ".join(destination.buckets) or "none"
        click.echo(f"    Buckets:     {buckets}")
        click.echo(f"    Redaction:   {destination.redaction_label}")
        click.echo()

    if not any_route_enabled:
        click.echo("  No Splunk integrations are currently enabled.")
        click.echo()


def _print_splunk_next_steps(did_o11y: bool, did_logs: bool, did_enterprise: bool = False) -> None:
    click.echo("  Next steps:")
    click.echo("    1. Start (or restart) the DefenseClaw sidecar:")
    click.echo("       defenseclaw-gateway restart")
    if did_logs:
        click.echo("    2. Open local Splunk Web at http://127.0.0.1:8000")
        if _native_windows_local_splunk():
            click.echo("       Web authentication is disabled in Splunk Free mode.")
            click.echo("       To view the HEC/runtime secrets explicitly: defenseclaw setup splunk --show-credentials")
        else:
            click.echo("       Log in with admin / the password from setup output above.")
            click.echo("       To view credentials later: defenseclaw setup splunk --show-credentials")
        click.echo("    3. Validate data in local Splunk")
    if did_enterprise:
        step = "3" if did_logs else "2"
        click.echo(f"    {step}. Validate data in Splunk Enterprise")
        click.echo("       index=<configured index> source=defenseclaw")
    click.echo()
    click.echo("  To disable:")
    if did_o11y and did_logs and did_enterprise:
        click.echo("    defenseclaw setup splunk --disable                 # all")
        click.echo("    defenseclaw setup splunk --disable --o11y          # O11y only")
        click.echo("    defenseclaw setup splunk --disable --logs          # local only")
        click.echo("    defenseclaw setup splunk --disable --enterprise    # Enterprise only")
    elif did_o11y and did_logs:
        click.echo("    defenseclaw setup splunk --disable            # both")
        click.echo("    defenseclaw setup splunk --disable --o11y     # O11y only")
        click.echo("    defenseclaw setup splunk --disable --logs     # local only")
    elif did_o11y and did_enterprise:
        click.echo("    defenseclaw setup splunk --disable                 # both")
        click.echo("    defenseclaw setup splunk --disable --o11y          # O11y only")
        click.echo("    defenseclaw setup splunk --disable --enterprise    # Enterprise only")
    elif did_logs and did_enterprise:
        click.echo("    defenseclaw setup splunk --disable                 # both")
        click.echo("    defenseclaw setup splunk --disable --logs          # local only")
        click.echo("    defenseclaw setup splunk --disable --enterprise    # Enterprise only")
    elif did_o11y:
        click.echo("    defenseclaw setup splunk --disable --o11y")
    elif did_logs:
        click.echo("    defenseclaw setup splunk --disable --logs")
    elif did_enterprise:
        click.echo("    defenseclaw setup splunk --disable --enterprise")


def _show_splunk_credentials(data_dir: str) -> None:
    """Explicitly display generated HEC and runtime-only bootstrap secrets."""
    env_file = os.path.join(data_dir, "splunk-bridge", "env", ".env")
    values: dict[str, str] = {}
    native = _native_windows_local_splunk()
    try:
        if native:
            from defenseclaw.observability.local_splunk import load_native_local_splunk_credentials

            values = load_native_local_splunk_credentials(data_dir)
        elif os.path.isfile(env_file):
            reject_symlink(env_file, what="Splunk bridge env file")
            values = _load_dotenv(env_file)
    except (OSError, ValueError, RuntimeError):
        values = {}

    password = values.get("SPLUNK_PASSWORD", "")
    hec_token = values.get("DEFENSECLAW_HEC_TOKEN", "")
    if not password and not hec_token:
        click.echo("  Splunk credentials not found.")
        click.echo(f"  Expected env file: {env_file}")
        click.echo("  Run 'defenseclaw setup splunk --logs' to start local Splunk.")
        return

    click.echo()
    if native:
        click.echo("  Local Splunk Generated Secrets")
        click.echo("  ──────────────────────────────")
        click.echo("    URL:       http://127.0.0.1:8000")
        click.echo("    Web auth:  disabled in Splunk Free mode (no login credentials)")
        if hec_token:
            click.echo(f"    HEC token: {hec_token}")
        if password:
            click.echo(f"    Runtime bootstrap secret: {password}")
            click.echo("    Note: this secret is required by the container at startup; it is not a Web login.")
    else:
        click.echo("  Splunk Web Credentials")
        click.echo("  ──────────────────────")
        click.echo("    URL:       http://127.0.0.1:8000")
        click.echo("    Username:  admin")
        click.echo(f"    Password:  {password}")
    click.echo()
