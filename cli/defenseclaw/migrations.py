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

"""Version-specific migrations for DefenseClaw upgrades.

Each migration is keyed to the target version it ships with. During upgrade,
all migrations between the old version and the new version are applied in
order via ``run_migrations``.

Design contract for every migration:

* **Idempotent** — safe to re-run on an already-migrated install.
* **Atomic** — mutations write to a temp file and rename, never partial
  state on a crash.
* **Fail-safe** — a failure in one step is logged and the migration
  continues; the upgrade itself never aborts due to a migration error,
  because a half-upgraded install with a half-applied migration is
  worse than an upgraded install with stale residue we can clean up
  later via ``defenseclaw doctor --fix``.
* **No-touch** — operators do nothing; the migration runs automatically
  during ``defenseclaw upgrade``.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field

import click

from defenseclaw import ux


def _ver_tuple(v: str) -> tuple[int, ...]:
    """Parse a semver string like '0.3.0' into a comparable tuple.

    Defensive against malformed input (e.g. ``0.3.0-rc1`` from a
    development build): non-numeric segments are coerced to ``0`` so
    range comparisons never raise.
    """
    out: list[int] = []
    for part in v.split("."):
        # Strip any pre-release suffix (e.g. "0-rc1" → "0").
        m = re.match(r"\d+", part)
        out.append(int(m.group(0)) if m else 0)
    return tuple(out)


# ---------------------------------------------------------------------------
# MigrationContext
# ---------------------------------------------------------------------------


@dataclass
class MigrationContext:
    """Inputs every migration needs.

    Older single-arg migrations (``_migrate_0_3_0``) only depended on
    ``openclaw_home``; the connector-architecture-v3 wave (PR #194)
    added on-disk state under ``data_dir`` (``.env``, ``device.key``,
    ``codex_backup.json``, ``active_connector.json``, ``hooks/``), so
    the context bundles both. New migrations should prefer the
    context fields over re-deriving paths from ``os.path.expanduser``
    so tests can inject temporary directories without monkey-patching
    HOME.
    """

    openclaw_home: str
    data_dir: str
    from_version: str = ""
    to_version: str = ""
    # changes accumulates a one-line summary per applied step. The
    # upgrade command surfaces these so an operator can audit what the
    # no-touch migration actually changed under their HOME.
    changes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Migration: 0.3.0
# ---------------------------------------------------------------------------


def _migrate_0_3_0(ctx: MigrationContext) -> None:
    """Remove legacy defenseclaw model/provider entries from openclaw.json.

    0.2.0's guardrail setup added models.providers.defenseclaw and/or
    models.providers.litellm to openclaw.json to redirect traffic, and set
    agents.defaults.model.primary to "defenseclaw/<model>".

    The fetch interceptor introduced in 0.3.0 handles routing transparently,
    so these entries are no longer needed and must be cleaned up on upgrade.

    Strategy: restore the pristine backup of openclaw.json that was captured
    before DefenseClaw first touched the file, then re-apply only the plugin
    registration that 0.3.0 needs. This is cleaner than surgically patching
    individual keys and avoids leaving behind stale or unexpected entries.

    Falls back to surgical removal if no pristine backup exists (e.g.
    guardrail was never enabled, or the backup was deleted).
    """
    oc_json = os.path.join(ctx.openclaw_home, "openclaw.json")
    if not os.path.isfile(oc_json):
        return

    from defenseclaw.guardrail import pristine_backup_path

    pristine = pristine_backup_path(oc_json, ctx.data_dir)

    if pristine:
        _migrate_0_3_0_from_pristine(oc_json, pristine)
    else:
        _migrate_0_3_0_surgical(oc_json)


def _migrate_0_3_0_from_pristine(oc_json: str, pristine: str) -> None:
    """Restore pristine openclaw.json and re-apply plugin registration."""
    try:
        with open(pristine) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        click.echo(f"    pristine backup unreadable ({exc}), falling back to surgical fix")
        _migrate_0_3_0_surgical(oc_json)
        return

    plugins = cfg.setdefault("plugins", {})
    allow = plugins.setdefault("allow", [])
    if "defenseclaw" not in allow:
        allow.append("defenseclaw")
    entries = plugins.setdefault("entries", {})
    if "defenseclaw" not in entries:
        entries["defenseclaw"] = {"enabled": True}
    else:
        entries["defenseclaw"]["enabled"] = True
    install_path = os.path.join(os.path.dirname(oc_json), "extensions", "defenseclaw")
    load = plugins.setdefault("load", {})
    paths = load.setdefault("paths", [])
    if install_path not in paths:
        paths.append(install_path)

    shutil.copy2(oc_json, oc_json + ".pre-0.3.0-migration")

    with open(oc_json, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    click.echo(f"    restored openclaw.json from pristine backup ({os.path.basename(pristine)})")
    click.echo("    re-applied plugin registration for 0.3.0")


def _migrate_0_3_0_surgical(oc_json: str) -> None:
    """Fallback: surgically remove legacy entries when no pristine backup exists."""
    try:
        with open(oc_json) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    changed = False
    changes = []

    providers = cfg.get("models", {}).get("providers", {})
    for key in ("defenseclaw", "litellm"):
        if key in providers:
            del providers[key]
            changes.append(f"removed providers.{key}")
            changed = True

    model = cfg.get("agents", {}).get("defaults", {}).get("model", {})
    primary = model.get("primary", "")
    if primary.startswith(("defenseclaw/", "litellm/")):
        restored = primary.split("/", 1)[1]
        model["primary"] = restored
        changes.append(f"restored model.primary: {primary} → {restored}")
        changed = True

    if not changed:
        click.echo("    (no legacy entries found — nothing to change)")
        return

    with open(oc_json, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    for c in changes:
        click.echo(f"    {c}")
    click.echo("    (no pristine backup found — applied surgical fix)")


# ---------------------------------------------------------------------------
# Migration: 0.4.0 — Connector architecture v3 (PR #194)
# ---------------------------------------------------------------------------
#
# PR #194 lands the connector v3 wave. The breaking-for-existing-users
# pieces this migration addresses, in order:
#
#   1. **DEFENSECLAW_GATEWAY_TOKEN bootstrap (S0.2)** — pre-v3 sidecars
#      fail-opened on missing token (loopback-allow). The new sidecar
#      fail-CLOSES on empty token, so any 0.3.x install that skipped
#      ``defenseclaw setup rotate-token`` would lock itself out of
#      /api/v1/inspect/* and the connector hook endpoints. We
#      synthesise a 32-byte CSPRNG hex token and atomically write it
#      to ``<data_dir>/.env`` with mode 0o600. The legacy
#      ``OPENCLAW_GATEWAY_TOKEN`` name is renamed if encountered so an
#      operator who hand-edited the .env keeps their value.
#
#   2. **File perms tighten** — ``.env``, ``device.key`` and any
#      ``*_backup.json`` left behind by intermediate dev builds are
#      ``chmod 0o600`` (S0.11/S0.15/H4/M3 require credentials-bearing
#      files to be operator-only).
#
#   3. **Legacy Codex env override files (S8.1 / F31)** — older
#      releases wrote ``codex_env.sh`` / ``codex.env`` under
#      ``data_dir`` that exported a global ``OPENAI_BASE_URL``. That
#      bled into non-Codex OpenAI SDK clients on the same box. The
#      new connector patches ``~/.codex/config.toml`` instead, scoped
#      to Codex. We delete the legacy files here so an upgrade leaves
#      the operator's host pristine, regardless of whether they ever
#      sourced the file from their shell rc.
#
#   4. **OTel claw.mode enum normalisation (S3.1 / F9)** — the
#      ``defenseclaw.claw.mode`` enum used to include ``nemoclaw`` and
#      ``opencode`` (forward-looking placeholders that never shipped a
#      Connector.Name() value). After PR #194 those values fail
#      schema validation in resource.schema.json. If ``config.yaml``
#      has either pinned, we coerce them to the closest live name
#      (``openclaw`` / ``codex``) so telemetry doesn't silently drop.
#
#   5. **Active-connector state seed** — pre-v3 had no
#      ``active_connector.json``. The sidecar's connector-handoff
#      logic (teardownPreviousConnector before Setup of the new one)
#      reads this file at boot to detect a switch. For an OpenClaw-
#      only install we seed it to "openclaw" so the very first
#      sidecar boot post-upgrade does NOT think the user has just
#      switched away from a phantom prior connector.
#
# This migration is intentionally permissive on errors: an individual
# step may fail (read-only filesystem, missing parent dir, custom
# DEFENSECLAW_HOME the operator forgot to migrate to the new path) but
# the upgrade itself MUST NOT abort. Each step logs a click warning
# and the migration moves on.

# Legacy Codex env override files retired in S8.1 / F31. Mirrors the
# constants in internal/gateway/connector/codex.go (codexEnvFileName,
# codexDotenvFileName) — drift here would silently leave the file on
# disk, which is exactly the failure mode we are migrating away from.
_LEGACY_CODEX_ENV_FILES = ("codex_env.sh", "codex.env")

# Legacy OTel claw.mode enum values that no longer round-trip through
# resource.schema.json after PR #194. Mapping target is the closest
# live connector name; we never invent a connector that wasn't already
# enabled, so for "opencode" (forward-looking placeholder for an
# agent that never shipped) we fall back to "openclaw" too rather than
# pretend the user opted into Codex.
_LEGACY_CLAW_MODE_REMAP = {
    "nemoclaw": "openclaw",
    "opencode": "openclaw",
}


def _migrate_0_4_0(ctx: MigrationContext) -> None:
    """No-touch migration for the connector-architecture-v3 wave (PR #194).

    Runs every step independently; any single failure is reported but
    does not block the rest of the migration. See the module-level
    docstring for the per-step rationale.
    """
    if not os.path.isdir(ctx.data_dir):
        # No data dir yet means the operator is upgrading from a
        # version that never finished its first ``defenseclaw setup``.
        # Nothing to migrate; the new sidecar will bootstrap on
        # first boot via the same firstboot.go path.
        click.echo(f"    (no data dir at {ctx.data_dir} — fresh install will bootstrap)")
        return

    _migrate_0_4_0_token_bootstrap(ctx)
    _migrate_0_4_0_tighten_perms(ctx)
    _migrate_0_4_0_remove_legacy_codex_env(ctx)
    _migrate_0_4_0_normalize_claw_mode(ctx)
    _migrate_0_4_0_seed_active_connector(ctx)
    _migrate_0_4_0_seed_hook_fail_mode(ctx)

    if ctx.changes:
        click.echo(f"    applied {len(ctx.changes)} change(s):")
        for c in ctx.changes:
            click.echo(f"      • {c}")
    else:
        click.echo("    (already on connector-v3 layout — no changes needed)")


def _migrate_0_4_0_token_bootstrap(ctx: MigrationContext) -> None:
    """Synthesise ``DEFENSECLAW_GATEWAY_TOKEN`` if missing.

    Mirrors EnsureGatewayToken in internal/gateway/firstboot.go so an
    operator running ``defenseclaw upgrade`` ends up with the same
    state the new sidecar would create on first boot. Doing it here
    means the very first post-upgrade gateway start has the token in
    place, so /api/v1/inspect/* doesn't 401 in the upgrade health
    check window.

    Comment-preservation contract: rewrites use ``_dotenv_update_keys``
    which patches matching ``KEY=VALUE`` lines in place and appends
    new keys at the end. Operator-curated comment lines, blank lines,
    and the order of unrelated keys are preserved byte-for-byte.
    """
    env_path = os.path.join(ctx.data_dir, ".env")

    existing = _parse_dotenv(env_path)

    # If the new var is already set, only fix file perms and return.
    if existing.get("DEFENSECLAW_GATEWAY_TOKEN", "").strip():
        return

    # Promote the legacy var name to the new canonical one without
    # rotating the secret value — operators may have wired it into
    # CI / agent process env, and silently rotating breaks them.
    legacy = existing.get("OPENCLAW_GATEWAY_TOKEN", "").strip()
    if legacy:
        if _dotenv_update_keys(
            env_path,
            updates={"DEFENSECLAW_GATEWAY_TOKEN": legacy},
            removes=("OPENCLAW_GATEWAY_TOKEN",),
        ):
            ctx.changes.append(
                "renamed legacy OPENCLAW_GATEWAY_TOKEN → DEFENSECLAW_GATEWAY_TOKEN in .env"
            )
        return

    # No token at all — synthesise a 32-byte CSPRNG hex string. Use
    # secrets.token_hex which wraps os.urandom; matches the Go
    # rand.Read + hex.EncodeToString contract in firstboot.go.
    token = secrets.token_hex(32)
    if _dotenv_update_keys(
        env_path,
        updates={"DEFENSECLAW_GATEWAY_TOKEN": token},
    ):
        ctx.changes.append(
            "generated first-boot DEFENSECLAW_GATEWAY_TOKEN at "
            f"{env_path} (mode 0600, 32-byte CSPRNG)"
        )


# Files under data_dir that carry credentials or pristine backups and
# must be operator-only. Aligned with the 0o600 mode the Go connectors
# use when they write fresh; this step exists to clean up files that a
# pre-PR194 release wrote with looser perms.
_DATA_DIR_SECRET_FILES = (
    ".env",
    "device.key",
    "codex_backup.json",
    "claudecode_backup.json",
    "zeptoclaw_backup.json",
    "codex_config_backup.json",
    "active_connector.json",
    "guardrail_runtime.json",
)


def _migrate_0_4_0_tighten_perms(ctx: MigrationContext) -> None:
    """chmod 0o600 every credentials-bearing file under data_dir.

    Idempotent: a file that is already 0o600 is unchanged (we still
    issue the chmod because it's cheap and avoids an extra stat).
    Files that don't exist are skipped silently.
    """
    for name in _DATA_DIR_SECRET_FILES:
        path = os.path.join(ctx.data_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            current = os.stat(path).st_mode & 0o777
            if current == 0o600:
                continue
            os.chmod(path, 0o600)
            ctx.changes.append(f"tightened perms on {name} ({oct(current)} → 0o600)")
        except OSError as exc:
            ux.warn(f"could not chmod {path}: {exc}", indent="    ")

    managed_root = os.path.join(ctx.data_dir, "connector_backups")
    if not os.path.isdir(managed_root):
        return
    for root, _dirs, files in os.walk(managed_root):
        for filename in files:
            path = os.path.join(root, filename)
            try:
                current = os.stat(path).st_mode & 0o777
                if current == 0o600:
                    continue
                os.chmod(path, 0o600)
                rel = os.path.relpath(path, ctx.data_dir)
                ctx.changes.append(f"tightened perms on {rel} ({oct(current)} → 0o600)")
            except OSError as exc:
                ux.warn(f"could not chmod {path}: {exc}", indent="    ")


def _migrate_0_4_0_remove_legacy_codex_env(ctx: MigrationContext) -> None:
    """Delete legacy codex_env.sh / codex.env files (S8.1 / F31).

    These were the global OPENAI_BASE_URL writes that bled into
    non-Codex OpenAI SDK clients. The new connector scopes routing to
    ``~/.codex/config.toml``'s ``[model_providers.*].base_url``.
    """
    for name in _LEGACY_CODEX_ENV_FILES:
        path = os.path.join(ctx.data_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            os.remove(path)
            ctx.changes.append(
                f"removed legacy codex env override {name} "
                "(S8.1: replaced by ~/.codex/config.toml patch)"
            )
        except OSError as exc:
            ux.warn(f"could not remove {path}: {exc}", indent="    ")


def _migrate_0_4_0_normalize_claw_mode(ctx: MigrationContext) -> None:
    """Rewrite legacy claw.mode values that fail OTel schema validation.

    We do a string-level rewrite of config.yaml rather than using the
    YAML loader because the loader pulls in the entire dataclass tree
    (which has its own back-compat handling for the very fields we are
    trying to migrate) — a surgical sed-style edit is safer here. The
    rewrite is anchored to the ``claw:`` block so a stray ``mode:
    nemoclaw`` somewhere else in config.yaml is not touched.
    """
    cfg_path = os.path.join(ctx.data_dir, "config.yaml")
    if not os.path.isfile(cfg_path):
        return

    try:
        with open(cfg_path) as f:
            text = f.read()
    except OSError as exc:
        ux.warn(f"could not read {cfg_path}: {exc}", indent="    ")
        return

    new_text = text
    for legacy, replacement in _LEGACY_CLAW_MODE_REMAP.items():
        # Match `mode: <legacy>` only inside the claw block. Since
        # YAML allows arbitrary indentation we look for the literal
        # `claw:` line followed (at any distance) by an indented
        # `mode: <legacy>`. The trailing-context group preserves any
        # closing quote, surrounding whitespace, and an optional
        # YAML inline comment (``mode: nemoclaw  # legacy``) so a
        # commented hand-edited line still normalizes cleanly. The
        # pattern still rejects flow-style mappings (``claw: { mode:
        # nemoclaw }``) — those round-trip correctly through
        # ``config.save()`` so the operator either edited them
        # manually or the upgrade is harmless.
        pattern = re.compile(
            r"(^claw:[ \t]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+mode:[ \t]*[\"']?)"
            + re.escape(legacy)
            + r"([\"']?[ \t]*(?:#[^\n]*)?$)",
            flags=re.MULTILINE,
        )
        new_text, count = pattern.subn(rf"\g<1>{replacement}\g<2>", new_text)
        if count:
            ctx.changes.append(
                f"normalized claw.mode: {legacy} → {replacement} "
                "(S3.1: legacy enum dropped from OTel schema)"
            )

    if new_text != text:
        if not _atomic_write_text(cfg_path, new_text):
            ux.warn(f"could not write {cfg_path}", indent="    ")


def _migrate_0_4_0_seed_active_connector(ctx: MigrationContext) -> None:
    """Seed ``<data_dir>/active_connector.json`` for pre-v3 installs.

    Without this seed, the post-upgrade sidecar boot would see no
    file and assume "first connector boot ever" — which is benign
    today, but on a future config change that surfaces a previous
    connector via guardrail.connector, the absence of an active
    connector marker would suppress the teardownPreviousConnector
    hop. Seeding the marker explicitly makes the on-disk state match
    what a fresh ``defenseclaw setup`` would have produced.
    """
    state_path = os.path.join(ctx.data_dir, "active_connector.json")
    if os.path.isfile(state_path):
        return

    # Best-effort active-connector inference. We don't load the full
    # config (it has v3-only fields) but we do read claw.mode out of
    # the raw YAML so the seed reflects the operator's actual setup.
    name = _read_active_connector_from_yaml(
        os.path.join(ctx.data_dir, "config.yaml")
    )
    if not name:
        # Pre-v3 default — config.yaml's claw.mode defaulted to
        # "openclaw" and that is the only connector that pre-v3
        # supported.
        name = "openclaw"

    payload = json.dumps({"name": name}, ensure_ascii=False)
    if _atomic_write_text(state_path, payload, mode=0o600):
        ctx.changes.append(
            f"seeded active_connector.json with {name!r} "
            "(pre-v3 had no connector state file)"
        )


_GUARDRAIL_BLOCK_RE = re.compile(
    # Captures the literal ``guardrail:`` header line (incl. trailing
    # newline) so we can re-emit it verbatim while inserting our key
    # immediately below it. We deliberately match only the header and
    # NOT the entire block — the block body is rewritten in place by
    # the substitution callback in _migrate_0_4_0_seed_hook_fail_mode,
    # which preserves every comment, blank line, and scalar quoting
    # choice the operator made under ``guardrail:``.
    r"^guardrail:[ \t]*\n",
    flags=re.MULTILINE,
)

# Detect whether ``hook_fail_mode:`` is already present anywhere
# inside the guardrail block. The block extends from the
# ``guardrail:`` header until the next top-level YAML key (a line
# that starts at column 0 and matches ``key:``) or end-of-file.
# Scoping the search to the block itself prevents a stray
# ``hook_fail_mode:`` under another section (e.g. a hand-edited
# alternative-config dump) from suppressing the seed.
_GUARDRAIL_HOOK_FAIL_MODE_RE = re.compile(
    r"^guardrail:[ \t]*\n"
    r"(?P<body>(?:[ \t]+[^\n]*\n|\n)*)",
    flags=re.MULTILINE,
)


def _migrate_0_4_0_seed_hook_fail_mode(ctx: MigrationContext) -> None:
    """Surface ``guardrail.hook_fail_mode`` in pre-existing config.yaml.

    Pre-v3 installs had no concept of a hook fail mode — every hook
    was hardcoded to fail-closed on any gateway error, which gave
    operators a strictly-bad UX whenever the gateway was down. The v3
    wave introduces a dedicated config field; the runtime default is
    ``"open"`` (set in defaultsFor() and EffectiveHookFailMode), but
    we also write the explicit value to YAML on upgrade so:

    1. Operators inspecting ~/.defenseclaw/config.yaml after upgrade
       SEE the new field and discover the knob exists. A field that
       only lives in defaults is invisible — operators reach for
       ``defenseclaw guardrail fail-mode`` only when they know it's
       a thing.
    2. The on-disk state is self-describing — no surprise behavior
       change if a future release changes the runtime default.

    Skipped silently when the operator has already set a value (any
    value — we never overwrite an explicit choice, even one we
    consider unsafe).

    Comment-preservation contract: the previous implementation
    round-tripped the file through ``yaml.safe_load`` +
    ``yaml.dump``, which silently stripped every comment, blank
    line, and scalar quoting choice the operator had curated. That
    was unacceptable in a no-touch migration. This implementation is
    surgical: it inserts the new key right after the ``guardrail:``
    header line, mirroring the indentation of the next non-blank
    body line so the result drops cleanly into a hand-formatted
    file. Everything else under ``guardrail:`` (comments, alphabetic
    or grouped key ordering, embedded blanks) survives byte-for-byte.
    """
    cfg_path = os.path.join(ctx.data_dir, "config.yaml")
    if not os.path.isfile(cfg_path):
        return

    try:
        with open(cfg_path) as f:
            text = f.read()
    except OSError as exc:
        ux.warn(f"could not read {cfg_path}: {exc}", indent="    ")
        return

    block_match = _GUARDRAIL_HOOK_FAIL_MODE_RE.search(text)
    if not block_match:
        # No ``guardrail:`` block at all — the operator is on the
        # no-guardrail path. Nothing to seed.
        return

    body = block_match.group("body")
    # Bail when the operator has already set the key anywhere in the
    # block — including a value we'd consider unsafe ("closed"). The
    # operator's explicit choice is sacred.
    if re.search(r"^[ \t]+hook_fail_mode\s*:", body, flags=re.MULTILINE):
        return

    indent = _detect_block_indent(body)
    insertion = f"{indent}hook_fail_mode: open\n"
    new_text = _GUARDRAIL_BLOCK_RE.sub(
        lambda m: m.group(0) + insertion, text, count=1,
    )

    if new_text == text:
        return

    if _atomic_write_text(cfg_path, new_text):
        ctx.changes.append(
            "seeded guardrail.hook_fail_mode='open' in config.yaml "
            "(pre-v3 hooks were always fail-closed; new default is fail-open "
            "to avoid bricking the agent on a gateway outage)"
        )


def _detect_block_indent(body: str) -> str:
    """Return the leading whitespace of the first non-blank body line.

    Used by ``_migrate_0_4_0_seed_hook_fail_mode`` so the inserted
    ``hook_fail_mode:`` line matches the operator's indentation
    style (two-space, four-space, or tab). Falls back to two spaces
    — the form ``config.save()`` emits — when the block is empty or
    starts with non-indented content.
    """
    for raw in body.splitlines():
        if not raw.strip():
            continue
        stripped = raw.lstrip(" \t")
        return raw[: len(raw) - len(stripped)] or "  "
    return "  "


# ---------------------------------------------------------------------------
# Internal helpers (atomic writes, dotenv parsing)
# ---------------------------------------------------------------------------


# Match KEY=VALUE on a single line, tolerating optional surrounding
# whitespace and an optional ``export`` prefix that some operators
# add when they hand-edit .env. Quoted values are unwrapped — the
# round-trip writer always emits unquoted values to match
# internal/gateway/firstboot.go::appendEnvLine.
_DOTENV_LINE = re.compile(
    r"""^\s*(?:export\s+)?
        (?P<key>[A-Za-z_][A-Za-z0-9_]*)
        \s*=\s*
        (?P<value>.*?)
        \s*$
    """,
    re.VERBOSE,
)


def _parse_dotenv(path: str) -> dict[str, str]:
    """Return a KEY→VALUE dict for the dotenv at ``path``.

    Lines that don't match KEY=VALUE (comments, blank lines, multi-
    line values) are silently dropped; we only care about the keys
    this migration touches and the writer round-trips the full file
    back atomically. The legacy parser is intentionally permissive
    rather than strict to match the bash-style .env conventions
    operators are used to.
    """
    out: dict[str, str] = {}
    if not os.path.isfile(path):
        return out
    try:
        with open(path) as f:
            for raw in f:
                line = raw.rstrip("\n").rstrip("\r")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = _DOTENV_LINE.match(stripped)
                if not m:
                    continue
                key = m.group("key")
                value = m.group("value")
                # Strip a single layer of matching quotes if present.
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                out[key] = value
    except OSError:
        return {}
    return out


def _atomic_write_dotenv(path: str, kv: dict[str, str]) -> bool:
    """Write ``kv`` as a sorted KEY=VALUE dotenv with mode 0o600.

    Returns True on success, False on failure (after logging a warning
    via click.echo so the operator sees the failure in the upgrade
    output). Atomic semantics: writes to ``path + ".tmp"`` and renames
    over the target, so a crash mid-write never leaves a half-written
    .env behind. Mirrors appendEnvLine in firstboot.go.

    Use ``_dotenv_update_keys`` instead when patching an existing
    .env: this writer collapses every comment, blank line, and the
    operator's chosen key order. Reserved for the rare path where we
    are creating a brand-new .env from scratch.
    """
    lines = [f"{k}={v}" for k, v in sorted(kv.items())]
    body = "\n".join(lines) + "\n"
    return _atomic_write_text(path, body, mode=0o600)


def _dotenv_update_keys(
    path: str,
    *,
    updates: dict[str, str] | None = None,
    removes: tuple[str, ...] = (),
) -> bool:
    """Patch a .env file in place, preserving comments and unrelated keys.

    The previous round-trip writer (``_atomic_write_dotenv`` over a
    parsed dict) lost every comment line, blank line, and the
    operator's chosen key order — unacceptable in a no-touch
    migration that we promise leaves the operator's curation intact.

    Algorithm:

      1. Read the file into memory as a list of raw lines (with line
         endings preserved).
      2. Walk every line. If it matches ``KEY=VALUE`` (the same
         permissive grammar ``_parse_dotenv`` accepts) AND its key is
         in ``removes``, drop the line. AND its key is in ``updates``,
         rewrite it as ``KEY=NEW_VALUE`` (preserving the trailing
         newline style of the original line) and mark the key as
         consumed. Otherwise keep the line verbatim.
      3. For any key in ``updates`` that wasn't seen during the walk,
         append ``KEY=VALUE`` at the end.
      4. Atomically write the result with mode ``0o600``.

    The function is idempotent and safe to re-run on an already-
    patched file (no-op when the desired KEY=VALUE pairs already
    match the file). Returns ``True`` on a successful write or no-op,
    ``False`` on a write failure (after logging via ``click.echo``).

    Used by ``_migrate_0_4_0_token_bootstrap`` to set
    ``DEFENSECLAW_GATEWAY_TOKEN`` and to retire
    ``OPENCLAW_GATEWAY_TOKEN`` without trampling operator-curated
    comments. The same helper is suitable for any future migration
    that needs to flip a single key in an existing .env.
    """
    upd = dict(updates or {})
    rem = set(removes)
    if not upd and not rem:
        return True

    if not os.path.isfile(path):
        # No existing file → fall back to the bulk writer because there
        # is nothing operator-curated to preserve. Comments don't exist
        # in a file we just synthesised.
        return _atomic_write_dotenv(path, upd)

    try:
        with open(path) as f:
            raw_lines = f.readlines()
    except OSError as exc:
        ux.warn(f"could not read {path}: {exc}", indent="    ")
        return False

    out_lines: list[str] = []
    consumed: set[str] = set()
    changed = False

    for raw in raw_lines:
        # Preserve the original line ending style (LF vs CRLF) so a
        # CRLF-terminated .env from a Windows operator doesn't
        # silently flip to LF on a partial rewrite.
        if raw.endswith("\r\n"):
            terminator = "\r\n"
            body = raw[:-2]
        elif raw.endswith("\n"):
            terminator = "\n"
            body = raw[:-1]
        else:
            terminator = ""
            body = raw

        stripped = body.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(raw)
            continue

        m = _DOTENV_LINE.match(stripped)
        if not m:
            out_lines.append(raw)
            continue

        key = m.group("key")
        if key in rem:
            changed = True
            continue  # drop the line entirely
        if key in upd:
            new_value = upd[key]
            new_line = f"{key}={new_value}{terminator}"
            if new_line != raw:
                changed = True
            out_lines.append(new_line)
            consumed.add(key)
            continue
        out_lines.append(raw)

    # Append keys that weren't already in the file. Use a final newline
    # if the file didn't end with one, so the appended block doesn't
    # glue itself onto the previous line.
    pending = [k for k in upd if k not in consumed]
    if pending:
        if out_lines and not out_lines[-1].endswith(("\n", "\r\n")):
            out_lines[-1] = out_lines[-1] + "\n"
        for key in pending:
            out_lines.append(f"{key}={upd[key]}\n")
        changed = True

    if not changed:
        # Still chmod to 0o600 in case the file's mode drifted; this
        # mirrors the perm-tighten step's guarantee.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return True

    return _atomic_write_text(path, "".join(out_lines), mode=0o600)


def _atomic_write_text(path: str, body: str, *, mode: int = 0o644) -> bool:
    """Atomically write ``body`` to ``path`` with the given file mode.

    Creates parent directories as needed (mode 0o700 for the directory
    when it carries the secret-bearing files this migration touches).
    Returns True on success.
    """
    parent = os.path.dirname(path)
    if parent:
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
        except OSError as exc:
            ux.warn(f"could not create {parent}: {exc}", indent="    ")
            return False
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        return True
    except OSError as exc:
        ux.warn(f"could not write {path}: {exc}", indent="    ")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def _read_active_connector_from_yaml(cfg_path: str) -> str:
    """Best-effort extract of ``claw.mode`` / ``guardrail.connector``.

    We do not import yaml here because PyYAML's loader will eagerly
    evaluate every key against the v3 schema (which produces noisy
    warnings on a pre-v3 file). The migration only needs the active
    connector NAME, so a regex scoped to the ``claw:`` and
    ``guardrail:`` blocks is sufficient and avoids depending on the
    Config dataclass shape.
    """
    if not os.path.isfile(cfg_path):
        return ""
    try:
        with open(cfg_path) as f:
            text = f.read()
    except OSError:
        return ""

    # guardrail.connector wins if explicitly set (matches Config
    # .activeConnector precedence in claw.go). The trailing
    # ``[\t ]*(?:#[^\n]*)?$`` group accepts both bare values and
    # values followed by a YAML inline comment so a hand-edited
    # ``connector: codex  # gpt only`` still resolves cleanly.
    m = re.search(
        r"^guardrail:[ \t]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+connector:[ \t]*[\"']?([A-Za-z0-9_-]+)[\"']?[ \t]*(?:#[^\n]*)?$",
        text,
        flags=re.MULTILINE,
    )
    if m and m.group(1).strip():
        return _normalize_legacy_connector(m.group(1))

    m = re.search(
        r"^claw:[ \t]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+mode:[ \t]*[\"']?([A-Za-z0-9_-]+)[\"']?[ \t]*(?:#[^\n]*)?$",
        text,
        flags=re.MULTILINE,
    )
    if m and m.group(1).strip():
        return _normalize_legacy_connector(m.group(1))
    return ""


def _normalize_legacy_connector(name: str) -> str:
    """Map legacy enum names to their post-PR194 canonical equivalents."""
    n = name.strip().lower()
    return _LEGACY_CLAW_MODE_REMAP.get(n, n)


# ---------------------------------------------------------------------------
# Migration: 0.5.0 — Purge stale flat-layout policy bundle
# ---------------------------------------------------------------------------
#
# Background: ≤0.3.x installers wrote the OPA policy bundle directly under
# ``<data_dir>/policies/`` (flat layout). 0.4.x switched to the canonical
# nested layout under ``<data_dir>/policies/rego/``. The upgrade path
# never deleted the flat-layout files, so operators ended up with BOTH
# copies on disk:
#
#   <data_dir>/policies/guardrail.rego          ← stale flat copy (March '26)
#   <data_dir>/policies/data.json               ← stale flat copy
#   <data_dir>/policies/rego/guardrail.rego     ← canonical (with HILT logic)
#   <data_dir>/policies/rego/data.json          ← canonical (with HILT data)
#
# The Go loader's ``resolveRegoDir`` (internal/policy/engine.go) used to
# prefer the parent layout first, so it compiled the OLD modules. The
# stale ``guardrail.rego`` predates the HILT confirm branch, so HIGH
# severity prompt-stage findings always returned ``alert`` — never
# ``confirm``. The HILT dialog still appeared at tool-call time because
# that path runs through a separate, non-Rego decision tree and reads
# HILT directly from ``config.yaml``. Net effect: HILT looked half-broken
# (only on tool calls, not on prompts) until the operator manually
# noticed the duplicate files.
#
# The Go loader was fixed to prefer the nested layout in the same
# changelist as this migration. The migration here closes the loop on
# disk so the residue doesn't keep tempting operators (or future
# debugging sessions) to question whether the right module is loaded.

# Files we know shipped under the legacy flat layout (≤0.3.x). The
# canonical 0.4.x bundle puts every one of these under ``policies/rego/``,
# so a flat-layout copy is, by definition, residue. We leave any other
# flat .rego files alone — operators sometimes drop hand-rolled custom
# rules into ``policies/`` and the migration must never destroy operator
# data.
_LEGACY_FLAT_REGO_FILENAMES = (
    "admission.rego",
    "audit.rego",
    "firewall.rego",
    "guardrail.rego",
    "sandbox.rego",
    "skill_actions.rego",
    "admission_test.rego",
    "audit_test.rego",
    "firewall_test.rego",
    "guardrail_test.rego",
    "sandbox_test.rego",
    "skill_actions_test.rego",
)


def _migrate_0_5_0(ctx: MigrationContext) -> None:
    """Delete the legacy flat-layout policy bundle if a nested one exists.

    Why this is safe:

    1. Only runs when the canonical nested layout is present at
       ``<data_dir>/policies/rego/``. If the nested directory is missing
       (operator deleted it, or stayed on the flat layout deliberately),
       we do nothing — preserving the operator's chosen layout.

    2. Only deletes files we shipped ourselves. Any *.rego file at the
       flat path that is NOT in ``_LEGACY_FLAT_REGO_FILENAMES`` is left
       alone so a hand-curated custom rule never disappears mid-upgrade.

    3. Atomic on a per-file basis: each ``os.remove`` either succeeds or
       leaves the file in place; we never half-delete a file. A failure
       to remove one file does not abort the migration.

    4. Idempotent: re-running on a clean install (no flat residue) is a
       no-op.

    The migration also retires ``<data_dir>/policies/data.json`` when a
    canonical ``<data_dir>/policies/rego/data.json`` exists. The flat
    data.json no longer feeds the loader after the engine fix, but it
    is the single most common source of confusion ("which data.json
    does the gateway read?") and the upgrade is the right time to
    eliminate the duplicate.
    """
    policies_dir = os.path.join(ctx.data_dir, "policies")
    nested_dir = os.path.join(policies_dir, "rego")

    if not os.path.isdir(nested_dir):
        # Operator removed or never installed the canonical layout.
        # Nothing to migrate; deleting the flat bundle here would leave
        # the gateway with no policy at all.
        return

    # Require at least one canonical .rego file before we touch the
    # flat layout. ``hasRegoFiles`` in the Go loader is satisfied by a
    # single .rego file, so we mirror that contract here.
    canonical_rego_present = any(
        name.endswith(".rego")
        for name in os.listdir(nested_dir)
        if os.path.isfile(os.path.join(nested_dir, name))
    )
    if not canonical_rego_present:
        return

    removed_rego: list[str] = []
    for name in _LEGACY_FLAT_REGO_FILENAMES:
        flat_path = os.path.join(policies_dir, name)
        if not os.path.isfile(flat_path):
            continue
        try:
            os.remove(flat_path)
            removed_rego.append(name)
        except OSError as exc:
            ux.warn(f"could not remove {flat_path}: {exc}", indent="    ")

    if removed_rego:
        ctx.changes.append(
            "removed legacy flat-layout policy bundle "
            f"({len(removed_rego)} file(s)) from {policies_dir} — "
            "fixes HILT prompt-stage confirm verdicts that were "
            "silently returning 'alert' against the stale modules"
        )

    # Retire the duplicate data.json if a canonical one exists. We only
    # touch the flat copy when we are CERTAIN the nested copy is the
    # one being read (canonical rego files present, nested data.json
    # exists), so an upgrade can never leave the gateway with no data.
    #
    # Non-destructive contract:
    #
    # * If the flat copy is byte-identical to the nested copy, delete it
    #   (pure residue, nothing to lose).
    # * If the contents differ, rename to ``data.json.pre-0.5.0`` so any
    #   operator hand-edits land in an obvious sidecar file rather than
    #   disappearing silently. The post-fix loader doesn't read either
    #   path at the flat layout, so the gateway sees no behavior change
    #   either way.
    # * Symlinks at the flat path are left alone — operators sometimes
    #   point ``policies/data.json`` at the nested copy on purpose, and
    #   removing or renaming a symlink could break that pattern.
    #
    # This trades a one-time stat+compare cost (tens of microseconds on
    # any realistic data.json) for "operator never loses an edit they
    # didn't realize was being orphaned by the engine fix".
    nested_data = os.path.join(nested_dir, "data.json")
    flat_data = os.path.join(policies_dir, "data.json")
    if not (os.path.isfile(nested_data) and os.path.isfile(flat_data)):
        return

    # Skip symlinks: filecmp on a symlink would resolve through it and
    # potentially short-circuit to "identical", but then ``os.remove``
    # would unlink the symlink while the operator's intent was a live
    # alias. Leave symlinks for operators to retire manually.
    if os.path.islink(flat_data):
        return

    import filecmp

    try:
        identical = filecmp.cmp(flat_data, nested_data, shallow=False)
    except OSError as exc:
        ux.warn(
            f"could not compare {flat_data} and {nested_data}: {exc}",
            indent="    ",
        )
        return

    if identical:
        try:
            os.remove(flat_data)
            ctx.changes.append(
                f"removed duplicate {flat_data} "
                f"(canonical {nested_data} is the one the loader reads)"
            )
        except OSError as exc:
            ux.warn(f"could not remove {flat_data}: {exc}", indent="    ")
        return

    # Differs from the nested canonical copy. Rename instead of delete
    # so any operator customization is preserved. Pick a fresh suffix
    # if one already exists from a prior partial upgrade so we never
    # clobber an earlier preservation.
    base_backup = flat_data + ".pre-0.5.0"
    backup_path = base_backup
    suffix = 1
    while os.path.exists(backup_path):
        backup_path = f"{base_backup}.{suffix}"
        suffix += 1
        if suffix > 100:  # noqa: PLR2004 — sanity cap on degenerate dirs
            ux.warn(
                f"too many existing backups at {base_backup}.* — "
                "leaving flat data.json in place",
                indent="    ",
            )
            return
    try:
        os.replace(flat_data, backup_path)
        ctx.changes.append(
            f"preserved operator-edited {flat_data} as {backup_path} "
            f"(differed from canonical {nested_data}; the gateway no longer "
            "reads the flat path after the resolveRegoDir fix)"
        )
    except OSError as exc:
        ux.warn(
            f"could not rename {flat_data} → {backup_path}: {exc}",
            indent="    ",
        )


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

# Ordered list of (version, description, callable). Each callable
# takes a :class:`MigrationContext` and mutates it (appending to
# ctx.changes) on a successful step.
MIGRATIONS: list[tuple[str, str, Callable[[MigrationContext], None]]] = [
    ("0.3.0", "Remove legacy model provider entries from openclaw.json", _migrate_0_3_0),
    (
        "0.4.0",
        "Connector architecture v3 — token bootstrap, perm tighten, "
        "legacy codex env cleanup, OTel enum normalize, active-connector "
        "seed, hook fail-mode default surface",
        _migrate_0_4_0,
    ),
    (
        "0.5.0",
        "Purge stale flat-layout policy bundle that blocked HILT prompt-stage "
        "confirmations (see _migrate_0_5_0 docstring)",
        _migrate_0_5_0,
    ),
]


def run_migrations(
    from_version: str,
    to_version: str,
    openclaw_home: str,
    data_dir: str | None = None,
) -> int:
    """Run all applicable migrations up to ``to_version``.

    Source of truth for "what has run" is the per-host migration
    cursor at ``<data_dir>/.migration_state.json`` (see
    ``defenseclaw.migration_state`` for the schema). The
    ``from_version`` argument is now advisory — it only matters on
    the very first call after a host upgrades to a build that
    persists the cursor (the bootstrap path).

    Why we moved from "version-range" to "cursor-driven":

    * Version-range gates re-fired migrations whenever the author
      forgot to bump ``__version__`` before tagging a release —
      because ``current_version`` lagged the actual installed bits.
    * Partial failures (one migration in a batch raised) were
      indistinguishable from "never ran" — operators who re-ran the
      upgrade hit the failed step, but the SUCCESSFUL earlier ones
      ran AGAIN against state they had already mutated.
    * Operators restoring from backup snapshots quietly drifted out
      of sync because nothing on disk recorded which migrations had
      observably executed.

    The cursor's ``applied`` set fixes all three: each migration is
    only run once per host, full stop, and a partial-failure batch
    leaves successful entries marked and failed entries unmarked so
    re-running picks up exactly where it left off.

    Backward-compat preserved on purpose:

    * The ``from_version`` / ``to_version`` API is unchanged.
    * ``from_version == to_version`` (the same-version reapply
      escape hatch used by ``defenseclaw upgrade --version <same>``)
      still re-runs the migration at exactly ``to_version`` even
      when the cursor says applied. That's a documented operator
      tool for "I think this migration didn't take, please force
      it"; without it, the only recovery would be ``defenseclaw
      doctor migration-state --unmark X.Y.Z`` followed by upgrade,
      which is more friction than the historical UX warrants.

    ``data_dir`` defaults to ``$DEFENSECLAW_HOME`` or
    ``~/.defenseclaw`` when not supplied. The optional argument lets
    ``cmd_upgrade.py`` thread the loaded ``Config.data_dir`` through
    so that operators with a non-default ``DEFENSECLAW_HOME`` get
    their migration applied at the right path.

    Returns the number of migrations actually executed (excludes
    cursor-skipped ones). Failures don't increment the counter and
    don't leave a cursor entry — the next upgrade will retry them.
    """
    from defenseclaw import migration_state

    if data_dir is None:
        data_dir = os.environ.get("DEFENSECLAW_HOME") or os.path.expanduser("~/.defenseclaw")

    from_t = _ver_tuple(from_version)
    to_t = _ver_tuple(to_version)
    same_version_reapply = from_t == to_t

    # Load the cursor; treat "missing" / "unparseable" / "future
    # schema" as "first upgrade on this host" and bootstrap from
    # ``from_version``. Bootstrap is conservative — it pre-marks
    # every registry entry whose version is at or below
    # ``from_version`` so we don't replay history on a host that's
    # already in steady state.
    state = migration_state.load(data_dir)
    if state is None:
        state = migration_state.bootstrap(
            None,
            from_version=from_version,
            package_version=to_version,
            registry_versions=[v for v, _, _ in MIGRATIONS],
        )
        # Persist the bootstrap snapshot eagerly so a crash mid-run
        # still leaves the host with a usable cursor for next time.
        # save() failure is non-fatal: we'll just bootstrap again
        # next upgrade (still idempotent).
        try:
            migration_state.save(data_dir, state)
        except OSError as exc:
            ux.warn(f"could not persist migration cursor: {exc}", indent="    ")

    applied_count = 0

    for ver, desc, fn in MIGRATIONS:
        ver_t = _ver_tuple(ver)

        # Never run a registry entry past the operator's target.
        # This guards the "registry has 0.6.0 but operator is
        # upgrading to 0.5.0" case (e.g. cherry-picked downgrade).
        if ver_t > to_t:
            continue

        # In the upgrade case, also exclude entries strictly below
        # ``from_version``. They should already be in the cursor;
        # the bootstrap above handled that. Skipping here is a
        # belt-and-suspenders against a malformed cursor that's
        # missing entries we'd otherwise replay unnecessarily.
        if not same_version_reapply and ver_t < from_t:
            continue

        already_applied = migration_state.is_applied(state, ver)

        # Same-version reapply intentionally bypasses the cursor for
        # the matching version — see backward-compat note in the
        # docstring. All OTHER versions still respect the cursor
        # even on same-version reapply (don't accidentally re-run
        # historical migrations).
        if already_applied and not (same_version_reapply and ver_t == to_t):
            continue

        click.echo(f"  {ux.dim('→')} Migration {ver}: {desc}")
        ctx = MigrationContext(
            openclaw_home=openclaw_home,
            data_dir=data_dir,
            from_version=from_version,
            to_version=to_version,
        )
        try:
            fn(ctx)
            ux.ok(f"Migration {ver} applied.", indent="    ")
        except Exception as exc:  # noqa: BLE001 — never abort upgrade on migration error
            ux.err(f"migration {ver} failed: {exc}", indent="    ")
            ux.subhead(
                "upgrade will continue; run 'defenseclaw doctor --fix' afterwards",
                indent="    ",
            )
            # Don't mark applied: next upgrade retries this exact
            # migration. Continue with the rest of the batch so a
            # single broken migration doesn't strand the host on
            # otherwise-applicable later ones.
            continue

        migration_state.mark_applied(
            state, ver, package_version=to_version,
        )
        applied_count += 1

        # Persist after every successful migration so a crash
        # halfway through a multi-migration batch loses at most one
        # migration's worth of "we just ran this" knowledge. The
        # cursor file is sub-kilobyte; the IO cost is negligible.
        try:
            migration_state.save(data_dir, state)
        except OSError as exc:
            ux.warn(f"could not persist migration cursor after {ver}: {exc}", indent="    ")

    return applied_count
