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

    DeepSec S3.HIGH_BUG ("Migration can overwrite live OpenClaw config with a
    stale pristine snapshot"): the previous strategy restored a pristine
    backup taken BEFORE DefenseClaw first touched openclaw.json and then
    re-applied only the plugin registration. That destroyed any model
    providers, plugin entries, approval settings, or workspace config the
    operator added between the pristine snapshot and the upgrade. The
    pristine-restore branch is removed; we always surgically patch the
    live config so operator changes are preserved.
    """
    oc_json = os.path.join(ctx.openclaw_home, "openclaw.json")
    if not os.path.isfile(oc_json):
        return

    _migrate_0_3_0_surgical(oc_json)


def _migrate_0_3_0_surgical(oc_json: str) -> None:
    """Surgically remove legacy entries from the LIVE openclaw.json.

    Mutates only the keys DefenseClaw 0.2.x added (models.providers.defenseclaw,
    models.providers.litellm, defenseclaw/litellm-prefixed primary model) and
    re-registers the 0.3.0 plugin entry. All other operator-managed config
    (other providers, plugin entries, approvals, workspace) is preserved.
    """
    try:
        with open(oc_json) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        click.echo(f"    openclaw.json unreadable ({exc}); skipping surgical fix")
        return

    if not isinstance(cfg, dict):
        click.echo("    openclaw.json is not a JSON object; skipping surgical fix")
        return

    changed = False
    changes = []

    # Step 1: remove ONLY the legacy defenseclaw/litellm provider entries
    # that 0.2.0 injected. Any other provider the operator added stays.
    providers = cfg.get("models", {}).get("providers", {})
    if isinstance(providers, dict):
        for key in ("defenseclaw", "litellm"):
            if key in providers:
                del providers[key]
                changes.append(f"removed providers.{key}")
                changed = True

    # Step 2: restore the unprefixed primary model name. We only touch
    # values that start with the legacy prefixes; bare model names from
    # the operator are not modified.
    model = cfg.get("agents", {}).get("defaults", {}).get("model", {})
    if isinstance(model, dict):
        primary = model.get("primary", "")
        if isinstance(primary, str) and primary.startswith(("defenseclaw/", "litellm/")):
            restored = primary.split("/", 1)[1]
            model["primary"] = restored
            changes.append(f"restored model.primary: {primary} → {restored}")
            changed = True

    # Step 3: re-register the DefenseClaw plugin entry that 0.3.0 needs.
    # We add only the keys we own; existing plugin registrations from
    # the operator are not modified.
    plugins = cfg.setdefault("plugins", {})
    if isinstance(plugins, dict):
        allow = plugins.setdefault("allow", [])
        if isinstance(allow, list) and "defenseclaw" not in allow:
            allow.append("defenseclaw")
            changes.append("added plugins.allow[defenseclaw]")
            changed = True
        entries = plugins.setdefault("entries", {})
        if isinstance(entries, dict):
            existing = entries.get("defenseclaw")
            if not isinstance(existing, dict):
                entries["defenseclaw"] = {"enabled": True}
                changes.append("added plugins.entries.defenseclaw")
                changed = True
            elif not existing.get("enabled"):
                existing["enabled"] = True
                changes.append("enabled plugins.entries.defenseclaw")
                changed = True
        install_path = os.path.join(
            os.path.dirname(oc_json), "extensions", "defenseclaw"
        )
        load = plugins.setdefault("load", {})
        if isinstance(load, dict):
            paths = load.setdefault("paths", [])
            if isinstance(paths, list) and install_path not in paths:
                paths.append(install_path)
                changes.append("added plugins.load.paths[defenseclaw]")
                changed = True

    if not changed:
        click.echo("    (no legacy entries found and plugin already registered)")
        return

    # Always back up the live config before mutating it. This gives the
    # operator a single-step rollback path if the surgical patch turns
    # out to break their setup.
    try:
        shutil.copy2(oc_json, oc_json + ".pre-0.3.0-migration")
    except OSError as exc:
        click.echo(f"    WARNING: could not back up openclaw.json ({exc})")

    with open(oc_json, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    for c in changes:
        click.echo(f"    {c}")
    click.echo("    (surgical migration applied; live config preserved)")


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

# Legacy Codex env override files retired in S8.1 / F31 and finally
# the surrounding proxy surface was removed in PR #265. We still scrub
# these files on upgrade because they may exist on disk for users
# coming from a release that did write them.
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
    _migrate_0_4_0_token_env_in_config(ctx)
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


def _migrate_0_4_0_token_env_in_config(ctx: MigrationContext) -> None:
    """Avarice F-3395: migrate stale ``gateway.token_env`` references.

    The 0.4.0 migration above renames ``OPENCLAW_GATEWAY_TOKEN`` to
    ``DEFENSECLAW_GATEWAY_TOKEN`` in ``~/.defenseclaw/.env`` but the
    legacy installer also wrote ``gateway.token_env: OPENCLAW_GATEWAY_TOKEN``
    into ``config.yaml``. Python and TypeScript clients honour an
    explicit ``token_env`` first, so on upgraded installs they kept
    reading the (now deleted) env name and sent unauthenticated
    ``/api/v1/inspect/*`` requests. The OpenClaw plugin's tool
    inspection path turns those 401s into ``allow/observe``, so the
    enforcement bypass is silent. We rewrite ``token_env`` in
    ``config.yaml`` to the new name so the upgraded clients read the
    same key the sidecar minted.
    """
    config_path = os.path.join(ctx.data_dir, "config.yaml")
    if not os.path.isfile(config_path):
        return
    try:
        with open(config_path, encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        return
    if "OPENCLAW_GATEWAY_TOKEN" not in content:
        return
    # Conservative line-rewriter that only touches the right-hand
    # side of `token_env:` lines pointing at the legacy name. We
    # avoid a full YAML round-trip to preserve operator comments and
    # ordering byte-for-byte.
    new_lines: list[str] = []
    rewritten = 0
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if (stripped.startswith("token_env:")
                and "OPENCLAW_GATEWAY_TOKEN" in line):
            new_lines.append(line.replace(
                "OPENCLAW_GATEWAY_TOKEN", "DEFENSECLAW_GATEWAY_TOKEN", 1))
            rewritten += 1
            continue
        new_lines.append(line)
    if rewritten == 0:
        return
    try:
        # Atomic rewrite via tempfile + rename to avoid a partial
        # write if the operator interrupts us mid-migration.
        tmp = config_path + ".tmp-f3395"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.writelines(new_lines)
        os.chmod(tmp, 0o600)
        os.replace(tmp, config_path)
    except OSError as exc:
        ux.warn(f"could not migrate token_env in {config_path}: {exc}", indent="    ")
        return
    ctx.changes.append(
        f"migrated {rewritten} stale gateway.token_env reference(s) in config.yaml "
        "(F-3395)"
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
    was hardcoded to fail-OPEN on any gateway error, which made the
    response-layer boundary silently leakable. The v3 wave introduced
    a dedicated config field, and v4 (avarice F-0681) flipped the
    BUILT-IN default to ``"closed"`` so new installs deny by default.

    To avoid a noisy behavior change under existing operators, this
    migration writes ``hook_fail_mode: open`` into ANY pre-existing
    config.yaml that doesn't already pin the field. That preserves
    the legacy fail-OPEN behavior for upgraders while letting fresh
    installs (which never run any migration on v4+) inherit the safer
    default. Operators see the new field on next ``cat config.yaml``
    and can opt into "closed" via ``defenseclaw guardrail fail-mode``
    or by hand-editing the YAML.

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
            "(legacy fail-open behavior preserved for upgraders; v4 "
            "fresh installs default to 'closed' per avarice F-0681)"
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

    DeepSec S2.MEDIUM ("Gateway token is written through a fixed-name
    temp file before permissions are tightened"): the previous
    implementation used ``open(path + ".tmp", "w")``, which created a
    new file with permissions derived from 0666 masked by the process
    umask, *then* called :func:`os.chmod`. On a multi-user host with a
    permissive umask -- or a stale broadly-readable ``<target>.tmp``
    file -- another local user could race-read the gateway token (or
    any other secret-bearing migration write) during the write window.

    The new implementation:

    * Tightens the parent directory to 0o700 *before* writing, including
      when the directory already exists with a more permissive mode (the
      old code only set 0o700 on creation via ``mode=`` to ``makedirs``).
    * Uses :func:`tempfile.mkstemp` in the *target* directory with mode
      0o600 from creation, so the secret bytes never exist on disk with
      a broader mode and the temp pathname is unpredictable.
    * Refuses pre-existing symlinks at the final ``path`` to avoid
      writing through to an attacker-controlled target.
    * Calls :func:`os.fsync` before :func:`os.replace` to durably flush
      the secret bytes ahead of the rename, so a crash mid-rename does
      not leave a half-written file.

    Returns True on success.
    """
    import tempfile

    parent = os.path.dirname(path) or "."
    try:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    except OSError as exc:
        ux.warn(f"could not create {parent}: {exc}", indent="    ")
        return False
    # Tighten the parent dir even when it already existed with a more
    # permissive mode (`exist_ok=True` does not re-apply the mode arg).
    if mode <= 0o600:
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
    if os.path.islink(path):
        ux.warn(
            f"refusing to follow symlink at secret target {path}",
            indent="    ",
        )
        return False
    fd = -1
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=".tmp.",
            suffix=os.path.basename(path) or ".tmp",
            dir=parent,
        )
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1  # ownership transferred; fdopen closes on exit
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        # Re-apply the requested mode after replace in case the FS
        # quirks restored a different mode (e.g. tmpfs ACL inheritance).
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        return True
    except OSError as exc:
        ux.warn(f"could not write {path}: {exc}", indent="    ")
        return False
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


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
    """0.5.0 upgrade — two independent sub-steps.

    Step 1: ``_migrate_0_5_0_purge_flat_policy_bundle``
            Deletes the legacy flat-layout policy bundle now that the
            Go loader prefers ``<data_dir>/policies/rego/``. Closes
            the HILT prompt-stage confirm-verdict regression.

    Step 2: ``_migrate_0_5_0_strip_codex_enforcement_keys``
            Removes the retired ``codex_enforcement_enabled`` and
            ``claudecode_enforcement_enabled`` guardrail keys from
            config.yaml. The LLM proxy data path for Codex / Claude
            Code is removed in 0.5.0; enforcement is now selected by
            the existing ``guardrail.mode`` field via the agent's
            native hook bus (PreToolUse deny verdict on policy hits).

    Each sub-step is independent and isolated by its own try/except
    so a failure in one does not block the other. The migration as a
    whole is permissive on errors — the upgrade itself NEVER aborts;
    failures are logged and surfaced via ``defenseclaw doctor --fix``.
    """
    try:
        _migrate_0_5_0_purge_flat_policy_bundle(ctx)
    except Exception as exc:  # noqa: BLE001 — never abort upgrade on migration error
        ux.warn(f"policy-bundle cleanup step failed: {exc}", indent="    ")
    try:
        _migrate_0_5_0_strip_codex_enforcement_keys(ctx)
    except Exception as exc:  # noqa: BLE001 — never abort upgrade on migration error
        ux.warn(f"legacy enforcement-key strip step failed: {exc}", indent="    ")


def _migrate_0_5_0_purge_flat_policy_bundle(ctx: MigrationContext) -> None:
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
# Migration: 0.5.0 — sub-step: strip legacy guardrail.*_enforcement_enabled
# ---------------------------------------------------------------------------
#
# 0.5.0 also retires the LLM proxy data path for Codex and Claude
# Code. Pre-0.5.0 guardrail config exposed two boolean fields that
# selected between the (now-removed) LLM proxy data path and the
# hook-only data path for those connectors:
#
#   guardrail.codex_enforcement_enabled: bool
#   guardrail.claudecode_enforcement_enabled: bool
#
# Both fields are gone from the schema. The only supported enforcement
# surface for those connectors is now the agent's native hook bus
# (PreToolUse / UserPromptSubmit / PostToolUse). Enforcement vs
# observation is selected via the existing ``guardrail.mode`` field —
# ``action`` causes the PreToolUse hook to return a deny verdict on
# policy hits, ``observe`` records only.
#
# Pre-0.5.0 config.yaml files on disk carry the legacy fields. The Go
# loader (which uses viper's UnmarshalExact) and the Python config
# loader (Pydantic with strict=False) both quietly ignore unknown
# keys today, so leaving them in place would not break boot. But:
#
#   * The TUI's "configedit" panel would surface stale fields the
#     operator can no longer edit usefully.
#   * ``defenseclaw doctor`` may complain about config drift.
#   * Operators reading config.yaml would have no way of knowing
#     whether the fields still matter; the file is the source of
#     truth for "what is this gateway doing" and dead fields make
#     that diagnostic noisy.
#
# The cleanup is byte-level (no YAML round-trip) so operator
# comments, blank lines, and key ordering inside the ``guardrail:``
# block are preserved exactly. The substitution is anchored to the
# guardrail block — a stray top-level ``codex_enforcement_enabled``
# elsewhere in config.yaml is intentionally NOT touched.

# Legacy keys to strip from the ``guardrail:`` block. The two
# enforcement booleans are mutually independent — an operator who
# explicitly opted into one but not the other will have only one key
# on disk; the migration handles either combination.
_LEGACY_GUARDRAIL_ENFORCEMENT_KEYS: tuple[str, ...] = (
    "codex_enforcement_enabled",
    "claudecode_enforcement_enabled",
)


def _migrate_0_5_0_strip_codex_enforcement_keys(ctx: MigrationContext) -> None:
    """Drop legacy guardrail.*_enforcement_enabled keys from config.yaml.

    Idempotent: a config.yaml that has already been migrated (no
    matching keys present) is a no-op. Failures on read or write are
    logged via ux.warn and the migration continues — leaving stale
    keys in place is strictly less bad than aborting the upgrade.

    Comment-preservation contract: each match is deleted line-by-line
    inside the ``guardrail:`` block, including any trailing inline
    comment on the same line (``codex_enforcement_enabled: true  #
    legacy``). Surrounding lines — comments above/below, blank
    separator lines, and unrelated keys — are untouched. The
    indentation of the deleted line is also preserved structurally
    by virtue of the regex never touching neighbouring lines.

    Action-mode preservation: this migration only DELETES keys. It
    does NOT mutate ``guardrail.mode``. An operator who had set
    ``codex_enforcement_enabled: true`` AND ``guardrail.mode: action``
    keeps action mode (it now routes through the hook surface
    automatically). An operator who had set ``true`` but left mode at
    ``observe`` is left at observe — the same posture they had before
    the upgrade, just expressed through the surviving knob.
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

    block_match = re.search(
        r"^guardrail:[ \t]*\n(?P<body>(?:[ \t]+[^\n]*\n|\n)*)",
        text,
        flags=re.MULTILINE,
    )
    if not block_match:
        return

    body_start = block_match.start("body")
    body_end = block_match.end("body")
    body = block_match.group("body")

    removed: list[str] = []
    new_body = body
    for key in _LEGACY_GUARDRAIL_ENFORCEMENT_KEYS:
        # Match the full line carrying the legacy key (with its
        # trailing newline). The pattern accepts any value form
        # (quoted/unquoted bool, optional inline comment) and any
        # leading indentation the operator chose.
        pattern = re.compile(
            r"^[ \t]+" + re.escape(key) + r"\s*:[^\n]*\n",
            flags=re.MULTILINE,
        )
        new_body, count = pattern.subn("", new_body)
        if count:
            removed.append(key)

    if not removed:
        return

    new_text = text[:body_start] + new_body + text[body_end:]
    if new_text == text:
        return

    if not _atomic_write_text(cfg_path, new_text):
        ux.warn(f"could not write {cfg_path}", indent="    ")
        return

    ctx.changes.append(
        "stripped legacy guardrail enforcement key(s) "
        f"({', '.join(removed)}) from config.yaml — Codex/Claude Code "
        "now enforce via the agent's native hook bus selected by "
        "guardrail.mode (action returns a PreToolUse deny verdict)"
    )


# ---------------------------------------------------------------------------
# Migration: gateway.token_env realignment (registered at version 0.7.0)
# ---------------------------------------------------------------------------
#
# The version key in MIGRATIONS is what the cursor uses to decide
# whether to fire — symbol names and docstrings deliberately avoid
# pinning to it so a future release manager can re-key without
# touching the implementation.


def _migrate_gateway_token_env_realign(ctx: MigrationContext) -> None:
    """Single-step wrapper around ``_align_gateway_token_env_in_config``.

    Repoints stale ``gateway.token_env: OPENCLAW_GATEWAY_TOKEN`` in
    config.yaml to the canonical ``DEFENSECLAW_GATEWAY_TOKEN`` so
    the Python CLI and the Go gateway agree on the env var name
    out of the box. The runtime fall-through in
    ``GatewayConfig.resolved_token`` already MASKS the drift; this
    migration cleans up the config so operators no longer rely on
    that fall-through.

    Wrapped in try/except per the migration playbook — a failure in
    this step never aborts the upgrade; the auto-detect fall-through
    keeps the CLI working until the operator runs ``defenseclaw
    doctor --fix`` (which does the same rewrite under operator
    confirmation).
    """
    try:
        _align_gateway_token_env_in_config(ctx)
    except Exception as exc:  # noqa: BLE001 — never abort upgrade on migration error
        ux.warn(f"gateway token_env rename step failed: {exc}", indent="    ")


def _align_gateway_token_env_in_config(ctx: MigrationContext) -> None:
    """Rewrite ``gateway.token_env: OPENCLAW_GATEWAY_TOKEN`` → ``DEFENSECLAW_GATEWAY_TOKEN``.

    Trigger conditions (ALL must hold):

    * ``config.yaml`` exists at ``<data_dir>/config.yaml``.
    * The file contains a ``gateway:`` block with
      ``token_env: OPENCLAW_GATEWAY_TOKEN`` (the bootstrap default
      from before the rebranding fix's defaults patch).
    * The dotenv at ``<data_dir>/.env`` carries
      ``DEFENSECLAW_GATEWAY_TOKEN`` with a non-empty value (the
      0.4.0 token-bootstrap migration normally promotes the legacy
      var into this name; this migration just finishes the job on
      the config side).

    The dotenv-population check is the safety gate: we never want to
    repoint ``token_env`` at an env var that doesn't exist anywhere,
    because that turns a *silently-working-via-fall-through* config
    into a *visibly-broken-with-no-fall-back* one. Better to leave
    the legacy default in place and let the auto-detect ladder keep
    serving requests.

    Idempotent: if ``token_env`` already says
    ``DEFENSECLAW_GATEWAY_TOKEN`` (Phase 3 default, or already
    migrated), this is a no-op.

    Comment-preservation contract: the regex matches ONLY the
    ``token_env:`` line inside the ``gateway:`` block. Inline
    comments on the same line are preserved; surrounding comments,
    blank separators, and unrelated keys are untouched. Indentation
    of the rewritten line is preserved exactly (we substitute the
    value, not the line).

    Custom-override safety: if ``token_env`` points at any var name
    OTHER than ``OPENCLAW_GATEWAY_TOKEN`` (operator pinned a custom
    name via ``defenseclaw setup gateway``), the migration leaves it
    alone. Operator intent always wins over migration defaults.
    """
    cfg_path = os.path.join(ctx.data_dir, "config.yaml")
    if not os.path.isfile(cfg_path):
        return

    # Safety gate: only proceed if the canonical token is actually
    # set in the dotenv. Without this, we'd repoint at an empty var
    # and break the request path that the Phase 1+2 fall-through is
    # currently keeping alive.
    env_path = os.path.join(ctx.data_dir, ".env")
    existing_env = _parse_dotenv(env_path)
    if not existing_env.get("DEFENSECLAW_GATEWAY_TOKEN", "").strip():
        return

    try:
        with open(cfg_path) as f:
            text = f.read()
    except OSError as exc:
        ux.warn(f"could not read {cfg_path}: {exc}", indent="    ")
        return

    # Find the ``gateway:`` block. Same pattern shape as
    # ``_migrate_0_5_0_strip_codex_enforcement_keys`` — matches the
    # block header plus indented body, stopping at the next top-level
    # key. ``[ \t]*`` after the colon tolerates trailing whitespace
    # that some YAML formatters add.
    block_match = re.search(
        r"^gateway:[ \t]*\n(?P<body>(?:[ \t]+[^\n]*\n|\n)*)",
        text,
        flags=re.MULTILINE,
    )
    if not block_match:
        return

    body_start = block_match.start("body")
    body_end = block_match.end("body")
    body = block_match.group("body")

    # Match the ``token_env: OPENCLAW_GATEWAY_TOKEN`` line. The value
    # may be unquoted (most common), single-quoted, or double-quoted;
    # we accept all three so we never miss a legitimately-formatted
    # legacy entry. An inline comment after the value is preserved
    # because the substitution only touches the captured value group.
    pattern = re.compile(
        r"""
        (?P<prefix>^[ \t]+token_env\s*:\s*)   # indent + key + colon + space
        (?P<quote>["']?)                       # optional opening quote
        OPENCLAW_GATEWAY_TOKEN                 # the literal legacy value
        (?P=quote)                             # matching closing quote
        (?P<suffix>[ \t]*(?:\#[^\n]*)?\n)      # trailing space + optional comment + newline
        """,
        flags=re.MULTILINE | re.VERBOSE,
    )

    new_body, count = pattern.subn(
        lambda m: f"{m.group('prefix')}{m.group('quote')}DEFENSECLAW_GATEWAY_TOKEN{m.group('quote')}{m.group('suffix')}",
        body,
    )
    if count == 0:
        return

    new_text = text[:body_start] + new_body + text[body_end:]
    if new_text == text:
        return

    if not _atomic_write_text(cfg_path, new_text):
        ux.warn(f"could not write {cfg_path}", indent="    ")
        return

    ctx.changes.append(
        "repointed gateway.token_env from OPENCLAW_GATEWAY_TOKEN to "
        "DEFENSECLAW_GATEWAY_TOKEN in config.yaml — matches the env "
        "var the Go gateway writes on first boot, removes reliance on "
        "the resolved_token auto-detect fall-through"
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
        "confirmations; strip retired guardrail.{codex,claudecode}_enforcement_enabled "
        "keys (LLM proxy data path for Codex / Claude Code removed; enforcement "
        "now routed through the agent's native hook bus via guardrail.mode=action) "
        "— see _migrate_0_5_0 docstring",
        _migrate_0_5_0,
    ),
    (
        # Ships in the 0.7.0 release. The function name deliberately
        # does NOT mention a version so re-keying here at merge time
        # (if a different version is cut) needs no rename.
        "0.7.0",
        "Repoint legacy gateway.token_env=OPENCLAW_GATEWAY_TOKEN in config.yaml "
        "to the canonical DEFENSECLAW_GATEWAY_TOKEN so the Python CLI and the Go "
        "gateway agree on the env var name (closes the 'gateway token unavailable' "
        "trip the runtime fall-through in GatewayConfig.resolved_token already masks) "
        "— see _migrate_gateway_token_env_realign docstring",
        _migrate_gateway_token_env_realign,
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
