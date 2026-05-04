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

"""OpenClaw-specific guardrail wiring.

This module is the home for the on-disk patching that connects the
DefenseClaw guardrail proxy to OpenClaw via ``~/.openclaw/openclaw.json``.
It was extracted from the historical ``guardrail.py`` (S4.4) so the
common connector machinery in :mod:`defenseclaw.guardrail` could shed
its hard dependency on OpenClaw. The other connectors (Codex, Claude
Code, ZeptoClaw) carry their wiring in their own modules — see
:mod:`defenseclaw.connector_paths` and the Go-side ``Connector.Setup``.

Public surface (call this module via ``from defenseclaw.guardrail
import …`` for back-compat — :mod:`defenseclaw.guardrail` re-exports
every name listed here):

* :func:`patch_openclaw_config`
* :func:`restore_openclaw_config`
* :func:`uninstall_openclaw_plugin`
* :func:`detect_current_model`
* :func:`record_pristine_backup`
* :func:`pristine_backup_path`

Everything else is treated as private to OpenClaw flows; the test
suite still reaches in for ``_backup`` /
``_register_plugin_in_config`` etc. via the back-compat
re-export, so the leading-underscore helpers below stay public to
the package.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path


def patch_openclaw_config(
    openclaw_config_file: str,
    model_name: str,  # kept for API compat — no longer used (fetch interceptor handles routing)
    proxy_port: int,  # kept for API compat — no longer used
    master_key: str,  # kept for API compat — no longer used
    original_model: str,
    guardrail_host: str = "localhost",
    data_dir: str = "",
    enable_plugin_approvals: bool = False,
) -> str | None:
    """Register the DefenseClaw plugin in openclaw.json.

    The fetch interceptor handles all traffic routing transparently —
    no provider entry or model redirection is needed. This function only
    registers the plugin so OpenClaw loads it on startup.

    When ``data_dir`` is provided we write a *pristine* timestamped
    backup to ``<data_dir>/backups/`` the very first time DefenseClaw
    touches this ``openclaw.json`` and record it in
    ``<data_dir>/openclaw-backups.json``. That gives ``uninstall`` and
    ``doctor --fix`` a deterministic rollback target even after many
    ``.bak.N`` rotations have occurred.
    """
    _ = model_name, proxy_port, master_key, guardrail_host  # unused — fetch interceptor handles routing
    path = _expand(openclaw_config_file)

    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    # Record pristine backup BEFORE any writes so we always capture the
    # untouched file. ``record_pristine_backup`` is idempotent — once a
    # pristine copy exists for this config path it will not be
    # overwritten on subsequent patches.
    if data_dir:
        with contextlib.suppress(OSError):
            record_pristine_backup(path, data_dir)

    _backup(path)

    prev_model = (
        cfg.get("agents", {}).get("defaults", {}).get("model", {}).get("primary", "")
    )

    plugins = cfg.setdefault("plugins", {})
    allow = plugins.setdefault("allow", [])
    if "defenseclaw" not in allow:
        allow.append("defenseclaw")

    # Re-enable plugin entry (may have been disabled by restore_openclaw_config).
    entries = plugins.setdefault("entries", {})
    if "defenseclaw" not in entries:
        entries["defenseclaw"] = {"enabled": True}
    else:
        entries["defenseclaw"]["enabled"] = True

    oc_home = os.path.dirname(path)
    install_path = os.path.join(oc_home, "extensions", "defenseclaw")
    load = plugins.setdefault("load", {})
    paths = load.setdefault("paths", [])
    if install_path not in paths:
        paths.append(install_path)

    if enable_plugin_approvals:
        approvals = cfg.setdefault("approvals", {})
        plugin_approvals = approvals.setdefault("plugin", {})
        plugin_approvals["enabled"] = True
        plugin_approvals.setdefault("mode", "session")

    with _preserve_ownership(path):
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")

    _install_codeguard_skill_deferred(openclaw_config_file)

    return prev_model or original_model


def restore_openclaw_config(openclaw_config_file: str, original_model: str) -> bool:
    """Remove the DefenseClaw plugin registration from openclaw.json.

    The fetch interceptor required no model or provider changes, so there is
    nothing to revert — just remove the plugin entries.
    """
    _ = original_model  # unused — kept for API compat
    path = _expand(openclaw_config_file)

    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

    _backup(path)

    # Remove leftover defenseclaw provider entry if present from older setups.
    if "models" in cfg and "providers" in cfg["models"]:
        cfg["models"]["providers"].pop("defenseclaw", None)
        cfg["models"]["providers"].pop("litellm", None)

    if "plugins" in cfg:
        plugins = cfg["plugins"]
        allow = plugins.get("allow", [])
        if "defenseclaw" in allow:
            allow.remove("defenseclaw")
        entries = plugins.get("entries", {})
        if "defenseclaw" in entries:
            entries["defenseclaw"]["enabled"] = False
        oc_home = os.path.dirname(path)
        install_path = os.path.join(oc_home, "extensions", "defenseclaw")
        paths = plugins.get("load", {}).get("paths", [])
        if install_path in paths:
            paths.remove(install_path)

    with _preserve_ownership(path):
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")

    return True


# NOTE: install_openclaw_plugin lived here previously. The gateway's
# OpenClawConnector.Setup() now installs the embedded plugin directly
# into ~/.openclaw/extensions/defenseclaw and patches openclaw.json on
# every sidecar boot, so there is no separate Python-side install step.
# `uninstall_openclaw_plugin` is kept for `defenseclaw uninstall`, which
# has to revert the plugin even if the gateway is already gone.


def uninstall_openclaw_plugin(openclaw_home: str) -> str:
    """Uninstall the DefenseClaw plugin from OpenClaw.

    Tries ``openclaw plugins uninstall defenseclaw`` first, falls back
    to removing the extensions directory and config entries manually.

    Returns:
        ``"cli"``    — uninstalled via openclaw CLI
        ``"manual"`` — removed directory manually
        ``""``       — plugin was not installed
        ``"error"``  — removal failed (permissions, etc.)
    """
    oc_home = _expand(openclaw_home)
    target_dir = os.path.join(oc_home, "extensions", "defenseclaw")
    oc_config = os.path.join(oc_home, "openclaw.json")
    is_installed = os.path.isdir(target_dir) or os.path.islink(target_dir)

    if not is_installed:
        _unregister_plugin_from_config(oc_config)
        return ""

    _remove_from_plugins_allow(oc_config, "defenseclaw")

    try:
        from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix
        prefix = openclaw_cmd_prefix()
        result = subprocess.run(
            [*prefix, openclaw_bin(), "plugins", "uninstall", "defenseclaw"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return "cli"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        if os.path.islink(target_dir):
            os.unlink(target_dir)
        elif os.path.isdir(target_dir):
            shutil.rmtree(target_dir)
        _unregister_plugin_from_config(oc_config)
        return "manual"
    except OSError:
        return "error"


def detect_current_model(openclaw_config_file: str) -> tuple[str, str]:
    """Read the current model from openclaw.json. Returns
    ``(model_id, provider_prefix)``."""
    path = _expand(openclaw_config_file)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return "", ""

    primary = (
        cfg.get("agents", {}).get("defaults", {}).get("model", {}).get("primary", "")
    )
    if "/" in primary:
        provider, _model_id = primary.split("/", 1)
        return primary, provider
    return primary, ""


# ------------------------------------------------------------------
# Internal helpers (still public to the package — exercised by the
# legacy test_guardrail.py via the back-compat re-export shim).
# ------------------------------------------------------------------


def _unregister_plugin_from_config(openclaw_config: str) -> None:
    """Remove defenseclaw plugin entries from openclaw.json."""
    path = _expand(openclaw_config)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    plugins = cfg.get("plugins", {})
    changed = False

    entries = plugins.get("entries", {})
    if "defenseclaw" in entries:
        del entries["defenseclaw"]
        changed = True

    installs = plugins.get("installs", {})
    if "defenseclaw" in installs:
        install_path = installs["defenseclaw"].get("installPath", "")
        del installs["defenseclaw"]
        changed = True

        paths = plugins.get("load", {}).get("paths", [])
        if install_path in paths:
            paths.remove(install_path)

    if changed:
        with _preserve_ownership(path):
            with open(path, "w") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
                f.write("\n")


def _register_plugin_in_config(openclaw_config: str, source_dir: str) -> None:
    """Register the defenseclaw plugin in openclaw.json (manual fallback).

    Mirrors what ``openclaw plugins install`` does: adds entries to
    plugins.load.paths, plugins.installs, and plugins.entries so
    OpenClaw discovers and loads the plugin.
    """
    path = _expand(openclaw_config)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    plugins = cfg.setdefault("plugins", {})

    entries = plugins.setdefault("entries", {})
    if "defenseclaw" not in entries:
        entries["defenseclaw"] = {"enabled": True}

    oc_home = os.path.dirname(path)
    install_path = os.path.join(oc_home, "extensions", "defenseclaw")
    load = plugins.setdefault("load", {})
    paths = load.setdefault("paths", [])
    if install_path not in paths:
        paths.append(install_path)

    allow = plugins.setdefault("allow", [])
    if "defenseclaw" not in allow:
        allow.append("defenseclaw")

    version = "0.0.0"
    try:
        pkg_json = os.path.join(source_dir, "package.json")
        with open(pkg_json) as f:
            version = json.load(f).get("version", version)
    except (OSError, json.JSONDecodeError):
        pass

    from datetime import datetime, timezone
    installs = plugins.setdefault("installs", {})
    installs["defenseclaw"] = {
        "source": "path",
        "sourcePath": source_dir,
        "installPath": install_path,
        "version": version,
        "installedAt": datetime.now(timezone.utc).isoformat(),
    }

    with _preserve_ownership(path):
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")


def _remove_from_plugins_allow(openclaw_config: str, plugin_id: str) -> None:
    """Remove a plugin id from plugins.allow in openclaw.json (if present)."""
    path = _expand(openclaw_config)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    allow = cfg.get("plugins", {}).get("allow", [])
    if plugin_id not in allow:
        return

    allow.remove(plugin_id)
    with _preserve_ownership(path):
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return str(Path.home() / p[2:])
    return p


@contextmanager
def _preserve_ownership(path: str):
    """Capture a file's uid/gid before a write and restore it afterwards.

    Only relevant in standalone sandbox mode where setup commands run
    as root and would otherwise re-create files owned by root,
    breaking sandbox user access. Skipped entirely for non-root
    callers since ``os.chown`` requires elevated privileges.
    """
    if os.getuid() != 0:
        yield
        return

    uid = gid = None
    try:
        st = os.stat(path)
        uid, gid = st.st_uid, st.st_gid
    except OSError:
        pass

    yield

    if uid is not None:
        with contextlib.suppress(OSError):
            os.chown(path, uid, gid)


# ---------------------------------------------------------------------------
# Pristine backup index — keeps a one-time snapshot of openclaw.json
# at first DefenseClaw write so uninstall/doctor have a known-good
# rollback target.
# ---------------------------------------------------------------------------

BACKUP_INDEX_FILENAME = "openclaw-backups.json"
BACKUP_SUBDIR = "backups"


def _backup_index_path(data_dir: str) -> str:
    return os.path.join(data_dir, BACKUP_INDEX_FILENAME)


def _read_backup_index(data_dir: str) -> dict:
    """Load the backup index, returning an empty doc on any failure.

    Schema (v1)::

        {
          "version": 1,
          "entries": {
            "<abs openclaw.json path>": {
              "pristine": "<abs path to timestamped copy>",
              "captured_at": "<ISO-8601 UTC>"
            }
          }
        }
    """
    path = _backup_index_path(data_dir)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"version": 1, "entries": {}}


def _write_backup_index(data_dir: str, doc: dict) -> None:
    """Atomically persist the backup index, creating *data_dir* as needed."""
    os.makedirs(data_dir, exist_ok=True)
    path = _backup_index_path(data_dir)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def record_pristine_backup(openclaw_config_file: str, data_dir: str) -> str | None:
    """Capture a one-time pristine snapshot of *openclaw_config_file*.

    This is idempotent: once an entry exists for this path in the
    backup index, subsequent calls are no-ops. Returns the absolute
    path to the pristine snapshot on first capture, or ``None`` when
    no snapshot was taken (either no source file, already recorded,
    or the copy failed).
    """
    src = _expand(openclaw_config_file)
    if not os.path.isfile(src):
        return None
    if not data_dir:
        return None

    index = _read_backup_index(data_dir)
    entries = index.setdefault("entries", {})
    src_abs = os.path.abspath(src)
    if src_abs in entries and os.path.isfile(entries[src_abs].get("pristine", "")):
        return None  # already captured a valid snapshot

    import datetime
    backup_dir = os.path.join(data_dir, BACKUP_SUBDIR)
    os.makedirs(backup_dir, exist_ok=True)

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    basename = os.path.basename(src) or "openclaw.json"
    dest = os.path.join(backup_dir, f"{basename}.{stamp}.pristine")
    try:
        shutil.copy2(src, dest)
    except OSError:
        return None

    entries[src_abs] = {
        "pristine": os.path.abspath(dest),
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
    }
    index["version"] = 1
    try:
        _write_backup_index(data_dir, index)
    except OSError:
        # Best-effort: the snapshot exists on disk, but we couldn't
        # index it. Uninstall will have to fall back to the .bak files.
        with contextlib.suppress(OSError):
            os.unlink(dest)
        return None
    return os.path.abspath(dest)


def pristine_backup_path(openclaw_config_file: str, data_dir: str) -> str | None:
    """Return the pristine snapshot path for *openclaw_config_file*, if any."""
    if not data_dir:
        return None
    index = _read_backup_index(data_dir)
    entry = index.get("entries", {}).get(os.path.abspath(_expand(openclaw_config_file)))
    if not entry:
        return None
    pristine = entry.get("pristine", "")
    return pristine if pristine and os.path.isfile(pristine) else None


def _backup(path: str) -> None:
    """Create a numbered backup of a file."""
    if not os.path.isfile(path):
        return
    bak = path + ".bak"
    if os.path.exists(bak):
        found = False
        for i in range(1, 100):
            candidate = f"{path}.bak.{i}"
            if not os.path.exists(candidate):
                bak = candidate
                found = True
                break
        if not found:
            import time
            bak = f"{path}.bak.{int(time.time() * 1000)}.{os.getpid()}"
    st = os.stat(path)
    shutil.copy2(path, bak)
    with contextlib.suppress(OSError):
        os.chown(bak, st.st_uid, st.st_gid)


def _install_codeguard_skill_deferred(openclaw_config_file: str) -> None:
    """Install the CodeGuard skill when guardrail connects to OpenClaw.

    This handles the case where the user ran ``defenseclaw init``
    before OpenClaw was installed, then later runs ``defenseclaw
    guardrail enable``.
    """
    try:
        from defenseclaw.codeguard_skill import ensure_codeguard_skill
        from defenseclaw.config import load

        cfg = load()
        ensure_codeguard_skill(cfg.claw_home_dir(), openclaw_config_file)
    except Exception:
        pass
