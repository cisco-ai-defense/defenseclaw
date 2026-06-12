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

"""Explicit, opt-in Project CodeGuard native asset installation.

Server-side CodeGuard scanning is always independent from this module. The
functions here only copy optional native skill/rule assets into agent-owned
directories when the operator explicitly runs ``defenseclaw codeguard install``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from defenseclaw import connector_paths
from defenseclaw.paths import bundled_codeguard_dir

# Allow-listed character class for the per-target archive sub-directory.
# Connector and target are normalized to one of a small known set elsewhere
# in this module, but we belt-and-brace here in case a future caller
# bypasses _normalize_target / _resolve_connector and supplies a raw
# string that could otherwise traverse out of the archive root.
_ARCHIVE_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class CodeGuardAssetStatus:
    connector: str
    target: str
    path: str
    status: str
    detail: str = ""

    def format(self) -> str:
        suffix = f" ({self.detail})" if self.detail else ""
        if self.path:
            return f"{self.status} {self.path}{suffix}"
        return f"{self.status}{suffix}"


def codeguard_status(cfg, connector: str | None = None, target: str = "skill") -> CodeGuardAssetStatus:
    connector = _resolve_connector(cfg, connector)
    target = _normalize_target(target)
    path = _target_path(cfg, connector, target)
    if not path:
        return CodeGuardAssetStatus(connector, target, "", "unsupported", f"{connector} has no {target} install target")
    if target == "skill":
        if _is_codeguard_skill_dir(path):
            return CodeGuardAssetStatus(connector, target, path, "installed")
        if os.path.exists(path):
            return CodeGuardAssetStatus(
                connector,
                target,
                path,
                "conflict",
                "existing path is not recognizable as CodeGuard",
            )
        return CodeGuardAssetStatus(connector, target, path, "missing")
    if _is_codeguard_rule_file(path):
        return CodeGuardAssetStatus(connector, target, path, "installed")
    if os.path.exists(path):
        return CodeGuardAssetStatus(
            connector,
            target,
            path,
            "conflict",
            "existing file is not recognizable as CodeGuard",
        )
    return CodeGuardAssetStatus(connector, target, path, "missing")


def install_codeguard_asset(
    cfg,
    *,
    connector: str | None = None,
    target: str = "skill",
    replace: bool = False,
) -> str:
    """Install a CodeGuard native asset if absent.

    Existing valid CodeGuard assets are skipped. Existing non-CodeGuard paths
    are treated as conflicts unless *replace* is true.
    """
    status = codeguard_status(cfg, connector=connector, target=target)
    if status.status == "unsupported":
        return status.format()
    if status.status == "installed" and not replace:
        return f"already installed at {status.path}"
    if status.status == "conflict" and not replace:
        return f"conflict at {status.path} (use --replace to overwrite)"

    source_dir = _find_skill_source()
    if source_dir is None:
        return "skipped (skill source not found in package)"

    archive_root = _archive_root(cfg)
    archived: str | None = None

    if target == "skill":
        archived = _archive_path(
            status.path, archive_root, status.connector, target, replace=replace
        )
        _replace_path(status.path, replace=replace)
        os.makedirs(os.path.dirname(status.path), exist_ok=True)
        shutil.copytree(source_dir, status.path)
        if status.connector == "openclaw":
            _enable_codeguard_in_openclaw(_expand(cfg.claw.config_file))
        suffix = f" (previous content archived to {archived})" if archived else ""
        return f"installed to {status.path}{suffix}"

    content = _rule_content(source_dir)
    archived = _archive_path(
        status.path, archive_root, status.connector, target, replace=replace
    )
    _replace_path(status.path, replace=replace)
    os.makedirs(os.path.dirname(status.path), exist_ok=True)
    with open(status.path, "w", encoding="utf-8") as f:
        f.write(content)
    suffix = f" (previous content archived to {archived})" if archived else ""
    return f"installed to {status.path}{suffix}"


def install_codeguard_skill(cfg, connector: str | None = None, replace: bool = False) -> str:
    """Backward-compatible explicit skill installer."""
    return install_codeguard_asset(cfg, connector=connector, target="skill", replace=replace)


def ensure_codeguard_skill(claw_home: str, openclaw_config: str, connector: str = "") -> None:
    """Deprecated no-op retained for older callers.

    Native CodeGuard assets are fully opt-in; CLI startup, init, sandbox setup,
    and sidecar setup must not call through to an implicit installer.
    """
    _ = claw_home
    _ = openclaw_config
    _ = connector


def _resolve_connector(cfg, connector: str | None) -> str:
    if connector:
        return connector_paths.normalize(connector)
    if hasattr(cfg, "active_connector"):
        return connector_paths.normalize(cfg.active_connector())
    return connector_paths.normalize(getattr(getattr(cfg, "guardrail", object()), "connector", "") or "openclaw")


def _normalize_target(target: str) -> str:
    target = (target or "skill").strip().lower()
    if target not in {"skill", "rule"}:
        raise ValueError("target must be 'skill' or 'rule'")
    return target


def _target_path(cfg, connector: str, target: str) -> str:
    if target == "skill":
        if connector == "scout":
            return os.path.join(str(Path.home()), ".copilot", "skills", "codeguard")
        dirs = connector_paths.skill_dirs(
            connector,
            openclaw_home=getattr(getattr(cfg, "claw", object()), "home_dir", None),
            openclaw_config=getattr(getattr(cfg, "claw", object()), "config_file", None),
        )
        return os.path.join(dirs[0], "codeguard") if dirs else ""
    cwd = os.getcwd()
    if connector == "cursor":
        return os.path.join(cwd, ".cursor", "rules", "codeguard.mdc")
    if connector == "copilot":
        return os.path.join(cwd, ".github", "instructions", "codeguard.instructions.md")
    if connector == "windsurf":
        for parent in (
            os.path.join(cwd, ".windsurf", "rules"),
            os.path.join(cwd, ".codeium", "windsurf", "rules"),
        ):
            if os.path.isdir(parent):
                return os.path.join(parent, "codeguard.md")
        return ""
    return ""


def _replace_path(path: str, *, replace: bool) -> None:
    if not os.path.exists(path):
        return
    if not replace:
        return
    if os.path.isdir(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _archive_root(cfg) -> str:
    """Return the absolute directory used for opt-in CodeGuard backups.

    Prefers ``cfg.data_dir`` (the persisted DefenseClaw home), falling
    back to ``$DEFENSECLAW_HOME`` and finally ``~/.defenseclaw`` so the
    archive is always under the operator's owner-only state directory.
    The directory is created with mode ``0o700`` because the archived
    payload may carry user-authored skill/rule content.
    """
    data_dir = (getattr(cfg, "data_dir", None) or "").strip()
    if not data_dir:
        data_dir = os.environ.get("DEFENSECLAW_HOME", "").strip()
    if not data_dir:
        data_dir = str(Path.home() / ".defenseclaw")
    return os.path.join(data_dir, "connector_backups", "codeguard")


def _archive_slug(value: str) -> str:
    """Sanitize *value* for use as a single archive sub-directory name.

    Returns a non-empty token from the ``[A-Za-z0-9._-]`` allow-list.
    Empty inputs (or inputs that reduce to nothing after sanitization)
    fall back to ``"_"`` so we never create an archive path that points
    at the parent directory.
    """
    cleaned = _ARCHIVE_SLUG_RE.sub("_", (value or "").strip())
    cleaned = cleaned.strip(".-_")
    return cleaned or "_"


def _archive_path(
    path: str,
    archive_root: str,
    connector: str,
    target: str,
    *,
    replace: bool,
) -> str | None:
    """Copy *path* into the per-connector archive before --replace deletes it.

    Returns the archive directory on success, ``None`` when there is
    nothing to archive (target absent or operator did not pass
    ``--replace``).

    Every directory we create under the archive root is forced to
    ``0o700`` because ``os.makedirs(mode=...)`` only applies the mode
    to the *leaf* directory — intermediates are created with the
    default 0o777 masked by the current umask (typically 0o022,
    yielding world-readable 0o755). Listing
    ``${data_dir}/connector_backups/codeguard/`` reveals which
    connectors are installed, which is operator state we do not want
    leaked to other local users.
    """
    if not replace:
        return None
    if not os.path.exists(path):
        return None
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target_dir = os.path.join(
        archive_root,
        _archive_slug(connector),
        _archive_slug(target),
        ts,
    )
    # stop_at is the directory ABOVE archive_root (i.e. data_dir
    # itself, which the operator may have set to ~ or similar). The
    # walk tightens connector_backups, codeguard, <connector>,
    # <target>, and <ts> — every DefenseClaw-owned dir under the
    # operator-owned data_dir gets 0o700 if we created it.
    _makedirs_owner_only(target_dir, stop_at=os.path.dirname(os.path.dirname(archive_root)))
    dest = os.path.join(target_dir, os.path.basename(path) or "previous")
    if os.path.isdir(path):
        shutil.copytree(path, dest, symlinks=False)
    else:
        shutil.copy2(path, dest)
    return target_dir


def _makedirs_owner_only(path: str, *, stop_at: str = "") -> None:
    """Create *path* and tighten every newly-created component to 0o700.

    Walks from ``stop_at`` (exclusive) down to *path*, creating each
    directory and setting the mode to ``0o700`` as we go. Directories
    that already exist are left untouched on the way down — we only
    chmod paths we created — so this helper never narrows perms on a
    pre-existing user dir like ``~/`` or ``~/.defenseclaw``.

    ``stop_at`` defaults to the empty string which means "walk all the
    way up to the filesystem root". Callers pass an explicit value
    when they only want to harden the subtree they own.
    """
    components: list[str] = []
    current = path
    stop_at = os.path.abspath(stop_at) if stop_at else ""
    while True:
        components.append(current)
        parent = os.path.dirname(current)
        if not parent or parent == current:
            break
        if stop_at and os.path.abspath(parent) == stop_at:
            break
        current = parent
    components.reverse()
    for comp in components:
        existed = os.path.isdir(comp)
        try:
            os.makedirs(comp, exist_ok=True)
        except OSError:
            # Re-raise so the caller sees the underlying error
            # (typically permissions on the parent), instead of
            # silently failing to archive.
            raise
        if not existed:
            try:
                os.chmod(comp, 0o700)
            except OSError:
                # chmod can fail on filesystems that don't honor POSIX
                # modes (CIFS, exFAT). The MkdirAll already applied
                # the mode argument to the leaf, and an unwritable
                # archive will surface its own error on shutil.copy2.
                pass


def _is_codeguard_skill_dir(path: str) -> bool:
    manifest = os.path.join(path, "SKILL.md")
    try:
        text = Path(manifest).read_text(encoding="utf-8")
    except OSError:
        return False
    return _looks_like_codeguard(text)


def _is_codeguard_rule_file(path: str) -> bool:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return False
    return _looks_like_codeguard(text)


def _looks_like_codeguard(text: str) -> bool:
    return "CodeGuard" in text and (
        "CG-CRED-" in text
        or "Project CodeGuard" in text
        or "defenseclaw:codeguard" in text
    )


def _find_skill_source() -> str | None:
    d = bundled_codeguard_dir()
    if d.is_dir() and (d / "SKILL.md").is_file():
        return str(d)
    return None


def _rule_content(source_dir: str) -> str:
    manifest = Path(source_dir, "SKILL.md").read_text(encoding="utf-8")
    body = manifest.split("---", 2)[-1].strip() if manifest.startswith("---") else manifest.strip()
    return "<!-- defenseclaw:codeguard managed=true -->\n\n" + body + "\n"


def _enable_codeguard_in_openclaw(openclaw_config: str) -> None:
    path = _expand(openclaw_config)
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    skills = cfg.setdefault("skills", {})
    entries = skills.setdefault("entries", {})
    if isinstance(entries.get("codeguard"), dict) and entries["codeguard"].get("enabled") is True:
        return
    entries["codeguard"] = {"enabled": True}
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
    except OSError:
        pass


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return str(Path.home() / p[2:])
    return p
