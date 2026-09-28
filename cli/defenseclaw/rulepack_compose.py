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

"""Compose a guardrail rule pack from a base pack plus opt-in protection packs.

Uses Policy Creator's layering (``docs-site/components/policy-creator/
sections/deterministic-coverage.tsx`` ``applyPack``), once per protection pack
in catalog order: drop every rule whose id the pack ships, then append the
pack's rules to the rule file with the same name (taking the pack's
``category``), or add the file.

The composed directory holds the base pack's rule-pack components (the YAML
files the Go loader recognizes, byte for byte unless merged), the merged rule
files and a ``defenseclaw-pack.json`` manifest recording the base and the
layered packs. The Go loader only inventories ``*.yaml``, so the manifest is
invisible to it. Building happens in a hidden staging directory next to the
target so a pack is validated before anything points at it.
"""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from typing import Any

import yaml

from defenseclaw import policy_catalog

# Mirrors internal/guardrail/rulepack.go knownJudgeNames.
_JUDGE_NAMES = ("exfil", "injection", "pii", "tool-injection")
_TOP_LEVEL_COMPONENTS = ("suppressions.yaml", "sensitive-tools.yaml")
_SCOPE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class ComposeError(Exception):
    """A protected pack can't be composed or installed; nothing was switched."""


def protected_scope_name(scope: str) -> str:
    """Directory-safe scope name (``global`` or a canonical connector name)."""
    name = (scope or "").strip().lower()
    if not _SCOPE_NAME.match(name):
        raise ComposeError(f"{scope!r} can't be used in a rule-pack directory name.")
    return name


def is_composed(pack_dir: str) -> bool:
    return policy_catalog.read_protection_manifest(pack_dir) is not None


def resolve_base(cfg: Any, pack_path: str) -> tuple[str, str]:
    """``(path, name)`` of the pack a scope's layers sit on.

    A composed pack points at its recorded base (followed through any chain
    of manifests); anything else is its own base.
    """
    path = pack_path
    seen: set[str] = set()
    for _ in range(8):
        manifest = policy_catalog.read_protection_manifest(path)
        if manifest is None:
            if not path or not os.path.isdir(path):
                raise ComposeError(f"The rule pack {path or '(none)'} doesn't exist.")
            name, _kind = policy_catalog.pack_name_for_path(cfg, path)
            return path, name
        seen.add(os.path.realpath(path))
        base = policy_catalog.normalize_pack_path(manifest.base)
        if os.path.realpath(base) in seen:
            raise ComposeError(f"The base recorded in {path} points back at itself.")
        if not os.path.isdir(base):
            raise ComposeError(
                f"The base pack {manifest.base_name or base} recorded in {path} no longer exists ({base}). "
                "Pick a pack with defenseclaw guardrail use-pack first."
            )
        path = base
    raise ComposeError(f"Too many layers of composed packs under {pack_path}.")


def _components(base_dir: str) -> list[str]:
    """Relative paths of the recognized rule-pack YAML components of a pack."""
    out = [name for name in _TOP_LEVEL_COMPONENTS if os.path.lexists(os.path.join(base_dir, name))]
    for name in _JUDGE_NAMES:
        rel = os.path.join("judge", f"{name}.yaml")
        if os.path.lexists(os.path.join(base_dir, rel)):
            out.append(rel)
    rules_dir = os.path.join(base_dir, "rules")
    if os.path.isdir(rules_dir):
        try:
            names = sorted(os.listdir(rules_dir))
        except OSError as exc:
            raise ComposeError(f"Can't read {rules_dir}: {exc}") from exc
        out.extend(os.path.join("rules", name) for name in names if name.endswith(".yaml"))
    return out


def _check_regular(base_dir: str, rel_paths: Sequence[str]) -> None:
    # The gateway refuses symbolic links inside a pack; never follow one here.
    for rel in ("judge", "rules", *rel_paths):
        full = os.path.join(base_dir, rel)
        if os.path.islink(full):
            raise ComposeError(f"{full} is a symbolic link; the gateway refuses those in a rule pack.")
    for rel in rel_paths:
        full = os.path.join(base_dir, rel)
        if not os.path.isfile(full):
            raise ComposeError(f"{full} isn't a regular file.")


def _rule_id(rule: object) -> str:
    if not isinstance(rule, Mapping):
        return ""
    raw = rule.get("id")
    return raw.strip() if isinstance(raw, str) else ""


def merge_rule_files(
    base: Mapping[str, Mapping[str, Any]],
    packs: Sequence[Sequence[tuple[str, Mapping[str, Any]]]],
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Layer each pack's ``(filename, mapping)`` rule files onto *base*.

    Returns the merged ``filename -> mapping`` files and the names of the
    files that changed or were added. Inputs are not mutated.
    """
    files: dict[str, dict[str, Any]] = {name: copy.deepcopy(dict(data)) for name, data in base.items()}
    changed: set[str] = set()
    for pack_files in packs:
        incoming = {_rule_id(rule) for _name, data in pack_files for rule in data.get("rules") or []}
        incoming.discard("")
        for name, data in files.items():
            rules = list(data.get("rules") or [])
            kept = [rule for rule in rules if _rule_id(rule) not in incoming]
            if len(kept) != len(rules):
                data["rules"] = kept
                changed.add(name)
        for name, pack_data in pack_files:
            pack_rules = [copy.deepcopy(rule) for rule in pack_data.get("rules") or [] if isinstance(rule, Mapping)]
            existing = files.get(name)
            if existing is not None:
                if "category" in pack_data:
                    existing["category"] = pack_data["category"]
                existing["rules"] = list(existing.get("rules") or []) + pack_rules
            else:
                added = copy.deepcopy(dict(pack_data))
                added["rules"] = pack_rules
                files[name] = added
            changed.add(name)
    return files, changed


def _dump_rule_file(data: Mapping[str, Any]) -> str:
    # One line per scalar: no folding of long regexes or CEL expressions.
    return yaml.safe_dump(dict(data), sort_keys=False, default_flow_style=False, allow_unicode=True, width=1 << 30)


def _pack_rule_files(name: str, use_cases_root: str | None) -> list[tuple[str, dict[str, Any]]]:
    source = policy_catalog.protection_pack_dir(name, use_cases_root)
    files = policy_catalog.load_rule_files(source) if source else []
    if not files:
        raise ComposeError(f"The {name} protection pack has no rules to add.")
    return files


def check_target(final: str) -> None:
    """Refuse to replace a directory that ``guardrail protection`` didn't make."""
    if not os.path.lexists(final):
        return
    if os.path.islink(final) or not os.path.isdir(final) or not is_composed(final):
        raise ComposeError(
            f"{final} already exists and wasn't composed by defenseclaw guardrail protection; move it aside first."
        )


def stage_pack(
    *,
    base_dir: str,
    base_name: str,
    protection: Sequence[str],
    layer: Sequence[str],
    final: str,
    use_cases_root: str | None = None,
) -> str:
    """Build the composed pack in a hidden directory next to *final*.

    *layer* are the packs to merge (in order); *protection* is what the
    manifest records (it may also name packs already built into the base).
    Returns the staging directory; the caller validates it, then calls
    :func:`install_pack` or :func:`discard`.
    """
    base_dir = os.path.realpath(base_dir)
    components = _components(base_dir)
    _check_regular(base_dir, components)
    parent = os.path.dirname(final)
    try:
        os.makedirs(parent, exist_ok=True)
        staged = tempfile.mkdtemp(prefix=f".{os.path.basename(final)}.", dir=parent)
    except OSError as exc:
        raise ComposeError(f"Can't create a staging directory in {parent}: {exc}") from exc
    try:
        # mkdtemp is 0700; keep the base pack's permissions instead.
        shutil.copymode(base_dir, staged)
        for rel in components:
            dest = os.path.join(staged, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(os.path.join(base_dir, rel), dest)

        base_files: dict[str, dict[str, Any]] = {}
        for rel in components:
            directory, name = os.path.split(rel)
            if directory != "rules" or name == "local-patterns.yaml":
                continue
            data = policy_catalog.load_policy_yaml(os.path.join(staged, rel))
            if data is None or not isinstance(data.get("rules", []), list):
                raise ComposeError(f"{os.path.join(base_dir, rel)} isn't a readable rule file.")
            if "rules" in data:
                base_files[name] = data

        packs = [_pack_rule_files(name, use_cases_root) for name in layer]
        merged, changed = merge_rule_files(base_files, packs)
        os.makedirs(os.path.join(staged, "rules"), exist_ok=True)
        for name in sorted(changed):
            with open(os.path.join(staged, "rules", name), "w", encoding="utf-8") as fh:
                fh.write(_dump_rule_file(merged[name]))

        manifest = {
            "version": 1,
            "base": base_dir,
            "base_name": base_name,
            "protection": list(protection),
        }
        with open(os.path.join(staged, policy_catalog.PROTECTION_MANIFEST), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
            fh.write("\n")
    except ComposeError:
        discard(staged)
        raise
    except (OSError, yaml.YAMLError, ValueError) as exc:
        discard(staged)
        raise ComposeError(f"Couldn't compose the pack: {exc}") from exc
    return staged


def discard(staged: str) -> None:
    shutil.rmtree(staged, ignore_errors=True)


def install_pack(staged: str, final: str) -> None:
    """Move *staged* to *final*, replacing a previously composed pack."""
    check_target(final)
    backup = ""
    try:
        if os.path.lexists(final):
            backup = os.path.join(os.path.dirname(final), f".{os.path.basename(final)}.old-{secrets.token_hex(4)}")
            os.replace(final, backup)
        try:
            os.replace(staged, final)
        except OSError:
            if backup:
                os.replace(backup, final)
                backup = ""
            raise
    except OSError as exc:
        discard(staged)
        raise ComposeError(f"Couldn't put the composed pack at {final}: {exc}") from exc
    if backup:
        shutil.rmtree(backup, ignore_errors=True)


def remove_pack(path: str) -> bool:
    """Delete a composed pack directory (never anything without a manifest)."""
    if not path or os.path.islink(path) or not os.path.isdir(path) or not is_composed(path):
        return False
    if not os.path.basename(os.path.normpath(path)).startswith(policy_catalog.PROTECTED_PACK_PREFIX):
        return False
    shutil.rmtree(path, ignore_errors=True)
    return not os.path.exists(path)


__all__ = [
    "ComposeError",
    "check_target",
    "discard",
    "install_pack",
    "is_composed",
    "merge_rule_files",
    "protected_scope_name",
    "remove_pack",
    "resolve_base",
    "stage_pack",
]
