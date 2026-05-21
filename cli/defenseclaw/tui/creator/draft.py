# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``PolicyDraftModel`` - in-flight draft state with file persistence.

Mirrors the React Creator's ``localStorage`` cache, but uses
``<data_dir>/policy-creator/drafts/<slug>.json`` instead of browser
storage so:

* Drafts survive across TUI sessions.
* The CLI's ``defenseclaw policy edit <name>`` can reuse the same
  drafts directory without coupling to a browser-side state store.
* Tests can assert against the on-disk JSON shape directly.

The draft file holds a ``Policy`` plus the wizard's step pointer plus
the ``answers`` map (Quick Start scratch state). All three layers are
stored together so reopening a half-finished draft restores the
operator at the exact step they left off on.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from defenseclaw.tui.creator.presets import load_preset, policy_from_yaml
from defenseclaw.tui.creator.types import Policy, PresetName

# Slug pattern matching the CLI's policy-name validation
# (`cli/defenseclaw/commands/cmd_policy.py`'s ``_validate_name``).
# Empty / wildcard names are filtered upstream; this helps map a
# user-typed name to a stable filename.
_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def _slugify(name: str) -> str:
    cleaned = _SLUG_RE.sub("-", name.strip()).strip("-").lower()
    return cleaned or "untitled"


@dataclass
class DraftMetadata:
    """Sidecar metadata persisted alongside the policy snapshot."""

    slug: str = ""
    based_on: PresetName = "default"
    last_updated_iso: str = ""
    quick_start_step: int = 0
    quick_start_answers: dict[str, Any] = field(default_factory=dict)
    last_section: str = ""  # last Playground section the operator viewed


def drafts_dir(data_dir: Path) -> Path:
    """Return ``<data_dir>/policy-creator/drafts``, ensuring parents exist."""
    out = data_dir / "policy-creator" / "drafts"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _policy_to_json_dict(policy: Policy) -> dict[str, Any]:
    """Convert a ``Policy`` to a JSON-safe dict using ``asdict``.

    ``dataclasses.asdict`` recursively turns nested dataclasses into
    plain dicts. Tuple fields aren't used in the schema (we prefer
    list[...] in the dataclass defs), so the output is JSON-safe
    without further coercion.
    """
    return asdict(policy)


def _policy_from_json_dict(name: str, data: dict[str, Any]) -> Policy:
    """Inverse of ``_policy_to_json_dict``.

    The persisted JSON came from ``asdict(policy)``; ``policy_from_yaml``
    parses the same shape from disk YAML, so we reuse it.
    """
    return policy_from_yaml(name, data)


def policy_from_dict(data: dict[str, Any]) -> Policy:
    """Public alias for the JSON-dict -> ``Policy`` hydrator.

    Used by ``creator/share.py`` when decoding an imported share-link
    payload. The ``name`` falls back to the dict's own ``name`` field
    rather than a synthetic placeholder so a draft re-imported into
    the wizard keeps the operator's chosen identifier intact.
    """
    name = str(data.get("name") or "")
    return _policy_from_json_dict(name, data)


@dataclass
class DraftSnapshot:
    """One on-disk policy draft."""

    policy: Policy
    metadata: DraftMetadata


class PolicyDraftModel:
    """In-memory + on-disk draft state for the Creator.

    Lifecycle:
    1. Operator opens the Creator. ``open_draft(name)`` either reads
       an existing draft from ``drafts_dir/<slug>.json`` or seeds a
       fresh ``Policy`` from a preset (whichever ``based_on`` says).
    2. UI mutates ``self.policy`` directly; calling ``save()`` flushes
       to disk atomically.
    3. ``commit(target_dir)`` is the "I'm done" exit path - validators
       run, the policy emitter (Phase 7) writes the gateway-ready
       YAML/JSON, and the draft file is removed (the operator can
       still recover via the activity log).

    The model is intentionally NOT a Textual reactive container; the
    panel layer wraps it so this class stays unit-testable without
    booting an App.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.policy = Policy()
        self.metadata = DraftMetadata()
        self._loaded_from_path: Path | None = None

    # -- open / load -----------------------------------------------------

    def new_from_preset(self, name: str, *, preset: PresetName = "default") -> None:
        """Seed a brand-new draft from a bundled preset.

        ``name`` becomes the policy name and the draft filename slug.
        The preset is loaded fresh from disk (we don't share Policy
        instances between drafts).
        """
        seeded = load_preset(preset)
        seeded.name = name
        seeded.basedOn = preset
        self.policy = seeded
        self.metadata = DraftMetadata(slug=_slugify(name), based_on=preset)
        self._loaded_from_path = None

    def load(self, slug: str) -> bool:
        """Try to load an existing draft by slug.

        Returns True iff a valid draft was found and parsed; False
        means "no draft exists" (caller should ``new_from_preset``
        instead). A partial / corrupt file returns False rather than
        raising — the operator should never lose access to the
        Creator because of a bad disk byte.
        """
        path = drafts_dir(self.data_dir) / f"{slug}.json"
        if not path.is_file():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        if not isinstance(data, dict):
            return False
        policy_data = data.get("policy")
        meta_data = data.get("metadata")
        if not isinstance(policy_data, dict) or not isinstance(meta_data, dict):
            return False
        try:
            self.policy = _policy_from_json_dict(meta_data.get("slug", slug), policy_data)
        except (TypeError, ValueError):
            return False
        self.metadata = DraftMetadata(
            slug=str(meta_data.get("slug") or slug),
            based_on=str(meta_data.get("based_on") or "default"),  # type: ignore[arg-type]
            last_updated_iso=str(meta_data.get("last_updated_iso") or ""),
            quick_start_step=int(meta_data.get("quick_start_step") or 0),
            quick_start_answers=dict(meta_data.get("quick_start_answers") or {}),
            last_section=str(meta_data.get("last_section") or ""),
        )
        self._loaded_from_path = path
        return True

    def list_drafts(self) -> list[str]:
        """Return slugs of every draft on disk, alphabetic."""
        directory = drafts_dir(self.data_dir)
        return sorted(p.stem for p in directory.iterdir() if p.suffix == ".json")

    # -- save / discard --------------------------------------------------

    def save(self) -> Path:
        """Atomically write the draft to disk.

        Uses tmp+rename to avoid a partial file if the TUI crashes
        mid-flush. Returns the destination path so the caller can
        echo it in the activity strip.
        """
        from datetime import datetime, timezone

        slug = self.metadata.slug or _slugify(self.policy.name or "untitled")
        self.metadata.slug = slug
        self.metadata.last_updated_iso = datetime.now(timezone.utc).isoformat()

        target = drafts_dir(self.data_dir) / f"{slug}.json"
        tmp = target.with_suffix(".json.tmp")
        payload = {
            "policy": _policy_to_json_dict(self.policy),
            "metadata": asdict(self.metadata),
        }
        # Mode 0600 because the draft can contain operator-typed
        # patterns / webhook URLs / env-name hints. Not as sensitive
        # as a full secret, but worth restricting to the owner.
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=False),
            encoding="utf-8",
        )
        try:
            tmp.chmod(0o600)
        except OSError:
            # Filesystem may not honor chmod (Windows); soft-fail.
            pass
        tmp.replace(target)
        self._loaded_from_path = target
        return target

    def discard(self) -> bool:
        """Delete the on-disk draft file, if any.

        Returns True iff a file was present and removed. The
        in-memory ``policy`` / ``metadata`` are left intact so the
        operator can change their mind before exiting.
        """
        path = self._loaded_from_path or (
            drafts_dir(self.data_dir) / f"{self.metadata.slug}.json"
            if self.metadata.slug
            else None
        )
        if path is None or not path.is_file():
            return False
        try:
            path.unlink()
        except OSError:
            return False
        self._loaded_from_path = None
        return True

    # -- diff vs preset --------------------------------------------------

    def diff_vs_preset(self) -> dict[str, Any]:
        """Return a shallow per-section diff vs the original preset.

        The result maps section names ("admission", "guardrail", ...)
        to True when they differ from the preset's value, False when
        identical. The Playground uses this to render a "(modified)"
        badge next to changed sections.
        """
        baseline = load_preset(self.metadata.based_on)
        baseline.name = self.policy.name
        baseline.description = self.policy.description
        baseline.basedOn = self.policy.basedOn

        baseline_dict = _policy_to_json_dict(baseline)
        current_dict = _policy_to_json_dict(self.policy)

        return {
            section: baseline_dict.get(section) != current_dict.get(section)
            for section in baseline_dict
            if section not in {"name", "description", "basedOn"}
        }

    @property
    def is_dirty(self) -> bool:
        """True iff anything in the policy differs from the preset."""
        return any(self.diff_vs_preset().values())
