# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path

import pytest
from defenseclaw.inventory.ai_signatures import (
    SignaturePackError,
    install_signature_pack,
    load_ai_signatures,
    validate_signature_pack,
)


def test_ai_signature_catalog_contains_supported_and_shadow_agents():
    signatures = load_ai_signatures()
    ids = {sig.id for sig in signatures}

    for expected in {
        "codex",
        "claudecode",
        "hermes",
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
        "aider",
        "ai-sdks",
        "qwen-code",
        "openhands",
        "lmstudio",
        "claude-desktop",
    }:
        assert expected in ids


def test_packaged_catalog_matches_go_catalog():
    repo = Path(__file__).resolve().parents[2]
    go_catalog = json.loads((repo / "internal" / "inventory" / "ai_signatures.json").read_text(encoding="utf-8"))
    py_catalog_path = repo / "cli" / "defenseclaw" / "inventory" / "ai_signatures.json"
    py_catalog = json.loads(py_catalog_path.read_text(encoding="utf-8"))

    assert py_catalog == go_catalog


def test_custom_signature_pack_loads_from_managed_dir(tmp_path):
    pack_dir = tmp_path / "signature-packs"
    pack_dir.mkdir()
    pack = pack_dir / "custom.json"
    pack.write_text(
        json.dumps({
            "version": 1,
            "signatures": [{
                "id": "custom-ai",
                "name": "Custom AI",
                "vendor": "Example",
                "category": "ai_cli",
                "confidence": 0.75,
                "binary_names": ["custom-ai"],
            }],
        }),
        encoding="utf-8",
    )

    signatures = load_ai_signatures(data_dir=tmp_path, disabled_signature_ids=["codex"])
    ids = {sig.id for sig in signatures}

    assert "custom-ai" in ids
    assert "codex" not in ids


def test_workspace_signature_pack_requires_opt_in(tmp_path):
    workspace = tmp_path / "workspace"
    pack = workspace / ".defenseclaw" / "ai-signatures.json"
    pack.parent.mkdir(parents=True)
    pack.write_text(
        json.dumps({
            "version": 1,
            "signatures": [{
                "id": "workspace-ai",
                "name": "Workspace AI",
                "vendor": "Example",
                "category": "workspace_artifact",
                "confidence": 0.6,
            }],
        }),
        encoding="utf-8",
    )

    assert "workspace-ai" not in {sig.id for sig in load_ai_signatures(scan_roots=[str(workspace)])}
    assert "workspace-ai" in {
        sig.id
        for sig in load_ai_signatures(scan_roots=[str(workspace)], allow_workspace_signatures=True)
    }


def test_install_signature_pack_is_atomic_and_conflict_safe(tmp_path):
    source = tmp_path / "custom-pack.json"
    source.write_text(
        json.dumps({
            "version": 1,
            "id": "custom-pack",
            "signatures": [{
                "id": "custom-installed-ai",
                "name": "Custom Installed AI",
                "vendor": "Example",
                "category": "ai_cli",
                "confidence": 0.7,
            }],
        }),
        encoding="utf-8",
    )

    dest = install_signature_pack(source, data_dir=tmp_path)

    assert dest == tmp_path / "signature-packs" / "custom-pack.json"
    assert dest.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
    with pytest.raises(SignaturePackError):
        install_signature_pack(source, data_dir=tmp_path)


def test_validate_signature_pack_rejects_duplicate_ids(tmp_path):
    source = tmp_path / "bad.json"
    source.write_text(
        json.dumps({
            "version": 1,
            "signatures": [
                {"id": "dup", "name": "Dup", "vendor": "Example", "category": "ai_cli", "confidence": 0.5},
                {"id": "dup", "name": "Dup 2", "vendor": "Example", "category": "ai_cli", "confidence": 0.5},
            ],
        }),
        encoding="utf-8",
    )

    with pytest.raises(SignaturePackError, match="duplicate"):
        validate_signature_pack(source)
