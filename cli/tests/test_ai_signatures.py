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

from defenseclaw.inventory.ai_signatures import load_ai_signatures


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
