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

"""Shared AI signature catalog helpers for CLI rendering/tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path


@dataclass(frozen=True)
class AISignature:
    id: str
    name: str
    vendor: str
    category: str
    confidence: float
    supported_connector: str = ""
    binary_names: tuple[str, ...] = ()
    process_names: tuple[str, ...] = ()
    application_names: tuple[str, ...] = ()
    config_paths: tuple[str, ...] = ()
    extension_ids: tuple[str, ...] = ()
    mcp_paths: tuple[str, ...] = ()
    package_names: tuple[str, ...] = ()
    env_var_names: tuple[str, ...] = ()
    domain_patterns: tuple[str, ...] = ()
    history_patterns: tuple[str, ...] = ()
    local_endpoints: tuple[str, ...] = ()


def load_ai_signatures() -> list[AISignature]:
    """Load the packaged catalog; source-tree tests verify parity with Go."""
    payload = json.loads(_catalog_text())
    if payload.get("version") != 1:
        raise ValueError("unsupported AI signature catalog version")
    out: list[AISignature] = []
    for raw in payload.get("signatures", []):
        out.append(
            AISignature(
                id=str(raw.get("id", "")).strip().lower(),
                name=str(raw.get("name", "")).strip(),
                vendor=str(raw.get("vendor", "")).strip(),
                category=str(raw.get("category", "")).strip().lower(),
                confidence=float(raw.get("confidence", 0.5) or 0.5),
                supported_connector=str(raw.get("supported_connector", "")).strip().lower(),
                binary_names=tuple(raw.get("binary_names", []) or []),
                process_names=tuple(raw.get("process_names", []) or []),
                application_names=tuple(raw.get("application_names", []) or []),
                config_paths=tuple(raw.get("config_paths", []) or []),
                extension_ids=tuple(raw.get("extension_ids", []) or []),
                mcp_paths=tuple(raw.get("mcp_paths", []) or []),
                package_names=tuple(raw.get("package_names", []) or []),
                env_var_names=tuple(raw.get("env_var_names", []) or []),
                domain_patterns=tuple(raw.get("domain_patterns", []) or []),
                history_patterns=tuple(raw.get("history_patterns", []) or []),
                local_endpoints=tuple(raw.get("local_endpoints", []) or []),
            )
        )
    return out


def _catalog_text() -> str:
    source_tree_catalog = Path(__file__).resolve().parents[3] / "internal" / "inventory" / "ai_signatures.json"
    if source_tree_catalog.exists():
        return source_tree_catalog.read_text(encoding="utf-8")
    return resources.files("defenseclaw").joinpath("inventory/ai_signatures.json").read_text(encoding="utf-8")
