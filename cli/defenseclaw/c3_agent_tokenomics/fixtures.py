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
from typing import Any

from defenseclaw.paths import bundled_c3_agent_tokenomics_dir


def package_data_text(*parts: str) -> str:
    """Read text from the packaged Cisco Cloud Control tokenomics demo data directory."""
    return (bundled_c3_agent_tokenomics_dir().joinpath(*parts)).read_text(encoding="utf-8")


def package_data_json(*parts: str) -> Any:
    return json.loads(package_data_text(*parts))


def read_json(path: str | Path | None, default_parts: tuple[str, ...]) -> Any:
    """Read JSON from an explicit path or from packaged demo data.

    The Cisco Cloud Control BFF uses this helper so tests, local demos, and
    Kubernetes fixtures all exercise the same DTO logic.
    """
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    return package_data_json(*default_parts)


def default_o11y_rows() -> list[dict[str, Any]]:
    return package_data_json("samples", "o11y_token_metric_rows.json")


def default_galileo_payload() -> dict[str, Any]:
    return package_data_json("samples", "galileo_runtime_controls.json")
