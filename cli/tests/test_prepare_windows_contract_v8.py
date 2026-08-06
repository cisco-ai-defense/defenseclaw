# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml


def _load_helper():
    path = Path(__file__).parents[2] / "scripts" / "prepare-windows-contract-v8.py"
    spec = importlib.util.spec_from_file_location("prepare_windows_contract_v8", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("source", ["config_version: 8\n", "config_version: 8\nobservability: {}\n"])
def test_preparer_accepts_only_fresh_v8_shapes(tmp_path: Path, source: str) -> None:
    helper = _load_helper()
    config = tmp_path / "config.yaml"
    jsonl = tmp_path / "gateway.jsonl"
    config.write_text(source, encoding="utf-8")

    helper.prepare_windows_contract_v8(
        config,
        data_dir=tmp_path,
        jsonl_path=jsonl,
        validator=lambda _path, _data_dir: None,
    )

    result = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert result["observability"]["destinations"] == [
        {
            "name": "windows-contract-jsonl",
            "kind": "jsonl",
            "path": str(jsonl),
        }
    ]


def test_preparer_refuses_operator_observability_graph(tmp_path: Path) -> None:
    helper = _load_helper()
    config = tmp_path / "config.yaml"
    original = (
        "config_version: 8\n"
        "observability:\n"
        "  destinations:\n"
        "    - name: operator-console\n"
        "      kind: console\n"
    )
    config.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="absent or empty"):
        helper.prepare_windows_contract_v8(
            config,
            data_dir=tmp_path,
            jsonl_path=tmp_path / "gateway.jsonl",
            validator=lambda _path, _data_dir: None,
        )

    assert config.read_text(encoding="utf-8") == original


def test_preparer_is_idempotent_for_exact_owned_destination(tmp_path: Path) -> None:
    helper = _load_helper()
    config = tmp_path / "config.yaml"
    jsonl = tmp_path / "gateway.jsonl"
    original = yaml.safe_dump(
        {
            "config_version": 8,
            "observability": {
                "destinations": [
                    {
                        "name": "windows-contract-jsonl",
                        "kind": "jsonl",
                        "path": str(jsonl),
                    }
                ]
            },
        },
        sort_keys=False,
    )
    config.write_text(original, encoding="utf-8")

    helper.prepare_windows_contract_v8(
        config,
        data_dir=tmp_path,
        jsonl_path=jsonl,
        validator=lambda _path, _data_dir: None,
    )

    assert config.read_text(encoding="utf-8") == original


def test_preparer_refuses_similar_non_owned_destination(tmp_path: Path) -> None:
    helper = _load_helper()
    config = tmp_path / "config.yaml"
    original = yaml.safe_dump(
        {
            "config_version": 8,
            "observability": {
                "destinations": [
                    {
                        "name": "windows-contract-jsonl",
                        "kind": "jsonl",
                        "path": str(tmp_path / "different.jsonl"),
                    }
                ]
            },
        },
        sort_keys=False,
    )
    config.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="exact owned"):
        helper.prepare_windows_contract_v8(
            config,
            data_dir=tmp_path,
            jsonl_path=tmp_path / "gateway.jsonl",
            validator=lambda _path, _data_dir: None,
        )

    assert config.read_text(encoding="utf-8") == original
