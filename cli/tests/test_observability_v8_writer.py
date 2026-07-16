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

import os
import stat
from pathlib import Path

import pytest
from defenseclaw.observability.v8_config import V8ConfigError
from defenseclaw.observability.v8_writer import mutate_v8_config
from defenseclaw.observability.v8_yaml import V8YAMLMutation


def _source() -> str:
    return """config_version: 8
# keep top-level context
observability:
  # capacity choice
  local:
    retention_days: 90 # keep inline
  destinations:
    - name: collector
      kind: otlp
      endpoint: https://collector.example.test
"""


def test_mutate_v8_config_preserves_comments_validates_and_replaces_atomically(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_source())
    os.chmod(path, 0o640)
    calls: list[tuple[str, str | None]] = []

    def validator(candidate: str, data_dir: str | None) -> None:
        calls.append((candidate, data_dir))
        text = Path(candidate).read_text()
        assert "retention_days: 30 # keep inline" in text
        if os.name == "posix":
            assert stat.S_IMODE(os.stat(candidate).st_mode) == 0o640
        else:
            from defenseclaw.file_permissions import windows_acl_write_error

            assert windows_acl_write_error(candidate) is None

    result = mutate_v8_config(
        path,
        [V8YAMLMutation.set(("observability", "local", "retention_days"), 30)],
        data_dir=str(tmp_path),
        validator=validator,
    )

    assert result.changed
    assert result.before_sha256 != result.after_sha256
    assert len(calls) == 1
    assert calls[0][1] == str(tmp_path)
    assert not Path(calls[0][0]).exists()
    final = path.read_text()
    assert "# keep top-level context" in final
    assert "# capacity choice" in final
    assert "retention_days: 30 # keep inline" in final
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    else:
        from defenseclaw.file_permissions import windows_acl_write_error

        assert windows_acl_write_error(path) is None


def test_mutate_v8_config_noop_still_runs_canonical_validation(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_source())
    validated: list[str] = []

    def validator(candidate: str, _data_dir: str | None) -> None:
        validated.append(Path(candidate).read_text())

    result = mutate_v8_config(
        path,
        [V8YAMLMutation.set(("observability", "local", "retention_days"), 90)],
        validator=validator,
    )
    assert not result.changed
    assert result.before_sha256 == result.after_sha256
    assert validated == [_source()]
    assert path.read_text() == _source()
    assert not list(tmp_path.glob(".config.yaml.observability-v8-*.tmp"))


def test_mutate_v8_config_noop_rejects_semantically_invalid_source(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    source = """config_version: 8
observability:
  destinations:
    - name: broken
      kind: unsupported-kind
"""
    path.write_text(source)

    with pytest.raises(V8ConfigError):
        mutate_v8_config(
            path,
            [V8YAMLMutation.set(("observability", "destinations", 0, "name"), "broken")],
            validator=lambda *_: pytest.fail("canonical validator must follow semantic validation"),
        )
    assert path.read_text() == source


def test_mutate_v8_config_validation_failure_keeps_original(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_source())

    def validator(_candidate: str, _data_dir: str | None) -> None:
        raise RuntimeError("candidate rejected")

    with pytest.raises(RuntimeError, match="candidate rejected"):
        mutate_v8_config(
            path,
            [V8YAMLMutation.set(("observability", "local", "retention_days"), 30)],
            validator=validator,
        )
    assert path.read_text() == _source()
    assert not list(tmp_path.glob(".config.yaml.observability-v8-*.tmp"))


def test_mutate_v8_config_rejects_validator_candidate_mutation(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_source())

    def validator(candidate: str, _data_dir: str | None) -> None:
        staged = Path(candidate)
        staged.write_text(staged.read_text().replace("retention_days: 30", "retention_days: 31"))

    with pytest.raises(RuntimeError, match="candidate changed"):
        mutate_v8_config(
            path,
            [V8YAMLMutation.set(("observability", "local", "retention_days"), 30)],
            validator=validator,
        )
    assert path.read_text() == _source()
    assert not list(tmp_path.glob(".config.yaml.observability-v8-*.tmp"))


def test_mutate_v8_config_rejects_validator_candidate_replacement(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_source())

    def validator(candidate: str, _data_dir: str | None) -> None:
        staged = Path(candidate)
        replacement = staged.with_suffix(".replacement")
        replacement.write_bytes(staged.read_bytes())
        os.chmod(replacement, stat.S_IMODE(os.stat(staged).st_mode))
        os.replace(replacement, staged)

    with pytest.raises(RuntimeError, match="candidate changed"):
        mutate_v8_config(
            path,
            [V8YAMLMutation.set(("observability", "local", "retention_days"), 30)],
            validator=validator,
        )
    assert path.read_text() == _source()
    assert not list(tmp_path.glob(".config.yaml.observability-v8-*.tmp"))


def test_mutate_v8_config_dry_run_validates_without_replacing(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_source())
    validated: list[str] = []

    def validator(candidate: str, _data_dir: str | None) -> None:
        validated.append(Path(candidate).read_text())

    result = mutate_v8_config(
        path,
        [V8YAMLMutation.set(("observability", "local", "retention_days"), 30)],
        validator=validator,
        dry_run=True,
    )
    assert result.changed
    assert len(validated) == 1
    assert "retention_days: 30" in validated[0]
    assert path.read_text() == _source()
    assert not list(tmp_path.glob(".config.yaml.observability-v8-*.tmp"))


def test_mutate_v8_config_detects_uncooperative_source_change(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_source())

    def validator(_candidate: str, _data_dir: str | None) -> None:
        path.write_text(_source().replace("retention_days: 90", "retention_days: 45"))

    with pytest.raises(RuntimeError, match="changed while"):
        mutate_v8_config(
            path,
            [V8YAMLMutation.set(("observability", "local", "retention_days"), 30)],
            validator=validator,
        )
    assert "retention_days: 45" in path.read_text()


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics differ on Windows")
def test_mutate_v8_config_rejects_symlink_target(tmp_path: Path) -> None:
    real = tmp_path / "real.yaml"
    real.write_text(_source())
    link = tmp_path / "config.yaml"
    link.symlink_to(real)
    with pytest.raises(OSError, match="symbolic link"):
        mutate_v8_config(
            link,
            [V8YAMLMutation.set(("observability", "local", "retention_days"), 30)],
            validator=lambda *_: None,
        )
    assert real.read_text() == _source()
