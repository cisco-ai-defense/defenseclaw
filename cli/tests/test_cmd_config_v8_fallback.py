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

"""The field-naming fallback of `config validate` reads no more than the v8 limit."""

from __future__ import annotations

import builtins

from defenseclaw.commands import cmd_config
from defenseclaw.config_inspect import ConfigInspectError
from defenseclaw.observability.v8_config import MAX_SOURCE_BYTES


def _refusal() -> ConfigInspectError:
    return ConfigInspectError("candidate field=$; reason=configuration could not be compiled safely", field_path="$")


def test_an_oversized_source_keeps_the_canonical_refusal_and_is_not_read_whole(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_bytes(b"config_version: 8\n" + b"#" * (MAX_SOURCE_BYTES + 10))
    reads: list[int] = []
    real_open = builtins.open

    def recording_open(file, mode="r", *args, **kwargs):
        stream = real_open(file, mode, *args, **kwargs)
        if str(file) == str(path) and "b" in mode:
            real_read = stream.read

            def read(size=-1):
                reads.append(size)
                return real_read(size)

            stream.read = read
        return stream

    monkeypatch.setattr(builtins, "open", recording_open)
    mirrored: list[bytes] = []
    monkeypatch.setattr(cmd_config, "load_validate_v8", lambda raw, **_: mirrored.append(raw))
    exc = _refusal()
    assert cmd_config._v8_failure_detail(str(path), exc) == str(exc)
    assert reads == [MAX_SOURCE_BYTES + 1], reads
    assert mirrored == []


def test_a_source_within_the_limit_still_names_the_field(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 8\nopenshell:\n  llm: bogus\n", encoding="utf-8")
    detail = cmd_config._v8_failure_detail(str(path), _refusal())
    assert "openshell.llm" in detail, detail
