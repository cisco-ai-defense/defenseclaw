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

"""observability.local.path resolves like the Go compiler (GAP-0005)."""

import os

import pytest
from defenseclaw.config import _audit_database_path


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("", "{data}/audit.db"),
        ("~/.defenseclaw/audit.db", "{home}/.defenseclaw/audit.db"),
        ("events/audit.db", "{data}/events/audit.db"),
        ("{home}/abs.db", "{home}/abs.db"),
    ],
)
def test_audit_database_path_expands_home_and_anchors_relative_paths(tmp_path, monkeypatch, written, expected):
    home = tmp_path / "home"
    data = tmp_path / "data"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    raw = {"observability": {"local": {"path": written.format(home=home)}}} if written else {}
    want = os.path.normpath(expected.format(home=home, data=data))
    assert _audit_database_path(raw, str(data)) == want
