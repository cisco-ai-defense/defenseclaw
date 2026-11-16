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

from __future__ import annotations


def test_low_space_audit_open_error_names_disk_cause(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace

    from defenseclaw import audit_capacity

    monkeypatch.setattr(
        audit_capacity.shutil, "disk_usage",
        lambda _path: SimpleNamespace(free=119 * 1024 * 1024),
    )
    detail = audit_capacity.audit_open_failure_notice(
        str(tmp_path / "audit.db"), RuntimeError("unable to open database file")
    )
    assert "too little usable space" in detail
    assert "119 MiB" in detail


def test_permission_cause_wins_over_low_space(tmp_path, monkeypatch) -> None:
    # GAP-1172: low free space must not hide an access-denied open.
    import os
    from types import SimpleNamespace

    from defenseclaw import audit_capacity

    monkeypatch.setattr(
        audit_capacity.shutil, "disk_usage",
        lambda _path: SimpleNamespace(free=100 * 1024 * 1024),
    )
    db_path = str(tmp_path / "audit.db")
    detail = audit_capacity.audit_open_failure_notice(db_path, PermissionError(13, "Permission denied"))
    assert "permission denied" in detail and "too little usable space" not in detail
    if os.name != "nt":
        # SQLite's generic open error in a folder this account cannot write.
        monkeypatch.setattr(audit_capacity.os, "access", lambda *_args, **_kwargs: False)
        detail = audit_capacity.audit_open_failure_notice(db_path, RuntimeError("unable to open database file"))
        assert "permission denied" in detail and "too little usable space" not in detail
