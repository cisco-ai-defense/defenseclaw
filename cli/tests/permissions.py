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

"""Permission assertions shared by cross-platform security regressions."""

from __future__ import annotations

import os
import stat
import subprocess


def grant_everyone(path: str | os.PathLike[str], perm: str = "F") -> None:
    """Grant the well-known Everyone SID broad access for negative-path tests."""
    ace = f"*S-1-1-0:{perm}" if os.path.isfile(path) else f"*S-1-1-0:(OI)(CI){perm}"
    subprocess.run(
        ["icacls", os.fspath(path), "/grant", ace],
        check=True,
        capture_output=True,
        text=True,
    )


def set_known_windows_directory_acl(path: str | os.PathLike[str], *, everyone_write: bool = False) -> None:
    """Replace inheritance with a deterministic disposable-directory DACL."""
    grants = ["*S-1-3-4:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"]
    if everyone_write:
        grants.append("*S-1-1-0:(OI)(CI)F")
    subprocess.run(
        ["icacls", os.fspath(path), "/inheritance:r", "/grant:r", *grants],
        check=True,
        capture_output=True,
        text=True,
    )


def assert_owner_only_file(path: str | os.PathLike[str]) -> None:
    """Assert POSIX 0600 or the equivalent protected Windows DACL."""
    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"
        return

    from defenseclaw.file_permissions import _windows_acl_snapshot, windows_acl_write_error

    problem = windows_acl_write_error(path)
    assert problem is None, problem
    owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    assert null_dacl is False
    write_mask = 0x10000000 | 0x40000000 | 0x000D0156
    writable_sids = {
        sid
        for permissions, access_mode, _inheritance, sid in entries
        if access_mode in (1, 2) and permissions & write_mask
    }
    assert "S-1-5-18" in writable_sids
    assert owner_sid in writable_sids or "S-1-3-4" in writable_sids


def assert_owner_only_directory(path: str | os.PathLike[str]) -> None:
    """Assert POSIX 0700 or the equivalent protected Windows DACL."""
    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o700, f"expected 0700, got {oct(mode)}"
        return

    assert_owner_only_file(path)
    from defenseclaw.file_permissions import _windows_acl_snapshot, _windows_current_user_sid

    current_sid = _windows_current_user_sid()
    trusted = {"S-1-3-4", "S-1-5-18", current_sid}
    _owner_sid, _null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    for permissions, access_mode, inheritance, sid in entries:
        if access_mode not in (1, 2) or permissions == 0:
            continue
        if sid in trusted:
            continue
        if sid == "S-1-3-0" and inheritance & 0x08:
            continue
        raise AssertionError(f"directory ACL grants access to untrusted SID {sid or '<unknown>'}")
