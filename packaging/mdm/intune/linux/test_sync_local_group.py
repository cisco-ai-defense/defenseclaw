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

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).with_name("sync-local-group.sh")


def test_existing_group_is_not_rewritten(tmp_path):
    """An existing local group must not become managed just by naming it."""
    source = SCRIPT.read_text()
    source = source.replace('GROUP_NAME="replace-with-local-group"', 'GROUP_NAME="sudo"')
    source = source.replace(
        'MEMBERS=() # Example: (alice bob). This script owns the complete member list.',
        'MEMBERS=(newadmin)',
    )
    source = source.replace(
        "[[ $EUID == 0 ]] || { echo 'error: run as root' >&2; exit 1; }",
        ": # Test uses command stubs instead of root",
    )
    source = source.replace('STATE_DIR=/var/lib/defenseclaw-intune/local-groups', f'STATE_DIR={tmp_path / "state"}')
    script = tmp_path / "sync-local-group.sh"
    script.write_text(source)

    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    getent = stub_dir / "getent"
    getent.write_text('#!/usr/bin/env bash\n'
                      '[[ $1 == -s ]] && shift 2\n'
                      'case "$1:$2" in\n'
                      '  passwd:newadmin) echo "newadmin:x:1001:1001::/home/newadmin:/bin/bash" ;;\n'
                      '  group:sudo) echo "sudo:x:27:oldadmin" ;;\n'
                      '  *) exit 2 ;;\n'
                      'esac\n')
    getent.chmod(0o755)
    gpasswd = stub_dir / "gpasswd"
    gpasswd.write_text('#!/usr/bin/env bash\nprintf "called" > "$CALL_LOG"\n')
    gpasswd.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env['PATH']}"
    env["CALL_LOG"] = str(tmp_path / "gpasswd-called")
    result = subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True, check=False)

    assert result.returncode != 0
    assert "not owned by this script" in result.stderr
    assert not (tmp_path / "gpasswd-called").exists()


def _run_with_member(tmp_path, member):
    source = SCRIPT.read_text()
    source = source.replace('GROUP_NAME="replace-with-local-group"', 'GROUP_NAME="dcgroup"')
    source = source.replace(
        'MEMBERS=() # Example: (alice bob). This script owns the complete member list.',
        f"MEMBERS=('{member}')",
    )
    source = source.replace(
        "[[ $EUID == 0 ]] || { echo 'error: run as root' >&2; exit 1; }",
        ": # Test uses command stubs instead of root",
    )
    source = source.replace('STATE_DIR=/var/lib/defenseclaw-intune/local-groups', f'STATE_DIR={tmp_path / "state"}')
    script = tmp_path / "sync-local-group.sh"
    script.write_text(source)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir(exist_ok=True)
    getent = stub_dir / "getent"
    getent.write_text('#!/usr/bin/env bash\n'
                      '[[ $1 == -s ]] && shift 2\n'
                      'case "$1:$2" in\n'
                      '  passwd:john.doe) echo "john.doe:x:1001:1001::/home/john.doe:/bin/bash" ;;\n'
                      '  passwd:1001) echo "john.doe:x:1001:1001::/home/john.doe:/bin/bash" ;;\n'
                      '  group:dcgroup) echo "dcgroup:x:4000:" ;;\n'
                      '  *) exit 2 ;;\n'
                      'esac\n')
    getent.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env['PATH']}"
    return subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True, check=False)


def test_dotted_local_account_name_is_accepted(tmp_path):
    """A local account named john.doe passes the member check (GAP-1275)."""
    result = _run_with_member(tmp_path, "john.doe")
    assert "invalid user name" not in result.stderr
    assert "no local account" not in result.stderr
    # It stops later, at the existing group this test does not own.
    assert "not owned by this script" in result.stderr


def test_member_names_that_are_not_account_names_are_refused(tmp_path):
    for member in ("1001", ".hidden", "-rf", "a,b", "a:b"):
        sub = tmp_path / f"case{abs(hash(member))}"
        sub.mkdir()
        result = _run_with_member(sub, member)
        assert result.returncode == 2, (member, result.stderr)
        assert "invalid user name" in result.stderr
