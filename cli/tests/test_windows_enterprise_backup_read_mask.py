r"""GAP-2014: the backup-intent read refuses every right that can write.

OpenFileReadOnlyWithBackupRetry (GAP-1220, GAP-2005) retries a denied open
with SeBackupPrivilege enabled and FILE_FLAG_BACKUP_SEMANTICS. Its handle must
stay read-only by construction, so the access mask it accepts excludes the
write rights and also MAXIMUM_ALLOWED (every right the DACL or an enabled
privilege grants) and ACCESS_SYSTEM_SECURITY (which also writes the SACL).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"


def _helper() -> str:
    text = MODULE.read_text(encoding="utf-8")
    start = text.index("private static IntPtr OpenFileReadOnlyWithBackupRetry(")
    end = text.index("IntPtr handle = CreateFileW(", start)
    return text[start:end]


def test_the_backup_read_refuses_every_right_that_can_write() -> None:
    helper = _helper()
    constants = {
        name: int(value, 16)
        for name, value in re.findall(r"const uint (\w+) = (0x[0-9A-Fa-f]+);", helper)
    }
    guard = re.search(r"if \(\(access & \(([^;]+?)\)\) != 0\)\s+throw new ArgumentException", helper, re.S)
    assert guard is not None, helper
    refused = 0
    for name in re.findall(r"\w+", guard.group(1)):
        refused |= constants[name]
    write_dac, write_owner, delete = 0x00040000, 0x00080000, 0x00010000
    file_write = 0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0100
    for right in (0x40000000, 0x10000000, write_dac, write_owner, delete, file_write,
                  0x02000000, 0x01000000):
        assert refused & right == right, hex(right)
    # Read rights stay allowed: the capture asks for exactly these.
    for right in (0x80000000, 0x00020000, 0x00000080):
        assert refused & right == 0, hex(right)
