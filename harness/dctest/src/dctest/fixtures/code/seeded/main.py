"""dctest fixture: deliberately weak Python file.

CodeGuard should flag the patterns below at high/critical severity. dctest
asserts at least one finding with a populated rule_id. This file is for
the dctest harness only and is never imported.
"""

from __future__ import annotations

import os
import subprocess


def login(user_input: str) -> bool:
    fake_creds = {
        "username": "admin",
        "password": "p@ssw0rd-NOT-REAL-fixture-only",
    }
    cmd = "echo " + user_input
    subprocess.run(cmd, shell=True, check=False)
    target = "/etc/passwd"
    return os.path.exists(target) and fake_creds["password"] != ""


def md5_token(value: str) -> str:
    import hashlib
    return hashlib.md5(value.encode()).hexdigest()
