"""Okta verifier account-source regression."""

import os
import pathlib
import subprocess

SCRIPT = pathlib.Path(__file__).with_name("verify-okta-identity.sh")


def test_local_passwd_entry_does_not_count_as_okta_user(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    commands = {
        "systemctl": "#!/bin/sh\nexit 0\n",
        "getent": """#!/bin/sh
if [ "$1" = "-s" ] && [ "$2" = "sss" ]; then exit 2; fi
if [ "$1" = "passwd" ]; then
    printf '%s\\n' 'dc-r102-local:x:1710001:1720001::/home/dc-r102-local:/bin/bash'
    exit 0
fi
exit 2
""",
        "id": "#!/bin/sh\nprintf '%s\\n' dc-r102-local\n",
    }
    for name, body in commands.items():
        command = fake_bin / name
        command.write_text(body)
        command.chmod(0o755)
    cfg_rules = tmp_path / "cfg_rules.ini"
    cfg_rules.write_text("option = ldap_use_ppolicy\n")
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["OKTA_KIT_SSSD_CFG_RULES"] = str(cfg_rules)
    result = subprocess.run(
        ["bash", str(SCRIPT), "--user", "dc-r102-local", "--skip-defenseclaw"],
        env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "SSSD" in result.stdout
    assert "dc-r102-local" in result.stdout
