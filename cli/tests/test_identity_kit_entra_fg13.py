import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENTRA = ROOT / "packaging/identity/entra"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


@pytest.mark.parametrize("mode", ["extension-fails", "role-fails", "extension-missing"])
def test_entra_ssh_distinguishes_failed_azure_reads_from_absence(tmp_path: Path, mode: str) -> None:
    az = tmp_path / "az"
    az.write_text(
        "#!/bin/sh\ncase \"$*\" in\n"
        "  'account show'*) echo subscription-id;;\n"
        "  'vm show'*) printf '/subscriptions/example/vm\\nLinux\\nSystemAssigned\\n';;\n"
        "  'ad user show'*) echo user-id;;\n"
        "  'vm extension list'*) if [ \"$AZ_TEST_MODE\" = extension-fails ]; then echo 'AuthorizationFailed: tenant-specific-value' >&2; exit 1; fi;;\n"
        "  'role assignment list'*) if [ \"$AZ_TEST_MODE\" = role-fails ]; then echo 'AuthorizationFailed: tenant-specific-value' >&2; exit 1; fi; echo 0;;\n"
        "esac\n",
        encoding="ascii",
    )
    az.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ENTRA / "setup-entra-ssh-linux.sh"), "-g", "rg", "-n", "vm", "--user", "alice@example.test"],
        env={**os.environ, "AZ": str(az), "AZ_TEST_MODE": mode}, capture_output=True, text=True, timeout=10,
    )
    combined = result.stdout + result.stderr
    if mode.endswith("fails"):
        assert result.returncode != 0
        assert "could not read" in combined and "AuthorizationFailed" in combined
        assert "tenant-specific-value" not in combined
        assert "would: give" not in combined
        if mode == "extension-fails":
            assert "would: install" not in combined
    else:
        assert result.returncode == 0, combined
        assert "would: install" in combined
