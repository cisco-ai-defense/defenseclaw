from __future__ import annotations

import subprocess
from pathlib import Path


def test_shell_installer_reprompts_after_unknown_connector() -> None:
    source = (Path(__file__).resolve().parents[2] / "scripts" / "install.sh").read_text()
    function = source.split("pick_connector() {", 1)[1].split("\n}\n", 1)[0]
    script = (
        'CONNECTOR_CHOICES="codex claudecode"\n'
        'step() { :; }; ok() { :; }; warn() { :; }\n'
        'read_tty_line() { IFS= read -r line <&3; printf "%s" "$line"; }\n'
        "exec 3<<< $'banana\\n2'\n"
        "pick_connector() {" + function + "\n}\n"
        'pick_connector; printf "%s" "$CONNECTOR"\n'
    )
    completed = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert completed.stdout.strip().endswith("claudecode")
    assert completed.stderr.count("Choice [default 1=codex]") == 2
