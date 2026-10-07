# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The Tetragon hand-off of the defenseclaw-enterprise package's preremove.

The sensor helper records the DefenseClaw kernel policies it loaded into the
host's Tetragon in /var/lib/defenseclaw-sensor/tetragon-loaded. They outlive
the helper, so a package change that leaves a helper behind that does not
manage them must remove them first. These tests run the real scriptlet with
a fake helper, fake tetra, dpkg and systemctl on PATH, and only marker
policy names.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packaging" / "linux" / "preremove.sh"

RECORDED = [
    "defenseclaw-controls-0a1b2c3d",
    "defenseclaw-observe-11112222",
]
# Lines the helper never writes: a customer's own name in DefenseClaw's
# prefix and a malformed line. Neither is ever passed to tetra.
FOREIGN = ["defenseclaw-foo", "defenseclaw-controls-XYZ; touch dccert-block-marker"]

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")


class _Host:
    def __init__(self, tmp: Path, *, helper_supports_cleanup: bool = True, tetra: str | None = "ok",
                 installed_version: str = "1.1.0", recorded: list[str] | None = None) -> None:
        self.tmp = tmp
        self.log = tmp / "calls.log"
        self.log.write_text("", encoding="utf-8")
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.path = tmp / "path"
        self.path.mkdir()
        self.sensor = tmp / "sensor"
        self.sensor.mkdir()
        self.run_systemd = tmp / "run-systemd"
        self.run_systemd.mkdir()
        names = RECORDED if recorded is None else recorded
        if names:
            (self.sensor / "tetragon-loaded").write_text("\n".join(names + FOREIGN) + "\n", encoding="utf-8")
        check = 0 if helper_supports_cleanup else 2
        self._tool(self.bin / "defenseclaw-sensor-helper", f"""
            if [ "$*" = "--tetragon-cleanup --check" ]; then exit {check}; fi
            if [ "$*" = "--tetragon-cleanup" ] && [ {check} = 0 ]; then
                for name in $(grep -E -x 'defenseclaw-[a-z-]+-[0-9a-f]{{8}}' "{self.sensor}/tetragon-loaded"); do
                    echo "removed $name"
                done
                : >"{self.sensor}/tetragon-loaded"
                exit 0
            fi
            echo "flag provided but not defined: $1" >&2
            exit 2
        """)
        self._tool(self.bin / "defenseclaw-gateway", "exit 0")
        self._tool(self.path / "systemctl", "exit 0")
        self._tool(self.path / "dpkg-query", f'printf %s "{installed_version}"')
        self._tool(self.path / "dpkg", """
            [ "$1" = --compare-versions ] && [ "$3" = lt ] || exit 2
            [ "$2" != "$4" ] && [ "$(printf '%s\\n%s\\n' "$2" "$4" | sort -V | head -n 1)" = "$2" ]
        """)
        if tetra == "ok":
            self._tool(self.path / "tetra", "exit 0")
        elif tetra is not None:
            # Fails for one name only.
            self._tool(self.path / "tetra", f'[ "$3" = "{tetra}" ] && exit 1; exit 0')

    def _tool(self, path: Path, body: str) -> None:
        lines = [line[12:] if line.startswith(" " * 12) else line for line in body.strip("\n").splitlines()]
        path.write_text(
            "#!/bin/sh\n"
            f'echo "{path.name} $*" >>"{self.log}"\n' + "\n".join(lines) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def script(self) -> str:
        text = SCRIPT.read_text(encoding="utf-8")
        replacements = {
            "gateway=/opt/defenseclaw/bin/defenseclaw-gateway": f"gateway={self.bin}/defenseclaw-gateway",
            "state=/var/lib/defenseclaw-enterprise": f"state={self.tmp}/enterprise-state",
            "helper=/opt/defenseclaw/bin/defenseclaw-sensor-helper": f"helper={self.bin}/defenseclaw-sensor-helper",
            "sensor_state=/var/lib/defenseclaw-sensor": f"sensor_state={self.sensor}",
            "/run/systemd/system": str(self.run_systemd),
            # tetra must be root-owned; the test files belong to this user.
            '"$candidate" 2>/dev/null)" = 0 ]': f'"$candidate" 2>/dev/null)" = {os.getuid()} ]',
            "/usr/local/bin/tetra /usr/bin/tetra": "",
        }
        for old, new in replacements.items():
            assert old in text, old
            text = text.replace(old, new)
        return text

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = {"PATH": f"{self.path}:/usr/bin:/bin", "LC_ALL": "C"}
        return subprocess.run(["sh", "-c", self.script(), "preremove", *args], capture_output=True,
                              text=True, check=False, env=env)

    def calls(self) -> list[str]:
        return [line for line in self.log.read_text(encoding="utf-8").splitlines() if line]

    def recorded(self) -> list[str]:
        path = self.sensor / "tetragon-loaded"
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line] if path.exists() else []


def test_rpm_upgrade_to_a_tetragon_aware_helper_leaves_the_policies_to_it(tmp_path: Path) -> None:
    host = _Host(tmp_path)
    result = host.run("1")
    assert result.returncode == 0
    assert result.stdout == result.stderr == ""
    assert host.calls() == ["defenseclaw-sensor-helper --tetragon-cleanup --check"]
    assert host.recorded() == RECORDED + FOREIGN


def test_rpm_downgrade_deletes_only_recorded_names_with_tetra(tmp_path: Path) -> None:
    host = _Host(tmp_path, helper_supports_cleanup=False)
    result = host.run("1")
    assert result.returncode == 0, result.stderr
    deletes = [call for call in host.calls() if call.startswith("tetra ")]
    assert deletes == [f"tetra tracingpolicy delete {name}" for name in RECORDED]
    for name in RECORDED:
        assert f"removed the Tetragon policy {name}" in result.stdout
    assert host.recorded() == []
    assert "dccert-block-marker" not in "".join(host.calls())


def test_rpm_downgrade_without_tetra_names_the_policies_and_the_restart(tmp_path: Path) -> None:
    host = _Host(tmp_path, helper_supports_cleanup=False, tetra=None)
    result = host.run("1")
    assert result.returncode == 0
    for name in RECORDED:
        assert name in result.stderr
    assert "systemctl restart tetragon" in result.stderr
    assert host.recorded() == RECORDED


def test_rpm_downgrade_keeps_the_name_tetra_could_not_delete(tmp_path: Path) -> None:
    host = _Host(tmp_path, helper_supports_cleanup=False, tetra=RECORDED[1])
    result = host.run("1")
    assert result.returncode == 0
    assert host.recorded() == [RECORDED[1]]
    assert RECORDED[1] in result.stderr and RECORDED[0] not in result.stderr


def test_deb_downgrade_stops_the_helper_and_runs_its_cleanup(tmp_path: Path) -> None:
    host = _Host(tmp_path, installed_version="1.1.0")
    result = host.run("upgrade", "1.0.0")
    assert result.returncode == 0, result.stderr
    calls = host.calls()
    stop = calls.index("systemctl stop defenseclaw-sensor-helper.service")
    assert calls.index("defenseclaw-sensor-helper --tetragon-cleanup") > stop
    assert not any(call.startswith("tetra ") for call in calls)
    assert host.recorded() == []


@pytest.mark.parametrize("new_version", ["1.2.0", "1.1.0"])
def test_deb_upgrade_or_reinstall_leaves_the_policies_to_the_new_helper(tmp_path: Path, new_version: str) -> None:
    host = _Host(tmp_path, installed_version="1.1.0")
    result = host.run("upgrade", new_version)
    assert result.returncode == 0
    assert result.stdout == result.stderr == ""
    assert not any(call.startswith(("systemctl", "defenseclaw-sensor-helper", "tetra")) for call in host.calls())
    assert host.recorded() == RECORDED + FOREIGN


def test_deb_downgrade_whose_cleanup_fails_says_what_is_left(tmp_path: Path) -> None:
    host = _Host(tmp_path, helper_supports_cleanup=False, installed_version="1.1.0")
    result = host.run("upgrade", "1.0.0")
    assert result.returncode == 0
    for name in RECORDED:
        assert name in result.stderr
    assert "systemctl restart tetragon" in result.stderr


@pytest.mark.parametrize("args", [("1",), ("upgrade", "1.0.0")])
def test_nothing_recorded_touches_nothing(tmp_path: Path, args: tuple[str, ...]) -> None:
    host = _Host(tmp_path, helper_supports_cleanup=False, recorded=[])
    result = host.run(*args)
    assert result.returncode == 0
    assert result.stdout == result.stderr == ""
    assert host.calls() == []
