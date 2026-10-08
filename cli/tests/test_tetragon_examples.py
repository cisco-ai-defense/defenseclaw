# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the Tetragon fleet examples (packaging/mdm/linux/examples/tetragon).

The guide at docs-site/content/docs/enterprise/tetragon.mdx embeds these files
verbatim. These checks keep them honest: they parse, the config template renders
for every ring and fits the config schema, every DefenseClaw command they run is
documented in the CLI reference, the fleet script summarizes correctly against a
fake ssh, and the guide shows exactly what the files contain.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "packaging" / "mdm" / "linux" / "examples" / "tetragon"
GUIDE = ROOT / "docs-site" / "content" / "docs" / "enterprise" / "tetragon.mdx"
CLI_REFERENCE = ROOT / "docs-site" / "content" / "docs" / "reference" / "cli.mdx"
SCHEMA = ROOT / "schemas" / "config" / "v8" / "defenseclaw-config.schema.json"

PLAYS = ("harden-tetragon.yml", "defenseclaw-tetragon.yml", "fleet-readiness.yml", "emergency-pause.yml")
ALL_FILES = (*PLAYS, "config.yaml.j2", "fleet-readiness.sh")
GATEWAY = "/opt/defenseclaw/bin/defenseclaw-gateway"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_the_example_set_is_complete_and_nothing_else_is_there() -> None:
    assert sorted(path.name for path in EXAMPLES.iterdir()) == sorted(ALL_FILES)


def test_examples_are_ascii_with_lf_endings_and_the_script_is_executable() -> None:
    for name in ALL_FILES:
        data = (EXAMPLES / name).read_bytes()
        assert all(byte < 0x80 for byte in data), f"{name} has non-ASCII bytes"
        assert b"\r\n" not in data, f"{name} has CRLF line endings"
        assert data.endswith(b"\n"), f"{name} must end with a newline"
    mode = (EXAMPLES / "fleet-readiness.sh").stat().st_mode
    assert mode & stat.S_IXUSR, "fleet-readiness.sh must be executable"


@pytest.mark.parametrize("name", PLAYS)
def test_plays_parse_and_have_the_play_shape(name: str) -> None:
    plays = yaml.safe_load(_text(EXAMPLES / name))
    assert isinstance(plays, list) and plays, name
    for play in plays:
        assert play.get("name") and play.get("hosts") and play.get("tasks"), name
        assert play.get("become") is True, f"{name}: every play runs as root"
        for task in play["tasks"]:
            assert task.get("name"), f"{name}: every task has a name"
            assert not any(key in task for key in ("shell", "ansible.builtin.shell")), (
                f"{name}: use argv with ansible.builtin.command, never a shell string"
            )


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-playbook is not installed")
@pytest.mark.parametrize("name", PLAYS)
def test_plays_pass_ansible_syntax_check(name: str) -> None:
    result = subprocess.run(
        ["ansible-playbook", "--syntax-check", "-i", "localhost,", str(EXAMPLES / name)],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "ANSIBLE_LOCALHOST_WARNING": "False"},
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_hardening_play_follows_the_guide() -> None:
    play = yaml.safe_load(_text(EXAMPLES / "harden-tetragon.yml"))[0]
    variables = play["vars"]
    assert variables["tetragon_required"] == {"server-address": "unix:///var/run/tetragon/tetragon.sock"}
    assert variables["tetragon_required_for_enforce"] == {"keep-sensors-on-exit": "false"}
    assert set(variables["tetragon_recommended"]) == {"metrics-server", "health-server-address"}
    # DefenseClaw does not need ancestors, and they cost CPU on every event.
    assert "enable-ancestors" not in json.dumps(variables)
    assert [handler["name"] for handler in play["handlers"]] == ["Restart Tetragon"]


def test_ring_variables_are_left_to_group_vars() -> None:
    # GAP-0029: play vars outrank inventory group_vars in Ansible, so a ring
    # variable the play also sets never takes effect (the pilot ring stayed in
    # consume). Every variable the play's header lists for group_vars is read
    # with a default instead.
    text = _text(EXAMPLES / "defenseclaw-tetragon.yml")
    ring_variables = set(re.findall(r"^#\s+(defenseclaw_[a-z_]+):", text, re.MULTILINE))
    assert {"defenseclaw_tetragon_mode", "defenseclaw_tetragon_burn_in", "defenseclaw_tetragon_enforce_ack"} <= ring_variables
    play = yaml.safe_load(text)[0]
    assert not ring_variables & set(play.get("vars", {})), "a ring variable is pinned in the play's vars"
    readiness = next(task for task in play["tasks"] if "tetragon" in task.get("ansible.builtin.command", {}).get("argv", []))
    assert "defenseclaw_tetragon_mode | default('consume')" in readiness["ansible.builtin.command"]["argv"][-1]
    assert "default('consume')" in readiness["when"]


def _render(**variables: Any) -> str:
    jinja2 = pytest.importorskip("jinja2")
    # Ansible's template module trims the newline after a block tag.
    env = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
    return env.from_string(_text(EXAMPLES / "config.yaml.j2")).render(**variables)


RINGS = {
    "default": ({}, {"mode": "consume", "customer_events": "agent"}),
    "consume": ({"defenseclaw_tetragon_mode": "consume"}, {"mode": "consume", "customer_events": "agent"}),
    "pilot": (
        {"defenseclaw_tetragon_mode": "observe", "defenseclaw_tetragon_burn_in": "40h"},
        {"mode": "observe", "customer_events": "agent", "burn_in": "40h"},
    ),
    "enforce": (
        {
            "defenseclaw_tetragon_mode": "enforce",
            "defenseclaw_tetragon_enforce_ack": "sha256:08b71155b713",
            "defenseclaw_guardrail_mode": "action",
        },
        {"mode": "enforce", "customer_events": "agent", "enforce_ack": "sha256:08b71155b713"},
    ),
    "enforce-upgrade": (
        {
            "defenseclaw_tetragon_mode": "enforce",
            "defenseclaw_tetragon_enforce_ack": ["sha256:08b71155b713", "sha256:000000000000"],
        },
        {
            "mode": "enforce",
            "customer_events": "agent",
            "enforce_ack": ["sha256:08b71155b713", "sha256:000000000000"],
        },
    ),
    "no-customer-events": (
        {"defenseclaw_tetragon_mode": "observe", "defenseclaw_tetragon_customer_events": "off"},
        {"mode": "observe", "customer_events": "off"},
    ),
    "zero-burn-in": (
        {"defenseclaw_tetragon_mode": "observe", "defenseclaw_tetragon_burn_in": 0},
        {"mode": "observe", "customer_events": "agent", "burn_in": 0},
    ),
}


@pytest.mark.parametrize("ring", sorted(RINGS))
def test_config_template_renders_each_ring(ring: str) -> None:
    variables, want = RINGS[ring]
    config = yaml.safe_load(_render(**variables))
    assert config["config_version"] == 9
    assert config["deployment_mode"] == "managed_enterprise"
    assert config["enterprise"]["profile"] == "standalone"
    assert config["enterprise"]["tetragon"] == want
    # A kernel control denies only for a connector in action mode: the ring
    # variable sets it, and the default stays observe.
    assert config["guardrail"]["mode"] == variables.get("defenseclaw_guardrail_mode", "observe")
    # Plane C must be on, or the Tetragon mode is off.
    assert config["ai_discovery"]["runtime"]["enabled"] is True
    assert config["ai_discovery"]["runtime"]["enable_host_plane"] is True


def _tetragon_schema(node: Any) -> dict[str, Any] | None:
    if isinstance(node, dict):
        candidate = node.get("tetragon")
        if isinstance(candidate, dict) and "mode" in candidate.get("properties", {}):
            return candidate
        for value in node.values():
            found = _tetragon_schema(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = _tetragon_schema(value)
            if found is not None:
                return found
    return None


@pytest.mark.parametrize("ring", sorted(RINGS))
def test_rendered_config_fits_the_config_schema(ring: str) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(_text(SCHEMA))
    properties = (_tetragon_schema(schema) or {}).get("properties", {})
    if "customer_events" not in properties:
        pytest.skip("the config schema has no enterprise.tetragon.customer_events yet")
    variables, _ = RINGS[ring]
    config = yaml.safe_load(_render(**variables))
    jsonschema.Draft202012Validator(schema).validate(config)


def _gateway_commands(name: str) -> list[list[str]]:
    """Every defenseclaw-gateway argument list a file runs, without the binary."""
    commands: list[list[str]] = []
    path = EXAMPLES / name
    if name.endswith(".sh"):
        for match in re.finditer(r"\$GW ([^\"\n]+)", _text(path)):
            commands.append([word for word in match.group(1).split() if not word.startswith("$")])
        return commands

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            argv = node.get("argv")
            if isinstance(argv, list) and argv and "defenseclaw_gateway" in str(argv[0]):
                commands.append([str(word) for word in argv[1:]])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(yaml.safe_load(_text(path)))
    return commands


def test_every_gateway_command_and_flag_is_documented_in_the_cli_reference() -> None:
    reference = _text(CLI_REFERENCE)
    seen = 0
    for name in (*PLAYS, "fleet-readiness.sh"):
        for argv in _gateway_commands(name):
            if "enterprise" not in argv:
                continue
            seen += 1
            assert argv[:2] == ["enterprise", "linux"], f"{name}: {argv}"
            action = [word for word in argv[2:] if not word.startswith("-") and not word.startswith("{{") and "/" not in word]
            # `tetragon verify ...` is a two-word action; the others are one word.
            phrase = " ".join(action[:2]) if action[:1] == ["tetragon"] else action[0]
            assert f"| `{phrase}` |" in reference, f"{name}: `{phrase}` is not a row of the CLI reference"
            for flag in (word for word in argv if word.startswith("--")):
                assert f"`{flag}" in reference, f"{name}: {flag} is not in the CLI reference"
    assert seen >= 7


def _guide_fences() -> dict[str, list[str]]:
    fences: dict[str, list[str]] = {}
    for match in re.finditer(r"^```[\w-]* title=\"([^\"]+)\"\n(.*?)\n```$", _text(GUIDE), re.MULTILINE | re.DOTALL):
        fences.setdefault(match.group(1), []).append(match.group(2) + "\n")
    return fences


def test_the_guide_shows_exactly_what_the_example_files_contain() -> None:
    fences = _guide_fences()
    for name in ALL_FILES:
        assert name in fences, f"{GUIDE.name} does not show {name} (a code block titled {name!r})"
        for block in fences[name]:
            assert block == _text(EXAMPLES / name), f"the block titled {name!r} differs from the file"


# Per-user burn-in toward enforce as `tetragon verify --json` reports it: the
# state the helper published, verify's own ready, reset and monitor-only, and
# the phase the fleet summary counts by.
_USERS = {
    "enforcing": {"state": "enforcing", "ready": True, "reset": False, "monitor_only": False, "phase": "enforcing"},
    "ready": {"state": "monitor", "ready": True, "reset": False, "monitor_only": False, "phase": "ready"},
    "burn_in": {"state": "burn_in", "ready": False, "reset": False, "monitor_only": False, "phase": "burn_in"},
    # In observe every user is "monitor": verify still says where its burn-in is.
    "monitor": {"state": "monitor", "reason": "observe mode", "ready": False, "reset": False, "monitor_only": False, "phase": "burn_in"},
    "reset": {"state": "monitor", "ready": False, "reset": True, "monitor_only": False, "phase": "reset"},
    "monitor_only": {"state": "monitor", "ready": False, "reset": False, "monitor_only": True, "phase": "monitor_only"},
    # GAP-0056: neither of these is in burn-in.
    "no_agent": {"state": "inactive", "reason": "kernel_enforce_inactive: no anchors", "ready": False, "reset": False,
                 "monitor_only": False, "phase": "no_agent"},
    "held": {"state": "monitor", "reason": "kernel_binary_anchor_scope_limited", "ready": False, "reset": False,
             "monitor_only": False, "phase": "held"},
}


def _verify(ready: bool, digest: str, users: list[str], failing: tuple[str, ...] = ()) -> dict[str, Any]:
    checks = [{"id": check, "status": "fail"} for check in failing] or [{"id": "tetragon.running", "status": "pass"}]
    return {
        "ready": ready,
        "kernel_policy": digest,
        "checks": checks,
        "users": [{"uid": 1000 + index, **_USERS[kind]} for index, kind in enumerate(users)],
    }


_FLEET_USERS = ["enforcing", "ready", "burn_in", "monitor", "reset", "monitor_only", "no_agent", "held", "held"]
_FLEET_COUNTS = [
    "Users enforcing: 1",
    "Users ready for enforce: 1",
    "Users in burn-in: 2",
    "Users reset by a hit: 1",
    "Users monitor-only (connector in observe mode): 1",
    "Users with no agent installed: 1",
    "Users held in monitor (a deny-anchor limit, a pause or an operator change): 2",
]


def test_fleet_play_counts_users_from_verify() -> None:
    jinja2 = pytest.importorskip("jinja2")
    play = yaml.safe_load(_text(EXAMPLES / "fleet-readiness.yml"))[0]
    summary = next(task for task in play["tasks"] if task["name"] == "Summarize the fleet")
    users = _verify(True, "sha256:08b71155b713", _FLEET_USERS)["users"]
    env = jinja2.Environment()
    lines = [env.from_string(line).render(fleet_users_all=users) for line in summary["ansible.builtin.debug"]["msg"] if line.startswith("Users")]
    assert lines == _FLEET_COUNTS
    keep = next(task for task in play["tasks"] if task["name"] == "Keep what the summary needs")
    # Everything comes from verify: one command per host.
    assert all("fleet_verify" in str(value) for value in keep["ansible.builtin.set_fact"].values())
    assert [task["name"] for task in play["tasks"] if "ansible.builtin.command" in task] == ["Check readiness for the mode"]


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is required")
class TestFleetReadinessScript:
    SCRIPT = EXAMPLES / "fleet-readiness.sh"

    def _fleet(self, tmp_path: Path, hosts: dict[str, tuple[int, Any]]) -> tuple[Path, Path]:
        """A fake ssh in front of PATH that answers per host from files."""
        bin_dir = tmp_path / "bin"
        data = tmp_path / "data"
        bin_dir.mkdir()
        data.mkdir()
        for host, (rc, verify) in hosts.items():
            (data / f"{host}.rc").write_text(str(rc), encoding="utf-8")
            (data / f"{host}.verify").write_text(json.dumps(verify), encoding="utf-8")
        fake = bin_dir / "ssh"
        fake.write_text(
            "#!/bin/sh\n"
            'while [ "$#" -gt 2 ]; do shift; done\n'
            'host=$1; command=$2\n'
            f'data="{data}"\n'
            'if [ "$host" = unreachable ]; then exit 255; fi\n'
            'case "$command" in\n'
            '*"tetragon verify"*) cat "$data/$host.verify"; exit "$(cat "$data/$host.rc")" ;;\n'
            "esac\n"
            "exit 3\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        hostfile = tmp_path / "hosts"
        hostfile.write_text("# the fleet\n\n" + "\n".join(hosts) + "\n", encoding="utf-8")
        return bin_dir, hostfile

    def _run(self, bin_dir: Path, mode: str, hostfile: Path) -> subprocess.CompletedProcess[str]:
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(hostfile.parent)}
        return subprocess.run(["sh", str(self.SCRIPT), mode, str(hostfile)], capture_output=True, text=True, env=env, timeout=60)

    def test_all_ready_exits_zero(self, tmp_path: Path) -> None:
        digest = "sha256:08b71155b713"
        bin_dir, hostfile = self._fleet(
            tmp_path,
            {
                "a": (0, _verify(True, digest, _FLEET_USERS[:3])),
                "b": (0, _verify(True, digest, _FLEET_USERS[3:])),
            },
        )
        result = self._run(bin_dir, "enforce", hostfile)
        assert result.returncode == 0, result.stderr
        assert "a: ready for enforce" in result.stdout
        assert "Hosts ready: 2 of 2" in result.stdout
        assert "Hosts not ready: none" in result.stdout
        for line in _FLEET_COUNTS:
            assert line + "\n" in result.stdout
        assert f"Kernel controls digests: {digest}\n" in result.stdout

    def test_an_observe_ring_counts_its_burn_in(self, tmp_path: Path) -> None:
        # The main use: an observe ring checked for enforce. Every user is in
        # state monitor there; the counts come from verify's burn-in fields.
        bin_dir, hostfile = self._fleet(
            tmp_path, {"pilot": (0, _verify(True, "sha256:08b71155b713", ["monitor", "reset", "ready"]))}
        )
        result = self._run(bin_dir, "enforce", hostfile)
        assert result.returncode == 0, result.stderr
        for line in ("Users enforcing: 0", "Users ready for enforce: 1", "Users in burn-in: 1", "Users reset by a hit: 1"):
            assert line + "\n" in result.stdout

    def test_a_host_that_is_not_ready_names_its_failing_checks_and_exits_one(self, tmp_path: Path) -> None:
        bin_dir, hostfile = self._fleet(
            tmp_path,
            {
                "a": (0, _verify(True, "sha256:08b71155b713", ["enforcing"])),
                "b": (1, _verify(False, "sha256:111111111111", ["reset"], ("tetragon.api", "kernel.bpf_lsm"))),
            },
        )
        result = self._run(bin_dir, "enforce", hostfile)
        assert result.returncode == 1, result.stderr
        assert "b: not ready for enforce: tetragon.api, kernel.bpf_lsm" in result.stdout
        assert "Hosts ready: 1 of 2" in result.stdout
        assert "Hosts not ready: b" in result.stdout
        assert "Users reset by a hit: 1" in result.stdout
        assert "(more than one means hosts run different builds)" in result.stdout

    def test_an_unreachable_host_is_reported_and_exits_two(self, tmp_path: Path) -> None:
        bin_dir, hostfile = self._fleet(
            tmp_path,
            {
                "a": (0, _verify(True, "sha256:08b71155b713", [])),
                "unreachable": (0, _verify(True, "", [])),
            },
        )
        result = self._run(bin_dir, "observe", hostfile)
        assert result.returncode == 2
        assert "unreachable: could not be checked (exit 255)" in result.stdout
        assert "Hosts not checked: unreachable" in result.stdout

    def test_bad_arguments_exit_two_without_touching_a_host(self, tmp_path: Path) -> None:
        bin_dir, hostfile = self._fleet(tmp_path, {"a": (0, _verify(True, "", []))})
        assert self._run(bin_dir, "everything", hostfile).returncode == 2
        assert self._run(bin_dir, "observe", tmp_path / "missing").returncode == 2
