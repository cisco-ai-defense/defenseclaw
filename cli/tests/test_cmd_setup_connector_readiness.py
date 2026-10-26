from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from defenseclaw import config as dcconfig
from defenseclaw import agent_selection, fail_mode, hook_integrity
from defenseclaw.commands import cmd_doctor, cmd_setup
from defenseclaw.connector_contracts import (
    connector_lock_contract_invariant,
    resolve_connector_contract,
)
from defenseclaw.doctor_hooks import WindowsHookCheck
from defenseclaw.fail_mode import connector_registration_lock_state

TEN_CONNECTORS = (
    "codex",
    "claudecode",
    "cursor",
    "devin",
    "copilot",
    "antigravity",
    "opencode",
    "amp",
    "hermes",
)


def _guardrail(mode: str = "observe", fail_mode: str = "open") -> SimpleNamespace:
    return SimpleNamespace(
        connectors={},
        hook_fail_mode=fail_mode,
        effective_mode=lambda _name: mode,
        effective_hook_fail_mode=lambda _name: fail_mode,
        effective_hilt=lambda _name: SimpleNamespace(enabled=False),
    )


def _config(data_dir: Path) -> SimpleNamespace:
    return SimpleNamespace(
        data_dir=str(data_dir),
        deployment_mode="local",
        environment="test",
        guardrail=_guardrail(),
        gateway=SimpleNamespace(api_port=18970, resolved_token=lambda: "token"),
        connector_workspace_dir=lambda: "",
        plugin_dirs=lambda _name: [],
    )


def _entry(connector: str, root: Path) -> dict[str, object]:
    raw_version = (
        "1.18.10"
        if connector == "opencode"
        else "3000.4.25"
        if connector == "devin"
        else ""
    )
    compatibility = resolve_connector_contract(connector, raw_version)
    assert compatibility.contract is not None
    config_path = root / f"{connector}-config.json"
    runtime_path = root / f"{connector}-runtime.bin"
    config_path.write_text("defenseclaw\n", encoding="utf-8")
    runtime_path.write_bytes(f"{connector}-runtime".encode())
    return {
        "connector": connector,
        "raw_agent_version": raw_version,
        "normalized_agent_version": compatibility.normalized_version,
        "contract_id": compatibility.contract.contract_id,
        "compatibility_status": compatibility.status,
        "hook_script_version": compatibility.contract.hook_script_version,
        "hook_fail_mode": "open",
        "hook_script_digests": {runtime_path.name: "sha256:" + hashlib.sha256(runtime_path.read_bytes()).hexdigest()},
        "locations": {
            "hook_config_paths": [str(config_path)],
            "hook_script_paths": [str(runtime_path)],
        },
    }


def _patch_registration_ready(monkeypatch, entry: dict[str, object]) -> None:
    monkeypatch.setattr(
        fail_mode,
        "connector_registration_lock_state",
        lambda _cfg, _connector: (str(entry["hook_fail_mode"]), None),
    )
    monkeypatch.setattr(
        fail_mode,
        "_registration_lock_state",
        lambda _cfg, _connector, **_kwargs: (str(entry["hook_fail_mode"]), None),
    )


@pytest.mark.parametrize("connector", TEN_CONNECTORS)
def test_contract_lock_accepts_exact_eleven(connector: str, tmp_path: Path) -> None:
    assert connector_lock_contract_invariant(connector, _entry(connector, tmp_path)) == ""


def test_contract_lock_accepts_kiro_not_gated_without_hook_paths() -> None:
    assert (
        connector_lock_contract_invariant(
            "kiro",
            {
                "connector": "kiro",
                "raw_agent_version": "kiro-cli 2.27.1",
                "compatibility_status": "not-gated",
                "hook_fail_mode": "open",
            },
        )
        == ""
    )


@pytest.mark.parametrize("mode", ("observe", "action"))
@pytest.mark.parametrize("allow_drift", (False, True))
def test_kiro_cli_below_hook_floor_is_refused_by_setup_and_its_lock(
    mode: str, allow_drift: bool, tmp_path: Path, monkeypatch,
) -> None:
    """GAP-0227: before kiro-cli 2.27.1 a non-interactive ``--v3`` run loads no
    hooks, so setup refuses that kiro-cli in both modes and its registration
    lock no longer counts as a supported not-gated one. The Kiro IDE launcher's
    bare version is not a kiro-cli version and is not gated."""

    if allow_drift:
        monkeypatch.setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "1")

    def setup_accepts(version: str) -> bool:
        signal = SimpleNamespace(version=version, installed=True, error="", binary_path="")
        return cmd_setup._check_connector_version_supported_for_setup(
            "kiro", mode=mode, emit=False, data_dir=str(tmp_path),
            _discovery=SimpleNamespace(agents={"kiro": signal}),
        )

    def lock(version: str) -> str:
        return connector_lock_contract_invariant(
            "kiro",
            {"connector": "kiro", "raw_agent_version": version, "compatibility_status": "not-gated", "hook_fail_mode": "closed"},
        )

    for below in ("kiro-cli 2.26.1", "kiro-cli 2.24.1"):
        assert not setup_accepts(below), below
        assert lock(below) == "contract", below
    for supported in ("kiro-cli 2.27.1", "kiro-cli 3.0.0", "1.1.14"):
        assert setup_accepts(supported), supported
        assert lock(supported) == "", supported


@pytest.mark.parametrize("mode", ("observe", "action"))
def test_kiro_setup_accepts_supported_ide_and_reports_old_cli(mode: str, tmp_path: Path, monkeypatch) -> None:
    warnings: list[str] = []
    monkeypatch.setattr(cmd_setup.ux, "warn", warnings.append)
    signal = SimpleNamespace(
        version="1.0.182", installed=True, error="", binary_path="/usr/local/bin/kiro",
        kiro_cli_version="kiro-cli 2.26.1", kiro_ide_version="1.0.182",
    )
    assert cmd_setup._check_connector_version_supported_for_setup(
        "kiro", mode=mode, emit=True, data_dir=str(tmp_path),
        _discovery=SimpleNamespace(agents={"kiro": signal}),
    )
    assert any("kiro-cli 2.26.1 is below 2.27.1" in warning for warning in warnings)


@pytest.mark.parametrize("connector", ("antigravity",))
def test_contract_lock_accepts_go_omitted_unversioned_fields(connector: str, tmp_path: Path) -> None:
    entry = _entry(connector, tmp_path)
    entry.pop("raw_agent_version")
    entry.pop("normalized_agent_version")

    assert connector_lock_contract_invariant(connector, entry) == ""


def test_contract_lock_rejects_explicit_null_agent_version(tmp_path: Path) -> None:
    entry = _entry("antigravity", tmp_path)
    entry["raw_agent_version"] = None

    assert connector_lock_contract_invariant("antigravity", entry) == "version"


@pytest.mark.parametrize(
    ("field", "value", "invariant"),
    (
        ("contract_id", "wrong-contract", "contract"),
        ("hook_script_version", "v999", "version"),
        ("hook_fail_mode", "maybe", "fail-mode"),
    ),
)
def test_contract_lock_reports_exact_corrupt_invariant(
    field: str,
    value: str,
    invariant: str,
    tmp_path: Path,
) -> None:
    entry = _entry("amp", tmp_path)
    entry[field] = value
    assert connector_lock_contract_invariant("amp", entry) == invariant


def test_contract_lock_rejects_noncanonical_location(tmp_path: Path) -> None:
    entry = _entry("amp", tmp_path)
    locations = copy.deepcopy(entry["locations"])
    assert isinstance(locations, dict)
    locations["hook_config_paths"] = [str(tmp_path / "peer" / ".." / "amp-config.json")]
    entry["locations"] = locations
    assert connector_lock_contract_invariant("amp", entry) == "location"


class _WindowsOs:
    """The os module as one module sees it on Windows; pathlib and every other module keep the host's os."""

    name = "nt"

    def __getattr__(self, attr: str) -> object:
        return getattr(os, attr)


def _fake_windows(monkeypatch: pytest.MonkeyPatch, module: object) -> None:
    # Setting os.name globally turns every Path into an uninstantiable WindowsPath on this host.
    monkeypatch.setattr(module, "os", _WindowsOs())


def test_protected_executable_reports_identity_location_and_digest(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "amp.exe"
    executable.write_bytes(b"MZamp")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    entry = {
        "agent_executable_source": "setup-selected",
        "agent_executable": str(executable),
        "agent_executable_sha256": digest,
    }
    _fake_windows(monkeypatch, agent_selection)
    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", lambda *_args: True)
    assert agent_selection.setup_agent_lock_executable_invariant(str(tmp_path), "amp", entry) == ""

    wrong_identity = dict(entry, agent_executable=str(tmp_path / "other.exe"))
    assert agent_selection.setup_agent_lock_executable_invariant(str(tmp_path), "amp", wrong_identity) == "executable"

    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", lambda *_args: False)
    assert agent_selection.setup_agent_lock_executable_invariant(str(tmp_path), "amp", entry) == "location"

    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", lambda *_args: True)
    stale_digest = dict(entry, agent_executable_sha256="0" * 64)
    assert agent_selection.setup_agent_lock_executable_invariant(str(tmp_path), "amp", stale_digest) == "digest"


def test_opencode_protected_executable_requires_exact_sst_location(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "opencode.exe"
    executable.write_bytes(b"MZopencode")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    entry = {
        "agent_executable_source": "setup-selected",
        "agent_executable": str(executable),
        "agent_executable_sha256": digest,
    }
    _fake_windows(monkeypatch, agent_selection)
    monkeypatch.setattr(
        agent_selection,
        "is_setup_trusted_binary",
        lambda *_args: (_ for _ in ()).throw(AssertionError("OpenCode must use exact SST admission")),
    )
    monkeypatch.setattr(agent_selection, "_is_windows_opencode_setup_binary", lambda path: path == str(executable))

    assert agent_selection.setup_agent_lock_executable_invariant(str(tmp_path), "opencode", entry) == ""
    monkeypatch.setattr(agent_selection, "_is_windows_opencode_setup_binary", lambda _path: False)
    assert agent_selection.setup_agent_lock_executable_invariant(str(tmp_path), "opencode", entry) == "location"




def _write_amp_runtime(tmp_path: Path) -> tuple[SimpleNamespace, dict[str, object]]:
    cfg = _config(tmp_path)
    entry = _entry("amp", tmp_path)
    config_path = Path(entry["locations"]["hook_config_paths"][0])
    config_path.write_text(
        '// DefenseClaw Amp policy bridge\nconst DC_FAIL_MODE: string = "open";\n/api/v1/amp/hook\n',
        encoding="utf-8",
    )
    lock = {"version": 2, "connectors": {"amp": entry}}
    (tmp_path / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["amp"], "inactive_names": []}),
        encoding="utf-8",
    )
    return cfg, entry


def _patch_amp_readiness_leaves(monkeypatch, cfg: SimpleNamespace, entry: dict[str, object]) -> None:
    config_path = entry["locations"]["hook_config_paths"][0]
    runtime_paths = entry["locations"]["hook_script_paths"]
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    monkeypatch.setattr(agent_selection, "setup_agent_lock_executable_invariant", lambda *_args: "")
    monkeypatch.setattr(cmd_doctor, "_hook_health_paths_from_lock", lambda *_args: [config_path])
    monkeypatch.setattr(cmd_doctor, "_hook_runtime_paths_from_lock", lambda *_args: runtime_paths)
    monkeypatch.setattr(cmd_doctor, "_managed_plugin_drift", lambda *_args: "")


def test_slow_real_dispatch_is_bounded_and_cannot_publish_late(monkeypatch, tmp_path: Path) -> None:
    cfg, entry = _write_amp_runtime(tmp_path)
    _patch_amp_readiness_leaves(monkeypatch, cfg, entry)
    started = threading.Event()
    release = threading.Event()

    def slow_marker(*_args) -> bool:
        started.set()
        release.wait(2.0)
        return True

    monkeypatch.setattr(cmd_doctor, "_file_references_marker", slow_marker)
    monkeypatch.setattr(fail_mode, "_platform_runtime_source", lambda *_args: ("amp-plugin", "open"))
    before = time.monotonic()
    result = cmd_setup._wait_for_connector_runtime(str(tmp_path), ["amp"], None, None, timeout=0.15)
    elapsed = time.monotonic() - before
    assert started.is_set(), result
    assert not result
    assert result.connector == "amp"
    assert result.invariant == "deadline"
    assert elapsed < 0.6
    release.set()
    time.sleep(0.05)
    assert not result


def test_gateway_unavailable_never_starts_connector_validation(monkeypatch, tmp_path: Path) -> None:
    cfg, entry = _write_amp_runtime(tmp_path)
    _patch_amp_readiness_leaves(monkeypatch, cfg, entry)
    started = False

    def marker(*_args) -> bool:
        nonlocal started
        started = True
        return True

    monkeypatch.setattr(cmd_doctor, "_file_references_marker", marker)
    monkeypatch.setattr(cmd_setup, "_read_gateway_health", lambda *_args, **_kwargs: None)
    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path),
        ["amp"],
        None,
        None,
        timeout=0.05,
        require_gateway_health=True,
    )
    assert not result
    assert result.invariant == "gateway-health"
    assert not started


def test_hermes_pending_reload_is_not_setup_ready(monkeypatch, tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    entry = _entry("hermes", tmp_path)
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"hermes": entry}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(agent_selection, "setup_agent_lock_executable_invariant", lambda *_args: "")
    monkeypatch.setattr(cmd_doctor, "hermes_profile_unsupported_reason", lambda *_args: "")
    monkeypatch.setattr(
        cmd_doctor,
        "_windows_native_hook_check",
        lambda *_args, **_kwargs: WindowsHookCheck(
            "pending-reload",
            "registration is on disk but live=false",
        ),
    )
    monkeypatch.setattr(fail_mode, "_platform_runtime_source", lambda *_args: ("hook-script", "open"))
    readiness = cmd_doctor.connector_setup_readiness(cfg, "hermes")
    assert not readiness
    assert readiness.connector == "hermes"
    assert readiness.invariant == "live-runtime"


def test_transient_runtime_detail_wins_over_digest_context() -> None:
    detail = (
        "digest: OpenCode hooks: warn: managed plugin digest current; "
        "runtime load unverified: no authenticated load heartbeat"
    )

    assert cmd_doctor._setup_readiness_invariant(detail, default="registration") == "live-runtime"
    assert cmd_doctor._setup_readiness_invariant("managed plugin digest mismatch", default="registration") == "digest"


def test_setup_wait_retries_transient_opencode_heartbeat(monkeypatch, tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    entry = _entry("opencode", tmp_path)
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"opencode": entry}}),
        encoding="utf-8",
    )
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["opencode"], "inactive_names": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    attempts = 0

    def readiness(*_args) -> cmd_doctor.ConnectorSetupReadiness:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return cmd_doctor.ConnectorSetupReadiness(
                False,
                "opencode",
                "live-runtime",
                "digest current; runtime load unverified: no authenticated load heartbeat",
            )
        return cmd_doctor.ConnectorSetupReadiness(True, "opencode", "ready")

    monkeypatch.setattr(cmd_doctor, "connector_setup_readiness", readiness)

    result = cmd_setup._wait_for_connector_runtime(str(tmp_path), ["opencode"], None, None, timeout=0.5)

    assert result
    assert attempts == 2


def test_setup_wait_accepts_opencode_that_has_not_loaded_the_plugin_yet(monkeypatch, tmp_path: Path) -> None:
    """setup opencode failed every time on Linux: a closed OpenCode never reports its load."""
    cfg = _config(tmp_path)
    entry = _entry("opencode", tmp_path)
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"opencode": entry}}),
        encoding="utf-8",
    )
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["opencode"], "inactive_names": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    monkeypatch.setattr(cmd_setup, "_OPENCODE_LOAD_HEARTBEAT_GRACE_SECONDS", 0.0)
    monkeypatch.setattr(
        cmd_doctor,
        "connector_setup_readiness",
        lambda *_args: cmd_doctor.ConnectorSetupReadiness(
            False,
            "opencode",
            "live-runtime",
            "OpenCode hooks: warn: managed plugin digest current; runtime load unverified: "
            "no authenticated load heartbeat; OpenCode may be stopped or idle",
        ),
    )

    readiness = cmd_setup._wait_for_connector_runtime(str(tmp_path), ["opencode"], None, None, timeout=2.0)

    assert readiness
    assert (readiness.connector, readiness.invariant) == ("opencode", "pending-reload")


def test_setup_wait_commits_truthful_hermes_pending_reload(monkeypatch, tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    entry = _entry("hermes", tmp_path)
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"hermes": entry}}),
        encoding="utf-8",
    )
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["hermes"], "inactive_names": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    monkeypatch.setattr(
        cmd_doctor,
        "connector_setup_readiness",
        lambda *_args: cmd_doctor.ConnectorSetupReadiness(
            False,
            "hermes",
            "executable",
            "Hook contract: fail: on-disk Windows-native executable registration is valid; "
            "runtime_state=pending-reload; running Hermes hosts are unverified; live=false",
        ),
    )
    monkeypatch.setattr(cmd_doctor, "_hermes_host_running", lambda: True)

    readiness = cmd_setup._wait_for_connector_runtime(
        str(tmp_path),
        ["hermes"],
        None,
        None,
        timeout=0.5,
    )

    assert readiness
    assert (readiness.connector, readiness.invariant) == ("hermes", "pending-reload")
    assert "live=false" in readiness.detail

    # GAP-1235: with no Hermes host running there is nothing to reload, as doctor says.
    monkeypatch.setattr(cmd_doctor, "_hermes_host_running", lambda: False)
    readiness = cmd_setup._wait_for_connector_runtime(str(tmp_path), ["hermes"], None, None, timeout=0.5)
    assert readiness
    assert readiness.invariant != "pending-reload"


@pytest.mark.parametrize(
    ("invariant", "detail"),
    [
        (
            "live-runtime",
            "OpenCode hooks: warn: managed plugin digest current; runtime load unverified: "
            "no authenticated load heartbeat; OpenCode may be stopped or idle",
        ),
        # GAP-1763: right after the restart the status has no OpenCode row yet.
        (
            "digest",
            "OpenCode hooks: warn: plugin installed at ~/.config/opencode/plugins/defenseclaw.js "
            "(digest current); runtime load unverified: authenticated status has no OpenCode connector row",
        ),
    ],
)
def test_setup_wait_does_not_skip_an_idle_opencode_peer(
    monkeypatch, tmp_path: Path, capsys, invariant: str, detail: str
) -> None:
    """GAP-1271: a stopped OpenCode peer is not 'skipped' with a re-run hint."""
    cfg = _config(tmp_path)
    entries = {name: _entry(name, tmp_path) for name in ("codex", "opencode")}
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": entries}),
        encoding="utf-8",
    )
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["codex", "opencode"], "inactive_names": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)

    def readiness(_cfg, name):
        if name == "opencode":
            return cmd_doctor.ConnectorSetupReadiness(False, "opencode", invariant, detail)
        return cmd_doctor.ConnectorSetupReadiness(True, name, "ready")

    monkeypatch.setattr(cmd_doctor, "connector_setup_readiness", readiness)

    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["codex", "opencode"], None, None, timeout=0.5, required={"codex"}
    )

    assert result
    output = capsys.readouterr().out
    assert "skipping opencode" not in output
    assert "Re-run setup" not in output


def test_setup_wait_skips_a_peer_the_restarted_gateway_refused(monkeypatch, tmp_path: Path, capsys) -> None:
    """GAP-1710: a fresh roster without Cursor must not fail and roll back setup amp."""
    cfg = _config(tmp_path)
    entries = {name: _entry(name, tmp_path) for name in ("amp", "codex", "cursor")}
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": entries}),
        encoding="utf-8",
    )
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["amp", "codex"], "inactive_names": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    monkeypatch.setattr(
        cmd_doctor, "connector_setup_readiness", lambda _cfg, name: cmd_doctor.ConnectorSetupReadiness(True, name, "ready")
    )

    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["amp", "codex", "cursor"], None, None, timeout=0.5, required={"amp"}
    )

    assert result
    assert result.skipped == frozenset({"cursor"})
    output = capsys.readouterr().out
    assert "skipping cursor: the restarted gateway did not activate it" in output
    assert "defenseclaw setup cursor" in output
    # The connector being set up is never skipped.
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["codex"], "inactive_names": []}),
        encoding="utf-8",
    )
    assert not cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["amp", "codex"], None, None, timeout=0.3, required={"amp"}
    )


def test_restart_services_does_not_wait_for_a_refused_peer_in_the_api(monkeypatch, tmp_path: Path) -> None:
    """GAP-1710: the API wait must not expect a peer the runtime wait skipped."""
    seen: list[list[str]] = []
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(cmd_setup, "_hook_runtime_wait_targets", lambda *_args: ["hermes", "claudecode", "copilot"])
    monkeypatch.setattr(cmd_setup, "_unverified_setup_peers", frozenset)
    monkeypatch.setattr(
        cmd_setup,
        "_wait_for_connector_runtime",
        lambda *_args, **_kwargs: cmd_setup._ConnectorRuntimeReadiness(True, skipped=frozenset({"copilot"})),
    )

    def api_wait(*_args, expected_connectors=(), **_kwargs):
        seen.append(list(expected_connectors))
        return True

    monkeypatch.setattr(cmd_setup, "_wait_for_defense_gateway_api", api_wait)

    cmd_setup._restart_services(str(tmp_path), connector="hermes", wait_for_connector_ready=True)

    assert seen == [["hermes", "claudecode"]]


def test_setup_wait_remembers_a_refused_peer_for_the_summary(monkeypatch, tmp_path: Path) -> None:
    """GAP-2013: the closing Summary learns which peer the gateway refused."""
    cfg = _config(tmp_path)
    entries = {name: _entry(name, tmp_path) for name in ("amp", "codex", "cursor")}
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": entries}),
        encoding="utf-8",
    )
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["amp", "codex"], "inactive_names": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    monkeypatch.setattr(
        cmd_doctor, "connector_setup_readiness", lambda _cfg, name: cmd_doctor.ConnectorSetupReadiness(True, name, "ready")
    )

    with click.Context(click.Command("setup")):
        result = cmd_setup._wait_for_connector_runtime(
            str(tmp_path), ["amp", "codex", "cursor"], None, None, timeout=0.5, required={"amp"}
        )
        assert result
        assert cmd_setup._runtime_skipped_setup_peers() == frozenset({"cursor"})


def test_restart_services_roster_line_leaves_out_a_refused_peer(monkeypatch, tmp_path: Path) -> None:
    """GAP-2013: a peer setup skipped is not named as protected in the closing line."""
    hints: list[str] = []
    roster = ["claudecode", "codex", "hermes", "opencode"]
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(cmd_setup, "_hook_runtime_wait_targets", lambda *_args: list(roster))
    monkeypatch.setattr(cmd_setup, "_unverified_setup_peers", frozenset)
    monkeypatch.setattr(cmd_setup, "_wait_for_defense_gateway_api", lambda *_args, **_kwargs: True)
    # Keep this readiness test independent of the build host's OpenCode home.
    from defenseclaw import connector_paths

    monkeypatch.setattr(
        connector_paths, "connector_config_files",
        lambda _name: [str(tmp_path / "opencode" / "plugins" / "defenseclaw.js")],
    )
    monkeypatch.setattr(
        cmd_setup,
        "_wait_for_connector_runtime",
        lambda *_args, **_kwargs: cmd_setup._ConnectorRuntimeReadiness(True, skipped=frozenset({"hermes"})),
    )
    monkeypatch.setattr(cmd_setup.ux, "subhead", hints.append)

    cmd_setup._restart_services(str(tmp_path), connector="opencode", connectors=roster, wait_for_connector_ready=True)

    assert any(hint.startswith("3 hook connectors (claudecode, codex, opencode):") for hint in hints), hints
    assert not any("hermes" in hint for hint in hints), hints


def test_batch_readiness_requires_every_selected_connector(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(cmd_setup, "_hook_runtime_wait_targets", lambda *_args: ["codex", "cursor"])
    monkeypatch.setattr(cmd_setup, "_unverified_setup_peers", frozenset)
    monkeypatch.setattr(cmd_setup, "_wait_for_defense_gateway_api", lambda *_args, **_kwargs: True)

    def wait(*_args, **kwargs):
        captured.update(kwargs)
        return cmd_setup._ConnectorRuntimeReadiness(True)

    monkeypatch.setattr(cmd_setup, "_wait_for_connector_runtime", wait)
    cmd_setup._restart_services(
        str(tmp_path), connector="codex", connectors=["codex", "cursor"],
        wait_for_connector_ready=True, required_connectors=frozenset({"codex", "cursor"}),
    )
    assert captured["required"] == {"codex", "cursor"}


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode check")
def test_opencode_writable_plugin_folder_is_named_before_restart(monkeypatch, tmp_path: Path) -> None:
    from defenseclaw import connector_paths

    folder = tmp_path / ".config" / "opencode" / "plugins"
    folder.mkdir(parents=True)
    folder.chmod(0o775)
    plugin = folder / "defenseclaw.js"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    restarted = []
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_args, **_kwargs: restarted.append(True))
    with pytest.raises(click.ClickException) as caught:
        cmd_setup._restart_services(str(tmp_path), connector="opencode", wait_for_connector_ready=True)
    assert str(folder) in str(caught.value)
    assert "chmod go-w" in str(caught.value)
    assert restarted == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode check")
@pytest.mark.parametrize("batch", [False, True])
def test_opencode_preflight_precedes_config_write(monkeypatch, tmp_path: Path, batch: bool) -> None:
    from defenseclaw import connector_paths
    from defenseclaw.context import AppContext

    folder = tmp_path / "plugins"
    folder.mkdir(mode=0o775)
    folder.chmod(0o775)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        connector_paths, "connector_config_files", lambda _name: [str(folder / "defenseclaw.js")]
    )
    cfg = _config(tmp_path)
    writes = []
    cfg.save = lambda: writes.append(True)
    app = AppContext()
    app.cfg = cfg
    if batch:
        ctx = click.Context(cmd_setup.setup, obj=app)
        with ctx, pytest.raises(click.ClickException, match="group/other writable"):
            cmd_setup._apply_setup_batch(
                ctx, app, ["opencode"], mode="action", restart=True,
                prompt_per_connector=False,
            )
    else:
        with pytest.raises(click.ClickException, match="group/other writable"):
            cmd_setup._apply_hook_connector_setup(
                app, connector="opencode", mode="action", restart=True,
            )
    assert writes == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode check")
@pytest.mark.parametrize(
    "restart_kwargs",
    [{"teardown": True}, {"title": cmd_setup._ROLLBACK_RESTART_TITLE}],
)
def test_opencode_teardown_or_rollback_skips_setup_folder_preflight(
    monkeypatch, tmp_path: Path, restart_kwargs: dict
) -> None:
    from defenseclaw import connector_paths

    folder = tmp_path / ".config" / "opencode" / "plugins"
    folder.mkdir(parents=True)
    folder.chmod(0o775)
    plugin = folder / "defenseclaw.js"
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])

    def reached_restart(*_args, **_kwargs):
        raise RuntimeError("restart reached")

    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", reached_restart)
    with pytest.raises(RuntimeError, match="restart reached"):
        cmd_setup._restart_services(
            str(tmp_path), connector="opencode", wait_for_connector_ready=True, **restart_kwargs
        )


def test_restart_services_labels_hermes_pending_reload_without_live_claim(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    hints: list[str] = []
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(cmd_setup, "_wait_for_defense_gateway_api", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        cmd_setup,
        "_wait_for_connector_runtime",
        lambda *_args, **_kwargs: cmd_setup._ConnectorRuntimeReadiness(
            True,
            "hermes",
            "pending-reload",
            "running Hermes hosts are unverified; live=false",
        ),
    )
    monkeypatch.setattr(cmd_setup.ux, "subhead", hints.append)

    cmd_setup._restart_services(
        str(tmp_path),
        connector="hermes",
        wait_for_connector_ready=True,
    )

    output = capsys.readouterr().out
    assert "waiting for verified setup... ! (restart any open Hermes session" in output
    assert "connector runtime: waiting for verified setup... ✓" not in output
    assert any("keeps its old hooks until it is restarted" in hint for hint in hints)
    # GAP-1782: no internal state names in user output.
    for text in [output, *hints]:
        assert "live=false" not in text and "pending-reload" not in text and "--passive" not in text


def test_upstream_fail_open_remains_distinct_from_configured_mode(monkeypatch, tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    cfg.guardrail = _guardrail(fail_mode="closed")
    # Under Secure Client the Hermes hook is the upstream fail-open one; per-user
    # it follows its fail mode on every OS (GAP-0150, GAP-0269).
    cfg.deployment_mode = "managed_enterprise"
    monkeypatch.setattr("defenseclaw.fail_mode._is_windows", lambda: True)
    entry = _entry("hermes", tmp_path)
    entry["hook_fail_mode"] = "closed"
    _patch_registration_ready(monkeypatch, entry)
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"hermes": entry}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(agent_selection, "setup_agent_lock_executable_invariant", lambda *_args: "")
    monkeypatch.setattr(cmd_doctor, "hermes_profile_unsupported_reason", lambda *_args: "")
    monkeypatch.setattr(
        cmd_doctor,
        "_windows_native_hook_check",
        lambda *_args, **_kwargs: WindowsHookCheck("healthy", "registered"),
    )
    monkeypatch.setattr(cmd_doctor, "_hermes_windows_execution_probe", lambda check: check)
    monkeypatch.setattr(
        cmd_doctor,
        "_check_hermes_hooks",
        lambda _cfg, result: cmd_doctor._emit(
            "pass",
            cmd_doctor._HERMES_HOOKS_LABEL,
            "healthy: registered",
            r=result,
        ),
    )
    readiness = cmd_doctor.connector_setup_readiness(cfg, "hermes")
    assert readiness
    assert readiness.detail == "configured=closed; effective=open"


@pytest.mark.parametrize("connector", ("codex", "claudecode", "devin", "amp", "opencode"))
def test_observe_readiness_compares_lock_to_mode_aware_desired_fail_mode(
    monkeypatch,
    tmp_path: Path,
    connector: str,
) -> None:
    cfg = _config(tmp_path)
    cfg.guardrail = _guardrail(mode="observe", fail_mode="closed")
    primary_label = cmd_doctor._SETUP_READINESS_PRIMARY_LABELS[connector]

    monkeypatch.setattr(
        "defenseclaw.fail_mode.connector_registration_lock_state",
        lambda *_args: ("open", ""),
    )
    monkeypatch.setattr(
        "defenseclaw.fail_mode.connector_fail_mode_report",
        lambda *_args, **_kwargs: {
            "configured": "closed",
            "desired": "open",
            "effective": "open",
        },
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_check_hook_contract_lock",
        lambda _cfg, _name, result: result.record("pass", "Hook contract", "current"),
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_check_connector_hooks",
        lambda _cfg, _name, result: result.record("pass", primary_label, "current"),
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_check_codex_otel_alignment",
        lambda _cfg, result: (
            result.record("pass", "Codex OTel environment", "current"),
            result.record("pass", "Codex OTel runtime", "current"),
        ),
    )

    readiness = cmd_doctor.connector_setup_readiness(cfg, connector)

    assert readiness
    assert readiness.detail == "configured=closed; effective=open"


def test_readiness_rejects_lock_that_disagrees_with_mode_aware_desired_fail_mode(
    monkeypatch,
    tmp_path: Path,
) -> None:
    cfg = _config(tmp_path)
    monkeypatch.setattr(
        "defenseclaw.fail_mode.connector_registration_lock_state",
        lambda *_args: ("open", ""),
    )
    monkeypatch.setattr(
        "defenseclaw.fail_mode.connector_fail_mode_report",
        lambda *_args, **_kwargs: {
            "configured": "closed",
            "desired": "closed",
            "effective": "open",
        },
    )

    readiness = cmd_doctor.connector_setup_readiness(cfg, "codex")

    assert not readiness
    assert readiness.invariant == "fail-mode"
    assert readiness.detail == "lock=open configured=closed effective=open"




def test_copilot_stale_launcher_returns_executable_invariant(monkeypatch, tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    entry = _entry("copilot", tmp_path)
    _patch_registration_ready(monkeypatch, entry)
    _fake_windows(monkeypatch, cmd_doctor)
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"copilot": entry}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cmd_doctor,
        "copilot_settings_resolution",
        lambda *_args: SimpleNamespace(errors=(), disable_all_hooks=False),
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_windows_native_hook_check",
        lambda *_args, **_kwargs: WindowsHookCheck("stale", "registered launcher executable is stale"),
    )
    # fail_mode keeps the host's os, so supply the mode the Windows .hookcfg would render.
    monkeypatch.setattr("defenseclaw.fail_mode._platform_runtime_source", lambda *_args: ("windows-sidecar", "open"))
    monkeypatch.setattr("defenseclaw.fail_mode._shared_hook_sidecar_drift", lambda *_args: None)
    readiness = cmd_doctor.connector_setup_readiness(cfg, "copilot")
    assert not readiness
    assert (readiness.connector, readiness.invariant) == ("copilot", "executable")


@pytest.mark.parametrize(("rendered", "ready"), [("open", False), (None, False), ("closed", True)])
def test_readiness_requires_the_rendered_windows_mode_to_match_the_lock(
    monkeypatch, tmp_path: Path, rendered: str | None, ready: bool
) -> None:
    # Review round 2: config and the lock say closed, but the Windows .hookcfg
    # the native hook reads says open (or nothing). The hook then lets calls
    # run with the gateway down, so Setup must not report ready.
    cfg = _config(tmp_path)
    cfg.guardrail = _guardrail(mode="action", fail_mode="closed")
    entry = _entry("copilot", tmp_path)
    entry["hook_fail_mode"] = "closed"
    _patch_registration_ready(monkeypatch, entry)
    monkeypatch.setattr(fail_mode, "_is_windows", lambda: True)
    monkeypatch.setattr(fail_mode, "_native_deny_registration_freshness", lambda *_args: None, raising=False)
    hooks = tmp_path / "hooks"
    hooks.mkdir(exist_ok=True)
    if rendered is not None:
        (hooks / ".hookcfg").write_text(
            json.dumps({"version": 2, "gateway_addr": "127.0.0.1:18970", "fail_modes": {"copilot": rendered}}),
            encoding="utf-8",
        )
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"copilot": entry}}),
        encoding="utf-8",
    )

    def passing(label: str):
        return lambda _cfg, _name, r, *_args, **_kwargs: cmd_doctor._emit("pass", label, "ok", r=r)

    monkeypatch.setattr(cmd_doctor, "_check_hook_contract_lock", passing("Hook contract"))
    monkeypatch.setattr(cmd_doctor, "_check_connector_hooks", passing("Copilot hooks"))
    readiness = cmd_doctor.connector_setup_readiness(cfg, "copilot")
    assert bool(readiness) is ready, readiness
    if not ready:
        assert readiness.invariant == "fail-mode"
        assert f"rendered={rendered or 'missing'}" in readiness.detail


def test_opencode_recovery_setup_uses_call_time_mode_without_rendered_mode(monkeypatch, tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    # The real GuardrailConfig: a stub with the method hid that the class had
    # none, so the exemption never applied (GAP-1354).
    cfg.guardrail = dcconfig.GuardrailConfig()
    entry = _entry("opencode", tmp_path)
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"opencode": entry}}), encoding="utf-8"
    )
    monkeypatch.setattr(fail_mode, "connector_registration_lock_state", lambda *_: ("open", ""))
    monkeypatch.setattr(fail_mode, "connector_fail_mode_report", lambda *_a, **_kw: {
        "configured": "open", "desired": "open", "effective": "open",
        "sources": [{"name": "opencode-plugin", "mode": None}],
    })

    def passing(label: str):
        return lambda _cfg, _name, r, *_args, **_kwargs: cmd_doctor._emit("pass", label, "ok", r=r)

    monkeypatch.setattr(cmd_doctor, "_check_hook_contract_lock", passing("Hook contract"))
    monkeypatch.setattr(cmd_doctor, "_check_connector_hooks", passing("OpenCode hooks"))
    readiness = cmd_doctor.connector_setup_readiness(cfg, "opencode")
    assert readiness, readiness


def test_readiness_lock_reports_digest_drift(monkeypatch, tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    entry = _entry("amp", tmp_path)
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"amp": entry}}),
        encoding="utf-8",
    )
    runtime_path = Path(entry["locations"]["hook_script_paths"][0])
    runtime_path.write_bytes(b"changed")
    monkeypatch.setattr(agent_selection, "setup_agent_lock_executable_invariant", lambda *_args: "")
    _mode, drift = connector_registration_lock_state(cfg, "amp")
    assert drift == "registration-digest-stale"


def test_snapshot_reports_one_peer_contract_drift(tmp_path: Path) -> None:
    lock = {"version": 2, "connectors": {name: _entry(name, tmp_path) for name in TEN_CONNECTORS}}
    lock["connectors"]["copilot"]["contract_id"] = "wrong"
    state = {"version": 3, "names": list(TEN_CONNECTORS), "inactive_names": []}
    result = cmd_setup._connector_runtime_snapshot_failure(
        state,
        2,
        lock,
        2,
        expected=set(TEN_CONNECTORS),
        previous_state_marker=1,
        previous_lock_marker=1,
    )
    assert not result
    assert (result.connector, result.invariant) == ("copilot", "contract")


def test_snapshot_accepts_exact_eleven_roster(tmp_path: Path) -> None:
    lock = {"version": 2, "connectors": {name: _entry(name, tmp_path) for name in TEN_CONNECTORS}}
    state = {"version": 3, "names": list(TEN_CONNECTORS), "inactive_names": []}
    assert cmd_setup._connector_runtime_snapshot_ready(
        state,
        2,
        lock,
        2,
        expected=set(TEN_CONNECTORS),
        previous_state_marker=1,
        previous_lock_marker=1,
    )


def test_runtime_state_accepts_omitted_empty_active_roster() -> None:
    assert cmd_setup._connector_runtime_state_sets(
        {"version": 3, "inactive_names": ["cursor"]}
    ) == (set(), {"cursor"})
    assert cmd_setup._connector_runtime_state_sets(
        {"version": 3, "names": None, "inactive_names": ["cursor"]}
    ) is None


def test_wait_targets_keep_the_complete_desired_roster(tmp_path: Path) -> None:
    (tmp_path / "active_connector.json").write_text(
        json.dumps(
            {
                "version": 3,
                "names": ["amp", "codex", ],
                "inactive_names": [],
            }
        ),
        encoding="utf-8",
    )

    assert cmd_setup._hook_runtime_wait_targets(
        ["amp", "claudecode", "codex", "kiro",  "opencode"],
        str(tmp_path),
        "kiro",
    ) == ["amp", "claudecode", "codex", "kiro", "opencode", ]


def test_snapshot_accepts_superset_active_roster(tmp_path: Path) -> None:
    lock = {
        "version": 2,
        "connectors": {
            "amp": _entry("amp", tmp_path),
            "codex": _entry("codex", tmp_path),
            "kiro": {
                "connector": "kiro",
                "raw_agent_version": "kiro-cli 2.27.1",
                "compatibility_status": "not-gated",
                "hook_fail_mode": "open",
            },
        },
    }
    state = {
        "version": 3,
        "names": ["amp", "codex", "kiro"],
        "inactive_names": ["claudecode", "opencode"],
    }
    assert cmd_setup._connector_runtime_snapshot_ready(
        state,
        2,
        lock,
        2,
        expected={"amp", "codex", "kiro"},
        previous_state_marker=1,
        previous_lock_marker=1,
    )
    missing = cmd_setup._connector_runtime_snapshot_failure(
        state,
        2,
        lock,
        2,
        expected={"amp", "claudecode", "codex", "kiro"},
        previous_state_marker=1,
        previous_lock_marker=1,
    )
    assert not missing
    assert (missing.connector, missing.invariant) == ("claudecode", "roster")


def test_kiro_setup_readiness_accepts_installed_native_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = _config(tmp_path)
    hook_path = tmp_path / "kiro-hooks" / "defenseclaw.json"
    hook_path.parent.mkdir(parents=True)
    script = str(tmp_path / "hooks" / "kiro-hook.sh")
    hooks = list(hook_integrity._owned_file_renders(cfg, "kiro", script).values())
    hook_path.write_text(json.dumps({"version": "v1", "hooks": hooks}) + "\n", encoding="utf-8")
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps(
            {
                "version": 2,
                "connectors": {
                    "kiro": {
                        "connector": "kiro",
                        "compatibility_status": "not-gated",
                        "hook_fail_mode": "open",
                        "locations": {"hook_config_paths": [str(hook_path)]},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    _patch_registration_ready(monkeypatch, {"hook_fail_mode": "open"})
    monkeypatch.setattr(
        fail_mode,
        "connector_fail_mode_report",
        lambda *_args, **_kwargs: {"configured": "open", "desired": "open", "effective": "open"},
    )

    readiness = cmd_doctor.connector_setup_readiness(cfg, "kiro")

    assert readiness
    assert (readiness.connector, readiness.invariant) == ("kiro", "ready")


class TestLockContractFailureDetail:
    """An agent that updates past its last reviewed hook contract is not a
    corrupt lock. The gate reported both as "protected lock contract is
    invalid", which sent the operator looking for tampering instead of at the
    version they had just upgraded -- and because the gate covers the whole
    desired roster, the message surfaced while setting up an unrelated
    connector.
    """

    def test_ungated_version_names_the_version_and_the_fix(self) -> None:
        entry = {
            "connector": "devin",
            "raw_agent_version": "devin 3000.0.1 (9c803229faa4)",
            "normalized_agent_version": "3000.0.1",
            "compatibility_status": "unknown",
            "compatibility_reason": "no hook contract matches normalized agent version",
            "hook_fail_mode": "open",
        }
        invariant = connector_lock_contract_invariant("devin", entry)
        assert invariant, "precondition: an ungated version must fail the invariant"
        detail = cmd_setup._lock_contract_failure_detail("devin", entry, invariant)
        assert "covers devin 3000.0.1 (9c803229faa4)," in detail
        assert "defenseclaw guardrail disable --connector devin" in detail
        assert "hook_contracts.json" not in detail and "invalid" not in detail
        # A lock from before untested newer versions were accepted.
        newer = {**entry, "raw_agent_version": "9999.1.1", "normalized_agent_version": "9999.1.1"}
        detail = cmd_setup._lock_contract_failure_detail("devin", newer, invariant)
        assert "predates" in detail and "defenseclaw-gateway restart" in detail

    @pytest.mark.parametrize("removed", ["omni" + "gent", "open" + "hands"])
    def test_removed_connector_in_old_lock_names_cleanup_without_setup_advice(
        self, removed: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert cmd_setup.removed_connectors.is_removed(removed)
        assert cmd_setup.removed_connectors.is_removed("open-hands")
        assert cmd_setup.removed_connectors.is_removed("open_hands")
        assert not cmd_setup.removed_connectors.is_removed("devin")
        entry = {
            "connector": removed,
            "raw_agent_version": "0.10.0",
            "normalized_agent_version": "0.10.0",
            "compatibility_status": "unknown",
            "hook_fail_mode": "closed",
        }
        invariant = connector_lock_contract_invariant(removed, entry)
        assert invariant
        detail = cmd_setup._lock_contract_failure_detail(removed, entry, invariant)
        assert "removed in 1.0.4" in detail
        assert "defenseclaw doctor" in detail
        assert "Install a supported" not in detail
        assert "guardrail disable" not in detail

        lock = tmp_path / "hook_contract_lock.json"
        lock.write_text(json.dumps({"version": 2, "connectors": {removed: entry}}), encoding="utf-8")
        keep, skipped = cmd_setup._partition_unconvergeable_peers(
            str(lock), {"kiro", removed}, required={"kiro"}
        )
        output = capsys.readouterr().out
        assert keep == {"kiro"} and skipped == frozenset({removed})
        assert "removed in 1.0.4" in output
        assert "Re-run setup for" not in output
        assert "guardrail disable" not in output

        lock.write_text(
            json.dumps({"version": 2, "connectors": {removed: entry, "devin": {**entry, "connector": "devin"}}}),
            encoding="utf-8",
        )
        cmd_setup._partition_unconvergeable_peers(
            str(lock), {"kiro", removed, "devin"}, required={"kiro"}
        )
        mixed_output = capsys.readouterr().out
        assert "Re-run setup for devin" in mixed_output
        assert f"Re-run setup for {removed}" not in mixed_output

    def test_refused_retired_peer_never_gets_setup_advice(self, monkeypatch, tmp_path: Path, capsys) -> None:
        cfg = _config(tmp_path)
        (tmp_path / "hook_contract_lock.json").write_text(
            json.dumps({"version": 2, "connectors": {"amp": _entry("amp", tmp_path)}}),
            encoding="utf-8",
        )
        (tmp_path / "active_connector.json").write_text(
            json.dumps({"version": 3, "names": ["amp"], "inactive_names": []}),
            encoding="utf-8",
        )
        monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
        monkeypatch.setattr(
            cmd_doctor,
            "connector_setup_readiness",
            lambda _cfg, name: cmd_doctor.ConnectorSetupReadiness(True, name, "ready"),
        )
        result = cmd_setup._wait_for_connector_runtime(
            str(tmp_path), ["amp", "omnigent"], None, None, timeout=0.5, required={"amp"}
        )
        assert result and result.skipped == frozenset({"omnigent"})
        output = capsys.readouterr().out
        assert "removed in 1.0.4" in output
        assert "defenseclaw doctor" in output
        assert "defenseclaw setup omnigent" not in output

    def test_retired_peer_with_readiness_failure_never_gets_retry_advice(
        self, monkeypatch, tmp_path: Path, capsys
    ) -> None:
        cfg = _config(tmp_path)
        (tmp_path / "hook_contract_lock.json").write_text(
            json.dumps({"version": 2, "connectors": {"amp": _entry("amp", tmp_path), "omnigent": {}}}),
            encoding="utf-8",
        )
        (tmp_path / "active_connector.json").write_text(
            json.dumps({"version": 3, "names": ["amp", "omnigent"], "inactive_names": []}),
            encoding="utf-8",
        )
        monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
        monkeypatch.setattr(
            cmd_setup, "_partition_unconvergeable_peers", lambda _path, expected, **_kwargs: (expected, frozenset())
        )
        monkeypatch.setattr(cmd_setup, "_connector_runtime_snapshot_ready", lambda *_args, **_kwargs: True)

        def readiness(_cfg, name):
            if name == "omnigent":
                return cmd_doctor.ConnectorSetupReadiness(False, name, "version", "install a supported version")
            return cmd_doctor.ConnectorSetupReadiness(True, name, "ready")

        monkeypatch.setattr(cmd_doctor, "connector_setup_readiness", readiness)
        result = cmd_setup._wait_for_connector_runtime(
            str(tmp_path), ["amp", "omnigent"], None, None, timeout=0.5, required={"amp"}
        )
        assert result
        output = capsys.readouterr().out
        assert "removed in 1.0.4" in output
        assert "Re-run setup for omnigent" not in output
        assert "install a supported version" not in output

    def test_unversioned_agent_names_a_missing_install(self) -> None:
        # GAP-1285: OpenCode not installed for the account reports no version.
        entry = {"connector": "opencode", "compatibility_status": "unversioned", "hook_fail_mode": "open"}
        invariant = connector_lock_contract_invariant("opencode", entry)
        if invariant != "version":
            pytest.skip("opencode now has a default contract for an unversioned agent")
        detail = cmd_setup._lock_contract_failure_detail("opencode", entry, invariant)
        assert "installed and on PATH" in detail and "defenseclaw setup opencode" in detail
        assert "invalid" not in detail

    def test_malformed_entry_still_reads_as_invalid(self) -> None:
        # A lock whose recorded connector does not match, or whose fields are
        # nonsense, is a genuine integrity failure and must keep saying so.
        for entry in ({"connector": "cursor"}, {"connector": "devin", "compatibility_status": "bogus"}, None):
            invariant = connector_lock_contract_invariant("devin", entry)
            assert invariant, f"precondition: {entry!r} must fail the invariant"
            detail = cmd_setup._lock_contract_failure_detail("devin", entry, invariant)
            assert detail == f"protected lock {invariant} is invalid"

    def test_supported_version_is_not_reached(self) -> None:
        # Sanity: a connector whose version resolves to a real contract does
        # not fail the invariant at all, so no detail is produced.
        compatibility = resolve_connector_contract("codex", "0.125.0")
        if not (compatibility.contract and compatibility.supported):
            pytest.skip("codex 0.125.0 is no longer covered by a pinned contract")


class TestUnconvergeablePeersAreSkipped:
    """A peer that cannot converge must not block the connector being set up.

    The readiness gate covers the whole desired roster. One agent that has
    moved past its last reviewed hook contract used to fail -- or hang --
    every `defenseclaw setup <other connector>` run, and the non-convergence
    rollback then deleted that other connector's freshly written hook files.
    """

    def _lock(self, tmp_path: Path, entries: dict) -> str:
        path = tmp_path / "hook_contract_lock.json"
        path.write_text(json.dumps({"version": 2, "connectors": entries}), encoding="utf-8")
        return str(path)

    def _ungated_entry(self, connector: str) -> dict:
        return {
            "connector": connector,
            "raw_agent_version": "3000.0.1",
            "normalized_agent_version": "3000.0.1",
            "compatibility_status": "unknown",
            "hook_fail_mode": "open",
        }

    def test_peer_with_no_contract_is_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        lock = self._lock(tmp_path, {"devin": self._ungated_entry("devin")})
        keep, tolerated = cmd_setup._partition_unconvergeable_peers(
            lock, {"kiro", "devin"}, required={"kiro"}
        )
        assert keep == {"kiro"}
        assert tolerated == frozenset({"devin"})
        assert "skipping devin" in capsys.readouterr().out

    def test_removed_peer_is_skipped_without_rerun_advice(self, tmp_path: Path, capsys) -> None:
        lock = self._lock(tmp_path, {"omnigent": self._ungated_entry("omnigent")})
        keep, tolerated = cmd_setup._partition_unconvergeable_peers(
            lock, {"codex", "omnigent"}, required={"codex"}
        )
        output = capsys.readouterr().out
        assert keep == {"codex"} and tolerated == frozenset({"omnigent"})
        # The train words it "was removed in 1.0.4" (w25-retired).
        assert "removed in 1.0.4" in output
        assert "guardrail disable --connector omnigent" not in output
        assert "Re-run setup for omnigent" not in output

    def test_the_setup_target_is_never_skipped(self, tmp_path: Path) -> None:
        # If the connector being configured cannot converge, that is a real
        # failure. Skipping it would report success for an unenforced agent.
        lock = self._lock(tmp_path, {"devin": self._ungated_entry("devin")})
        keep, tolerated = cmd_setup._partition_unconvergeable_peers(
            lock, {"devin"}, required={"devin"}
        )
        assert keep == {"devin"}
        assert tolerated == frozenset()

    def test_unpublished_peer_is_still_waited_for(self, tmp_path: Path) -> None:
        # An absent entry is ordinary startup timing, not a permanent failure.
        lock = self._lock(tmp_path, {})
        keep, tolerated = cmd_setup._partition_unconvergeable_peers(
            lock, {"kiro", "devin"}, required={"kiro"}
        )
        assert keep == {"kiro", "devin"}
        assert tolerated == frozenset()

    def test_unreadable_lock_does_not_tolerate_anything(self, tmp_path: Path) -> None:
        keep, tolerated = cmd_setup._partition_unconvergeable_peers(
            str(tmp_path / "missing.json"), {"kiro", "devin"}, required={"kiro"}
        )
        assert keep == {"kiro", "devin"}
        assert tolerated == frozenset()

    def test_skipped_peer_keeps_its_lock_entry_without_failing_the_gate(self) -> None:
        # The skipped peer's recorded authority is deliberately left in place;
        # the coverage check must not then read it as an unexpected peer.
        kiro = {
            "connector": "kiro",
            "compatibility_status": "not-gated",
            "hook_fail_mode": "open",
        }
        lock = {"version": 2, "connectors": {"kiro": kiro, "devin": self._ungated_entry("devin")}}
        assert cmd_setup._hook_contract_lock_entry_covers("kiro", kiro), "precondition: kiro entry is valid"
        assert not cmd_setup._hook_contract_lock_covers(lock, {"kiro"}, set())
        assert cmd_setup._hook_contract_lock_covers(
            lock, {"kiro"}, set(), frozenset({"devin"})
        )

    def test_departed_peer_left_in_the_lock_is_tolerated_without_remediation(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `guardrail disable --connector devin` drops devin from the roster
        # but its lock entry survives until teardown reclaims it. Without
        # this, disabling the broken connector turned an expected-peer
        # failure into an unexpected-peer failure and still blocked setup.
        lock = self._lock(tmp_path, {"devin": self._ungated_entry("devin")})
        keep, tolerated = cmd_setup._partition_unconvergeable_peers(
            lock, {"kiro"}, required={"kiro"}
        )
        assert keep == {"kiro"}
        assert tolerated == frozenset({"devin"})
        assert "devin" not in capsys.readouterr().out

    def test_retired_connector_lock_does_not_appear_in_hermes_setup(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        retired = "open" + "hands"
        lock = self._lock(tmp_path, {retired: self._ungated_entry(retired)})
        keep, tolerated = cmd_setup._partition_unconvergeable_peers(
            lock, {"hermes"}, required={"hermes"}
        )
        assert keep == {"hermes"}
        assert tolerated == frozenset({retired})
        assert retired not in capsys.readouterr().out


def test_hermes_summary_skips_reload_advice_when_no_host_runs(monkeypatch, capsys) -> None:
    # GAP-1339: with no Hermes host running there is nothing to reload.
    def summary() -> str:
        cmd_setup._print_observability_summary("hermes", None, mode="observe", os_name="posix")
        return capsys.readouterr().out

    monkeypatch.setattr(cmd_doctor, "_hermes_host_running", lambda: False)
    idle = summary()
    assert "unverified; reload/restart required" not in idle
    assert "Reload/restart every running Hermes" not in idle
    assert "the next one starts with the DefenseClaw hooks" in idle

    monkeypatch.setattr(cmd_doctor, "_hermes_host_running", lambda: True)
    running = summary()
    assert "unverified; reload/restart required" in running
    assert "Reload/restart every running Hermes" in running


def _agent_settings_refusal_runtime(monkeypatch, tmp_path: Path) -> str:
    """Codex refused by its own settings, Claude Code running (GAP-0578)."""
    cfg = _config(tmp_path)
    entries = {name: _entry(name, tmp_path) for name in ("claudecode", "codex")}
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": entries}),
        encoding="utf-8",
    )
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["claudecode"], "inactive_names": []}),
        encoding="utf-8",
    )
    reason = (
        "Codex hooks are turned off in /home/u/.codex/config.toml ([features] hooks = false), "
        "so Codex runs no DefenseClaw hook; turn them back on with: codex features enable hooks"
    )
    health = {
        "started_at": "2026-10-22T18:22:00Z",
        "guardrail": {"state": "running", "details": {
            "connectors": ["claudecode"],
            "connectors_not_started": ["codex"],
            "connectors_refused_by_agent_settings": {"codex": reason},
        }},
    }
    monkeypatch.setattr(cmd_setup, "_read_gateway_health", lambda *_args, **_kwargs: health)
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    monkeypatch.setattr(
        cmd_doctor, "connector_setup_readiness", lambda _cfg, name: cmd_doctor.ConnectorSetupReadiness(True, name, "ready")
    )
    return reason


def test_setup_wait_fails_at_once_with_the_agent_settings_reason(monkeypatch, tmp_path: Path) -> None:
    """GAP-0578: `setup codex` with Codex hooks off fails with the fix, not a timeout."""
    reason = _agent_settings_refusal_runtime(monkeypatch, tmp_path)
    started = time.monotonic()
    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["claudecode", "codex"], None, None, timeout=2.0,
        require_gateway_health=True, required={"codex"},
    )
    assert not result
    assert (result.connector, result.invariant, result.detail) == ("codex", "agent-settings", reason)
    assert time.monotonic() - started < 1.5


def test_setup_wait_skips_a_peer_with_the_agent_settings_reason(monkeypatch, tmp_path: Path, capsys) -> None:
    """GAP-0578: `setup claude-code` while Codex hooks are off converges for Claude Code."""
    _agent_settings_refusal_runtime(monkeypatch, tmp_path)
    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["claudecode", "codex"], None, None, timeout=2.0,
        require_gateway_health=True, required={"claudecode"},
    )
    assert result
    assert result.skipped == frozenset({"codex"})
    assert "skipping codex: Codex hooks are turned off" in capsys.readouterr().out


def test_rollback_wait_accepts_a_connector_its_agent_settings_refused(monkeypatch, tmp_path: Path, capsys) -> None:
    """GAP-0578: the rollback restart restores that exact registration, so the
    gateway that runs the other connectors is not reported as down."""
    _agent_settings_refusal_runtime(monkeypatch, tmp_path)
    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["claudecode", "codex"], None, None, timeout=2.0,
        require_gateway_health=True, required={"codex"}, accept_agent_settings_refusals=True,
    )
    assert result
    assert result.skipped == frozenset({"codex"})
    assert "skipping codex: Codex hooks are turned off" in capsys.readouterr().out


def test_only_the_rollback_restart_accepts_agent_settings_refusals(monkeypatch, tmp_path: Path) -> None:
    """GAP-0578: a forward setup still fails for the connector it sets up."""
    seen: list[bool] = []
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(cmd_setup, "_hook_runtime_wait_targets", lambda *_args: ["claudecode", "codex"])
    monkeypatch.setattr(cmd_setup, "_unverified_setup_peers", frozenset)
    monkeypatch.setattr(cmd_setup, "_wait_for_defense_gateway_api", lambda *_args, **_kwargs: True)

    def wait(*_args, **kwargs):
        seen.append(kwargs.get("accept_agent_settings_refusals", False))
        return cmd_setup._ConnectorRuntimeReadiness(True)

    monkeypatch.setattr(cmd_setup, "_wait_for_connector_runtime", wait)
    cmd_setup._restart_services(str(tmp_path), connector="codex", wait_for_connector_ready=True)
    cmd_setup._restart_services(
        str(tmp_path), connector="codex", wait_for_connector_ready=True, title=cmd_setup._ROLLBACK_RESTART_TITLE
    )
    assert seen == [False, True]


def _not_started_runtime(monkeypatch, tmp_path: Path, reason: str) -> None:
    """Codex skipped by the restarted gateway with *reason*, Claude Code running (GAP-0620)."""
    cfg = _config(tmp_path)
    entries = {name: _entry(name, tmp_path) for name in ("claudecode", "codex")}
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": entries}),
        encoding="utf-8",
    )
    (tmp_path / "active_connector.json").write_text(
        json.dumps({"version": 3, "names": ["claudecode"], "inactive_names": []}),
        encoding="utf-8",
    )
    health = {
        "started_at": "2026-10-22T19:52:00Z",
        "guardrail": {"state": "running", "details": {
            "connectors": ["claudecode"],
            "connectors_not_started": ["codex"],
            "connectors_not_started_reasons": {"codex": reason},
        }},
    }
    monkeypatch.setattr(cmd_setup, "_read_gateway_health", lambda *_args, **_kwargs: health)
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    monkeypatch.setattr(
        cmd_doctor, "connector_setup_readiness", lambda _cfg, name: cmd_doctor.ConnectorSetupReadiness(True, name, "ready")
    )


def test_setup_wait_names_why_the_gateway_did_not_start_the_added_connector(monkeypatch, tmp_path: Path) -> None:
    """GAP-0620: `setup codex` (Add) with Codex not on PATH failed with only
    "roster: active=claudecode; expected=claudecode,codex" after the whole wait."""
    reason = (
        "inspect effective Codex managed requirements: exec: \"codex\": executable file not found in $PATH"
    )
    _not_started_runtime(monkeypatch, tmp_path, reason)
    monkeypatch.setattr(cmd_setup.agent_discovery, "_binary_path_for_agent", lambda *_args: "")
    started = time.monotonic()
    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["claudecode", "codex"], None, None, timeout=2.0,
        require_gateway_health=True, required={"codex"},
    )
    assert not result
    assert (result.connector, result.invariant) == ("codex", "not-started")
    assert "Codex (codex) is not on PATH" in result.detail
    assert reason in result.detail
    assert time.monotonic() - started < 1.5


def test_setup_wait_names_a_peer_the_gateway_did_not_start(monkeypatch, tmp_path: Path, capsys) -> None:
    """GAP-0620: a skipped peer is named with the gateway's reason, not only "gateway.log"."""
    _not_started_runtime(monkeypatch, tmp_path, "connector codex agent version \"\" is not verified")
    monkeypatch.setattr(cmd_setup.agent_discovery, "_binary_path_for_agent", lambda *_args: "/usr/bin/codex")
    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["claudecode", "codex"], None, None, timeout=2.0,
        require_gateway_health=True, required={"claudecode"},
    )
    assert result
    out = capsys.readouterr().out
    assert "skipping codex" in out
    assert 'connector codex agent version "" is not verified' in out
    assert "not on PATH" not in out


def test_roster_failure_names_an_agent_that_is_not_on_path(monkeypatch, tmp_path: Path) -> None:
    """GAP-0620: without a gateway reason, the roster mismatch still names the missing agent."""
    monkeypatch.setattr(cmd_setup.agent_discovery, "_binary_path_for_agent", lambda *_args: "")
    failure = cmd_setup._connector_runtime_snapshot_failure(
        {"version": 3, "names": ["claudecode"], "inactive_names": []}, 1, {"connectors": {}}, 1,
        expected={"claudecode", "codex"}, previous_state_marker=None, previous_lock_marker=None,
    )
    assert (failure.connector, failure.invariant) == ("codex", "roster")
    assert failure.detail.startswith("Codex (codex) is not on PATH")
    assert "active=claudecode; expected=claudecode,codex" in failure.detail


def test_setup_wait_names_the_gateway_error_when_the_guardrail_stopped(monkeypatch, tmp_path: Path) -> None:
    """GAP-0620: "restarted gateway guardrail is error" now carries the gateway's error."""
    cfg = _config(tmp_path)
    health = {
        "started_at": "2026-10-22T19:52:00Z",
        "guardrail": {"state": "error", "last_error": "connector codex setup failed: codex not found"},
    }
    monkeypatch.setattr(cmd_setup, "_read_gateway_health", lambda *_args, **_kwargs: health)
    monkeypatch.setattr(cmd_setup, "load_config", lambda **_kwargs: cfg)
    result = cmd_setup._wait_for_connector_runtime(
        str(tmp_path), ["codex"], None, None, timeout=2.0, require_gateway_health=True, required={"codex"},
    )
    assert not result
    assert result.invariant == "gateway-state"
    assert result.detail == "restarted gateway guardrail is error: connector codex setup failed: codex not found"


def _gateway_check_agent_settings(monkeypatch, payload: dict) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(list(argv))
        return SimpleNamespace(returncode=1 if payload.get("refused") else 0, stdout=json.dumps(payload) + "\n",
                               stderr="")

    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr(cmd_setup, "run_pinned_executable", run)
    return calls


def test_setup_refuses_agent_settings_before_it_changes_anything(monkeypatch, tmp_path: Path, capsys) -> None:
    """GAP-0615: `setup codex --restart` with a config.toml that does not parse
    restarted the gateway, which could not start Codex, and the rollback left
    the gateway stopped. Setup now asks the gateway's check first and stops
    before it changes anything or restarts the gateway."""
    reason = (
        "Codex config C:\\Users\\u\\.codex\\config.toml does not parse (toml: line 180 (last key \"t6z2_broken\"): "
        "expected character ]); fix the file, then run: defenseclaw-gateway restart"
    )
    calls = _gateway_check_agent_settings(
        monkeypatch, {"connector": "codex", "action": "check-agent-settings", "refused": True, "reason": reason}
    )
    touched: list[str] = []
    monkeypatch.setattr(
        cmd_setup, "_check_connector_version_supported_for_setup", lambda *_a, **_k: touched.append("version")
    )
    monkeypatch.setattr(cmd_setup, "_capture_setup_config_snapshot", lambda *_a, **_k: touched.append("snapshot"))
    monkeypatch.setattr(cmd_setup, "_restart_services", lambda *_a, **_k: touched.append("restart"))
    app = SimpleNamespace(cfg=_config(tmp_path))
    ok = cmd_setup._apply_hook_connector_setup(app, connector="codex", mode="action", restart=True)
    assert ok is False
    assert touched == []
    assert calls and calls[0][1:5] == ["connector", "check-agent-settings", "--connector", "codex"]
    err = capsys.readouterr().err
    assert "config.toml does not parse" in err
    assert "Setup changed nothing and the gateway keeps running as it was" in err
    assert "defenseclaw-gateway restart" not in err


@pytest.mark.parametrize("connector", ("claudecode", "copilot"))
@pytest.mark.parametrize("requested_scope", ("new", "global"))
def test_setup_prechecks_the_requested_workspace_when_switching_away_from_refusal(
    monkeypatch, tmp_path: Path, connector: str, requested_scope: str,
) -> None:
    old_workspace = tmp_path / "old-workspace"
    new_workspace = tmp_path / "new-workspace"
    old_workspace.mkdir()
    new_workspace.mkdir()
    cfg = _config(tmp_path)
    cfg.claw = SimpleNamespace(workspace_dir=str(old_workspace))
    seen: list[list[str]] = []
    touched: list[str] = []

    def check(argv, **_kwargs):
        seen.append(list(argv))
        scope = argv[argv.index("--workspace-dir") + 1] if "--workspace-dir" in argv else str(old_workspace)
        refused = scope == str(old_workspace)
        payload = {
            "connector": connector, "action": "check-agent-settings", "refused": refused,
            "reason": "old workspace sets disableAllHooks=true" if refused else "",
        }
        return SimpleNamespace(returncode=1 if refused else 0, stdout=json.dumps(payload) + "\n", stderr="")

    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr(cmd_setup, "run_pinned_executable", check)
    monkeypatch.setattr(
        cmd_setup, "_check_connector_version_supported_for_setup",
        lambda *_args, **_kwargs: touched.append("version") or False,
    )
    monkeypatch.setattr(cmd_setup, "_capture_setup_config_snapshot", lambda *_a, **_k: touched.append("snapshot"))
    requested = str(new_workspace) if requested_scope == "new" else None
    assert cmd_setup._apply_hook_connector_setup(
        SimpleNamespace(cfg=cfg), connector=connector, restart=True, workspace_dir=requested,
    ) is False
    assert seen and seen[0][seen[0].index("--workspace-dir") + 1] == (str(new_workspace) if requested else "")
    assert touched == ["version"]
    assert cfg.claw.workspace_dir == str(old_workspace)


def test_setup_codex_precheck_uses_selected_root_before_migrating(monkeypatch, tmp_path: Path) -> None:
    old_root = tmp_path / "old-codex"
    new_root = tmp_path / "new-codex"
    old_root.mkdir()
    new_root.mkdir()
    (old_root / "config.toml").write_text("[features]\nhooks = false\n", encoding="utf-8")
    (new_root / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(new_root))
    monkeypatch.setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", str(old_root))
    cfg = _config(tmp_path)
    touched: list[str] = []
    seen_env: list[dict[str, str]] = []

    def check(_argv, **kwargs):
        env = kwargs["env"]
        seen_env.append(env)
        # The gateway pins an existing registration to the old root unless
        # the explicit setup marker matches the selected CODEX_HOME.
        root = new_root if env.get("DEFENSECLAW_EXPLICIT_CODEX_SETUP") == str(new_root) else old_root
        refused = "hooks = false" in (root / "config.toml").read_text(encoding="utf-8")
        payload = {
            "connector": "codex", "action": "check-agent-settings", "refused": refused,
            "reason": f"Codex config {root / 'config.toml'} turns hooks off" if refused else "",
        }
        return SimpleNamespace(returncode=1 if refused else 0, stdout=json.dumps(payload) + "\n", stderr="")

    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr(cmd_setup, "run_pinned_executable", check)
    monkeypatch.setattr(
        cmd_setup, "_check_connector_version_supported_for_setup",
        lambda *_args, **_kwargs: touched.append("version") or False,
    )
    assert cmd_setup._apply_hook_connector_setup(
        SimpleNamespace(cfg=cfg), connector="codex", restart=True,
    ) is False
    assert seen_env and seen_env[0]["DEFENSECLAW_EXPLICIT_CODEX_SETUP"] == str(new_root)
    assert seen_env[0]["CODEX_HOME"] == str(new_root)
    assert touched == ["version"]


@pytest.mark.parametrize(
    ("connector", "reason", "cause"),
    [
        (
            "claudecode",
            "inspect Claude Code user settings /home/u/.claude/settings.json: settings source is a link "
            "to /private/tmp/x.json, outside your home folder; replace the link",
            "outside your home folder",
        ),
        (
            "claudecode",
            "inspect Claude Code user settings /home/u/.claude/settings.json: settings source is a link "
            "that cannot be followed: no such file or directory",
            "cannot be followed",
        ),
        (
            "codex",
            "Codex config /home/u/.codex/config.toml cannot be read: permission denied; fix the file",
            "permission denied",
        ),
    ],
)
def test_setup_preserves_unreadable_settings_cause_without_restarting(
    monkeypatch, tmp_path: Path, capsys, connector: str, reason: str, cause: str,
) -> None:
    calls = _gateway_check_agent_settings(
        monkeypatch,
        {"connector": connector, "action": "check-agent-settings", "refused": True, "reason": reason},
    )
    touched: list[str] = []
    monkeypatch.setattr(
        cmd_setup, "_check_connector_version_supported_for_setup", lambda *_a, **_k: touched.append("version")
    )
    monkeypatch.setattr(cmd_setup, "_capture_setup_config_snapshot", lambda *_a, **_k: touched.append("snapshot"))
    monkeypatch.setattr(cmd_setup, "_restart_services", lambda *_a, **_k: touched.append("restart"))

    app = SimpleNamespace(cfg=_config(tmp_path))
    assert cmd_setup._apply_hook_connector_setup(app, connector=connector, mode="action", restart=True) is False
    assert touched == []
    assert calls and calls[0][1:5] == ["connector", "check-agent-settings", "--connector", connector]
    message = capsys.readouterr().err
    assert reason in message
    assert cause in message
    assert "Setup changed nothing and the gateway keeps running as it was" in message


def test_setup_continues_when_the_agent_settings_let_hooks_run(monkeypatch, tmp_path: Path) -> None:
    """GAP-0615: usable settings, an older gateway without the check, or a
    connector without such settings change nothing about setup."""
    _gateway_check_agent_settings(monkeypatch, {"connector": "codex", "refused": False})
    assert cmd_setup._agent_settings_refusal(_config(tmp_path), "codex") == ""
    calls = _gateway_check_agent_settings(monkeypatch, {})
    assert cmd_setup._agent_settings_refusal(_config(tmp_path), "codex") == ""
    assert cmd_setup._agent_settings_refusal(_config(tmp_path), "cursor") == ""
    # Every connector is asked: the shared hook config is checked for all (GAP-1325).
    assert len(calls) == 2
    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda: "")
    assert cmd_setup._agent_settings_refusal(_config(tmp_path), "claudecode") == ""


@pytest.mark.parametrize("connector", ("claudecode", "hermes", "cursor", "opencode"))
def test_setup_refuses_a_malformed_shared_hook_sidecar_for_every_connector(
    monkeypatch, tmp_path: Path, connector: str
) -> None:
    """GAP-1325: `setup claude-code --no-restart` saved its change and said it
    succeeded while hooks/.hookcfg was malformed (fail_modes null), which every
    hook of the data directory closes on. The gateway's check now refuses it
    for every connector, and setup stops before it changes anything."""
    reason = (
        f"the shared hook config {tmp_path}/hooks/.hookcfg is malformed (parse hook config sidecar: fail_modes "
        "is not an object), so every DefenseClaw hook of this data directory closes on it; move the file aside "
        "and restart the gateway (defenseclaw-gateway restart), which writes it again from config.yaml"
    )
    calls = _gateway_check_agent_settings(
        monkeypatch, {"connector": connector, "action": "check-agent-settings", "refused": True, "reason": reason}
    )
    assert "is malformed" in cmd_setup._agent_settings_refusal(_config(tmp_path), connector)
    assert calls and calls[0][1:5] == ["connector", "check-agent-settings", "--connector", connector]
