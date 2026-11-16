# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A 0.8.x per-user Setup install beside this one: verifier order, refusal before any write, advice wording (cowork GAP-0098..0102)."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import bootstrap, config_inspect, gateway, gateway_path  # noqa: E402
from defenseclaw.commands import cmd_setup, cmd_uninstall, legacy_setup_install  # noqa: E402

posix_only = pytest.mark.skipif(os.name == "nt", reason="uses POSIX modes")


# ---- S1: the trusted-verifier fallback order is env, own layout, PATH, canonical


def _verifier_order(env: str, sibling: str | None, which: str | None, canonical: str, ok: set[str]):
    seen: list[str] = []

    def custody(binary: str, *, managed: bool) -> str:
        assert managed is False
        seen.append(binary)
        if binary not in ok:
            raise OSError("refused")
        return binary

    with (
        patch.object(gateway, "packaged_windows_install_root", return_value=None),
        patch.object(gateway, "_launcher_sibling_gateway", return_value=sibling),
        patch.object(gateway.shutil, "which", return_value=which),
        patch.object(gateway, "canonical_install_path", return_value=canonical),
        patch.object(gateway, "_trusted_connected_verifier_binary", side_effect=custody),
        patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_BIN": env}),
    ):
        try:
            return gateway._per_user_connected_verifier(), seen
        except OSError:
            return "", seen


def test_verifier_tries_env_then_own_layout_then_path_then_canonical() -> None:
    # Every candidate is tried, in this order, each through the custody check.
    assert _verifier_order("/env/gw", "/own/gw", "/path/gw", "/canon/gw", ok=set()) == (
        "",
        ["/env/gw", "/own/gw", "/path/gw", "/canon/gw"],
    )
    assert _verifier_order("/env/gw", "/own/gw", "/path/gw", "/canon/gw", ok={"/canon/gw"})[0] == "/canon/gw"


def test_a_sibling_that_fails_custody_still_lets_a_trusted_path_gateway_run() -> None:
    assert _verifier_order("", "/own/gw", "/path/gw", "/canon/gw", ok={"/path/gw", "/canon/gw"}) == (
        "/path/gw",
        ["/own/gw", "/path/gw"],
    )


def test_the_own_layout_wins_over_path_when_it_passes_custody() -> None:
    assert _verifier_order("", "/own/gw", "/path/gw", "/canon/gw", ok={"/own/gw", "/path/gw"}) == (
        "/own/gw",
        ["/own/gw"],
    )


def test_a_repeated_candidate_is_checked_once() -> None:
    assert _verifier_order("/path/gw", "/path/gw", "/path/gw", "/canon/gw", ok={"/path/gw"}) == (
        "/path/gw",
        ["/path/gw"],
    )


# ---- L6: path_gateway honours DEFENSECLAW_GATEWAY_BIN


def test_path_gateway_prefers_the_override_then_the_own_layout_then_path() -> None:
    with (
        patch.object(gateway_path, "_launcher_sibling_gateway", return_value="/own/gw"),
        patch.object(gateway.shutil, "which", return_value="/path/gw"),
    ):
        with patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_BIN": " /env/gw "}):
            assert gateway.path_gateway() == "/env/gw"
            assert gateway.path_gateway(honor_override=False) == "/own/gw"
        with patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_BIN": ""}):
            assert gateway.path_gateway() == "/own/gw"
    with (
        patch.object(gateway_path, "_launcher_sibling_gateway", return_value=None),
        patch.object(gateway.shutil, "which", return_value="/path/gw"),
        patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_BIN": ""}),
    ):
        assert gateway.path_gateway() == "/path/gw"


def test_readiness_names_the_gateway_it_found_not_path() -> None:
    from defenseclaw.config import default_config

    options = bootstrap.FirstRunOptions(connector="none")
    with (
        patch.object(bootstrap, "path_gateway", return_value="/own/bin/defenseclaw-gateway"),
        patch.object(bootstrap, "_scanner_availability", return_value=[]),
    ):
        steps = bootstrap.targeted_readiness(default_config(), options)
    step = next(s for s in steps if s.name == "Gateway binary")
    assert (step.status, step.detail) == ("pass", "found at /own/bin/defenseclaw-gateway")


# ---- S3: Doctor's gateway lifecycle candidate


def _gateway_file(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (gateway.GATEWAY_BIN_NAME + (".exe" if os.name == "nt" else ""))
    path.write_bytes(b"x")
    path.chmod(0o755)
    return path


def test_doctor_runs_the_own_gateway_before_one_on_path(tmp_path: Path) -> None:
    own = _gateway_file(tmp_path / "own")
    other = _gateway_file(tmp_path / "other")
    with (
        patch.object(gateway, "_launcher_sibling_gateway", return_value=str(own)),
        patch.object(gateway, "packaged_windows_install_root", return_value=None),
        patch.dict(os.environ, {"PATH": str(other.parent)}),
    ):
        assert cmd_setup._gateway_lifecycle_candidate() == str(own.resolve())
    with (
        patch.object(gateway, "_launcher_sibling_gateway", return_value=None),
        patch.object(gateway, "packaged_windows_install_root", return_value=None),
        patch.dict(os.environ, {"PATH": str(other.parent)}),
    ):
        assert cmd_setup._gateway_lifecycle_candidate() == str(other.resolve())


def test_doctor_with_an_explicit_search_path_ignores_the_own_layout(tmp_path: Path) -> None:
    own = _gateway_file(tmp_path / "own")
    other = _gateway_file(tmp_path / "other")
    with (
        patch.object(gateway, "_launcher_sibling_gateway", return_value=str(own)) as sibling,
        patch.object(gateway, "packaged_windows_install_root", return_value=None),
    ):
        assert cmd_setup._gateway_lifecycle_candidate(search_path=str(other.parent)) == str(other.resolve())
    sibling.assert_not_called()


def _cwd_first_which(monkeypatch: pytest.MonkeyPatch) -> None:
    """Search the working directory before an explicit path, as Python 3.12 does on Windows."""
    real_which = shutil.which

    def which(cmd, mode=os.F_OK | os.X_OK, path=None):
        if os.path.dirname(cmd):
            return real_which(cmd, mode, path)
        return real_which(cmd, mode, os.pathsep.join([os.curdir, path or ""]))

    monkeypatch.setattr(cmd_setup.shutil, "which", which)


def test_a_gateway_in_the_working_directory_does_not_hide_the_one_on_the_search_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A gateway built into the checkout (the CLI smoke test did) sits in the working
    # directory; the Windows lookup returned it first and the lifecycle then found no gateway.
    stray = _gateway_file(tmp_path / "work")
    wanted = _gateway_file(tmp_path / "wanted")
    monkeypatch.chdir(stray.parent)
    _cwd_first_which(monkeypatch)
    with (
        patch.object(gateway, "_launcher_sibling_gateway", return_value=None),
        patch.object(gateway, "packaged_windows_install_root", return_value=None),
        patch.object(gateway, "canonical_install_path", return_value=str(tmp_path / "absent")),
        patch.dict(os.environ, {"PATH": str(wanted.parent)}),
    ):
        assert cmd_setup._gateway_lifecycle_candidate() == str(wanted.resolve())
        assert cmd_setup._gateway_lifecycle_candidate(search_path=str(wanted.parent)) == str(wanted.resolve())


def test_a_gateway_only_in_the_working_directory_is_still_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stray = _gateway_file(tmp_path / "work")
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(stray.parent)
    _cwd_first_which(monkeypatch)
    with (
        patch.object(gateway, "_launcher_sibling_gateway", return_value=None),
        patch.object(gateway, "packaged_windows_install_root", return_value=None),
        patch.object(gateway, "canonical_install_path", return_value=str(tmp_path / "absent")),
    ):
        assert cmd_setup._gateway_lifecycle_candidate(search_path=str(empty)) is None


@posix_only
def test_doctor_still_applies_custody_to_the_own_gateway(tmp_path: Path) -> None:
    own = _gateway_file(tmp_path / "own")
    own.parent.chmod(0o777)
    try:
        with (
            patch.object(gateway, "_launcher_sibling_gateway", return_value=str(own)),
            patch.object(gateway, "packaged_windows_install_root", return_value=None),
        ):
            executable, reason = cmd_setup._gateway_lifecycle_resolution()
    finally:
        own.parent.chmod(0o755)
    assert executable is None
    assert "refusing to run" in reason and str(own.resolve()) in reason


# ---- S2/L1: init refuses over 0.8.x hooks before it writes, sets aside or starts anything


def _legacy_install(local: Path) -> legacy_setup_install.LegacySetupInstall:
    root = local / "Programs" / "DefenseClaw"
    return legacy_setup_install.LegacySetupInstall(
        root=str(root),
        version="0.8.10",
        data_root=str(local / ".defenseclaw"),
        cache=str(local / "DefenseClaw" / "InstallerCache"),
        hook_state=str(local / "DefenseClaw" / "HookRuntime" / "hook-runtime-state.json"),
    )


def _tree(base: Path) -> dict[str, bytes]:
    return {str(p.relative_to(base)): p.read_bytes() if p.is_file() else b"<dir>" for p in sorted(base.rglob("*"))}


def test_run_first_run_refuses_over_0_8_hooks_before_anything_is_written_or_started(tmp_path: Path) -> None:
    from defenseclaw import managed_leftovers

    from tests.helpers import record_test_setup_agent_selections

    base = Path(os.path.realpath(tmp_path))
    install = _legacy_install(base / "Local")
    data_dir = base / ".defenseclaw"
    data_dir.mkdir()
    # Leftovers of a removed managed install: set_aside_managed_leftovers would move them.
    (data_dir / "hook_contract_lock.json").write_text("{}", encoding="utf-8")
    claims = base / "claims"
    claims.mkdir()
    settings = base / ".claude" / "settings.json"
    settings.parent.mkdir()
    hook = os.path.join(install.root, "bin", "defenseclaw-hook.exe")
    settings.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": f'"{hook}" hook'}]}]}}),
        encoding="utf-8",
    )
    before = _tree(base)
    guards = {
        "set_aside": MagicMock(name="set_aside_managed_leftovers"),
        "snapshot": MagicMock(name="_capture_setup_config_snapshot"),
        "start": MagicMock(name="_start_gateway_structured"),
        "setup": MagicMock(name="_first_run_setup_refusal"),
    }
    with (
        patch.dict(os.environ, {"DEFENSECLAW_HOME": str(data_dir)}),
        patch("defenseclaw.agent_selection.record_setup_agent_selections", side_effect=record_test_setup_agent_selections),
        patch.object(legacy_setup_install, "find", return_value=install),
        patch.object(bootstrap, "connector_config_files", return_value=[str(settings)]),
        patch.object(bootstrap, "_API_PORT_CLAIM_DIR", str(claims)),
        patch.object(managed_leftovers, "set_aside_managed_leftovers", guards["set_aside"]),
        patch.object(cmd_setup, "_capture_setup_config_snapshot", guards["snapshot"]),
        patch.object(bootstrap, "_start_gateway_structured", guards["start"]),
        patch.object(bootstrap, "_first_run_setup_refusal", guards["setup"]),
        patch.object(bootstrap.subprocess, "run") as run,
        patch.object(bootstrap.subprocess, "Popen") as popen,
    ):
        report = bootstrap.run_first_run(
            bootstrap.FirstRunOptions(
                connector="claudecode", profile="observe", skip_install=True, start_gateway=True, verify=False
            )
        )

    assert report.status == "needs_attention"
    step = next(s for s in report.setup if s.name == "Older install")
    assert step.status == "fail" and str(settings) in step.detail and install.root in step.detail
    assert report.next_commands[0] == "defenseclaw uninstall"
    # Nothing was moved aside, snapshotted, started or run, and no file changed.
    for guard in (*guards.values(), popen):
        guard.assert_not_called()
    # Platform probes may run a command; none starts or asks a DefenseClaw program.
    assert not [c for c in run.call_args_list if "defenseclaw" in str(c.args).lower()]
    # The only new entry is the empty init lock sentinel that every first run takes.
    assert _tree(base) == {**before, os.path.join(".defenseclaw", "init.lock"): b""}
    assert not (data_dir / "config.yaml").exists()


# ---- S4: the refusal says what a default uninstall also does


def test_refusal_says_uninstall_also_stops_this_gateway_and_removes_its_hooks(tmp_path: Path) -> None:
    text = legacy_setup_install.hook_refusal(
        _legacy_install(tmp_path), [r"C:\Users\u\.claude\settings.json"], "defenseclaw init"
    )
    assert "No command removes only that install" in text
    assert "stops this release's gateway" in text and "removes the hooks of the connectors it has configured" in text
    assert "then run `defenseclaw init` again" in text


# ---- L2: only a hook command counts


def test_a_mention_outside_the_hook_commands_is_not_a_registration(tmp_path: Path) -> None:
    install = _legacy_install(tmp_path / "Local")
    folder = install.root
    mention = tmp_path / "mention.json"
    mention.write_text(json.dumps({"permissions": {"allow": [f"Read({folder}\\bin\\*)"]}, "hooks": {}}))
    toml_mention = tmp_path / "mention.toml"
    toml_mention.write_text(f'# notes: {folder}\\bin\n[history]\npath = "{folder}"\n', encoding="utf-8")
    toml_hook = tmp_path / "hook.toml"
    toml_hook.write_text(f'[[hooks.PreToolUse.hooks]]\ncommand = "{folder}\\\\bin\\\\defenseclaw-hook.exe"\n')
    cursor = tmp_path / "hooks.json"
    cursor.write_text(json.dumps({"version": 1, "hooks": {"onShell": [{"command": folder + "\\bin\\h.exe"}]}}))
    files = [str(mention), str(toml_mention), str(toml_hook), str(cursor)]
    assert legacy_setup_install.hook_entries(install, files) == [str(toml_hook), str(cursor)]


# ---- S6: a path named by an editable file is named, never advised for deletion


def test_a_folder_named_by_the_install_state_is_not_advised_for_deletion(tmp_path: Path) -> None:
    from tests.test_uninstall_legacy_setup_install import _install

    local = tmp_path.resolve() / "LocalAppData"
    local.mkdir()
    _install(local, install_root="C:\\Other\\Docs\x07\x1b[31m")
    with (
        patch.object(legacy_setup_install, "local_app_data", return_value=str(local)),
        patch.object(legacy_setup_install, "_ownership_problem", return_value=""),
    ):
        found = legacy_setup_install.find("win32")
    assert found is not None
    step = found.problem_step
    assert "C:\\Other\\Docs" in step and "ask an administrator to check that folder" in step
    assert "delete" not in step.lower()
    assert "\x07" not in step and "\x1b" not in step


# ---- L3: the other account is named when Windows can say who it is


def test_the_other_account_is_named_with_its_sid() -> None:
    lookup = "defenseclaw.inventory.claw_inventory._windows_account_name_for_sid"
    with patch(lookup, return_value="NT AUTHORITY\\SYSTEM"):
        assert legacy_setup_install._account_label("S-1-5-18") == "NT AUTHORITY\\SYSTEM, S-1-5-18"
    with patch(lookup, side_effect=OSError("no such account")):
        assert legacy_setup_install._account_label("S-1-5-21-9") == "S-1-5-21-9"
    assert legacy_setup_install._account_label("") == "unknown"


# ---- S7: the older-gateway version check runs the pinned file with a clean environment


def test_older_gateway_version_runs_pinned_without_loader_variables() -> None:
    done = MagicMock(stdout="defenseclaw-gateway version 0.8.10 (abc)")
    env = {"LD_PRELOAD": "/x.so", "DYLD_INSERT_LIBRARIES": "/y.dylib", "PATH": "/bin", "KEEP": "1"}
    with (
        patch.dict(os.environ, env, clear=True),
        patch.object(config_inspect, "run_pinned_executable", return_value=done) as pinned,
        patch.object(config_inspect.subprocess, "run") as plain,
    ):
        note = config_inspect._older_gateway_note("/old/defenseclaw-gateway")
    plain.assert_not_called()
    assert "0.8.10" in note and "/old/defenseclaw-gateway" in note
    assert pinned.call_args.args[0] == ["/old/defenseclaw-gateway", "--version"]
    passed = pinned.call_args.kwargs["env"]
    # The same list the config check strips (loader variables, PATH, interpreter paths).
    assert passed["KEEP"] == "1"
    assert not {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PATH"} & set(passed)


def test_older_gateway_note_is_empty_when_the_file_fails_its_custody_check() -> None:
    from defenseclaw.file_permissions import UnsafePathError

    with patch.object(config_inspect, "run_pinned_executable", side_effect=UnsafePathError("no", code="unsafe")):
        assert config_inspect._older_gateway_note("/old/defenseclaw-gateway") == ""


# ---- L5: the port claim goes after a successful stop, for the stopped ports only


@posix_only
def test_remove_own_claims_limited_to_the_given_ports(tmp_path: Path) -> None:
    for name in (
        "defenseclaw-api-port-18970",
        "defenseclaw-api-port-18980",
        "defenseclaw-guardrail-port-4000",
        "defenseclaw-guardrail-port-4010",
        "unrelated",
    ):
        (tmp_path / name).write_bytes(b"")
    with patch.object(bootstrap, "_API_PORT_CLAIM_DIR", str(tmp_path)):
        bootstrap.remove_own_api_port_claims(frozenset({18970, 4000}))
    assert sorted(os.listdir(tmp_path)) == [
        "defenseclaw-api-port-18980",
        "defenseclaw-guardrail-port-4010",
        "unrelated",
    ]


def _execute(stop) -> MagicMock:
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32",
        data_dir=r"C:\Users\u\.defenseclaw",
        install_root=r"C:\Users\u\.local\bin",
        stop_gateway=True,
    )
    with (
        patch.object(cmd_uninstall, "_validate_plan"),
        patch.object(cmd_uninstall, "_stop_gateway", stop),
        patch.object(cmd_uninstall, "_configured_claim_ports", return_value=frozenset({19000, 4000})),
        patch.object(cmd_uninstall, "_connector_teardown"),
        patch.object(cmd_uninstall, "_turn_guardrail_off"),
        patch.object(cmd_uninstall, "_remove_probe_created_state"),
        patch.object(cmd_uninstall, "_remove_created_dirs"),
        patch.object(cmd_uninstall, "_remove_orphan_copilot_plugin"),
        patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=False),
        patch.object(cmd_uninstall, "_render_execution_result"),
        patch.object(cmd_uninstall, "remove_own_api_port_claims") as claims,
    ):
        try:
            cmd_uninstall._execute_plan(plan)
        except cmd_uninstall.click.ClickException:
            pass  # a stop that failed stops the run
    return claims


def test_a_stopped_gateway_releases_exactly_its_configured_ports() -> None:
    _execute(MagicMock(return_value=True)).assert_called_once_with(frozenset({19000, 4000}))


def test_nothing_to_stop_or_a_failed_stop_keeps_the_claims() -> None:
    assert _execute(MagicMock(return_value=False)).call_count == 0
    failing = MagicMock(side_effect=cmd_uninstall.click.ClickException("could not stop sidecar: busy"))
    assert _execute(failing).call_count == 0
