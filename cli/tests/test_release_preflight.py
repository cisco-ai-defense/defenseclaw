# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release-preflight.py"
SPEC = importlib.util.spec_from_file_location("release_preflight", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_preflight)
POSIX_POLICY_PERSISTENCE = pytest.mark.skipif(
    os.name != "posix",
    reason="release baseline persistence requires O_NOFOLLOW descriptor custody",
)


def _baseline_policy() -> dict[str, object]:
    versions = [
        "0.8.7",
        "0.8.6",
        "0.8.5",
        "0.8.4",
        "0.7.2",
        "0.6.6",
        "0.5.0",
    ]
    return {
        "schema_version": 2,
        "published_baselines": versions,
        "published_baseline_config_versions": {
            version: 8 if tuple(int(part) for part in version.split(".")) >= (0, 8, 5) else 7 for version in versions
        },
        "platform_published_baselines": {"windows": ["0.8.7"]},
    }


def test_release_and_repair_requests_bind_to_reviewed_main_without_human_attestations() -> None:
    commit = "a" * 40
    assert (
        release_preflight.validate_request(
            operation="release",
            version="0.8.8",
            repository="cisco-ai-defense/defenseclaw",
            ref="refs/heads/main",
            commit=commit,
        )
        is None
    )
    assert (
        release_preflight.validate_request(
            operation="repair-channel",
            version="0.8.8",
            repository="cisco-ai-defense/defenseclaw",
            ref="refs/heads/main",
            commit=commit,
        )
        is None
    )

    invalid = (
        {"operation": "certify"},
        {"version": "v0.8.8"},
        {"repository": "attacker/defenseclaw"},
        {"ref": "refs/heads/feature"},
        {"commit": "A" * 40},
    )
    base = {
        "operation": "release",
        "version": "0.8.8",
        "repository": "cisco-ai-defense/defenseclaw",
        "ref": "refs/heads/main",
        "commit": commit,
    }
    for changes in invalid:
        with pytest.raises(release_preflight.ReleasePreflightError):
            release_preflight.validate_request(**{**base, **changes})


@POSIX_POLICY_PERSISTENCE
def test_target_newer_than_087_selects_seven_authenticated_posix_lanes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(_baseline_policy()), encoding="utf-8")
    path.chmod(0o600)

    selected = release_preflight.select_upgrade_baselines(
        policy_path=path,
        target="0.8.8",
    )

    assert selected == [
        "0.8.7",
        "0.8.6",
        "0.8.5",
        "0.8.4",
        "0.7.2",
        "0.6.6",
        "0.5.0",
    ]
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["platform_published_baselines"]["windows"] == []
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@POSIX_POLICY_PERSISTENCE
def test_baseline_policy_persistence_rejects_nonexclusive_custody(
    tmp_path: Path,
) -> None:
    original = (json.dumps(_baseline_policy()) + "\n").encode()
    target = tmp_path / "target.json"
    target.write_bytes(original)
    target.chmod(0o600)
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(target)
    hardlink = tmp_path / "hardlink.json"
    os.link(target, hardlink)

    for path in (symlink, hardlink):
        with pytest.raises(
            release_preflight.ReleasePreflightError,
            match="exclusive owner custody",
        ):
            release_preflight.select_upgrade_baselines(
                policy_path=path,
                target="0.8.8",
            )

    assert target.read_bytes() == original


@POSIX_POLICY_PERSISTENCE
def test_baseline_policy_persistence_detects_inode_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "effective.json"
    original = (json.dumps(_baseline_policy()) + "\n").encode()
    path.write_bytes(original)
    path.chmod(0o600)
    preserved = tmp_path / "preserved.json"
    real_open = os.open

    def swapping_open(
        candidate: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
    ) -> int:
        path.rename(preserved)
        path.write_bytes(original)
        path.chmod(0o600)
        return real_open(candidate, flags, mode)

    monkeypatch.setattr(release_preflight.os, "open", swapping_open)

    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match="custody changed while opening",
    ):
        release_preflight.select_upgrade_baselines(
            policy_path=path,
            target="0.8.8",
        )

    assert preserved.read_bytes() == original
    assert path.read_bytes() == original


@POSIX_POLICY_PERSISTENCE
def test_087_historical_shape_collapses_only_the_duplicate_086_lane(
    tmp_path: Path,
) -> None:
    policy = _baseline_policy()
    policy["published_baselines"] = policy["published_baselines"][1:]
    policy["published_baseline_config_versions"].pop("0.8.7")
    policy["platform_published_baselines"]["windows"] = []
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    path.chmod(0o600)

    selected = release_preflight.select_upgrade_baselines(
        policy_path=path,
        target="0.8.7",
    )

    assert selected == [
        "0.8.6",
        "0.8.5",
        "0.8.4",
        "0.7.2",
        "0.6.6",
        "0.5.0",
    ]


def test_future_matrix_fails_closed_when_exact_field_recovery_anchor_is_missing(
    tmp_path: Path,
) -> None:
    policy = _baseline_policy()
    policy["published_baselines"].remove("0.8.6")
    policy["published_baseline_config_versions"].pop("0.8.6")
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match=r"field-recovery baseline 0\.8\.6 is unavailable",
    ):
        release_preflight.select_upgrade_baselines(
            policy_path=path,
            target="0.8.8",
        )


@pytest.mark.parametrize(
    "windows",
    [
        ["0.8.7", "0.8.7"],
        ["0.8.6", "0.8.7"],
        ["0.8.3"],
        [False],
    ],
)
def test_windows_baseline_inventory_has_a_closed_ordered_schema(
    tmp_path: Path,
    windows: list[object],
) -> None:
    policy = _baseline_policy()
    policy["platform_published_baselines"]["windows"] = windows
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match="effective upgrade baseline policy is malformed",
    ):
        release_preflight.select_upgrade_baselines(
            policy_path=path,
            target="0.8.8",
        )


def test_release_after_088_keeps_windows_fresh_install_only(
    tmp_path: Path,
) -> None:
    policy = _baseline_policy()
    policy["published_baselines"].insert(0, "0.8.8")
    policy["published_baseline_config_versions"]["0.8.8"] = 8
    policy["platform_published_baselines"]["windows"] = ["0.8.8"]
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")

    selected = release_preflight.select_upgrade_baselines(
        policy_path=path,
        target="0.8.9",
    )

    assert selected == [
        "0.8.8",
        "0.8.6",
        "0.8.5",
        "0.8.4",
        "0.7.2",
        "0.6.6",
        "0.5.0",
    ]
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["platform_published_baselines"]["windows"] == []


def test_operator_git_state_requires_clean_exact_main() -> None:
    outputs = {
        ("git", "status", "--porcelain=v1", "--untracked-files=all"): "",
        ("git", "symbolic-ref", "--quiet", "--short", "HEAD"): "main\n",
        ("git", "fetch", "--no-tags", "origin", "main"): "",
        ("git", "rev-parse", "HEAD"): ("a" * 40) + "\n",
        ("git", "rev-parse", "origin/main"): ("a" * 40) + "\n",
    }

    def runner(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        key = tuple(command)
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=outputs[key],
            stderr="",
        )

    assert release_preflight._operator_git_state(runner=runner) == ("a" * 40, "main")


def test_release_request_rejects_upgrade_fixture_test_mode() -> None:
    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match="upgrade fixture test mode",
    ):
        release_preflight.validate_request(
            operation="release",
            version="0.8.9",
            repository="cisco-ai-defense/defenseclaw",
            ref="refs/heads/main",
            commit="a" * 40,
            environment={"DEFENSECLAW_UPGRADE_TEST_MODE": "1"},
        )


def test_gh_auth_token_is_forwarded_only_in_the_explicit_child_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for variable in release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT:
        monkeypatch.setenv(variable, f"hostile-{variable.lower()}")
    observed: list[tuple[list[str], dict[str, object]]] = []

    def runner(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.append((command, kwargs))
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="operator-token\n",
            stderr="",
        )

    child_environment = release_preflight._gh_authenticated_environment(runner=runner)

    assert len(observed) == 1
    command, kwargs = observed[0]
    assert command == ["gh", "auth", "token", "--hostname", "github.com"]
    discovery_environment = kwargs["env"]
    assert isinstance(discovery_environment, dict)
    assert release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT.isdisjoint(discovery_environment)
    assert "operator-token" not in discovery_environment.values()
    assert child_environment["GH_TOKEN"] == "operator-token"
    assert (release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT - {"GH_TOKEN"}).isdisjoint(child_environment)


def test_authenticated_github_environment_preserves_proxy_but_removes_trust_overrides() -> None:
    proxy_routing = {
        "http_proxy": "http://attacker.invalid:8080",
        "Https_Proxy": "http://attacker.invalid:8080",
        "aLl_PrOxY": "socks5://attacker.invalid:1080",
        "No_Proxy": "github.com",
    }
    hostile_runtime = {
        "ssl_cert_file": "/attacker/ca.pem",
        "Ssl_Cert_Dir": "/attacker/certs",
        "requests_ca_bundle": "/attacker/requests-ca.pem",
        "Curl_Ca_Bundle": "/attacker/curl-ca.pem",
        "git_ssl_cainfo": "/attacker/git-ca.pem",
        "Git_Ssl_Capath": "/attacker/git-certs",
        "gIt_SsL_nO_vErIfY": "true",
        "PythonPath": "/attacker/python",
        "pYtHoNsTaRtUp": "/attacker/startup.py",
        "gOdEbUg": "x509sha1=1",
        "PerlLib": "/attacker/perl",
        "sslkeylogfile": "/attacker/tls.keys",
        "DyLd_InSeRt_LiBrArIeS": "/attacker/injected.dylib",
        "ld_preload": "/attacker/injected.so",
        "Cosign_Future_Trust_Override": "/attacker/cosign",
        "Sigstore_Future_Trust_Override": "/attacker/sigstore",
        "Tuf_Future_Trust_Override": "/attacker/tuf",
    }
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "UNRELATED_SAFE_ENV": "preserved",
        **proxy_routing,
        **hostile_runtime,
    }

    authenticated = release_preflight._github_com_environment_with_token(
        "operator-token",
        environment=environment,
    )

    assert set(hostile_runtime).isdisjoint(authenticated)
    assert {name: authenticated[name] for name in proxy_routing} == proxy_routing
    assert authenticated["UNRELATED_SAFE_ENV"] == "preserved"
    assert authenticated["GH_TOKEN"] == "operator-token"


def test_operator_preflight_binds_every_github_call_to_authenticated_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40
    expected_baselines = [
        "0.8.7",
        "0.8.6",
        "0.8.5",
        "0.8.4",
        "0.7.2",
        "0.6.6",
        "0.5.0",
    ]
    for variable in release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT:
        monkeypatch.setenv(variable, f"hostile-{variable.lower()}")
    discovery_environment = release_preflight._sanitized_github_cli_environment(os.environ)
    authenticated_environment = {
        **discovery_environment,
        "GH_TOKEN": "operator-token",
    }
    observed: list[tuple[list[str], dict[str, object]]] = []

    def runner(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.append((command, kwargs))
        stdout = "operator-token\n" if command == ["gh", "auth", "token", "--hostname", "github.com"] else ""
        if "resolve_upgrade_baselines.py" in " ".join(command):
            output = Path(command[command.index("--output") + 1])
            output.write_text(json.dumps(_baseline_policy()), encoding="utf-8")
            output.chmod(0o600)
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    class FakeReleaseAPI:
        def __init__(
            self,
            *,
            repository: str,
            runner: release_preflight.Runner,
        ) -> None:
            assert repository == release_preflight.DEFAULT_REPOSITORY
            self.runner = runner

        def release_rows(self) -> list[dict[str, object]]:
            self.runner(["gh", "api", "releases"], env={"GITHUB_TOKEN": "ambient"})
            return []

    def fake_select_upgrade_baselines(*, policy_path: Path, target: str) -> list[str]:
        assert policy_path.name == "effective-upgrade-baselines.json"
        assert policy_path.is_file()
        assert target == "0.8.8"
        return expected_baselines

    monkeypatch.setattr(
        release_preflight,
        "_operator_git_state",
        lambda **_kwargs: (commit, "main"),
    )
    monkeypatch.setattr(release_preflight.release_api_retry, "GitHubReleaseAPI", FakeReleaseAPI)
    monkeypatch.setattr(
        release_preflight.release_api_retry,
        "require_releasable_namespace",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        release_preflight.release_candidate,
        "validate_release_progression",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        release_preflight,
        "select_upgrade_baselines",
        fake_select_upgrade_baselines,
    )

    plan = release_preflight.run_operator_preflight(
        operation="release",
        version="0.8.8",
        runner=runner,
    )

    assert plan["posix_upgrade_baselines"] == expected_baselines
    assert "release_channel_ruleset" not in plan
    assert plan["workflow_commit"] == commit
    assert plan["dispatch_command"].splitlines() == [
        "gh workflow run release.yaml --repo cisco-ai-defense/defenseclaw --ref main \\",
        "  -f operation=release \\",
        "  -f version=0.8.8",
    ]
    assert len(observed) == 3
    discovery_command, discovery_kwargs = observed[0]
    assert discovery_command == ["gh", "auth", "token", "--hostname", "github.com"]
    assert discovery_kwargs["env"] == discovery_environment
    assert any("resolve_upgrade_baselines.py" in " ".join(command) for command, _kwargs in observed)
    for _command, kwargs in observed[1:]:
        assert kwargs["env"] == authenticated_environment
        assert (release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT - {"GH_TOKEN"}).isdisjoint(kwargs["env"])


def test_workflow_request_is_local_validation_without_github_or_ruleset_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40
    observed: list[list[str]] = []

    def subprocess_runner(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(release_preflight.subprocess, "run", subprocess_runner)

    assert (
        release_preflight.main(
            [
                "request",
                "--operation",
                "release",
                "--version",
                "0.8.8",
                "--repository",
                release_preflight.DEFAULT_REPOSITORY,
                "--ref",
                "refs/heads/main",
                "--commit",
                commit,
            ]
        )
        == 0
    )
    assert observed == []


def test_workflow_uses_shared_request_and_baseline_preflight() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "release.yaml"
    workflow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    release_steps = workflow["jobs"]["release-preflight"]["steps"]
    repair_steps = workflow["jobs"]["repair-stable-channel"]["steps"]
    release_request = next(step for step in release_steps if step.get("name") == "Validate release request")
    repair_request = next(step for step in repair_steps if step.get("name") == "Validate repair request")
    baseline = next(
        step for step in release_steps if step.get("name") == "Resolve authenticated POSIX upgrade baselines"
    )

    assert "release-preflight.py request" in release_request["run"]
    assert "--operation release" in release_request["run"]
    assert release_request["env"]["RELEASE_VERSION_INPUT"] == "${{ inputs.version }}"
    assert "EXPECTED_RELEASE_COMMIT" not in release_request["env"]
    assert "--expected-commit" not in release_request["run"]
    assert "release-preflight.py request" in repair_request["run"]
    assert "--operation repair-channel" in repair_request["run"]
    assert repair_request["env"]["RELEASE_VERSION_INPUT"] == "${{ inputs.version }}"
    assert "EXPECTED_RELEASE_COMMIT" not in repair_request["env"]
    assert "IMMUTABLE_RELEASES_CONFIRMED" not in repair_request["env"]
    assert "--expected-commit" not in repair_request["run"]
    assert "--immutable-releases-confirmed" not in repair_request["run"]
    assert "release-preflight.py select-baselines" in baseline["run"]
    assert "required_families = " not in baseline["run"]


def test_dispatch_plan_never_mutates_release_state() -> None:
    release = release_preflight._dispatch_command(
        "release",
        "0.8.8",
        repository="cisco-ai-defense/defenseclaw",
    )
    repair = release_preflight._dispatch_command(
        "repair-channel",
        "0.8.8",
        repository="cisco-ai-defense/defenseclaw",
    )

    assert "gh workflow run release.yaml --repo cisco-ai-defense/defenseclaw --ref main" in release
    assert "-f operation=release" in release
    assert "-f operation=repair-channel" in repair
    assert "expected_commit" not in release + repair
    assert "immutable_releases_confirmed" not in repair
    assert "immutable_releases_confirmed" not in release
    assert "gh release create" not in release + repair
    assert "git tag" not in release + repair
