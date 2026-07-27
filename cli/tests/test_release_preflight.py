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


def _policy() -> dict[str, object]:
    return {
        "schema_version": 2,
        "source_type": "Organization",
        "source": "cisco-ai-defense",
        "target": "branch",
        "target_ref": "refs/heads/release-channel",
        "repository_condition": {
            "include": ["defenseclaw"],
            "exclude": [],
            "protected": True,
        },
        "required_rules": [
            "creation",
            "update",
            "deletion",
            "non_fast_forward",
        ],
        "publisher_bypass": {
            "actor_type": "Integration",
            "actor_id": 15368,
            "bypass_mode": "always",
        },
    }


def _ruleset(
    *,
    identifier: int = 42,
    include: list[str] | None = None,
    rules: list[str] | None = None,
    bypass: bool = True,
) -> dict[str, object]:
    return {
        "id": identifier,
        "name": "release-channel protection",
        "source_type": "Organization",
        "source": "cisco-ai-defense",
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "repository_name": {
                "include": ["defenseclaw"],
                "exclude": [],
                "protected": True,
            },
            "ref_name": {
                "include": include or ["refs/heads/release-channel"],
                "exclude": [],
            },
        },
        "rules": [
            {"type": item}
            for item in (
                rules
                or [
                    "creation",
                    "update",
                    "deletion",
                    "non_fast_forward",
                ]
            )
        ],
        "bypass_actors": (
            [
                {
                    "actor_type": "Integration",
                    "actor_id": 15368,
                    "bypass_mode": "always",
                }
            ]
            if bypass
            else []
        ),
    }


def _effective_rules(
    *,
    identifier: int = 42,
    rules: list[str] | None = None,
) -> list[dict[str, object]]:
    return [
        {"type": item, "ruleset_id": identifier}
        for item in (
            rules
            or [
                "creation",
                "update",
                "deletion",
                "non_fast_forward",
            ]
        )
    ]


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


def test_live_ruleset_contract_is_closed_and_accepts_exact_protection() -> None:
    policy = release_preflight.load_ruleset_policy()
    assert policy == _policy()
    assert release_preflight.validate_release_channel_rulesets(
        [_ruleset()],
        effective_rules=_effective_rules(),
        policy=policy,
    ) == (42, "release-channel protection")


@pytest.mark.parametrize(
    "ruleset",
    [
        _ruleset(include=["refs/heads/*"]),
        _ruleset(rules=["creation", "deletion", "non_fast_forward"]),
        _ruleset(bypass=False),
        {**_ruleset(), "enforcement": "evaluate"},
    ],
)
def test_live_ruleset_contract_rejects_broad_or_incomplete_protection(
    ruleset: dict[str, object],
) -> None:
    with pytest.raises(release_preflight.ReleasePreflightError):
        release_preflight.validate_release_channel_rulesets(
            [ruleset],
            effective_rules=_effective_rules(),
            policy=_policy(),
        )


def test_live_ruleset_contract_rejects_ambiguous_duplicate_publishers() -> None:
    with pytest.raises(release_preflight.ReleasePreflightError, match="found 2"):
        release_preflight.validate_release_channel_rulesets(
            [_ruleset(identifier=1), _ruleset(identifier=2)],
            effective_rules=[
                *_effective_rules(identifier=1),
                *_effective_rules(identifier=2),
            ],
            policy=_policy(),
        )


def test_live_ruleset_contract_rejects_extra_rule_or_bypass_actor() -> None:
    extra_rule = _ruleset(
        rules=[
            "creation",
            "update",
            "deletion",
            "non_fast_forward",
            "pull_request",
        ]
    )
    extra_bypass = _ruleset()
    extra_bypass["bypass_actors"].append(
        {
            "actor_type": "RepositoryRole",
            "actor_id": 5,
            "bypass_mode": "always",
        }
    )

    for ruleset in (extra_rule, extra_bypass):
        with pytest.raises(release_preflight.ReleasePreflightError):
            release_preflight.validate_release_channel_rulesets(
                [ruleset],
                effective_rules=_effective_rules(),
                policy=_policy(),
            )


def test_live_ruleset_contract_rejects_overlapping_effective_branch_rules() -> None:
    parent = {
        **_ruleset(identifier=77, include=["refs/heads/*"]),
        "name": "organization branch protection",
    }

    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match="overlapping or incomplete effective branch rules",
    ):
        release_preflight.validate_release_channel_rulesets(
            [_ruleset(), parent],
            effective_rules=[
                *_effective_rules(),
                {"type": "pull_request", "ruleset_id": 77},
            ],
            policy=_policy(),
        )


def test_live_ruleset_contract_rejects_unobserved_effective_ruleset_authority() -> None:
    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match="absent from the observed active branch-ruleset inventory",
    ):
        release_preflight.validate_release_channel_rulesets(
            [_ruleset()],
            effective_rules=[
                *_effective_rules(),
                {"type": "pull_request", "ruleset_id": 77},
            ],
            policy=_policy(),
        )


def test_workflow_ruleset_view_accepts_hidden_bypass_but_operator_does_not() -> None:
    workflow_view = _ruleset()
    workflow_view.pop("bypass_actors")

    assert release_preflight.validate_release_channel_rulesets(
        [workflow_view],
        effective_rules=_effective_rules(),
        policy=_policy(),
        require_publisher_bypass=False,
    ) == (42, "release-channel protection")
    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match="publisher bypass",
    ):
        release_preflight.validate_release_channel_rulesets(
            [workflow_view],
            effective_rules=_effective_rules(),
            policy=_policy(),
        )


def test_release_and_repair_requests_require_their_exact_authority() -> None:
    commit = "a" * 40
    assert release_preflight.validate_request(
        operation="release",
        version="0.8.8",
        repository="cisco-ai-defense/defenseclaw",
        ref="refs/heads/main",
        commit=commit,
        expected_commit=commit,
        immutable_releases_confirmed=True,
        rulesets=[_ruleset()],
        effective_rules=_effective_rules(),
    ) == (42, "release-channel protection")
    assert release_preflight.validate_request(
        operation="repair-channel",
        version="0.8.8",
        repository="cisco-ai-defense/defenseclaw",
        ref="refs/heads/main",
        commit=commit,
        expected_commit=commit,
        immutable_releases_confirmed=False,
        rulesets=[_ruleset()],
        effective_rules=_effective_rules(),
    ) == (42, "release-channel protection")

    invalid = (
        {"operation": "release", "immutable_releases_confirmed": False},
        {"operation": "repair-channel", "immutable_releases_confirmed": True},
        {"version": "v0.8.8"},
        {"repository": "attacker/defenseclaw"},
        {"ref": "refs/heads/feature"},
        {"commit": "A" * 40},
        {"expected_commit": "b" * 40},
    )
    base = {
        "operation": "release",
        "version": "0.8.8",
        "repository": "cisco-ai-defense/defenseclaw",
        "ref": "refs/heads/main",
        "commit": commit,
        "expected_commit": commit,
        "immutable_releases_confirmed": True,
        "rulesets": [_ruleset()],
        "effective_rules": _effective_rules(),
    }
    for changes in invalid:
        with pytest.raises(release_preflight.ReleasePreflightError):
            release_preflight.validate_request(**{**base, **changes})

    workflow_view = _ruleset()
    workflow_view.pop("bypass_actors")
    assert release_preflight.validate_request(
        **{
            **base,
            "rulesets": [workflow_view],
            "require_publisher_bypass": False,
        }
    ) == (42, "release-channel protection")


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


def test_release_after_088_fails_until_windows_upgrade_certification_exists(
    tmp_path: Path,
) -> None:
    policy = _baseline_policy()
    policy["published_baselines"].insert(0, "0.8.8")
    policy["published_baseline_config_versions"]["0.8.8"] = 8
    policy["platform_published_baselines"]["windows"] = ["0.8.8"]
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match=r"native Windows upgrade certification is required after 0\.8\.8",
    ):
        release_preflight.select_upgrade_baselines(
            policy_path=path,
            target="0.8.9",
        )


def test_ruleset_fetch_binds_list_ids_to_complete_detail() -> None:
    responses = [
        subprocess.CompletedProcess(
            args=["gh", "api"],
            returncode=0,
            stdout=json.dumps([{"id": 42}]),
            stderr="",
        ),
        subprocess.CompletedProcess(
            args=["gh", "api"],
            returncode=0,
            stdout=json.dumps(_ruleset()),
            stderr="",
        ),
    ]
    observed: list[list[str]] = []

    def runner(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return responses.pop(0)

    assert release_preflight.fetch_release_channel_rulesets(
        "cisco-ai-defense/defenseclaw",
        runner=runner,
    ) == [_ruleset()]
    assert observed[0][-1].endswith("rulesets?includes_parents=true&per_page=100&page=1")
    assert observed[1][-1].endswith("rulesets/42")
    assert not responses


def test_effective_rules_fetch_is_bound_to_exact_release_channel_branch() -> None:
    observed: list[list[str]] = []

    def runner(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(_effective_rules()),
            stderr="",
        )

    assert (
        release_preflight.fetch_effective_release_channel_rules(
            "cisco-ai-defense/defenseclaw",
            runner=runner,
        )
        == _effective_rules()
    )
    assert observed[0][-1] == ("repos/cisco-ai-defense/defenseclaw/rules/branches/release-channel?per_page=100&page=1")


def test_effective_rules_fetches_every_page_and_refuses_an_unbounded_inventory() -> None:
    first_page = [{"type": "update", "ruleset_id": index + 1} for index in range(100)]
    second_page = [{"type": "creation", "ruleset_id": 101}]
    responses = [first_page, second_page]
    observed: list[list[str]] = []

    def paginated_runner(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    assert (
        len(
            release_preflight.fetch_effective_release_channel_rules(
                "cisco-ai-defense/defenseclaw",
                runner=paginated_runner,
            )
        )
        == 101
    )
    assert observed[0][-1].endswith("per_page=100&page=1")
    assert observed[1][-1].endswith("per_page=100&page=2")
    assert not responses

    unbounded_calls = 0

    def unbounded_runner(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal unbounded_calls
        unbounded_calls += 1
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(first_page),
            stderr="",
        )

    with pytest.raises(
        release_preflight.ReleasePreflightError,
        match="exceeds the 1000-row safety bound",
    ):
        release_preflight.fetch_effective_release_channel_rules(
            "cisco-ai-defense/defenseclaw",
            runner=unbounded_runner,
        )
    assert unbounded_calls == 11


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

    def fake_rulesets(
        _repository: str,
        *,
        runner: release_preflight.Runner,
    ) -> list[dict[str, object]]:
        runner(["gh", "api", "rulesets"], env={"GITHUB_TOKEN": "ambient"})
        return [_ruleset()]

    def fake_effective_rules(
        _repository: str,
        *,
        runner: release_preflight.Runner,
    ) -> list[dict[str, object]]:
        runner(["gh", "api", "effective-rules"])
        return _effective_rules()

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
    monkeypatch.setattr(release_preflight, "fetch_release_channel_rulesets", fake_rulesets)
    monkeypatch.setattr(release_preflight, "fetch_effective_release_channel_rules", fake_effective_rules)
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
        immutable_releases_confirmed=True,
        runner=runner,
    )

    assert plan["posix_upgrade_baselines"] == expected_baselines
    assert len(observed) == 5
    discovery_command, discovery_kwargs = observed[0]
    assert discovery_command == ["gh", "auth", "token", "--hostname", "github.com"]
    assert discovery_kwargs["env"] == discovery_environment
    assert any("resolve_upgrade_baselines.py" in " ".join(command) for command, _kwargs in observed)
    for _command, kwargs in observed[1:]:
        assert kwargs["env"] == authenticated_environment
        assert (release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT - {"GH_TOKEN"}).isdisjoint(kwargs["env"])


def test_workflow_request_uses_explicit_github_com_token_and_sanitized_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40
    for variable in release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT:
        monkeypatch.setenv(variable, f"hostile-{variable.lower()}")
    monkeypatch.setenv("GH_TOKEN", "workflow-token")
    observed: list[dict[str, str]] = []

    def subprocess_runner(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        observed.append(environment)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    def fake_rulesets(
        _repository: str,
        *,
        runner: release_preflight.Runner,
    ) -> list[dict[str, object]]:
        runner(["gh", "api", "rulesets"], env={"GH_HOST": "attacker.invalid"})
        return [_ruleset()]

    def fake_effective_rules(
        _repository: str,
        *,
        runner: release_preflight.Runner,
    ) -> list[dict[str, object]]:
        runner(["gh", "api", "effective-rules"], env={"GH_REPO": "attacker/repository"})
        return _effective_rules()

    monkeypatch.setattr(release_preflight.subprocess, "run", subprocess_runner)
    monkeypatch.setattr(release_preflight, "fetch_release_channel_rulesets", fake_rulesets)
    monkeypatch.setattr(release_preflight, "fetch_effective_release_channel_rules", fake_effective_rules)

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
                "--expected-commit",
                commit,
                "--immutable-releases-confirmed",
                "true",
            ]
        )
        == 0
    )

    assert len(observed) == 2
    for environment in observed:
        assert environment["GH_TOKEN"] == "workflow-token"
        assert (release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT - {"GH_TOKEN"}).isdisjoint(environment)


def test_ruleset_admin_audit_discovers_and_binds_github_com_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for variable in release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT:
        monkeypatch.setenv(variable, f"hostile-{variable.lower()}")
    observed: list[tuple[list[str], dict[str, str]]] = []

    def subprocess_runner(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        observed.append((command, environment))
        stdout = "admin-token\n" if command == ["gh", "auth", "token", "--hostname", "github.com"] else ""
        return subprocess.CompletedProcess(args=command, returncode=0, stdout=stdout, stderr="")

    def fake_rulesets(
        _repository: str,
        *,
        runner: release_preflight.Runner,
    ) -> list[dict[str, object]]:
        runner(["gh", "api", "rulesets"])
        return [_ruleset()]

    def fake_effective_rules(
        _repository: str,
        *,
        runner: release_preflight.Runner,
    ) -> list[dict[str, object]]:
        runner(["gh", "api", "effective-rules"])
        return _effective_rules()

    monkeypatch.setattr(release_preflight.subprocess, "run", subprocess_runner)
    monkeypatch.setattr(release_preflight, "fetch_release_channel_rulesets", fake_rulesets)
    monkeypatch.setattr(release_preflight, "fetch_effective_release_channel_rules", fake_effective_rules)

    assert release_preflight.main(["ruleset-admin-audit"]) == 0
    assert observed[0][0] == ["gh", "auth", "token", "--hostname", "github.com"]
    assert release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT.isdisjoint(observed[0][1])
    assert len(observed) == 3
    for _command, environment in observed[1:]:
        assert environment["GH_TOKEN"] == "admin-token"
        assert (release_preflight.GITHUB_CLI_UNTRUSTED_ENVIRONMENT - {"GH_TOKEN"}).isdisjoint(environment)


def test_workflow_uses_shared_request_and_baseline_preflight() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "release.yaml"
    workflow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    release_steps = workflow["jobs"]["release-preflight"]["steps"]
    repair_steps = workflow["jobs"]["repair-stable-channel"]["steps"]
    release_request = next(
        step for step in release_steps if step.get("name") == "Validate release request and stable-channel protection"
    )
    repair_request = next(
        step for step in repair_steps if step.get("name") == "Validate repair request and stable-channel protection"
    )
    baseline = next(
        step for step in release_steps if step.get("name") == "Resolve authenticated POSIX upgrade baselines"
    )

    assert "release-preflight.py request" in release_request["run"]
    assert "--operation release" in release_request["run"]
    assert release_request["env"]["EXPECTED_RELEASE_COMMIT"] == "${{ inputs.expected_commit }}"
    assert '--expected-commit "$EXPECTED_RELEASE_COMMIT"' in release_request["run"]
    assert "release-preflight.py request" in repair_request["run"]
    assert "--operation repair-channel" in repair_request["run"]
    assert repair_request["env"]["EXPECTED_RELEASE_COMMIT"] == "${{ inputs.expected_commit }}"
    assert '--expected-commit "$EXPECTED_RELEASE_COMMIT"' in repair_request["run"]
    assert repair_request["env"]["IMMUTABLE_RELEASES_CONFIRMED"] == ("${{ inputs.immutable_releases_confirmed }}")
    assert '--immutable-releases-confirmed "$IMMUTABLE_RELEASES_CONFIRMED"' in repair_request["run"]
    assert "release-preflight.py select-baselines" in baseline["run"]
    assert "required_families = " not in baseline["run"]


def test_dispatch_plan_never_mutates_release_state() -> None:
    commit = "a" * 40
    release = release_preflight._dispatch_command(
        "release",
        "0.8.8",
        repository="cisco-ai-defense/defenseclaw",
        expected_commit=commit,
    )
    repair = release_preflight._dispatch_command(
        "repair-channel",
        "0.8.8",
        repository="cisco-ai-defense/defenseclaw",
        expected_commit=commit,
    )

    assert "gh workflow run release.yaml --repo cisco-ai-defense/defenseclaw --ref main" in release
    assert f"-f expected_commit={commit}" in release
    assert f"-f expected_commit={commit}" in repair
    assert "-f operation=release" in release
    assert "-f immutable_releases_confirmed=true" in release
    assert "-f operation=repair-channel" in repair
    assert "immutable_releases_confirmed" not in repair
    assert "gh release create" not in release + repair
    assert "git tag" not in release + repair
