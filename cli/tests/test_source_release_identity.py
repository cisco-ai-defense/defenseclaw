# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import release_candidate, source_release_identity

ROOT = Path(__file__).resolve().parents[2]
VERSION_PATHS = (
    "Makefile",
    "pyproject.toml",
    "uv.lock",
    "cli/defenseclaw/__init__.py",
    "extensions/defenseclaw/package.json",
    "extensions/defenseclaw/package-lock.json",
    "macos/DefenseClawMac/DefenseClawMac.xcodeproj/project.pbxproj",
    "release/source-install-identity.json",
)
SOURCE_FIXTURE_PATHS = VERSION_PATHS + (
    "internal/config/config.go",
    "internal/config/observability_v8_types.go",
    "cli/defenseclaw/install_publish.py",
    "scripts/source-install-publish.py",
    "scripts/source_release_identity.py",
)


def _copy_source_fixture(tmp_path: Path) -> Path:
    repo = tmp_path / "checkout"
    for relative in SOURCE_FIXTURE_PATHS:
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    return repo


def _write_executable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o755)


def _source_install_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    repo = _copy_source_fixture(tmp_path)
    install_dir = tmp_path / "home/.local/bin"
    cli = repo / ".venv/bin/defenseclaw"
    source_gateway = repo / "defenseclaw-gateway"
    installed_gateway = install_dir / "defenseclaw-gateway"
    _write_executable(cli, b"source cli\n")
    install_dir.mkdir(parents=True)
    (install_dir / "defenseclaw").symlink_to(cli)
    _write_executable(source_gateway, b"gateway-v1\n")
    _write_executable(installed_gateway, b"gateway-v1\n")
    return repo, install_dir, source_gateway, installed_gateway


def _preflight(
    tmp_path: Path,
    repo: Path,
    install_dir: Path,
    mode: str,
    *,
    dev_reclaim: bool = False,
) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "HOME": str(tmp_path / "home"),
        "DEFENSECLAW_HOME": str(tmp_path / "home/.defenseclaw"),
        "PATH": "/usr/bin:/bin",
    }
    requested_mode = f"dev-{mode}" if dev_reclaim else mode
    return subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/source-install-preflight.sh"),
            requested_mode,
            str(repo),
            str(install_dir),
            ".venv/bin",
            "defenseclaw",
            "defenseclaw-gateway",
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )


def _marker_payload(repo: Path, gateway: Path) -> dict[str, object]:
    return {
        "schema_version": 2,
        "checkout_root": str(repo.resolve()),
        "source_release": "0.8.5",
        "source_install_compatibility_epoch": 2,
        "runtime_config_version": 8,
        "gateway_sha256": hashlib.sha256(gateway.read_bytes()).hexdigest(),
    }


def test_reviewed_source_identity_binds_every_canonical_version_source() -> None:
    identity = source_release_identity.validate_source_tree(
        ROOT,
        expected_release="0.8.5",
    )

    assert identity == {
        "schema_version": 1,
        "source_release": "0.8.5",
        "source_install_compatibility_epoch": 2,
        "runtime_config_version": 8,
    }
    assert set(source_release_identity.checked_in_version_sources(ROOT).values()) == {"0.8.5"}
    assert source_release_identity.compatibility_config_version(ROOT) == 7
    assert source_release_identity.observability_v8_config_version(ROOT) == 8
    assert source_release_identity.runtime_config_version(ROOT) == 8
    assert release_candidate._reviewed_source_install_identity("0.8.5") == identity


def test_dynamic_release_identity_uses_dispatch_version_with_reviewed_epoch() -> None:
    identity = source_release_identity.release_identity_for_version("9.8.7", ROOT)

    assert identity == {
        "schema_version": 1,
        "source_release": "9.8.7",
        "source_install_compatibility_epoch": 2,
        "runtime_config_version": 8,
    }
    assert release_candidate._reviewed_source_install_identity("9.8.7") == identity


def test_hard_cut_cannot_reuse_bridge_source_identity(tmp_path: Path) -> None:
    repo = _copy_source_fixture(tmp_path)
    identity_path = repo / "release/source-install-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["source_install_compatibility_epoch"] = 1
    identity["runtime_config_version"] = 7
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    with pytest.raises(
        source_release_identity.SourceIdentityError,
        match="release 0.8.5 must use source-install compatibility epoch 2",
    ):
        source_release_identity.validate_source_tree(repo)


def test_release_stamp_is_idempotent_for_checked_in_development_version(tmp_path: Path) -> None:
    repo = _copy_source_fixture(tmp_path)
    stamp = repo / "scripts/stamp-version.sh"
    shutil.copy2(ROOT / "scripts/stamp-version.sh", stamp)
    before = {relative: (repo / relative).read_bytes() for relative in VERSION_PATHS}

    completed = subprocess.run(
        ["/bin/bash", str(stamp), "0.8.5"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert {relative: (repo / relative).read_bytes() for relative in VERSION_PATHS} == before


def test_release_stamp_applies_dynamic_future_version_to_every_release_surface(
    tmp_path: Path,
) -> None:
    repo = _copy_source_fixture(tmp_path)
    stamp = repo / "scripts/stamp-version.sh"
    shutil.copy2(ROOT / "scripts/stamp-version.sh", stamp)

    completed = subprocess.run(
        ["/bin/bash", str(stamp), "9.8.7"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert set(source_release_identity.checked_in_version_sources(repo).values()) == {
        "9.8.7"
    }
    identity = source_release_identity.validate_source_tree(
        repo,
        expected_release="9.8.7",
    )
    assert identity["source_release"] == "9.8.7"


def test_hard_cut_source_cannot_be_restamped_as_the_bridge(tmp_path: Path) -> None:
    repo = _copy_source_fixture(tmp_path)
    stamp = repo / "scripts/stamp-version.sh"
    shutil.copy2(ROOT / "scripts/stamp-version.sh", stamp)

    completed = subprocess.run(
        ["/bin/bash", str(stamp), "0.8.4"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode != 0
    assert "release 0.8.4 must use source-install compatibility epoch 1" in (
        completed.stdout + completed.stderr
    )


@pytest.mark.parametrize(
    ("relative", "old", "new", "message"),
    (
        (
            "internal/config/config.go",
            "const CurrentConfigVersion = 7",
            "const CurrentConfigVersion = 8",
            "compatibility ceiling",
        ),
        (
            "internal/config/observability_v8_types.go",
            "ObservabilityV8ConfigVersion        = 8",
            "ObservabilityV8ConfigVersion        = 9",
            "runtime_config_version does not match gateway source",
        ),
    ),
)
def test_hard_cut_source_identity_rejects_either_config_literal_drifting(
    tmp_path: Path,
    relative: str,
    old: str,
    new: str,
    message: str,
) -> None:
    repo = _copy_source_fixture(tmp_path)
    path = repo / relative
    source = path.read_text(encoding="utf-8")
    assert source.count(old) == 1
    path.write_text(source.replace(old, new), encoding="utf-8")

    with pytest.raises(source_release_identity.SourceIdentityError, match=message):
        source_release_identity.validate_source_tree(repo, expected_release="0.8.5")


def test_release_workflow_stamps_dispatch_version_and_tags_reviewed_commit() -> None:
    workflow = (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")
    tracked = workflow.index("git ls-files --error-unmatch --")
    stamp = workflow.index('scripts/stamp-version.sh "$RELEASE_TAG"', tracked)
    build_stamp = workflow.index('scripts/stamp-version.sh "$RELEASE_TAG"', stamp + 1)
    expected = workflow.index('--expected-release "$RELEASE_TAG"', build_stamp)
    extension_build = workflow.index("run: make extensions", expected)
    restore_generated = workflow.index("git restore --worktree --", extension_build)
    cleanliness_check = workflow.index(
        "git status --porcelain --untracked-files=all", restore_generated
    )
    gateway_build = workflow.index("goreleaser/goreleaser-action@", extension_build)
    package_stamp = workflow.index(
        'scripts/stamp-version.sh "$RELEASE_TAG"', build_stamp + 1
    )
    publish = workflow.index('gh release create "$RELEASE_TAG"')

    assert (
        tracked
        < stamp
        < build_stamp
        < expected
        < extension_build
        < restore_generated
        < cleanliness_check
        < gateway_build
        < package_stamp
        < publish
    )
    for relative in VERSION_PATHS:
        assert relative in workflow[tracked:stamp]
        assert relative in workflow[restore_generated:cleanliness_check]
    assert "Require reviewed source release identity" not in workflow
    assert "git diff --exit-code --" not in workflow[tracked:expected]
    assert '--target "$RELEASE_COMMIT"' in workflow[publish:]
    assert 'test "$remote_commit" = "$RELEASE_COMMIT"' in workflow[publish:]


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_legacy_source_marker_refuses_before_gateway_mutation(tmp_path: Path) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original = installed_gateway.read_bytes()
    source_gateway.write_bytes(b"gateway-v2\n")
    (install_dir / ".defenseclaw-source-root").write_text(
        f"{repo.resolve()}\ngateway_sha256={hashlib.sha256(original).hexdigest()}\n",
        encoding="utf-8",
    )

    completed = _preflight(tmp_path, repo, install_dir, "publish-gateway")

    assert completed.returncode != 0
    assert "legacy source-install marker" in completed.stdout + completed.stderr
    assert "No installed files or services were changed" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_markerless_source_with_managed_state_refuses_before_gateway_mutation(
    tmp_path: Path,
) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original = installed_gateway.read_bytes()
    source_gateway.write_bytes(b"gateway-v2\n")
    (tmp_path / "home/.defenseclaw").mkdir()

    completed = _preflight(tmp_path, repo, install_dir, "publish-gateway")

    assert completed.returncode != 0
    assert "original release identity is unknowable" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_make_all_dev_reclaim_admits_exact_markerless_source_checkout(
    tmp_path: Path,
) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original = installed_gateway.read_bytes()
    source_gateway.write_bytes(b"gateway-v2\n")
    (tmp_path / "home/.defenseclaw").mkdir()

    completed = _preflight(
        tmp_path,
        repo,
        install_dir,
        "check",
        dev_reclaim=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "source install refused" not in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_make_all_dev_reclaim_replaces_prior_release_marker_and_gateway(
    tmp_path: Path,
) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    source_gateway.write_bytes(b"gateway-v2\n")
    prior_marker = _marker_payload(repo, installed_gateway)
    prior_marker.update(
        {
            "source_release": "0.8.4",
            "source_install_compatibility_epoch": 1,
            "runtime_config_version": 7,
        }
    )
    marker = install_dir / ".defenseclaw-source-root"
    marker.write_text(json.dumps(prior_marker, sort_keys=True) + "\n", encoding="utf-8")
    (tmp_path / "home/.defenseclaw").mkdir()

    published = _preflight(
        tmp_path,
        repo,
        install_dir,
        "publish-gateway",
        dev_reclaim=True,
    )
    assert published.returncode == 0, published.stdout + published.stderr
    assert installed_gateway.read_bytes() == b"gateway-v2\n"

    claimed = _preflight(
        tmp_path,
        repo,
        install_dir,
        "claim",
        dev_reclaim=True,
    )
    assert claimed.returncode == 0, claimed.stdout + claimed.stderr
    validated = source_release_identity.validate_marker(
        marker,
        checkout_root=repo,
        source_release="0.8.5",
        compatibility_epoch=2,
        runtime_version=8,
    )
    assert validated[1] == hashlib.sha256(b"gateway-v2\n").hexdigest()


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_make_all_dev_reclaim_rejects_foreign_checkout_marker(
    tmp_path: Path,
) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original_gateway = installed_gateway.read_bytes()
    source_gateway.write_bytes(b"gateway-v2\n")
    foreign_marker = _marker_payload(repo, installed_gateway)
    foreign_marker["checkout_root"] = str(tmp_path / "different-checkout")
    marker = install_dir / ".defenseclaw-source-root"
    marker.write_text(json.dumps(foreign_marker, sort_keys=True) + "\n", encoding="utf-8")
    original_marker = marker.read_bytes()
    (tmp_path / "home/.defenseclaw").mkdir()

    completed = _preflight(
        tmp_path,
        repo,
        install_dir,
        "publish-gateway",
        dev_reclaim=True,
    )

    assert completed.returncode != 0
    assert "belongs to a different checkout" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original_gateway
    assert marker.read_bytes() == original_marker


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_make_all_dev_reclaim_rejects_newer_source_marker(
    tmp_path: Path,
) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original_gateway = installed_gateway.read_bytes()
    source_gateway.write_bytes(b"gateway-v2\n")
    future_marker = _marker_payload(repo, installed_gateway)
    future_marker.update(
        {
            "source_release": "0.8.6",
            "source_install_compatibility_epoch": 3,
            "runtime_config_version": 9,
        }
    )
    marker = install_dir / ".defenseclaw-source-root"
    marker.write_text(json.dumps(future_marker, sort_keys=True) + "\n", encoding="utf-8")
    original_marker = marker.read_bytes()
    (tmp_path / "home/.defenseclaw").mkdir()

    completed = _preflight(
        tmp_path,
        repo,
        install_dir,
        "publish-gateway",
        dev_reclaim=True,
    )

    assert completed.returncode != 0
    assert "newer than this checkout" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original_gateway
    assert marker.read_bytes() == original_marker


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_direct_install_ignores_developer_reclaim_environment_switch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, install_dir, _source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original = installed_gateway.read_bytes()
    (tmp_path / "home/.defenseclaw").mkdir()
    # This deliberately unsupported name must never become part of the public
    # environment-variable registry merely because the negative test exercises
    # it. Construct it at runtime so the static inventory continues to report
    # only variables that production code actually supports.
    unsupported_reclaim_env = "_".join(
        ("DEFENSECLAW", "SOURCE", "DEV", "RECLAIM")
    )
    monkeypatch.setenv(unsupported_reclaim_env, "1")

    completed = _preflight(tmp_path, repo, install_dir, "publish-gateway")

    assert completed.returncode != 0
    assert "original release identity is unknowable" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
@pytest.mark.parametrize(
    ("field", "mismatched"),
    (
        ("source_release", "0.8.4"),
        ("source_install_compatibility_epoch", 1),
        ("source_install_compatibility_epoch", True),
        ("runtime_config_version", 7),
    ),
)
def test_mismatched_source_identity_refuses_before_gateway_mutation(
    tmp_path: Path,
    field: str,
    mismatched: object,
) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original = installed_gateway.read_bytes()
    marker = _marker_payload(repo, installed_gateway)
    marker[field] = mismatched
    (install_dir / ".defenseclaw-source-root").write_text(
        json.dumps(marker, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    source_gateway.write_bytes(b"gateway-v2\n")

    completed = _preflight(tmp_path, repo, install_dir, "publish-gateway")

    assert completed.returncode != 0
    assert "belongs to another release identity" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_same_source_identity_allows_rebuild_and_refreshes_marker(tmp_path: Path) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)

    claimed = _preflight(tmp_path, repo, install_dir, "claim")
    assert claimed.returncode == 0, claimed.stdout + claimed.stderr
    source_gateway.write_bytes(b"gateway-v2\n")
    source_gateway.chmod(0o755)

    published = _preflight(tmp_path, repo, install_dir, "publish-gateway")
    assert published.returncode == 0, published.stdout + published.stderr
    reclaimed = _preflight(tmp_path, repo, install_dir, "claim")
    assert reclaimed.returncode == 0, reclaimed.stdout + reclaimed.stderr

    marker = json.loads((install_dir / ".defenseclaw-source-root").read_text(encoding="utf-8"))
    assert installed_gateway.read_bytes() == b"gateway-v2\n"
    assert marker == _marker_payload(repo, installed_gateway)


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_source_checkout_alias_claims_the_canonical_root(tmp_path: Path) -> None:
    repo, install_dir, _source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    alias = tmp_path / "checkout-alias"
    alias.symlink_to(repo, target_is_directory=True)

    claimed = _preflight(tmp_path, alias, install_dir, "claim")

    assert claimed.returncode == 0, claimed.stdout + claimed.stderr
    marker = json.loads((install_dir / ".defenseclaw-source-root").read_text(encoding="utf-8"))
    assert marker == _marker_payload(repo, installed_gateway)


@pytest.mark.skipif(os.name == "nt", reason="source preflight path resolution uses Bash")
def test_source_preflight_propagates_path_resolution_failures(tmp_path: Path) -> None:
    bash_environment = tmp_path / "bash-environment"
    bash_environment.write_text(
        """pwd() {
    if [[ "${FAIL_PWD_MODE:-}" == "repo-root" && "${1:-}" == "-P" ]]; then
        return 73
    fi
    if [[ "${FAIL_PWD_MODE:-}" == "install-dir" && "$#" -eq 0 ]]; then
        return 74
    fi
    builtin pwd "$@"
}
""",
        encoding="utf-8",
    )

    for failure_mode, install_dir, expected_status in (
        ("repo-root", str(tmp_path / "absolute-bin"), 73),
        ("install-dir", "relative-bin", 74),
    ):
        completed = subprocess.run(
            [
                "/bin/bash",
                str(ROOT / "scripts/source-install-preflight.sh"),
                "check",
                str(ROOT),
                install_dir,
                ".venv/bin",
                "defenseclaw",
                "defenseclaw-gateway",
            ],
            cwd=tmp_path,
            env={
                **os.environ,
                "BASH_ENV": str(bash_environment),
                "FAIL_PWD_MODE": failure_mode,
                "HOME": str(tmp_path / "home"),
                "DEFENSECLAW_HOME": str(tmp_path / "home/.defenseclaw"),
                "PATH": "/usr/bin:/bin",
            },
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )

        output = completed.stdout + completed.stderr
        assert completed.returncode == expected_status, output
        assert "source install refused" not in output


@pytest.mark.skipif(os.name == "nt", reason="path capture uses POSIX Bash test injection")
@pytest.mark.parametrize(
    ("install_dir", "expected"),
    (
        (r"C:\Users\runneradmin\.local\bin", "C:/Users/runneradmin/.local/bin"),
        (r"\\server\share\defenseclaw\bin", "//server/share/defenseclaw/bin"),
        ("/c/Users/runneradmin/.local/bin", "C:/Users/runneradmin/.local/bin"),
    ),
)
def test_windows_source_preflight_preserves_native_absolute_install_paths(
    tmp_path: Path,
    install_dir: str,
    expected: str,
) -> None:
    capture = tmp_path / "install-dir"
    bash_environment = tmp_path / "bash-environment"
    bash_environment.write_text(
        """cygpath() {
    if [[ "$1" == "-aw" && "$2" == "/c/Users/runneradmin/.local/bin" ]]; then
        printf '%s\\n' 'C:\\Users\\runneradmin\\.local\\bin'
        return 0
    fi
    return 96
}
python3() {
    if [[ "$1" == */source_release_identity.py && "$2" == "check" ]]; then
        printf '0.8.5\\t2\\t8\\n'
        return 0
    fi
    if [[ "$1" == */source-install-publish.py && "$2" == "ensure-directory" ]]; then
        printf '%s\\n' "$3" > "${PREFLIGHT_CAPTURE}"
        return 0
    fi
    return 97
}
""",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/source-install-preflight.sh"),
            "ensure-dir",
            str(ROOT),
            install_dir,
            ".venv/bin",
            "defenseclaw.exe",
            "defenseclaw-gateway.exe",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "BASH_ENV": str(bash_environment),
            "DEFENSECLAW_HOME": str(tmp_path / "managed-home"),
            "HOME": str(tmp_path / "home"),
            "OS": "Windows_NT",
            "PATH": "/usr/bin:/bin",
            "PREFLIGHT_CAPTURE": str(capture),
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert capture.read_text(encoding="utf-8").strip() == expected


@pytest.mark.skipif(os.name == "nt", reason="path capture uses POSIX Bash test injection")
def test_windows_source_preflight_refuses_unconvertible_msys_path_before_publication(
    tmp_path: Path,
) -> None:
    mutation = tmp_path / "publication-called"
    bash_environment = tmp_path / "bash-environment"
    bash_environment.write_text(
        """cygpath() {
    return 96
}
python3() {
    printf 'called\\n' > "${PREFLIGHT_MUTATION}"
    return 97
}
""",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/source-install-preflight.sh"),
            "ensure-dir",
            str(ROOT),
            "/c/Users/runneradmin/.local/bin",
            ".venv/bin",
            "defenseclaw.exe",
            "defenseclaw-gateway.exe",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "BASH_ENV": str(bash_environment),
            "HOME": str(tmp_path / "home"),
            "OS": "Windows_NT",
            "PATH": "/usr/bin:/bin",
            "PREFLIGHT_MUTATION": str(mutation),
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "Git Bash could not convert" in output
    assert "No installed files or services were changed" in output
    assert not mutation.exists()


def test_source_preflight_runs_before_dependency_install_or_make_mutations() -> None:
    installer = (ROOT / "scripts/install-dev.sh").read_text(encoding="utf-8")
    main = installer[installer.index("main() {") :]
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert main.index("source_install_ownership check") < main.index("check_os")
    assert main.index("source_install_ownership check") < main.index("setup_python_venv")
    assert "all: _source-install-dev-preflight" in makefile
    assert "$(MAKE) --no-print-directory _source-dev-install" in makefile
    assert "source-install-preflight.sh dev-check" in makefile
    assert "source-install-preflight.sh dev-publish-gateway" in makefile
    assert "source-install-preflight.sh dev-claim" in makefile
    assert "install: _source-install-preflight" in makefile
    cli_start = makefile.index("\ncli-install:") + 1
    gateway_start = makefile.index("\ngateway-install:", cli_start) + 1
    plugin_start = makefile.index("\nplugin-install:", gateway_start) + 1
    cli_install = makefile[cli_start:gateway_start]
    gateway_install = makefile[gateway_start:plugin_start]
    assert cli_install.startswith("cli-install: _source-install-preflight\n")
    assert "$(MAKE) --no-print-directory pycli" in cli_install
    assert gateway_install.startswith("gateway-install: _source-install-preflight cli-install\n")
    assert "$(MAKE) --no-print-directory gateway" in gateway_install
    assert "source-install-preflight.sh claim" in gateway_install
    assert "plugin-install: _source-install-preflight gateway-install" in makefile
    assert "SOURCE_PLUGIN_INSTALL_TARGET = $(if $(filter openclaw,$(CONNECTOR)),plugin-install" in makefile


def test_source_installer_go_floor_matches_go_module() -> None:
    installer = (ROOT / "scripts/install-dev.sh").read_text(encoding="utf-8")
    go_module = (ROOT / "go.mod").read_text(encoding="utf-8")

    module_version = next(line.removeprefix("go ") for line in go_module.splitlines() if line.startswith("go "))
    assert f'readonly MIN_GO_VERSION="{module_version}"' in installer
    for relative in ("README.md", "docs/INSTALL.md", "docs/E2E.md"):
        assert f"{module_version}+" in (ROOT / relative).read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="parallel source install uses POSIX Make")
def test_parallel_make_install_refuses_before_dependency_or_build_commands(
    tmp_path: Path,
) -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable")

    home = tmp_path / "home"
    install_dir = home / ".local/bin"
    release_cli = home / ".defenseclaw/.venv/bin/defenseclaw"
    _write_executable(release_cli, b"release cli\n")
    install_dir.mkdir(parents=True)
    (install_dir / "defenseclaw").symlink_to(release_cli)
    _write_executable(install_dir / "defenseclaw-gateway", b"release gateway\n")

    build_log = tmp_path / "build-called"
    fake_bin = tmp_path / "fake-bin"
    _write_executable(
        fake_bin / "uv",
        b'#!/bin/sh\nprintf "uv\\n" >> "$BUILD_LOG"\nexit 0\n',
    )
    _write_executable(
        fake_bin / "npm",
        b'#!/bin/sh\nprintf "npm\\n" >> "$BUILD_LOG"\nexit 0\n',
    )
    _write_executable(
        fake_bin / "go",
        b"#!/bin/sh\n"
        b'if [ "${1:-}" = "env" ] && [ "${2:-}" = "GOPATH" ]; then\n'
        b"  printf '/tmp\\n'\n"
        b"  exit 0\n"
        b"fi\n"
        b'printf "go-build\\n" >> "$BUILD_LOG"\n'
        b"exit 0\n",
    )
    environment = {
        **os.environ,
        "HOME": str(home),
        "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "BUILD_LOG": str(build_log),
    }

    completed = subprocess.run(
        [
            make,
            "--no-print-directory",
            "-j4",
            "install",
            "CONNECTOR=openclaw",
            f"INSTALL_DIR={install_dir}",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )

    assert completed.returncode != 0
    assert "source install refused" in completed.stdout + completed.stderr
    assert not build_log.exists()
    assert (install_dir / "defenseclaw").readlink() == release_cli
    assert (install_dir / "defenseclaw-gateway").read_bytes() == b"release gateway\n"
