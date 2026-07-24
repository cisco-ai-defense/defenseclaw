# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yaml"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
WINDOWS_CI_WORKFLOW = ROOT / ".github/workflows/windows-native.yml"
MACOS_CI_WORKFLOW = ROOT / ".github/workflows/macos-app.yml"
CERTIFICATION_WORKFLOW = ROOT / ".github/workflows/pre-release-certification.yml"
PROTOCOL_GATE = ROOT / "scripts/test-upgrade-protocol-release.sh"
HISTORICAL_BOOTSTRAP_GATE = ROOT / "scripts/test-historical-bootstrap-dependencies.sh"
RECEIPT_CHECK = ROOT / "scripts/check_upgrade_receipt.py"
MACOS_BUILD = ROOT / "scripts/build-macos-app-release.sh"
POSIX_INSTALLER = ROOT / "scripts/install.sh"
POSIX_FRESH_RELEASE = ROOT / "scripts/test-fresh-install-release.sh"
DIGEST_CAPABLE_UPLOAD_ACTION = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
COSIGN_INSTALLER_ACTION = "sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da"


def _bash_executable() -> str:
    """Select Git Bash on Windows instead of the WSL launcher."""

    if forced_bash := os.environ.get("DEFENSECLAW_TEST_BASH"):
        if Path(forced_bash).is_file():
            return forced_bash
        pytest.fail(f"DEFENSECLAW_TEST_BASH does not name a file: {forced_bash}")

    if os.name != "nt":
        return shutil.which("bash") or "bash"

    candidates: list[Path] = []
    if git := shutil.which("git"):
        candidates.append(Path(git).resolve().parent.parent / "bin" / "bash.exe")
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
        if root := os.environ.get(variable):
            candidates.append(Path(root) / "Git" / "bin" / "bash.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    pytest.skip("Git Bash is required for the POSIX release-workflow contract on Windows")


def _workflow() -> dict[str, object]:
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _ci_workflow() -> dict[str, object]:
    return yaml.load(CI_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _certification_workflow() -> dict[str, object]:
    return yaml.load(CERTIFICATION_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _windows_ci_workflow() -> dict[str, object]:
    return yaml.load(WINDOWS_CI_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_sensitive_plan_installs_cosign_before_historical_authentication() -> None:
    workflow = _ci_workflow()
    steps = workflow["jobs"]["release-validation-plan"]["steps"]
    cosign = next(
        index for index, step in enumerate(steps) if step.get("uses", "").startswith("sigstore/cosign-installer@")
    )
    resolver = next(index for index, step in enumerate(steps) if "resolve_upgrade_baselines.py" in step.get("run", ""))

    assert steps[cosign]["uses"] == ("sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da")
    assert cosign < resolver

    job = workflow["jobs"]["upgrade-smoke"]
    assert job["name"] == "Release Regression (deterministic)"
    rendered = str(job)
    assert "sigstore/cosign-installer" not in rendered
    assert "test_upgrade_smoke_static.py" in rendered
    assert "make upgrade-smoke-matrix" not in rendered
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "release.yaml@refs/heads/main" in workflow_text
    assert "cannot mint" in workflow_text


def test_installed_release_artifacts_mount_the_full_tui() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    smoke = (ROOT / "scripts/test-upgrade-release.sh").read_text(encoding="utf-8")

    for source, marker in (
        (ci, "installed_wheel_tui_mount=ok"),
        (ci, "installed_wheel_tui_origin=venv"),
        (smoke, "installed_target_tui_mount=ok"),
        (smoke, "installed_target_tui_origin=venv"),
    ):
        assert "import defenseclaw.tui.app as tui_app" in source
        assert "TUI imported outside wheel environment" in source
        assert "app.run_test(size=(120, 40))" in source
        assert marker in source
    assert "fresh_080_default_migration=ok" in smoke
    assert "legacy_unconfigured_generic_otlp_placeholder_omitted" in smoke
    assert "load_packaged_v7_compatibility_selection" in smoke
    assert "compatibility_selection=compatibility_selection" in smoke
    assert "post_status_mandatory_sqlite_write=ok" in smoke


def test_ci_wheel_metadata_prevents_floating_nonportable_scanner_resolution() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")

    assert '"litellm": ">=1.84.0,<1.92.0"' in ci
    assert "wheel metadata leaves cisco-ai-mcp-scanner floating" in ci
    assert "#sha256=[0-9a-f]{64}" in ci


def test_ci_executes_phase_separated_resolver_dependencies_before_positive_lanes() -> None:
    jobs = _ci_workflow()["jobs"]
    gate = jobs["historical-resolver-dependencies"]
    rendered = str(gate)
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    executable_gate = HISTORICAL_BOOTSTRAP_GATE.read_text(encoding="utf-8")

    assert gate["needs"] == "release-validation-plan"
    assert "needs.release-validation-plan.outputs.sensitive == 'true'" in gate["if"]
    assert "github.ref == 'refs/heads/main'" in gate["if"]
    assert gate["runs-on"] == "${{ matrix.runner }}"
    assert gate["strategy"] == {
        "fail-fast": "false",
        "matrix": {
            "include": [
                {
                    "runner": "ubuntu-latest",
                    "platform": "linux-amd64",
                    "runner_arch": "X64",
                },
                {
                    "runner": "macos-15",
                    "platform": "darwin-arm64",
                    "runner_arch": "ARM64",
                },
            ]
        },
    }
    assert "scripts/test-historical-bootstrap-dependencies.sh" in rendered
    assert 'test "$RUNNER_ARCH" = "${{ matrix.runner_arch }}"' in rendered
    assert "`uv pip check`" in workflow_text
    assert "release.yaml@refs/heads/main" in workflow_text
    assert "id-token" not in rendered
    assert "cosign" not in rendered
    assert "set -euo pipefail" in executable_gate
    assert "verify_constraint_scope" in executable_gate
    assert 'function("continue_post_hard_cut_upgrade", "validate_tarball_members")' in executable_gate
    assert "source.count(historical_handoff) != 1" in executable_gate
    assert "single authenticated hard-cut handoff" in executable_gate
    assert "handoff_existing_bridge_to_hard_cut" not in executable_gate
    assert "verify_uv_environment_isolation" in executable_gate
    assert "not-an-rfc3339-timestamp" in executable_gate
    assert "env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER" in executable_gate
    assert '--constraints "${CONSTRAINTS_FILE}"' in executable_gate
    assert '"${UV_BIN}" --no-config pip check' in executable_gate
    assert '"cisco-ai-mcp-scanner": "4.7.2"' in executable_gate
    assert '"litellm": "1.83.7"' in executable_gate
    assert executable_gate.count("install_and_check \\\n") == 2

    for name in ("selective-upgrade-smoke", "main-release-smoke"):
        assert "historical-resolver-dependencies" in jobs[name]["needs"]


def _step(job: dict[str, object], name: str) -> dict[str, object]:
    matches = [step for step in job["steps"] if step.get("name") == name]
    assert len(matches) == 1, f"missing unique step: {name}"
    return matches[0]


def test_release_is_one_manual_dispatch_from_reviewed_main() -> None:
    workflow = _workflow()
    triggers = workflow["on"]
    assert set(triggers) == {"workflow_dispatch"}
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"version", "immutable_releases_confirmed"}
    assert inputs["version"]["required"] == "true"
    assert inputs["version"]["type"] == "string"
    assert inputs["immutable_releases_confirmed"]["required"] == "true"
    assert inputs["immutable_releases_confirmed"]["default"] == "false"
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}
    assert workflow["concurrency"] == {
        "group": "release-${{ github.repository }}",
        "cancel-in-progress": "false",
    }

    jobs = workflow["jobs"]
    assert set(jobs) == {
        "release-preflight",
        "build-runtime-candidate",
        "macos-app",
        "windows-installer",
        "assemble-release-candidate",
        "release-smoke",
        "publish-release",
    }
    assert jobs["build-runtime-candidate"]["needs"] == "release-preflight"
    assert jobs["macos-app"]["needs"] == [
        "release-preflight",
        "build-runtime-candidate",
    ]
    assert jobs["windows-installer"]["needs"] == [
        "release-preflight",
        "build-runtime-candidate",
    ]
    assert jobs["assemble-release-candidate"]["needs"] == [
        "release-preflight",
        "build-runtime-candidate",
        "macos-app",
        "windows-installer",
    ]
    assert jobs["release-smoke"]["needs"] == [
        "release-preflight",
        "assemble-release-candidate",
    ]
    assert jobs["publish-release"]["needs"] == [
        "release-preflight",
        "assemble-release-candidate",
        "release-smoke",
    ]
    assert {name: job.get("timeout-minutes") for name, job in jobs.items() if name != "release-smoke"} == {
        "release-preflight": "20",
        "build-runtime-candidate": "45",
        "macos-app": "60",
        "windows-installer": "60",
        "assemble-release-candidate": "30",
        "publish-release": "45",
    }

    text = WORKFLOW.read_text(encoding="utf-8")
    for retired in (
        "lookup-certification:",
        "record-certification:",
        "platform-readiness:",
        "full-certification:",
        "select-candidate:",
        "windows-real-client-certification:",
        "operation=certify",
        "operation=release",
        "candidate_ref",
        "exact-SHA CI",
    ):
        assert retired not in text


def test_release_jobs_pin_the_bundle_verifier_binary() -> None:
    jobs = [*_workflow()["jobs"].values(), *_certification_workflow()["jobs"].values()]
    installers = [
        step
        for job in jobs
        for step in job.get("steps", [])
        if step.get("uses", "").startswith("sigstore/cosign-installer@")
    ]

    assert len(installers) == 6
    assert all(step["uses"] == COSIGN_INSTALLER_ACTION for step in installers)
    assert all(step.get("with") == {"cosign-release": "v2.6.2"} for step in installers)


def test_release_immutability_preflight_uses_operator_confirmation_without_admin_token() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "repos/$GITHUB_REPOSITORY/immutable-releases" not in text
    assert "IMMUTABLE_RELEASES_CONFIRMED" in text
    assert "inputs.immutable_releases_confirmed" in text
    assert "Immutable Releases confirmation required" in text
    assert "scripts/release_api_retry.py prove-published" in text
    helper = (ROOT / "scripts/release_api_retry.py").read_text(encoding="utf-8")
    assert '"isImmutable": payload.get("immutable")' in helper
    assert "verify_published_release" in helper


def test_release_automation_never_publishes_runtime_to_python_package_indexes() -> None:
    surfaces = [
        *sorted((ROOT / ".github/workflows").glob("*.y*ml")),
        ROOT / "Makefile",
        *sorted(
            path for path in (ROOT / "scripts").rglob("*") if path.is_file() and path.suffix in {".py", ".ps1", ".sh"}
        ),
    ]
    automation = "\n".join(path.read_text(encoding="utf-8") for path in surfaces).lower()

    for forbidden in (
        "pypa/gh-action-pypi-publish",
        "twine upload",
        "uv publish",
        "poetry publish",
        "hatch publish",
        "flit publish",
        "pdm publish",
        "pypi_api_token",
    ):
        assert forbidden not in automation

    release = WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/release_candidate.py prepare-runtime" in release
    candidate = (ROOT / "scripts/release_candidate.py").read_text(encoding="utf-8")
    assert 'f"defenseclaw-{version}-2-py3-none-any.dcwheel"' in candidate


def test_release_accepts_dispatch_sha_reachable_from_reviewed_main() -> None:
    preflight = _workflow()["jobs"]["release-preflight"]
    checkout = preflight["steps"][0]
    provenance = _step(preflight, "Verify release commit is reviewed on main")
    rendered = provenance["run"]

    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert provenance["env"]["SELECTED_COMMIT"] == "${{ github.sha }}"
    assert 'GITHUB_REF" != "refs/heads/main' in rendered
    assert 'test "$(git rev-parse HEAD)" = "$COMMIT"' in rendered
    assert "git fetch --no-tags origin main" in rendered
    assert 'git merge-base --is-ancestor "$COMMIT" origin/main' in rendered
    assert "is no longer reachable from reviewed origin/main" in rendered
    assert '"$(git rev-parse origin/main)" != "$COMMIT"' not in rendered

    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    for retired in (
        "required_ci_workflows",
        "CI_WAIT_ATTEMPTS",
        "CI_WAIT_MAX_SECONDS",
        "actions/workflows/ci.yml/runs",
        "actions/workflows/windows-native.yml/runs",
        "actions/workflows/macos-app.yml/runs",
        "certification receipt",
    ):
        assert retired not in workflow_text


def test_release_selects_six_authenticated_posix_upgrade_baselines(
    tmp_path: Path,
) -> None:
    preflight = _workflow()["jobs"]["release-preflight"]
    step = _step(preflight, "Resolve authenticated POSIX upgrade baselines")
    assert "scripts/resolve_upgrade_baselines.py" in step["run"]
    program = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]

    policy = tmp_path / "effective-upgrade-baselines.json"
    policy.write_text(
        json.dumps(
            {
                "published_baselines": [
                    "0.5.0",
                    "0.6.5",
                    "0.7.1",
                    "0.8.6",
                    "0.8.5",
                    "0.8.4",
                    "0.6.6",
                    "0.7.2",
                ],
                "platform_published_baselines": {
                    "windows": ["0.8.6"],
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "github-output"
    completed = subprocess.run(
        [sys.executable, "-", str(policy), "0.8.7", str(output)],
        input=program,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert output.read_text(encoding="utf-8") == (
        'upgrade_baselines=["0.8.6","0.8.5","0.8.4","0.7.2","0.6.6","0.5.0"]\n'
    )
    updated = json.loads(policy.read_text(encoding="utf-8"))
    assert updated["platform_published_baselines"]["windows"] == []


def test_release_target_must_advance_published_stable_state() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "gh api --paginate --slurp" in text
    assert '"repos/$GITHUB_REPOSITORY/releases?per_page=100"' in text
    assert "scripts/release_candidate.py validate-version" in text
    assert "--releases-json published-releases.json" in text


def test_build_once_candidate_is_reused_by_tests_and_publisher() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count("goreleaser/goreleaser-action@") == 1
    assert text.count("make dist-cli") == 1
    assert text.count("make dist-plugin") == 1
    assert text.count("make extensions") == 1
    assert text.count("scripts/release_candidate.py prepare-runtime") == 1
    assert text.count("scripts/release_candidate.py assemble") == 1
    assert text.count("cosign sign-blob") == 1
    assert text.count("scripts/release_candidate.py seal") == 1

    jobs = _workflow()["jobs"]
    build = jobs["build-runtime-candidate"]
    assert build["permissions"] == {"contents": "read"}
    assert "id-token" not in str(build)
    assert "release --clean --skip=sign" in str(build)

    assemble = jobs["assemble-release-candidate"]
    assert assemble["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert assemble["outputs"]["artifact_name"] == ("${{ steps.names.outputs.candidate }}")
    upload = next(step for step in assemble["steps"] if step.get("id") == "upload")
    assert upload["uses"] == DIGEST_CAPABLE_UPLOAD_ACTION
    assert upload["with"]["path"] == "release-candidate/"
    digest_guard = _step(assemble, "Require candidate artifact digest output")
    assert digest_guard["env"]["CANDIDATE_ARTIFACT_DIGEST"] == ("${{ steps.upload.outputs.artifact-digest }}")

    smoke = jobs["release-smoke"]
    assert smoke["uses"] == "./.github/workflows/pre-release-certification.yml"
    assert smoke["with"]["candidate_artifact"] == ("${{ needs.assemble-release-candidate.outputs.artifact_name }}")
    assert smoke["with"]["baselines"] == ("${{ needs.release-preflight.outputs.upgrade_baselines }}")
    publish = jobs["publish-release"]
    candidate_download = next(
        step for step in publish["steps"] if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert candidate_download["with"] == {
        "name": "${{ needs.assemble-release-candidate.outputs.artifact_name }}",
        "path": "release-candidate",
    }
    assert "scripts/release_candidate.py verify" in str(publish)

    smoke_text = CERTIFICATION_WORKFLOW.read_text(encoding="utf-8")
    for rebuilding_command in (
        "goreleaser",
        "make dist-cli",
        "make dist-plugin",
        "build-macos-app-release.sh",
        "build-windows-installer.ps1",
        "release_candidate.py prepare-runtime",
        "release_candidate.py assemble",
    ):
        assert rebuilding_command not in smoke_text


def test_runtime_candidate_keeps_generated_policy_outside_goreleaser_checkout() -> None:
    job = _workflow()["jobs"]["build-runtime-candidate"]
    steps = job["steps"]
    rendered = str(job)

    baseline_download = next(step for step in steps if step.get("uses", "").startswith("actions/download-artifact@"))
    assert baseline_download["with"]["path"] == ("${{ runner.temp }}/effective-baselines")
    baseline_binding = _step(
        job,
        "Bind effective baseline outside the source checkout",
    )
    assert (
        "UPGRADE_BASELINE_POLICY=$RUNNER_TEMP/effective-baselines/effective-upgrade-baselines.json"
    ) in baseline_binding["run"]

    first_stamp = rendered.index('scripts/stamp-version.sh "$RELEASE_TAG"')
    extension_build = rendered.index("make extensions", first_stamp)
    clean_step = _step(job, "Restore a clean source checkout before GoReleaser")
    clean = rendered.index(clean_step["name"])
    goreleaser = rendered.index("goreleaser/goreleaser-action@")
    second_stamp = rendered.index(
        'scripts/stamp-version.sh "$RELEASE_TAG"',
        first_stamp + 1,
    )
    assert first_stamp < extension_build < clean < goreleaser < second_stamp
    assert "git status --porcelain --untracked-files=all" in clean_step["run"]
    assert 'if [[ -n "$dirty" ]]' in clean_step["run"]


def test_release_certificate_is_canonicalized_and_authenticated_before_seal() -> None:
    assemble = _workflow()["jobs"]["assemble-release-candidate"]
    steps = assemble["steps"]
    sign_index, sign_step = next(
        (index, step)
        for index, step in enumerate(steps)
        if step.get("name") == "Sign and authenticate public checksum manifest"
    )
    seal_index, seal_step = next(
        (index, step) for index, step in enumerate(steps) if step.get("name") == "Seal all candidate bytes"
    )
    sign_script = sign_step["run"]
    seal_script = seal_step["run"]

    sign = sign_script.index("cosign sign-blob")
    canonicalize = sign_script.index("scripts/release_candidate.py canonicalize-certificate")
    authenticate = sign_script.index("scripts/verify-sigstore-blob.py")
    assert sign < canonicalize < authenticate
    assert sign_index + 1 == seal_index
    assert "--bundle=release-candidate/dist/checksums.txt.bundle" in sign_script
    assert (
        '--certificate-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yaml@refs/heads/main"'
    ) in sign_script
    assert "--certificate-identity-regexp" not in sign_script
    assert "scripts/release_candidate.py seal" in seal_script
    assert "scripts/release_candidate.py verify" in seal_script


def test_exact_posix_fresh_install_and_twelve_upgrade_cells_gate_publication() -> None:
    workflow = _certification_workflow()
    assert set(workflow["on"]) == {"workflow_call"}
    assert set(workflow["on"]["workflow_call"]["inputs"]) == {
        "candidate_artifact",
        "version",
        "commit",
        "baselines",
    }
    jobs = workflow["jobs"]
    assert set(jobs) == {
        "posix-fresh-install",
        "posix-upgrade",
        "windows-fresh-install",
    }
    assert jobs["posix-fresh-install"]["timeout-minutes"] == "30"
    assert jobs["posix-upgrade"]["timeout-minutes"] == "60"
    assert jobs["windows-fresh-install"]["timeout-minutes"] == "45"

    assert jobs["posix-fresh-install"]["strategy"] == {
        "fail-fast": "false",
        "matrix": {
            "include": [
                {
                    "runner": "ubuntu-latest",
                    "platform": "linux-amd64",
                    "runner_arch": "X64",
                },
                {
                    "runner": "macos-15",
                    "platform": "darwin-arm64",
                    "runner_arch": "ARM64",
                },
            ]
        },
    }
    fresh = str(jobs["posix-fresh-install"])
    assert "inputs.candidate_artifact" in fresh
    assert "scripts/release_candidate.py verify" in fresh
    assert "scripts/verify-sigstore-blob.py" in fresh
    assert "bash scripts/test-fresh-install-release.sh" in fresh

    upgrade_job = jobs["posix-upgrade"]
    assert upgrade_job["strategy"] == {
        "fail-fast": "false",
        "matrix": {
            "baseline": "${{ fromJSON(inputs.baselines) }}",
            "platform": [
                {
                    "runner": "ubuntu-latest",
                    "name": "linux-amd64",
                    "runner_arch": "X64",
                },
                {
                    "runner": "macos-15",
                    "name": "darwin-arm64",
                    "runner_arch": "ARM64",
                },
            ],
        },
    }
    upgrade = str(upgrade_job)
    assert "BASELINE': '${{ matrix.baseline }}" in upgrade
    assert "inputs.candidate_artifact" in upgrade
    assert "scripts/release_candidate.py verify" in upgrade
    assert "scripts/verify-sigstore-blob.py" in upgrade
    assert "bash scripts/test-upgrade-protocol-release.sh" in upgrade
    assert '--from-version "$BASELINE"' in upgrade
    assert "--success-path-only" in upgrade
    assert "--baseline-mode seed" in upgrade
    assert "baseline_dependencies=published" in upgrade
    assert 'if [[ "$BASELINE" == "0.8.4" ]]' in upgrade
    assert "baseline_dependencies=target" in upgrade
    assert '--baseline-dependencies "$baseline_dependencies"' in upgrade

    text = CERTIFICATION_WORKFLOW.read_text(encoding="utf-8")
    for retired in (
        "live-continuity",
        "test-observability-v8-upgrade-continuity.sh",
        "--refusal-contract-only",
        "--start-source-gateway",
        "certification-complete",
    ):
        assert retired not in text


def test_posix_fresh_install_gates_temporary_and_external_cosign_paths() -> None:
    text = POSIX_FRESH_RELEASE.read_text(encoding="utf-8")
    installer = POSIX_INSTALLER.read_text(encoding="utf-8")

    assert 'EXTERNAL_COSIGN="$(command -v cosign)"' in text
    assert 'readonly BOOTSTRAP_PATH="${BOOTSTRAP_HOME}/.local/bin:${BASE_TOOL_PATH}"' in text
    assert 'PATH="${BOOTSTRAP_PATH}" command -v cosign' in text
    assert '$(dirname "$(command -v cosign)")' not in text
    assert "Cosign was not found; authenticating temporary Cosign 2.6.3" in text
    assert 'mktemp -d "${TMPDIR:-/tmp}/defenseclaw-policy.XXXXXX"' in installer
    assert "assert_bootstrap_retired_privately" in text
    assert "EXTERNAL_TOOL_BIN}/cosign" in text
    assert "external Cosign wrapper was not invoked" in text
    assert '$(sha256_file "${EXTERNAL_COSIGN}")' in text


def test_macos_release_accepts_notarized_or_explicitly_unverified_candidate() -> None:
    jobs = _workflow()["jobs"]
    macos = jobs["macos-app"]
    build = _step(macos, "Build, sign, notarize, and package app")
    assert build["env"]["MACOS_REQUIRE_NOTARIZATION"] == "false"
    assert build["env"]["MACOS_GATEWAY_INPUT"] == ("${{ github.workspace }}/macos-runtime/defenseclaw")
    trust = _step(macos, "Accept notarized or explicitly unverified macOS assets")
    assert '"notarized")' in trust["run"]
    assert '"unverified")' in trust["run"]
    assert "macos-arm64-unverified.dmg" in trust["run"]
    assert "macos-arm64-unverified.zip" in trust["run"]
    assert "Unexpected macOS verification status" in trust["run"]
    assert macos["outputs"]["verification_status"] == ("${{ steps.app.outputs.verification_status }}")

    assemble = jobs["assemble-release-candidate"]
    rendered = str(assemble)
    assert "needs.macos-app.outputs.artifact_name" in rendered
    assert "needs.macos-app.outputs.verification_status" in rendered
    fresh_matrix = _certification_workflow()["jobs"]["posix-fresh-install"]["strategy"]["matrix"]["include"]
    assert any(row["platform"] == "darwin-arm64" for row in fresh_matrix)


def test_release_allows_absent_signing_credentials_but_rejects_partial_groups() -> None:
    jobs = _workflow()["jobs"]
    preflight = jobs["release-preflight"]
    assert preflight["environment"] == "release"
    credentials = _step(preflight, "Validate optional platform signing credentials")
    rendered = str(credentials)

    for name in (
        "MACOS_DEVELOPER_ID_P12_BASE64",
        "MACOS_DEVELOPER_ID_P12_PASSWORD",
        "MACOS_NOTARY_KEY_BASE64",
        "MACOS_NOTARY_KEY_ID",
        "MACOS_NOTARY_ISSUER_ID",
        "WINDOWS_SIGNING_CERT_BASE64",
        "WINDOWS_SIGNING_CERT_PASSWORD",
    ):
        assert f"${{{{ secrets.{name} != '' }}}}" in rendered
    assert "APPLE_CREDENTIAL_COUNT" in credentials["run"]
    assert "WINDOWS_CREDENTIAL_COUNT" in credentials["run"]
    assert "Apple signing/notarization credentials are partially configured" in credentials["run"]
    assert "Windows signing credentials are partially configured" in credentials["run"]
    assert "no Apple credentials; macOS assets will be explicitly unverified" in credentials["run"]
    assert "no Windows credentials; Windows Setup will be explicitly unverified" in credentials["run"]
    assert "Release signing credentials unavailable" not in credentials["run"]
    assert jobs["build-runtime-candidate"]["needs"] == "release-preflight"


def test_macos_app_consumes_and_validates_sealed_runtime_gateway() -> None:
    text = MACOS_BUILD.read_text(encoding="utf-8")
    assert 'GATEWAY_INPUT="${MACOS_GATEWAY_INPUT:-}"' in text
    assert "regular non-symlink candidate binary" in text
    assert 'cmp -s "${GATEWAY_INPUT}" "${GATEWAY}"' in text
    assert "Mach-O 64-bit executable arm64" in text
    assert '"${GATEWAY}" --version' in text
    assert "gateway candidate version mismatch" in text


def test_windows_release_accepts_signed_or_explicitly_unverified_setup_and_is_fresh_only() -> None:
    jobs = _workflow()["jobs"]
    windows = jobs["windows-installer"]
    rendered = str(windows)

    assert windows["runs-on"] == "windows-latest"
    assert windows["environment"] == "release"
    assert "WINDOWS_SIGNING_CERT_BASE64" in rendered
    assert "WINDOWS_SIGNING_CERT_PASSWORD" in rendered
    assert "Build native Setup with optional Authenticode" in rendered
    assert "Windows Setup provenance has an inconsistent signing state" in rendered
    assert "publishing an explicitly unverified Windows Setup" in rendered
    assert "invoke-windows-setup-standard-user-ci.ps1" in rendered
    assert "-Mode setup-acceptance" in rendered
    assert "-AllowCurrentUserSetupAcceptance" not in rendered
    windows_contract = (ROOT / "scripts/live-connector-e2e/test-windows.ps1").read_text(encoding="utf-8")
    assert "production release does not depend on provider-backed Windows live radar" in (windows_contract)
    assert "needs\\.windows-installer\\.outputs\\.artifact_id" in windows_contract
    assert "tested Windows artifact bundle directly" in windows_contract

    upload = next(step for step in windows["steps"] if step.get("id") == "windows-installer-artifact")
    expected = (
        "windows-installer-output/DefenseClawSetup-x64.exe\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.sha256\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.provenance.json\n"
        "windows-installer-output/DefenseClawSetup-x64.exe.sbom.json\n"
    )
    assert upload["with"]["path"] == expected

    assemble = jobs["assemble-release-candidate"]
    windows_download = next(
        step for step in assemble["steps"] if step.get("with", {}).get("path") == "candidate-input/windows"
    )
    assert windows_download["with"]["artifact-ids"] == ("${{ needs.windows-installer.outputs.artifact_id }}")
    assert "needs.windows-installer.outputs.artifact_digest" in str(assemble)

    release_text = WORKFLOW.read_text(encoding="utf-8")
    smoke_text = CERTIFICATION_WORKFLOW.read_text(encoding="utf-8")
    assert "--omit-windows-binaries" not in release_text
    assert "DefenseClawSetup-x64.exe.certification.json" not in release_text
    for retired in (
        "windows-upgrade:",
        "test-upgrade-release-windows.ps1",
        "live-connector-e2e",
        "-Operation release-certification",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        assert retired not in smoke_text

    windows_smoke = _certification_workflow()["jobs"]["windows-fresh-install"]
    assert windows_smoke["runs-on"] == "windows-latest"
    assert "scripts/test-fresh-install-release-windows.ps1" in str(windows_smoke)
    assert "-TargetVersion" in str(windows_smoke)
    assert "-SuccessPathOnly" not in str(windows_smoke)


def test_windows_install_ps1_smoke_uses_disposable_native_profile_and_layout() -> None:
    smoke = (ROOT / "scripts/test-fresh-install-release-windows.ps1").read_text(encoding="utf-8")
    disposable = (ROOT / "scripts/invoke-windows-setup-standard-user-ci.ps1").read_text(encoding="utf-8")

    assert "invoke-windows-setup-standard-user-ci.ps1" in smoke
    assert "-Mode bootstrap-acceptance" in smoke
    assert "-ArtifactRoot $ReleaseDir" in smoke
    assert "-TargetVersion $TargetVersion" in smoke
    assert "'bootstrap-acceptance'" in disposable
    assert "test-fresh-install-release-windows.ps1" in disposable
    assert "install.ps1" in disposable
    for asset in (
        "DefenseClawSetup-x64.exe",
        "DefenseClawSetup-x64.exe.provenance.json",
        "upgrade-manifest.json",
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "checksums.txt.bundle",
        "cosign-windows-amd64.exe",
    ):
        assert asset in disposable

    assert "GetFolderPath([Environment+SpecialFolder]::UserProfile)" in smoke
    assert "[Environment+SpecialFolder]::LocalApplicationData" in smoke
    assert "Programs\\DefenseClaw" in smoke
    assert "DefenseClaw\\InstallerCache" in smoke
    assert "Uninstall\\DefenseClaw" in smoke
    assert re.search(r"""['"]-Local['"]""", smoke)
    assert re.search(r"""['"]-Version['"]""", smoke)
    assert re.search(r"""['"]-CosignPath['"]""", smoke)
    assert "Native DefenseClaw Setup completed successfully" in smoke
    assert "Assert-ExactVersion -Executable $launcher" in smoke
    assert "Assert-ExactVersion -Executable $gateway" in smoke
    assert "$first = Invoke-CapturedProcess" in smoke
    assert "$second = Invoke-CapturedProcess" in smoke
    assert "DELETEUSERDATA=1" in smoke
    assert 'GetEnvironmentVariable("Path", "User")' in smoke
    assert "uninstall did not restore the original user PATH exactly" in smoke

    # Environment strings do not change Windows Known Folder resolution. The
    # release regression must never recreate the legacy fake-home test bed that
    # let direct Setup pass while the public bootstrap failed.
    assert "$env:USERPROFILE = $HomeRoot" not in smoke
    assert "$env:DEFENSECLAW_HOME = Join-Path $HomeRoot" not in smoke
    assert '".defenseclaw/.venv/Scripts/defenseclaw.exe"' not in smoke
    assert '".local\\bin\\defenseclaw-gateway.exe"' not in smoke
    assert "Second fresh-installer invocation unexpectedly succeeded" not in smoke


def test_windows_pr_ci_executes_public_bootstrap_against_authenticated_fixture() -> None:
    jobs = _windows_ci_workflow()["jobs"]
    bootstrap = jobs["public-bootstrap-acceptance"]
    rendered = str(bootstrap)

    assert bootstrap["runs-on"] == "windows-latest"
    assert int(bootstrap["timeout-minutes"]) >= 50
    assert bootstrap["permissions"] == {
        "actions": "read",
        "contents": "read",
    }
    assert bootstrap["env"]["BOOTSTRAP_FIXTURE_VERSION"] == "0.8.7"
    assert bootstrap["env"]["BOOTSTRAP_FIXTURE_RUN_ID"] == "30063491006"
    assert bootstrap["env"]["BOOTSTRAP_FIXTURE_ARTIFACT"] == ("release-candidate-30063491006-1")
    assert "sigstore/cosign-installer@" in rendered
    assert "gh release view" in rendered
    assert "gh release download" in rendered
    assert "actions/download-artifact@" in rendered
    assert "checksums.txt.bundle" in rendered
    assert "test-fresh-install-release-windows.ps1" in rendered
    assert "-ReleaseDir $env:DC_BOOTSTRAP_RELEASE_DIR" in rendered
    assert "-TargetVersion $env:BOOTSTRAP_FIXTURE_VERSION" in rendered
    assert "-StateRoot $bootstrapState" in rendered
    assert "-DiagnosticsRoot $env:DC_DIAGNOSTICS" in rendered
    smoke = (ROOT / "scripts/test-fresh-install-release-windows.ps1").read_text(encoding="utf-8")
    assert "-TimeoutSeconds 1800" in smoke

    required = jobs["windows-native-required"]
    assert "public-bootstrap-acceptance" in required["needs"]


def test_posix_installer_cannot_bypass_upgrade_graph_on_existing_install() -> None:
    text = POSIX_INSTALLER.read_text(encoding="utf-8")
    assert "An existing DefenseClaw installation was detected. No changes were made." in text
    assert "release-owned upgrade resolver" in text
    guard = text.index("An existing DefenseClaw installation was detected")
    assert guard < text.index("detect_platform", guard)


def test_publish_uses_all_assets_from_the_exact_tested_candidate() -> None:
    jobs = _workflow()["jobs"]
    publish = jobs["publish-release"]
    assert publish["environment"] == "release"
    assert publish["permissions"] == {"contents": "write"}
    for name, job in jobs.items():
        if name != "publish-release":
            assert job.get("permissions") != {"contents": "write"}

    rendered = str(publish)
    assert "needs.assemble-release-candidate.outputs.artifact_name" in rendered
    assert "scripts/release_candidate.py verify" in rendered
    assert "scripts/release_candidate.py list-assets" in rendered
    assert 'assets+=("release-candidate/dist/$name")' in rendered
    assert "--omit-windows-binaries" not in rendered

    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count("gh release create") == 1
    assert "gh release upload" not in text
    assert "git push" not in text
    assert "push:\n" not in text
    assert "Publish tag and selected sealed assets" in text
    assert "prove-published" in text


def test_release_publish_retries_only_after_absence_and_reconciles_ambiguity() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    publish = _workflow()["jobs"]["publish-release"]
    rendered = "\n".join(step.get("run", "") for step in publish["steps"])
    namespace = _step(publish, "Recheck remote release namespace")
    create = _step(publish, "Publish tag and selected sealed assets")

    assert publish["timeout-minutes"] == "45"
    assert text.count("scripts/release_api_retry.py require-absent") == 1
    assert "scripts/release_api_retry.py reconcile-create" in namespace["run"]
    assert "--candidate-root release-candidate" in namespace["run"]
    assert "--omit-windows-binaries" not in namespace["run"]
    assert "--check-main" not in namespace["run"]
    assert create["if"] == ("steps.release-namespace.outputs.create_required == 'true'")
    assert "for attempt in 1 2 3" in rendered
    assert "timeout --signal=TERM --kill-after=30s 10m" in rendered
    assert rendered.count("scripts/release_api_retry.py reconcile-create") == 2
    assert "--check-main" not in rendered
    assert 'reconcile_status" != "10"' in rendered
    assert "refusing another create" in rendered
    assert "Release API retries exhausted" in rendered
    assert "scripts/release_api_retry.py prove-published" in rendered
    create_index = rendered.index('gh release create "$RELEASE_TAG"')
    precheck_index = rendered.index("scripts/release_api_retry.py reconcile-create")
    reconcile_index = rendered.rindex("scripts/release_api_retry.py reconcile-create")
    prove_index = rendered.index("scripts/release_api_retry.py prove-published")
    assert precheck_index < create_index < reconcile_index < prove_index


def test_every_release_remote_action_is_commit_pinned() -> None:
    for path in (WORKFLOW, CERTIFICATION_WORKFLOW):
        uses = re.findall(
            r"^\s*- uses:\s*([^\s#]+)",
            path.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        assert uses
        for action in uses:
            assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), (path, action)


def test_every_ci_remote_action_is_commit_pinned() -> None:
    uses = re.findall(
        r"^\s*- uses:\s*([^\s#]+)",
        CI_WORKFLOW.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert uses
    for action in uses:
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), action


def test_protocol_gate_proves_both_refusal_paths_and_full_success() -> None:
    text = PROTOCOL_GATE.read_text(encoding="utf-8")
    for contract in (
        "CANDIDATE_MIN_PROTOCOL",
        "CANDIDATE_SCHEMA_VERSION",
        "CANDIDATE_RUNTIME_CONFIG_VERSION",
        "MINIMUM_SOURCE_VERSION",
        "REQUIRED_BRIDGE_VERSION",
        "OBSERVABILITY_V8_HARD_CUT_VERSION",
        "baseline_protocol",
        "baseline_has_schema_gate",
        "run_installed_controller_refusal",
        "for invocation in explicit latest",
        'patch_installed_upgrade_endpoint "${TARGET_VERSION}"',
        'defenseclaw "${command_args[@]}"',
        "run_candidate_updater_refusal",
        "run_candidate_updater_staged_success",
        "run_candidate_updater_direct_success",
        "prepare_required_bridge_assets",
        "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL",
        "UPGRADE_GATE_STOP_MARKER",
        "gateway sentinel PID changed",
        "assert_no_success_receipt",
        'record(openclaw_home, "openclaw")',
        "refusal-must-not-mutate",
        "run_one_upgrade_smoke",
        "manifest_array_contains tested_source_versions",
        "canonical gateway refusal envelope",
        "artifact-envelope",
        'resolver_args+=(--version "${TARGET_VERSION}")',
        'run_candidate_updater_staged_success "${baseline}" explicit',
        "fresh controller → ${OBSERVABILITY_V8_HARD_CUT_VERSION} → ${TARGET_VERSION}",
        "resolver_owned_post_cut_bridge",
        'run_candidate_updater_staged_success "${baseline}"',
        "stage_authenticated_baseline",
        "SUCCESS_PATH_ONLY",
        "REFUSAL_CONTRACT_ONLY",
        "assert_reviewed_resolver_asset_contract",
        "reviewed release-owned resolver assets failed byte-for-byte validation",
        "--refusal-contract-only requires a schema-2 candidate",
        "upgrade_supports_allow_unverified",
        "resolver never receives this flag",
        "Signed resolver success remains mandatory in release.yaml after candidate signing",
        "materialize_baseline_cli_startup_state",
        "PYTHONDONTWRITEBYTECODE=1",
        "interpreter caches are not release or operator state",
        "start_source_gateway_canary",
        "upgrade bridge|without --version",
    ):
        assert contract in text
    sealed_resolver = 'bash "${RELEASE_ROOT}/${TARGET_VERSION}/defenseclaw-upgrade.sh"'
    assert text.count(sealed_resolver) >= 3
    assert 'scripts/upgrade.sh" --yes' not in text
    assert not re.search(r"TARGET_VERSION[^\n]*0\.8\.", text)
    smoke = (ROOT / "scripts/test-upgrade-release.sh").read_text(encoding="utf-8")
    assert "force_latest_version" in smoke
    assert 'target_version = "{force_latest_version}"' in smoke
    assert "scripts/check_upgrade_receipt.py" in smoke
    assert "assert_staged_success_receipt" not in text
    verifier = RECEIPT_CHECK.read_text(encoding="utf-8")
    assert 'facts.get("migration_status") != "completed"' in verifier
    assert "FROM audit_events" in verifier


def test_external_resolver_boundaries_disable_python_bytecode() -> None:
    text = PROTOCOL_GATE.read_text(encoding="utf-8")
    for function_name in (
        "run_candidate_updater_refusal",
        "run_candidate_updater_staged_success",
        "run_candidate_updater_direct_success",
    ):
        match = re.search(
            rf"^{function_name}\(\) \{{\n(?P<body>.*?)^\}}$",
            text,
            re.MULTILINE | re.DOTALL,
        )
        assert match is not None, function_name
        body = match.group("body")
        assert "PYTHONDONTWRITEBYTECODE=1" in body, function_name
        assert 'bash "${RELEASE_ROOT}/${TARGET_VERSION}/defenseclaw-upgrade.sh"' in body


def test_exact_bridge_success_paths_require_authenticated_refresh_evidence() -> None:
    text = PROTOCOL_GATE.read_text(encoding="utf-8")
    staged_start = text.index("run_candidate_updater_staged_success() {")
    staged_end = text.index("\n}\n\nrun_candidate_updater_direct_success() {", staged_start)
    direct_start = staged_end + 3
    direct_end = text.index("\n}\n\nrun_protocol_case() {", direct_start)
    staged = text[staged_start:staged_end]
    direct = text[direct_start:direct_end]
    refresh = (
        "Refresh authenticated ${baseline} bridge → fresh controller → "
        "${OBSERVABILITY_V8_HARD_CUT_VERSION} → ${TARGET_VERSION}"
    )

    assert refresh in staged
    assert refresh in direct
    assert "staged upgrade log did not prove the resolved bridge handoff" in staged
    assert "release-owned resolver log did not prove the authenticated bridge refresh" in direct


def test_posix_refusal_snapshot_preserves_python_bytecode_paths(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        return

    protocol = PROTOCOL_GATE.read_text(encoding="utf-8")
    function_start = protocol.index("snapshot_state() {")
    program_marker = "\"${output}\" <<'PY'\n"
    program_start = protocol.index(program_marker, function_start) + len(program_marker)
    program_end = protocol.index("\nPY\n}", program_start)
    program = protocol[program_start:program_end]

    data_dir = tmp_path / "data"
    openclaw_home = tmp_path / "openclaw"
    package_dir = tmp_path / "package"
    cli_target = tmp_path / "cli-target"
    cli_link = tmp_path / "defenseclaw"
    gateway = tmp_path / "gateway"
    real_gateway = tmp_path / "gateway-real"
    for directory in (
        data_dir / "state",
        data_dir / ".venv" / "lib",
        openclaw_home,
        package_dir / "runtime",
        package_dir / "native",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    cli_target.write_text("cli\n", encoding="utf-8")
    cli_link.symlink_to(cli_target)
    gateway.write_text("gateway\n", encoding="utf-8")
    real_gateway.write_text("real gateway\n", encoding="utf-8")

    real_cache_files = []
    for cache_dir in (
        data_dir / "state" / "__pycache__",
        data_dir / ".venv" / "lib" / "__pycache__",
        openclaw_home / "__pycache__",
        package_dir / "runtime" / "__pycache__",
    ):
        cache_dir.mkdir()
        cache_file = cache_dir / "module.cpython-312.pyc"
        cache_file.write_bytes(b"runtime bytecode")
        real_cache_files.append(cache_file)
    standalone_pyc = package_dir / "module.pyc"
    standalone_pyc.write_bytes(b"standalone bytecode")

    def take_snapshot(output: Path) -> dict[str, object]:
        completed = subprocess.run(
            [
                sys.executable,
                "-",
                str(data_dir),
                str(openclaw_home),
                str(package_dir),
                str(cli_link),
                str(gateway),
                str(real_gateway),
                str(output),
            ],
            input=program,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return json.loads(output.read_text(encoding="utf-8"))

    before = take_snapshot(tmp_path / "before.json")
    for protected in (
        "data/state/__pycache__",
        "data/state/__pycache__/module.cpython-312.pyc",
        "venv/lib/__pycache__",
        "venv/lib/__pycache__/module.cpython-312.pyc",
        "openclaw/__pycache__",
        "openclaw/__pycache__/module.cpython-312.pyc",
        "installed-cli/runtime/__pycache__",
        "installed-cli/runtime/__pycache__/module.cpython-312.pyc",
        "installed-cli/module.pyc",
    ):
        assert protected in before

    for cache_file in real_cache_files:
        cache_file.write_bytes(b"new runtime bytecode")
    standalone_pyc.write_bytes(b"new standalone bytecode")
    after_cache_writes = take_snapshot(tmp_path / "after-cache-writes.json")
    assert after_cache_writes != before
    for protected in (
        "data/state/__pycache__/module.cpython-312.pyc",
        "venv/lib/__pycache__/module.cpython-312.pyc",
        "openclaw/__pycache__/module.cpython-312.pyc",
        "installed-cli/runtime/__pycache__/module.cpython-312.pyc",
        "installed-cli/module.pyc",
    ):
        assert after_cache_writes[protected]["sha256"] != before[protected]["sha256"]


def test_post_cut_bridge_uses_staged_release_resolver() -> None:
    completed = subprocess.run(
        [
            _bash_executable(),
            "-c",
            r"""
source "$1"
TARGET_VERSION="0.8.8"
CANDIDATE_MIN_PROTOCOL=2
CANDIDATE_SCHEMA_VERSION=2
MINIMUM_SOURCE_VERSION="0.8.4"
REQUIRED_BRIDGE_VERSION="0.8.4"
REFUSAL_CONTRACT_ONLY=0
SUCCESS_PATH_ONLY=0
stage_authenticated_baseline() { :; }
baseline_protocol() { printf '%s\n' 2; }
baseline_has_schema_gate() { printf '%s\n' 1; }
manifest_array_contains() { return 0; }
manifest_windows_sources_are_empty() { return 1; }
run_installed_controller_refusal() { printf '%s\n' unexpected-installed-refusal; return 97; }
run_one_upgrade_smoke() { printf '%s\n' unexpected-installed-success; return 96; }
run_candidate_updater_refusal() { return 95; }
run_candidate_updater_staged_success() { printf 'staged=%s\n' "$1"; }
run_candidate_updater_direct_success() { printf '%s\n' unexpected-direct-resolver; return 94; }
run_protocol_case "0.8.4"
""",
            "post-cut-bridge-test",
            str(PROTOCOL_GATE),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert "staged=0.8.4" in completed.stdout
    assert "unexpected-installed" not in completed.stdout
    assert "unexpected-direct-resolver" not in completed.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX hard-link permission contract")
def test_historical_endpoint_patch_does_not_mutate_a_hardlinked_cache(
    tmp_path: Path,
) -> None:
    smoke_home = tmp_path / "home"
    installed = smoke_home / ".defenseclaw/.venv/lib/python3.13/site-packages/defenseclaw/commands/cmd_upgrade.py"
    installed.parent.mkdir(parents=True)
    original = (
        'GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"\ntarget_version = _fetch_latest_version()\n'
    )
    installed.write_text(original, encoding="utf-8")
    installed.chmod(0o640)
    cached = tmp_path / "uv-cache-cmd_upgrade.py"
    os.link(installed, cached)
    shared_identity = (installed.stat().st_dev, installed.stat().st_ino)

    completed = subprocess.run(
        [
            _bash_executable(),
            "-c",
            ('source "$1"; SMOKE_HOME="$2"; RELEASE_URL="$3"; patch_installed_upgrade_endpoint "$4"'),
            "historical-endpoint-patch-test",
            str(ROOT / "scripts/test-upgrade-release.sh"),
            str(smoke_home),
            "http://127.0.0.1:43123/releases/download",
            "0.8.5",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert cached.read_text(encoding="utf-8") == original
    assert (cached.stat().st_dev, cached.stat().st_ino) == shared_identity
    assert cached.stat().st_nlink == 1
    assert installed.read_text(encoding="utf-8") == (
        'GITHUB_DL = "http://127.0.0.1:43123/releases/download"\ntarget_version = "0.8.5"\n'
    )
    assert (installed.stat().st_dev, installed.stat().st_ino) != shared_identity
    assert installed.stat().st_nlink == 1
    assert installed.stat().st_mode & 0o777 == 0o640
    assert not list(installed.parent.glob(".cmd_upgrade.py.protocol-endpoint-*"))


def test_protocol_gate_treats_a_baseline_without_upgrade_module_as_no_schema_gate(
    tmp_path: Path,
) -> None:
    text = PROTOCOL_GATE.read_text(encoding="utf-8")
    function = text.index("baseline_has_schema_gate() {")
    start = text.index("<<'PY'\n", function) + len("<<'PY'\n")
    end = text.index("\nPY\n}", start)
    program = text[start:end]
    baseline = tmp_path / "legacy.whl"
    with zipfile.ZipFile(baseline, "w") as archive:
        archive.writestr("defenseclaw/__init__.py", "")

    completed = subprocess.run(
        [sys.executable, "-c", program, str(baseline)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "0"


@pytest.mark.skipif(os.name == "nt", reason="release protocol cleanup requires POSIX bash")
def test_protocol_cleanup_accepts_an_empty_sentinel_array() -> None:
    completed = subprocess.run(
        [
            _bash_executable(),
            "-c",
            'source "$1"; REFUSAL_SENTINEL_PIDS=(); WORKDIR=""; SERVER_PID=""; protocol_cleanup',
            "protocol-cleanup-test",
            str(PROTOCOL_GATE),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="resolver asset validation requires POSIX bash")
def test_reviewed_resolver_asset_validation_fails_explicitly_without_errexit(
    tmp_path: Path,
) -> None:
    release_root = tmp_path / "release-root"
    (release_root / "0.8.4").mkdir(parents=True)
    completed = subprocess.run(
        [
            _bash_executable(),
            "-c",
            (
                'source "$1"; set +e; RELEASE_ROOT="$2"; TARGET_VERSION="0.8.4"; '
                "assert_reviewed_resolver_asset_contract; "
                'printf "%s\\n" "UNREACHABLE"'
            ),
            "resolver-contract-test",
            str(PROTOCOL_GATE),
            str(release_root),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "reviewed release-owned resolver assets failed byte-for-byte validation" in (
        completed.stdout + completed.stderr
    )
    assert "UNREACHABLE" not in completed.stdout


@pytest.mark.skipif(os.name == "nt", reason="release refusal contract requires POSIX bash")
def test_protocol_argument_parser_accepts_no_shared_arguments_under_nounset() -> None:
    completed = subprocess.run(
        [
            _bash_executable(),
            "-c",
            ('source "$1"; parse_protocol_args; printf "%s\\n" "$REFUSAL_CONTRACT_ONLY"'),
            "protocol-empty-arguments-test",
            str(PROTOCOL_GATE),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "0"


@pytest.mark.skipif(os.name == "nt", reason="release refusal contract requires POSIX bash")
def test_protocol_refusal_contract_option_preserves_shared_matrix_arguments() -> None:
    completed = subprocess.run(
        [
            _bash_executable(),
            "-c",
            (
                'source "$1"; '
                "parse_protocol_args --from-version 0.8.3 --baseline-mode seed "
                "--refusal-contract-only; "
                'printf "%s|%s|%s\\n" "$FROM_VERSION" "$BASELINE_MODE" '
                '"$REFUSAL_CONTRACT_ONLY"'
            ),
            "protocol-refusal-option-test",
            str(PROTOCOL_GATE),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "0.8.3|seed|1"


def test_posix_fresh_release_uses_physical_temp_homes_and_surfaces_installer_logs() -> None:
    source = POSIX_FRESH_RELEASE.read_text(encoding="utf-8")

    workdir = source.index('WORKDIR="$(mktemp -d')
    canonical = source.index('WORKDIR="$(cd "${WORKDIR}" && pwd -P)"')
    home = source.index('BOOTSTRAP_HOME="${WORKDIR}/bootstrap/home"')
    assert workdir < canonical < home
    assert 'cat "${WORKDIR}/bootstrap-install.log" >&2' in source
    assert 'cat "${WORKDIR}/external-install.log" >&2' in source
