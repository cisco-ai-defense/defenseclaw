# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yaml"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
CERTIFICATION_WORKFLOW = ROOT / ".github/workflows/pre-release-certification.yml"
PROTOCOL_GATE = ROOT / "scripts/test-upgrade-protocol-release.sh"
WINDOWS_PROTOCOL_GATE = ROOT / "scripts/test-upgrade-release-windows.ps1"
MACOS_BUILD = ROOT / "scripts/build-macos-app-release.sh"
POSIX_INSTALLER = ROOT / "scripts/install.sh"
POSIX_FRESH_RELEASE = ROOT / "scripts/test-fresh-install-release.sh"


def _workflow() -> dict[str, object]:
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _ci_workflow() -> dict[str, object]:
    return yaml.load(CI_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _certification_workflow() -> dict[str, object]:
    return yaml.load(
        CERTIFICATION_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )


def test_sensitive_plan_installs_cosign_before_historical_authentication() -> None:
    workflow = _ci_workflow()
    steps = workflow["jobs"]["release-validation-plan"]["steps"]
    cosign = next(
        index for index, step in enumerate(steps) if step.get("uses", "").startswith("sigstore/cosign-installer@")
    )
    resolver = next(
        index
        for index, step in enumerate(steps)
        if "resolve_upgrade_baselines.py" in step.get("run", "")
    )

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
    assert "nightly/manual certification" in workflow_text


def test_release_supports_nightly_certification_and_manual_promotion() -> None:
    workflow = _workflow()
    triggers = workflow["on"]
    assert triggers["schedule"] == [{"cron": "17 5 * * *"}]
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert inputs["operation"]["options"] == ["release", "certify"]
    assert inputs["version"]["required"] == "false"
    assert inputs["candidate_ref"]["required"] == "false"
    assert inputs["immutable_releases_confirmed"]["default"] == "false"
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}


def test_release_immutability_preflight_uses_operator_confirmation_without_admin_token() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert 'repos/$GITHUB_REPOSITORY/immutable-releases' not in text
    assert "IMMUTABLE_RELEASES_CONFIRMED" in text
    assert "inputs.immutable_releases_confirmed" in text
    assert "Immutable Releases confirmation required" in text
    assert "--json tagName,isDraft,isImmutable,assets" in text
    assert "scripts/release_candidate.py verify-published" in text


def test_release_automation_never_publishes_runtime_to_python_package_indexes() -> None:
    surfaces = [
        *sorted((ROOT / ".github/workflows").glob("*.y*ml")),
        ROOT / "Makefile",
        *sorted(
            path
            for path in (ROOT / "scripts").rglob("*")
            if path.is_file() and path.suffix in {".py", ".ps1", ".sh"}
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
    assert 'f"defenseclaw-{release_version}-2-py3-none-any.dcwheel"' in release


def test_release_requires_current_main_without_prescribing_repository_governance() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'GITHUB_REF" != "refs/heads/main' in text
    assert "is not the current origin/main tip" in text
    assert "refs/heads/release/" not in text
    for forbidden in (
        "defenseclaw-reviewers",
        "required_reviewers",
        "prevent_self_review",
        "can_admins_bypass",
        "protection_rules",
        'gh api "repos/$GITHUB_REPOSITORY/environments/',
    ):
        assert forbidden not in text
    jobs = _workflow()["jobs"]
    assert {name for name, job in jobs.items() if job.get("environment") == "release"} == {
        "macos-app",
        "publish-release",
    }


def test_release_target_must_advance_reviewed_and_published_stable_state() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "gh api --paginate --slurp" in text
    assert '"repos/$GITHUB_REPOSITORY/releases?per_page=100"' in text
    assert "scripts/release_candidate.py validate-version" in text
    assert "--releases-json published-releases.json" in text


def test_publish_job_promotes_only_a_selected_certified_candidate() -> None:
    jobs = _workflow()["jobs"]
    publish = jobs["publish-release"]
    assert set(publish["needs"]) == {
        "release-mode",
        "release-preflight",
        "select-candidate",
    }
    assert "needs.release-mode.outputs.operation == 'release'" in publish["if"]
    assert "needs.select-candidate.result == 'success'" in publish["if"]
    assert publish["environment"] == "release"
    assert publish["permissions"] == {"contents": "write"}
    for name, job in jobs.items():
        if name != "publish-release":
            assert job.get("permissions") != {"contents": "write"}


def test_windows_release_binaries_are_disabled_and_omitted() -> None:
    jobs = _workflow()["jobs"]
    certification = _certification_workflow()["jobs"]
    assert "windows-unpublished-refusal" in certification
    assert "windows-fresh-install" not in certification
    assert "windows-upgrade" not in certification
    assert "windows_prebridge_baselines == '[]'" in certification[
        "windows-unpublished-refusal"
    ]["if"]

    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    assert workflow_text.count("--omit-windows-binaries") == 2
    assert "publish_windows_binaries" not in workflow_text
    assert "Windows-specific binaries and SBOMs will not be published" in workflow_text


def test_build_once_candidate_is_reused_by_tests_and_publisher() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count("goreleaser/goreleaser-action@") == 1
    assert text.count("make dist-cli") == 1
    assert text.count("make dist-plugin") == 1
    assert text.count("make extensions") == 1
    assert text.count("scripts/release_candidate.py assemble") == 1
    assert "steps.upload.outputs.artifact-digest" in text

    jobs = _workflow()["jobs"]
    build_job = jobs["build-runtime-candidate"]
    build_rendered = str(build_job)
    assert build_job["permissions"] == {"contents": "read"}
    assert "id-token" not in build_rendered
    assert "sigstore/cosign-installer@" not in build_rendered
    assert "release --clean --skip=sign" in build_rendered

    assemble_job = jobs["assemble-release-candidate"]
    assemble_rendered = str(assemble_job)
    assert assemble_job["permissions"]["id-token"] == "write"
    assert "sigstore/cosign-installer@" in assemble_rendered
    assert "cosign sign-blob" in assemble_rendered
    assert text.count("cosign sign-blob") == 1

    macos_job = str(jobs["macos-app"])
    assert "scripts/release_candidate.py extract-gateway" in macos_job
    assert "MACOS_GATEWAY_INPUT" in macos_job
    assert "make extensions" not in macos_job

    certification = _certification_workflow()["jobs"]
    for name in (
        "linux-upgrade",
        "macos-upgrade",
        "historical-dependency-canary",
        "windows-unpublished-refusal",
        "posix-fresh-install",
        "live-continuity",
    ):
        rendered = str(certification[name])
        assert "inputs.candidate_artifact" in rendered
        assert "scripts/release_candidate.py verify" in rendered
    assert "needs.select-candidate.outputs.artifact_name" in str(
        jobs["publish-release"]
    )


def test_unpublished_windows_runtime_requires_sealed_native_refusal() -> None:
    job = _certification_workflow()["jobs"]["windows-unpublished-refusal"]
    rendered = str(job)

    assert job["runs-on"] == "windows-latest"
    assert job["if"] == "${{ inputs.windows_prebridge_baselines == '[]' }}"
    assert "inputs.candidate_artifact" in rendered
    assert "scripts/release_candidate.py verify" in rendered
    assert "scripts/verify-sigstore-blob.py" in rendered
    assert "scripts/test-upgrade-release-windows.ps1" in rendered
    assert "-UnpublishedWindowsRefusalOnly" in rendered
    complete = str(_certification_workflow()["jobs"]["certification-complete"])
    assert "needs.windows-unpublished-refusal.result" in complete


def test_release_certificate_is_canonicalized_and_authenticated_before_seal() -> None:
    assemble_job = _workflow()["jobs"]["assemble-release-candidate"]
    steps = assemble_job["steps"]
    sign_index, sign_step = next(
        (index, step)
        for index, step in enumerate(steps)
        if step.get("name") == "Sign and authenticate public checksum manifest"
    )
    seal_index, seal_step = next(
        (index, step)
        for index, step in enumerate(steps)
        if step.get("name") == "Seal all candidate bytes"
    )
    sign_script = sign_step["run"]
    seal_script = seal_step["run"]

    sign = sign_script.index("cosign sign-blob")
    canonicalize = sign_script.index(
        "scripts/release_candidate.py canonicalize-certificate"
    )
    authenticate = sign_script.index("scripts/verify-sigstore-blob.py")
    assert sign < canonicalize < authenticate
    assert sign_index + 1 == seal_index
    assert sign_script.count("canonicalize-certificate") == 1
    assert "--certificate release-candidate/dist/checksums.txt.pem" in sign_script
    assert (
        '--certificate-identity "https://github.com/$GITHUB_REPOSITORY/'
        '.github/workflows/release.yaml@refs/heads/main"'
    ) in sign_script
    assert (
        '--certificate-oidc-issuer "https://token.actions.githubusercontent.com"'
    ) in sign_script
    assert "--certificate-identity-regexp" not in sign_script
    assert "scripts/release_candidate.py seal" in seal_script


def test_sealed_candidate_must_pass_native_fresh_install_and_second_run_refusal() -> None:
    jobs = _certification_workflow()["jobs"]
    posix = str(jobs["posix-fresh-install"])
    includes = jobs["posix-fresh-install"]["strategy"]["matrix"]["include"]
    assert [item["platform"] for item in includes] == [
        "linux-amd64",
        "darwin-arm64",
    ]
    assert "scripts/test-fresh-install-release.sh" in posix
    assert "inputs.candidate_artifact" in posix
    assert "scripts/release_candidate.py verify" in posix


def test_posix_fresh_install_gates_temporary_and_external_cosign_paths() -> None:
    text = POSIX_FRESH_RELEASE.read_text(encoding="utf-8")
    installer = POSIX_INSTALLER.read_text(encoding="utf-8")

    # The primary install must not inherit the Cosign installed on the runner.
    assert 'EXTERNAL_COSIGN="$(command -v cosign)"' in text
    assert 'readonly BOOTSTRAP_PATH="${BOOTSTRAP_HOME}/.local/bin:${BASE_TOOL_PATH}"' in text
    assert 'PATH="${BOOTSTRAP_PATH}" command -v cosign' in text
    assert '$(dirname "$(command -v cosign)")' not in text
    assert 'Cosign was not found; authenticating temporary Cosign 2.6.3' in text
    assert 'mktemp -d "${TMPDIR:-/tmp}/defenseclaw-policy.XXXXXX"' in installer
    assert "assert_bootstrap_retired_privately" in text
    assert 'not retired into bounded custody' in text
    assert 'BOOTSTRAP_HOME}/.local/bin/cosign' in text

    # A second isolated installation must still exercise an explicit external
    # verifier and prove the installer did not mutate or replace that binary.
    assert 'EXTERNAL_TOOL_BIN}/cosign' in text
    assert 'external Cosign wrapper was not invoked' in text
    assert 'external-Cosign case unexpectedly used the bootstrap verifier' in text
    assert '$(sha256_file "${EXTERNAL_COSIGN}")' in text
    assert 'the ambient Cosign binary changed during fresh-install testing' in text


def test_real_historical_dependency_canaries_cover_common_oldest_and_running_source() -> None:
    job = _certification_workflow()["jobs"]["historical-dependency-canary"]
    assert job["strategy"]["matrix"] == "${{ fromJSON(inputs.historical_matrix) }}"
    rendered = str(job)
    assert "--baseline-dependencies published" in rendered
    assert "--success-path-only" in rendered
    assert "--start-source-gateway" in rendered
    assert "scripts/test-upgrade-protocol-release.sh" in rendered
    assert "scripts/release_candidate.py verify" in rendered


def test_macos_app_consumes_and_validates_sealed_runtime_gateway() -> None:
    text = MACOS_BUILD.read_text(encoding="utf-8")
    assert 'GATEWAY_INPUT="${MACOS_GATEWAY_INPUT:-}"' in text
    assert "regular non-symlink candidate binary" in text
    assert 'cmp -s "${GATEWAY_INPUT}" "${GATEWAY}"' in text
    assert "Mach-O 64-bit executable arm64" in text
    assert '"${GATEWAY}" --version' in text
    assert "gateway candidate version mismatch" in text


def test_release_conditionally_notarizes_or_publishes_explicit_unverified_assets() -> None:
    workflow = _workflow()
    macos_job = workflow["jobs"]["macos-app"]
    setup_uv_step = next(
        step
        for step in macos_job["steps"]
        if step.get("uses", "").startswith("astral-sh/setup-uv@")
    )
    assert setup_uv_step["with"]["enable-cache"] == "false"

    build_step = next(
        step
        for step in macos_job["steps"]
        if step.get("name") == "Build, sign, notarize, and package app"
    )
    assert build_step["env"]["MACOS_REQUIRE_NOTARIZATION"] == "false"

    rendered = str(macos_job)
    for secret in (
        "MACOS_DEVELOPER_ID_P12_BASE64",
        "MACOS_DEVELOPER_ID_P12_PASSWORD",
        "MACOS_NOTARY_KEY_BASE64",
        "MACOS_NOTARY_KEY_ID",
        "MACOS_NOTARY_ISSUER_ID",
    ):
        assert f"secrets.{secret}" in rendered
    assert "notarized)" in rendered
    assert "unverified)" in rendered
    assert "explicitly suffixed -unverified app assets" in rendered
    assert "signed-unnotarized)" not in rendered

    release_text = WORKFLOW.read_text(encoding="utf-8")
    assert "MACOS_VERIFICATION_STATUSES" in release_text
    assert "names == required" in release_text

    build_text = MACOS_BUILD.read_text(encoding="utf-8")
    assert 'VERIFICATION_STATUS="unverified"' in build_text
    assert '[[ "${VERIFICATION_STATUS}" != "notarized" ]]' in build_text
    assert '[[ "${VERIFICATION_STATUS}" != "unverified" ]]' in build_text


def test_posix_installer_cannot_bypass_upgrade_graph_on_existing_install() -> None:
    text = POSIX_INSTALLER.read_text(encoding="utf-8")
    assert "An existing DefenseClaw installation was detected. No changes were made." in text
    assert "release-owned upgrade resolver" in text
    guard = text.index("An existing DefenseClaw installation was detected")
    assert guard < text.index("detect_platform", guard)


def test_upgrade_matrix_is_manifest_and_reviewed_data_driven() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    jobs = _workflow()["jobs"]
    certification_jobs = _certification_workflow()["jobs"]
    assert "scripts/resolve_upgrade_baselines.py" in text
    assert "effective-upgrade-baselines.json" in text
    assert "--baselines effective-upgrade-baselines.json" in text
    assert 'json.dumps(older, separators=(",", ":"))' in text
    assert "platform_published_baselines" in text
    assert "platform_tested_source_versions" in text
    assert "tested_source_versions does not match the reviewed release matrix" in text
    assert "platform_tested_source_versions.windows does not match" in text
    assert "modern release candidate must use upgrade manifest schema 2" in text
    assert "runtime_config_version does not attest the expected bridge/hard-cut runtime" in text
    assert "required bridge is absent from the signed Windows matrix" in text
    assert "signed Windows matrix has no pre-bridge source" in text
    assert "unpublished Windows bridge requires an empty signed Windows matrix" in text
    assert "windows_prebridge_baselines" in text
    assert "CurrentConfigVersion" in text
    assert "ObservabilityV8ConfigVersion" in text
    assert "compatibility ceiling" in text
    for name in ("linux-upgrade", "macos-upgrade"):
        assert certification_jobs[name]["strategy"]["matrix"]["baseline"] == (
            "${{ fromJSON(inputs.baselines) }}"
        )
    certification_text = CERTIFICATION_WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/test-upgrade-protocol-release.sh" in certification_text
    assert "scripts/test-upgrade-release-windows.ps1" in certification_text
    assert "required_bridge_version" in text
    assert "min_upgrade_protocol" in text
    assert "auto_bridge_from does not match the reviewed pre-bridge matrix" in text
    assert "Resolve immutable published bridge provenance" in text
    assert '"isImmutable": True' in text
    assert "omit_windows_binaries = expected not in windows_baselines" in text
    assert "omit_windows_binaries=omit_windows_binaries" in text
    assert "payload_asset_names(expected, status)" in text
    assert "set(windows_release_binary_names(expected))" in text
    assert "if name in omitted_windows" in text
    assert "if name in assets" in text
    assert "scripts/verify-sigstore-blob.py" in text
    assert '--source-tree "$SOURCE_TREE"' in text
    assert '--bridge-checksums-sha256 "$BRIDGE_CHECKSUMS_SHA256"' in text
    assert not re.search(r"\b0\.8\.[45]\b", certification_text)


def test_only_final_step_can_create_remote_release_or_tag() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count("gh release create") == 1
    assert "gh release upload" not in text
    assert "git push" not in text
    assert "push:\n" not in text
    assert "Publish tag and selected sealed assets" in text
    assert "verify-published" in text


def test_every_remote_action_is_commit_pinned() -> None:
    uses = re.findall(r"^\s*- uses:\s*([^\s#]+)", WORKFLOW.read_text(encoding="utf-8"), re.MULTILINE)
    assert uses
    for action in uses:
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), action


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
    assert 'receipt.get("migration_status") != "completed"' in text
    for contract in (
        "CANDIDATE_MIN_PROTOCOL",
        "CANDIDATE_SCHEMA_VERSION",
        "CANDIDATE_RUNTIME_CONFIG_VERSION",
        "MINIMUM_SOURCE_VERSION",
        "REQUIRED_BRIDGE_VERSION",
        "baseline_protocol",
        "baseline_has_schema_gate",
        "run_installed_controller_refusal",
        "for invocation in explicit latest",
        'patch_installed_upgrade_endpoint "${TARGET_VERSION}"',
        'defenseclaw "${command_args[@]}"',
        "run_candidate_updater_refusal",
        "run_candidate_explicit_bridge_refusal",
        "run_candidate_updater_staged_success",
        "run_candidate_updater_direct_success",
        "manifest_windows_sources_are_empty",
        "immutable-bridge-empty-windows",
        "prepare_required_bridge_assets",
        "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL",
        "assert_staged_success_receipt",
        "UPGRADE_GATE_STOP_MARKER",
        "gateway sentinel PID changed",
        "assert_no_success_receipt",
        'record(openclaw_home, "openclaw")',
        "refusal-must-not-mutate",
        "run_one_upgrade_smoke",
        "manifest_array_contains tested_source_versions",
        "canonical gateway refusal envelope",
        "artifact-envelope",
        "there is intentionally no --version argument",
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
    assert text.count(sealed_resolver) >= 4
    assert 'scripts/upgrade.sh" --yes' not in text
    assert not re.search(r"TARGET_VERSION[^\n]*0\.8\.", text)
    smoke = (ROOT / "scripts/test-upgrade-release.sh").read_text(encoding="utf-8")
    assert "force_latest_version" in smoke
    assert 'target_version = "{force_latest_version}"' in smoke


def test_external_resolver_boundaries_disable_python_bytecode() -> None:
    text = PROTOCOL_GATE.read_text(encoding="utf-8")
    for function_name in (
        "run_candidate_updater_refusal",
        "run_candidate_explicit_bridge_refusal",
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


def test_protocol_gate_detects_an_empty_windows_source_matrix(tmp_path: Path) -> None:
    release_dir = tmp_path / "0.8.5"
    release_dir.mkdir()
    manifest = release_dir / "upgrade-manifest.json"

    def run_helper() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                "-c",
                (
                    'source "$1"; RELEASE_ROOT="$2"; TARGET_VERSION="0.8.5"; '
                    "manifest_windows_sources_are_empty"
                ),
                "windows-source-matrix-test",
                str(PROTOCOL_GATE),
                str(tmp_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    manifest.write_text(
        '{"platform_tested_source_versions":{"windows":[]}}\n',
        encoding="utf-8",
    )
    assert run_helper().returncode == 0

    manifest.write_text(
        '{"platform_tested_source_versions":{"windows":["0.8.3"]}}\n',
        encoding="utf-8",
    )
    assert run_helper().returncode == 1


def test_empty_windows_matrix_uses_bridge_refusal_then_current_resolver() -> None:
    completed = subprocess.run(
        [
            "bash",
            "-c",
            r'''
source "$1"
TARGET_VERSION="0.8.5"
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
manifest_windows_sources_are_empty() { return 0; }
run_installed_controller_refusal() { printf 'refusal=%s:%s\n' "$1" "$2"; }
run_one_upgrade_smoke() { printf '%s\n' unexpected-installed-success; return 97; }
run_candidate_updater_refusal() { return 96; }
run_candidate_explicit_bridge_refusal() { return 95; }
run_candidate_updater_staged_success() { return 94; }
run_candidate_updater_direct_success() { printf 'direct=%s\n' "$1"; }
run_protocol_case "0.8.4"
''',
            "bridge-empty-windows-test",
            str(PROTOCOL_GATE),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert "refusal=0.8.4:immutable-bridge-empty-windows" in completed.stdout
    assert "direct=0.8.4" in completed.stdout
    assert "unexpected-installed-success" not in completed.stdout


def test_historical_endpoint_patch_does_not_mutate_a_hardlinked_cache(
    tmp_path: Path,
) -> None:
    smoke_home = tmp_path / "home"
    installed = (
        smoke_home
        / ".defenseclaw/.venv/lib/python3.13/site-packages/defenseclaw/commands/cmd_upgrade.py"
    )
    installed.parent.mkdir(parents=True)
    original = (
        'GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"\n'
        "target_version = _fetch_latest_version()\n"
    )
    installed.write_text(original, encoding="utf-8")
    installed.chmod(0o640)
    cached = tmp_path / "uv-cache-cmd_upgrade.py"
    os.link(installed, cached)
    shared_identity = (installed.stat().st_dev, installed.stat().st_ino)

    completed = subprocess.run(
        [
            "bash",
            "-c",
            (
                'source "$1"; SMOKE_HOME="$2"; RELEASE_URL="$3"; '
                'patch_installed_upgrade_endpoint "$4"'
            ),
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
        'GITHUB_DL = "http://127.0.0.1:43123/releases/download"\n'
        'target_version = "0.8.5"\n'
    )
    assert (installed.stat().st_dev, installed.stat().st_ino) != shared_identity
    assert installed.stat().st_nlink == 1
    assert installed.stat().st_mode & 0o777 == 0o640
    assert not list(installed.parent.glob(".cmd_upgrade.py.protocol-endpoint-*"))


def test_windows_success_receipt_gate_matches_posix_terminal_invariants() -> None:
    text = WINDOWS_PROTOCOL_GATE.read_text(encoding="utf-8")
    assert 'status -in @("pending", "partial")' in text
    assert "Successful staged upgrade left a pending or partial receipt" in text
    assert "Successful staged upgrade left more than one terminal target receipt" in text
    assert '[string]$_.migration_status -eq "completed"' in text
    assert "$_.artifacts_verified -eq $true" in text
    assert "[string]::IsNullOrEmpty([string]$_.failure_code)" in text
    assert "Successful staged upgrade left duplicate succeeded receipts" in text
    assert "Successful staged upgrade left an invalid terminal target receipt" in text
    invalid_guard = text.index("$targetReceipts.Count -eq 1 -and $receiptMatches.Count -eq 0")
    audit_fallback = text.index("$targetReceipts.Count -eq 0", invalid_guard)
    assert invalid_guard < audit_fallback


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


def test_protocol_cleanup_accepts_an_empty_sentinel_array() -> None:
    completed = subprocess.run(
        [
            "bash",
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


def test_reviewed_resolver_asset_validation_fails_explicitly_without_errexit(
    tmp_path: Path,
) -> None:
    release_root = tmp_path / "release-root"
    (release_root / "0.8.4").mkdir(parents=True)
    completed = subprocess.run(
        [
            "bash",
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


def test_protocol_refusal_contract_option_preserves_shared_matrix_arguments() -> None:
    completed = subprocess.run(
        [
            "bash",
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
