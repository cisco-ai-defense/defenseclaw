# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Release guard for the unified macOS app's bundled runtime installer."""

from __future__ import annotations

import hashlib
import os
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "macos" / "DefenseClawMac" / "DefenseClawMac" / "DataLayer" / "RuntimeInstaller.swift"
SETTINGS = ROOT / "macos" / "DefenseClawMac" / "DefenseClawMac" / "Features" / "AppSettingsView.swift"
APP_STATE = ROOT / "macos" / "DefenseClawMac" / "DefenseClawMac" / "App" / "AppState.swift"
FILESYSTEM = ROOT / "macos" / "DefenseClawMac" / "DefenseClawMac" / "DataLayer" / "RuntimeInstallFilesystem.swift"
COMMAND_REGISTRY = ROOT / "macos" / "DefenseClawMac" / "DefenseClawMac" / "DataLayer" / "CommandRegistry.swift"
BUILD_MACOS_RELEASE = ROOT / "scripts" / "build-macos-app-release.sh"
VERIFY_MACOS_RELEASE = ROOT / "scripts" / "verify-macos-app-release.sh"
MACOS_CI_WORKFLOW = ROOT / ".github" / "workflows" / "macos-app.yml"
UPGRADE_RELEASE_SMOKE = ROOT / "scripts" / "test-upgrade-release.sh"


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_bundled_runtime_installer_is_fresh_install_only_before_mutation() -> None:
    source = _source()

    guard = source.index("RuntimeInstallFilesystem.existingManagedRuntimeMarker(home: home)")
    configured_cli_probe = source.index("await cli.locateBinary()", guard)
    gateway_probe = source.index('await cli.locateBinary(named: "defenseclaw-gateway")', configured_cli_probe)
    payload_verification = source.index('runtimeInstallState = .running("Verifying bundled payload")', gateway_probe)
    dependency_boundary = source.index('runtimeInstallState = .running("Locating uv")', payload_verification)

    assert guard < configured_cli_probe < gateway_probe < payload_verification < dependency_boundary
    assert "upgrade-from-older" not in source
    assert "liveGatewayPID" not in source


def test_bundled_runtime_guard_covers_complete_and_partial_standard_installs() -> None:
    helper = FILESYSTEM.read_text(encoding="utf-8")

    for marker in (
        'let dataHome = home + "/.defenseclaw"',
        'home + "/.local/bin/defenseclaw"',
        'home + "/.local/bin/defenseclaw-gateway"',
        'home + "/.local/bin/.defenseclaw-source-root"',
    ):
        assert marker in helper
    assert "lstat(pointer, &metadata) == 0" in helper
    assert "fileExists(atPath:" not in helper
    assert "!isLexicallyEmptyDirectory(dataHome)" in helper


def test_pre_activation_failure_cleanup_is_staging_only_and_atomic() -> None:
    source = _source()
    helper = FILESYSTEM.read_text(encoding="utf-8")

    assert source.count("RuntimeInstallFilesystem.cleanupFailedFreshInstall(") >= 4
    assert "stagingIdentity: PathIdentity" in helper
    assert "cleanupOwnedPath(stagingDir, identity: stagingIdentity)" in helper
    assert "createOwnedDirectory(stagingDir)" in source
    assert "Keep an empty real data-home" in helper
    assert "fileManager.removeItem(atPath: dataHome)" not in helper
    assert 'arguments: ["-rf", dataHome]' not in source


def test_final_identity_failure_cleans_every_known_stage() -> None:
    source = _source()
    guard = source.index("guard let gatewayStageIdentity, let cliStageIdentity,\n              let venvStageIdentity")
    failure = source.index(
        'runtimeInstallState = .failed("Runtime staging identity could not be verified;',
        guard,
    )
    branch = source[guard:failure]

    assert "cleanupKnownStages()" in branch
    assert "cleanupFailedFreshInstall(" not in branch


def test_bundled_runtime_refusal_names_exact_supported_upgrade_path() -> None:
    source = _source()
    refusal = source[source.index("private static func existingRuntimeRefusal") :]

    for required in (
        "fresh-install-only",
        "existing or partial DefenseClaw runtime",
        "No installed files or services were changed",
        "release-owned resolver in Terminal without --version",
        "tested-source policy",
        "the 0.8.4 bridge",
        "rollback, migrations, and health checks",
        "releases/download/",
        "defenseclaw-upgrade.sh",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "cosign verify-blob",
        "release.yaml@refs/heads/main",
        "https://token.actions.githubusercontent.com",
        "sha256sum",
        "shasum -a 256",
        "DefenseClaw upgrade resolver complete v1",
        "unset VERSION",
        "bash <(printf '%s\\\\n' \"$resolver\") --yes",
    ):
        assert required in refusal
    assert "raw.githubusercontent.com" not in refusal
    assert "| bash" not in refusal


def test_true_fresh_install_still_stages_and_verifies_both_components() -> None:
    source = _source()
    filesystem = FILESYSTEM.read_text(encoding="utf-8")

    for required in (
        'arguments: ["venv", stagingDir, "--clear", "--relocatable", "--python", "3.12"]',
        '"Verify staged DefenseClaw CLI"',
        '"Verify DefenseClaw CLI"',
        '"Verify DefenseClaw gateway"',
        "binary: gatewayDest",
        "runtimeInstallState = .succeeded",
    ):
        assert required in source
    gateway_stage = source.index("expectedSourceSHA256: payload.gatewaySHA256")
    signature_verify = source.index('"Verify release-attested gateway signature and identifier"', gateway_stage)
    assert gateway_stage < signature_verify
    gateway_install = source[
        source.index("// ── Gateway binary + CLI link, staged") : source.index(
            'runtimeInstallState = .running("Staging DefenseClaw CLI link")', signature_verify
        )
    ]
    assert "gatewayActivationPlan" not in source
    assert "GatewayActivationStep" not in filesystem
    assert "Normalize staged gateway signature" not in gateway_install
    assert '"-f", "-s", "-"' not in gateway_install
    assert "renameatx_np(" in filesystem
    assert "UInt32(RENAME_EXCL)" in filesystem
    assert "O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC" in filesystem
    assert "prepareActivationTargets" in source
    assert "activateNoReplace" in source
    assert "rollbackActivation(activation)" in source
    success = source.index("runtimeInstallState = .succeeded")
    assert source.index('"Verify DefenseClaw CLI"') < source.index('"Verify DefenseClaw gateway"') < success
    assert 'let stagingDir = venvDir + ".staging-" + UUID().uuidString' in source
    assert 'gatewayDest + ".install-" + UUID().uuidString' in source
    assert 'cliDest + ".install-" + UUID().uuidString' in source
    assert ".createOwnedSymbolicLink(" in source
    assert "symlinkat(targetPointer, pinned.descriptor, leafPointer)" in filesystem
    assert "symbolicLinkTarget(pinned.descriptor, parts.leaf) == target" in filesystem
    assert "entryIdentity(pinned.descriptor, parts.leaf) == ownedIdentity" in filesystem
    assert 'binary: "/bin/ln"' not in filesystem
    assert 'binary: "/bin/mv"' not in filesystem
    assert 'binary: "/bin/cp"' not in filesystem
    assert 'binary: "/bin/chmod"' not in filesystem
    assert "expectedSourceSHA256: payload.wheelSHA256" in source
    assert "decodeXORByte: RuntimePayload.protectedArtifactXORByte" in source
    assert "expectedSourceSHA256: payload.gatewaySHA256" in source
    assert "expectedSourceSHA256: overridesSHA256" in source
    assert "sourceHasher.update(data:" in filesystem
    assert "if let decodeXORByte" in filesystem
    assert "bytes[index] ^= decodeXORByte" in filesystem
    assert "(stripPrefix == nil) == (decodeXORByte == nil)" in filesystem
    assert "sourceDigestMismatch" in filesystem
    assert 'components: [".local", "bin"]' in source
    assert 'components: [".defenseclaw"]' in source
    assert "ensureRealDirectoryTree" in filesystem
    assert "mkdirat(current.descriptor" in filesystem
    assert 'appendingPathComponent("dc-uv-bootstrap")' not in source
    assert 'let stageName = "dc-uv-bootstrap-" + UUID().uuidString' in source
    assert "identity: stageIdentity" in source
    assert 'gateway["installed_sha256"] as? String' not in source
    assert "payload.gatewayInstalledSHA256" not in source
    assert '#"=identifier "com.cisco.defenseclaw.gateway""#' in source
    assert '"--verify", "--strict", "-R"' in source
    assert "signatureDisplay" not in source
    assert "== payload.gatewaySHA256" in source
    assert '"Verify staged DefenseClaw gateway"' in source

    build = BUILD_MACOS_RELEASE.read_text(encoding="utf-8")
    verify = VERIFY_MACOS_RELEASE.read_text(encoding="utf-8")
    assert 'codesign "${sign_args[@]}" --identifier com.cisco.defenseclaw.gateway' in build
    assert '"gateway": {"file": "defenseclaw-gateway", "sha256": gateway_sha}' in build
    assert "outer app signing changed the release-attested gateway bytes" in build
    for script in (build, verify):
        assert "GATEWAY_REQUIREMENT='=identifier \"com.cisco.defenseclaw.gateway\"'" in script
        assert 'codesign --verify --strict -R "${GATEWAY_REQUIREMENT}"' in script
        assert "defenseclaw-gateway.install-normalized" not in script
        assert "NORMALIZED_GATEWAY" not in script
        assert "installed_sha256" not in script
    assert "codesign --force --sign - --identifier" not in verify


def test_settings_do_not_advertise_bundled_repair_or_reinstall() -> None:
    settings = SETTINGS.read_text(encoding="utf-8")
    app_state = APP_STATE.read_text(encoding="utf-8")

    for required in (
        "fresh install only",
        "existing or partial runtime",
        "this action makes no changes",
        "release-owned latest-mode upgrade resolver",
    ):
        assert required in settings
    assert "Repair / Reinstall Runtime" not in settings
    assert "Bundled-payload fresh-install progress" in app_state


def test_macos_release_signer_requirement_pins_production_team_only() -> None:
    build = BUILD_MACOS_RELEASE.read_text(encoding="utf-8")
    verify = VERIFY_MACOS_RELEASE.read_text(encoding="utf-8")
    team_anchor = 'anchor apple generic and certificate leaf[subject.OU] = \\"${EXPECTED_TEAM_ID}\\"'

    for script in (build, verify):
        assert team_anchor in script
        assert '[[ "${EXPECTED_TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]]' in script

    base_requirement = "GATEWAY_REQUIREMENT='=identifier \"com.cisco.defenseclaw.gateway\"'"
    build_base = build.index(base_requirement)
    build_production = build.index('if [[ "${SIGNING_IDENTITY}" != "-" ]]', build_base)
    build_anchor = build.index("GATEWAY_REQUIREMENT+=", build_production)
    assert build_base < build_production < build_anchor

    status_detection = verify.index('[[ "${DMG}" != *-unverified.dmg ]] || DMG_UNVERIFIED=1')
    verify_base = verify.index(base_requirement)
    verify_production = verify.index('if [[ "${DMG_UNVERIFIED}" == "0" ]]', verify_base)
    verify_anchor = verify.index("GATEWAY_REQUIREMENT+=", verify_production)
    assert status_detection < verify_base < verify_production < verify_anchor
    assert 'APP_REQUIREMENT="=identifier \\"com.cisco.defenseclaw.macos\\"' in verify
    assert 'codesign --verify --strict -R "${APP_REQUIREMENT}"' in verify


def test_macos_release_signing_credentials_have_exact_optional_tristate() -> None:
    build = BUILD_MACOS_RELEASE.read_text(encoding="utf-8")

    for name in (
        "MACOS_DEVELOPER_ID_P12_BASE64",
        "MACOS_DEVELOPER_ID_P12_PASSWORD",
        "MACOS_NOTARY_KEY_BASE64",
        "MACOS_NOTARY_KEY_ID",
        "MACOS_NOTARY_ISSUER_ID",
    ):
        assert f'"${{{name}:-}}"' in build
    assert "APPLE_CREDENTIAL_COUNT != 0" in build
    assert "APPLE_CREDENTIAL_COUNT != ${#APPLE_CREDENTIAL_VALUES[@]}" in build
    assert (
        "Apple signing/notarization credentials are partially configured; provide all required values or none"
    ) in build
    assert 'SIGNING_IDENTITY="-"' in build
    assert 'VERIFICATION_STATUS="unverified"' in build
    assert "complete Apple credentials were configured, but signing and notarization did not complete" in build
    assert "credential-free macOS builds must remain explicitly unverified" in build
    assert "DefenseClawMac-${VERSION}-macos-arm64-unverified.dmg" in build
    assert "DefenseClawMac-${VERSION}-macos-arm64-unverified.zip" in build


def test_macos_package_ci_runs_for_every_exact_main_sha_with_stable_aggregate() -> None:
    workflow = yaml.load(
        MACOS_CI_WORKFLOW.read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    triggers = workflow["on"]

    assert set(triggers) == {"push", "pull_request", "workflow_dispatch"}
    assert triggers["push"] == {"branches": ["main"]}
    assert workflow["concurrency"] == {
        "group": ("macos-app-${{ github.event_name }}-${{ github.event.pull_request.number || github.sha }}"),
        "cancel-in-progress": "true",
    }
    aggregate = workflow["jobs"]["macos-app-required"]
    assert aggregate["name"] == "macOS App Required"
    assert aggregate["needs"] == ["license-headers", "build-and-test"]
    assert aggregate["if"] == "${{ always() }}"
    assert aggregate["steps"][0]["env"] == {
        "LICENSE_HEADERS_RESULT": "${{ needs.license-headers.result }}",
        "BUILD_AND_TEST_RESULT": "${{ needs.build-and-test.result }}",
    }
    command = aggregate["steps"][0]["run"]
    assert 'test "$LICENSE_HEADERS_RESULT" = success' in command
    assert 'test "$BUILD_AND_TEST_RESULT" = success' in command


def test_macos_ci_gates_release_wrappers_with_system_bash() -> None:
    workflow = yaml.load(
        MACOS_CI_WORKFLOW.read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    triggers = workflow["on"]
    watched_paths = triggers["pull_request"]["paths"]
    assert "scripts/test-upgrade-protocol-release.sh" in watched_paths
    assert ".github/workflows/pre-release-certification.yml" in watched_paths

    steps = workflow["jobs"]["build-and-test"]["steps"]
    gate = next(step for step in steps if step.get("name") == "Exercise release wrappers with system Bash")
    assert gate["env"] == {"DEFENSECLAW_TEST_BASH": "/bin/bash"}
    command = gate["run"]
    assert "/bin/bash --version" in command
    assert "uv run --frozen python -m pytest -q" in command
    assert "cli/tests/test_release_workflow_staged.py" in command
    assert "certification_upgrade_wrapper_is_nounset_safe_with_optional_arguments" in command
    assert "protocol_argument_parser_accepts_no_shared_arguments_under_nounset" in command


def test_macos_ci_builds_and_verifies_reviewed_runtime_fixture_first() -> None:
    workflow = MACOS_CI_WORKFLOW.read_text(encoding="utf-8")
    smoke = UPGRADE_RELEASE_SMOKE.read_text(encoding="utf-8")
    prepare = workflow.index("- name: Prepare reviewed runtime candidate fixture")
    package = workflow.index("- name: Build unified ad-hoc release artifact", prepare)
    fixture = workflow[prepare:package]

    for required in (
        "scripts/source_release_identity.py check --machine",
        "scripts/test-upgrade-release.sh",
        '--target-version "$version"',
        "--prepare-only",
        "--platform darwin/arm64",
        "Prepared candidate release root:",
        'ditto "$candidate_root/$version" dist',
        "scripts/release_candidate.py verify-runtime",
        "scripts/release_candidate.py extract-gateway",
        'echo "MACOS_CI_RELEASE_VERSION=$version"',
        'echo "MACOS_GATEWAY_INPUT=$GITHUB_WORKSPACE/',
    ):
        assert required in fixture

    verify_runtime = fixture.index("scripts/release_candidate.py verify-runtime")
    extract_gateway = fixture.index("scripts/release_candidate.py extract-gateway")
    cleanup = fixture.index("shutil.rmtree(workdir)")
    go_cache_cleanup = fixture.index("go clean -cache -modcache")
    uv_cache_cleanup = fixture.index("uv cache clean")
    export_version = fixture.index('echo "MACOS_CI_RELEASE_VERSION=$version"')
    assert verify_runtime < extract_gateway < cleanup < go_cache_cleanup < uv_cache_cleanup < export_version
    for confinement_check in (
        "candidate_root_input.is_symlink() or workdir_input.is_symlink()",
        "candidate_root_input.resolve(strict=True)",
        'candidate_root != workdir / "candidate-release"',
        'workdir_prefix = "defenseclaw-upgrade-smoke."',
        "workdir.parent not in trusted_roots",
    ):
        assert fixture.index(confinement_check, extract_gateway) < cleanup
    steps = yaml.safe_load(workflow)["jobs"]["build-and-test"]["steps"]
    setup_go = next(step for step in steps if str(step.get("uses", "")).startswith("actions/setup-go@"))
    setup_uv = next(step for step in steps if str(step.get("uses", "")).startswith("astral-sh/setup-uv@"))
    fixture_step = next(step for step in steps if step.get("name") == "Prepare reviewed runtime candidate fixture")
    assert setup_go["with"]["cache"] is False
    assert setup_uv["with"]["enable-cache"] is False
    assert fixture_step["env"] == {
        "GOCACHE": "${{ runner.temp }}/defenseclaw-macos-app-go-build-cache",
        "GOMODCACHE": "${{ runner.temp }}/defenseclaw-macos-app-go-module-cache",
        "UV_CACHE_DIR": "${{ runner.temp }}/defenseclaw-macos-app-uv-cache",
    }

    package_step = workflow[package : workflow.index("- uses:", package)]
    assert 'scripts/build-macos-app-release.sh "$MACOS_CI_RELEASE_VERSION" dist' in package_step
    assert "make macos-app-release" not in package_step
    for watched in (
        '"cli/**"',
        '"release/source-install-identity.json"',
        '"release/upgrade-baselines.json"',
        '"scripts/generate-upgrade-manifest.py"',
        '"scripts/release_candidate.py"',
        '"scripts/source_release_identity.py"',
        '"scripts/test-upgrade-protocol-release.sh"',
        '"scripts/test-upgrade-release.sh"',
        '".github/workflows/pre-release-certification.yml"',
    ):
        assert workflow.count(watched) == 1
    assert 'make -C "${build_root}" dist-cli DIST_DIR="${out}"' in smoke
    assert 'make -C "${build_root}" dist-plugin DIST_DIR="${out}"' in smoke
    assert '"${build_root}/scripts/generate-upgrade-manifest.py"' in smoke
    assert '"${build_root}/scripts/release_candidate.py" prepare-runtime' in smoke
    assert '"${build_root}/scripts/release_candidate.py" verify-runtime' in smoke


def test_macos_release_reclaims_build_intermediates_and_avoids_dmg_app_copy() -> None:
    build = BUILD_MACOS_RELEASE.read_text(encoding="utf-8")

    app_copy = build.index('ditto "${BUILT_APP}" "${PLAIN_APP}"')
    derived_cleanup = build.index('rm -rf "${DERIVED_DATA}"', app_copy)
    plain_sign = build.index('codesign "${sign_args[@]}" "${PLAIN_APP}"', derived_cleanup)
    dmg = build.index('echo "Creating unified drag-to-Applications DMG"')
    staging_link = build.index('ln -s /Applications "${UNIFIED_STAGE}/Applications"', dmg)
    source_size = build.index('DMG_SOURCE_KIB="$(du -sk "${UNIFIED_STAGE}"', staging_link)
    padded_size = build.index("DMG_SIZE_KIB=$((DMG_SOURCE_KIB + DMG_SOURCE_KIB / 5 + 65536))", source_size)
    image_create = build.index("hdiutil create", staging_link)
    unified_source = build.index('-srcfolder "${UNIFIED_STAGE}"', image_create)
    explicit_size = build.index('-size "${DMG_SIZE_KIB}k"', unified_source)

    assert (
        app_copy
        < derived_cleanup
        < plain_sign
        < dmg
        < staging_link
        < source_size
        < padded_size
        < image_create
        < unified_source
        < explicit_size
    )
    assert "DMG_STAGE=" not in build
    assert 'ditto "${APP}" "${DMG_STAGE}/DefenseClawMac.app"' not in build


def test_mac_app_runtime_update_exposes_only_runnable_authenticated_command() -> None:
    settings = SETTINGS.read_text(encoding="utf-8")
    app_state = APP_STATE.read_text(encoding="utf-8")
    update_checker = (ROOT / "macos/DefenseClawMac/DefenseClawMac/DataLayer/UpdateChecker.swift").read_text(
        encoding="utf-8"
    )
    main_window = (ROOT / "macos/DefenseClawMac/DefenseClawMac/Features/MainWindow.swift").read_text(encoding="utf-8")

    assert 'cli.run(arguments: ["upgrade", "--yes"])' not in app_state
    assert "Runtime upgrade was not started" in app_state
    assert "case actionRequired(guidance: String, command: String)" in update_checker
    assert "runtimeUpgradeState = .actionRequired(guidance: guidance, command: resolverCommand)" in app_state
    assert "case .actionRequired(let guidance, _)" in settings
    assert "case .actionRequired(let guidance, _)" in main_window
    assert 'Button("Copy Upgrade Command")' in settings
    assert 'Button("Copy Upgrade Command")' in main_window
    assert "copyToPasteboard(command)" in settings
    assert "copyToPasteboard(command)" in main_window
    assert "Copy Upgrade Path" not in settings
    assert "Show Upgrade Path" not in settings
    assert "Show Upgrade Path" not in main_window
    assert "isRuntimeFailed || isRuntimeActionRequired ? 4 : 1" in main_window
    assert "no installed files or services were changed" in app_state
    assert "authenticatedRuntimeUpgradeResolverCommand" in app_state
    assert "copy the authenticated resolver command" in app_state
    assert "defenseclaw-upgrade.sh" in settings
    assert "checksums" in settings
    assert "docs/CLI.md#upgrade" in settings
    assert "scripts/upgrade.sh resolver" not in app_state
    assert "scripts/upgrade.sh resolver" not in settings
    resolver_source = _source()
    assert "the 0.8.4 bridge" in resolver_source
    assert "rollback, migrations, and health checks" in resolver_source
    assert "Show Upgrade Command" in settings
    assert "The app does not run a bare CLI upgrade" in settings

    registry = COMMAND_REGISTRY.read_text(encoding="utf-8")
    assert "Run CLI upgrade preflight; hard cuts require the release-owned resolver" in registry
    assert 'summary: "Upgrade DefenseClaw"' not in registry


@pytest.mark.skipif(os.name == "nt", reason="macOS resolver validation requires /bin/bash")
def test_mac_app_resolver_command_is_raw_canonical_semver_gated_and_bash_syntax_valid() -> None:
    source = _source()
    function_start = source.index(
        "static func authenticatedRuntimeUpgradeResolverCommand(releaseTag: String) -> String?"
    )
    function_source = source[function_start:]
    assert 'releaseTag.hasPrefix("v") ? String(releaseTag.dropFirst()) : releaseTag' in function_source
    assert '#"^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"#' in function_source

    literal_start = function_source.index('return """') + len('return """')
    literal_end = function_source.index('        """', literal_start)
    command = textwrap.dedent(function_source[literal_start:literal_end]).strip()
    command = command.replace(
        r"\(assetBase)",
        "https://github.com/cisco-ai-defense/defenseclaw/releases/download/0.8.4",
    )
    command = command.replace(r"\\n", r"\n")

    assert command.startswith("(\n")
    assert command.endswith("\n)")
    assert "Authenticate and run" not in command
    assert "without --version" not in command
    assert "mktemp" not in command
    assert "curl --output" not in command
    assert 'checksums="$(curl ' in command
    assert 'resolver="$(curl ' in command
    assert "--certificate <(printf '%s\\n' \"$certificate\")" in command
    assert "--signature <(printf '%s\\n' \"$signature\")" in command
    assert "<(printf '%s\\n' \"$checksums\")" in command
    assert "printf '%s\\n' \"$resolver\" | sha" in command
    assert "bash -n <(printf '%s\\n' \"$resolver\")" in command
    assert "bash <(printf '%s\\n' \"$resolver\") --yes" in command
    assert command.index("unset VERSION") < command.index("bash <(printf '%s\\n' \"$resolver\") --yes")
    result = subprocess.run(
        ["/bin/bash", "-n"],
        input=command,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name == "nt", reason="macOS resolver execution requires /bin/bash")
def test_mac_app_resolver_command_executes_the_verified_in_memory_bytes(tmp_path: Path) -> None:
    source = _source()
    function_start = source.index(
        "static func authenticatedRuntimeUpgradeResolverCommand(releaseTag: String) -> String?"
    )
    function_source = source[function_start:]
    literal_start = function_source.index('return """') + len('return """')
    literal_end = function_source.index('        """', literal_start)
    command = textwrap.dedent(function_source[literal_start:literal_end]).strip()
    command = command.replace(
        r"\(assetBase)",
        "https://example.invalid/releases/0.8.4",
    ).replace(r"\\n", r"\n")

    resolver = textwrap.dedent(
        """\
        #!/usr/bin/env bash
        set -eu
        [ "${1:-}" = "--yes" ]
        printf 'ran\\n' > "$RESOLVER_RAN"
        # DefenseClaw upgrade resolver complete v1
        """
    )
    checksums = f"{hashlib.sha256(resolver.encode()).hexdigest()}  defenseclaw-upgrade.sh"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text(
        """#!/usr/bin/env python3
import os
import sys

url = sys.argv[-1]
assets = {
    "/checksums.txt": "FAKE_CHECKSUMS",
    "/checksums.txt.sig": "FAKE_SIGNATURE",
    "/checksums.txt.pem": "FAKE_CERTIFICATE",
    "/defenseclaw-upgrade.sh": "FAKE_RESOLVER",
}
key = next((value for suffix, value in assets.items() if url.endswith(suffix)), None)
if key is None:
    raise SystemExit(64)
sys.stdout.write(os.environ[key] + "\\n")
""",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    cosign = fake_bin / "cosign"
    cosign.write_text(
        """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
certificate = arguments[arguments.index("--certificate") + 1]
signature = arguments[arguments.index("--signature") + 1]
artifact = arguments[-1]
assert Path(certificate).read_text().rstrip("\\n") == os.environ["FAKE_CERTIFICATE"]
assert Path(signature).read_text().rstrip("\\n") == os.environ["FAKE_SIGNATURE"]
assert Path(artifact).read_text().rstrip("\\n") == os.environ["FAKE_CHECKSUMS"]
""",
        encoding="utf-8",
    )
    cosign.chmod(0o755)
    ran = tmp_path / "resolver-ran"
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_CHECKSUMS": checksums,
        "FAKE_SIGNATURE": "fixture-signature",
        "FAKE_CERTIFICATE": "fixture-certificate",
        "FAKE_RESOLVER": resolver.rstrip("\n"),
        "RESOLVER_RAN": str(ran),
    }

    completed = subprocess.run(
        ["/bin/bash", "-c", command],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
        env=environment,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert ran.read_text(encoding="utf-8") == "ran\n"
