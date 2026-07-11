# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Release guard for the unified macOS app's bundled runtime installer."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (
    ROOT
    / "macos"
    / "DefenseClawMac"
    / "DefenseClawMac"
    / "DataLayer"
    / "RuntimeInstaller.swift"
)
SETTINGS = (
    ROOT
    / "macos"
    / "DefenseClawMac"
    / "DefenseClawMac"
    / "Features"
    / "AppSettingsView.swift"
)
APP_STATE = (
    ROOT / "macos" / "DefenseClawMac" / "DefenseClawMac" / "App" / "AppState.swift"
)
FILESYSTEM = (
    ROOT
    / "macos"
    / "DefenseClawMac"
    / "DefenseClawMac"
    / "DataLayer"
    / "RuntimeInstallFilesystem.swift"
)
COMMAND_REGISTRY = (
    ROOT
    / "macos"
    / "DefenseClawMac"
    / "DefenseClawMac"
    / "DataLayer"
    / "CommandRegistry.swift"
)
BUILD_MACOS_RELEASE = ROOT / "scripts" / "build-macos-app-release.sh"
VERIFY_MACOS_RELEASE = ROOT / "scripts" / "verify-macos-app-release.sh"


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_bundled_runtime_installer_is_fresh_install_only_before_mutation() -> None:
    source = _source()

    guard = source.index("RuntimeInstallFilesystem.existingManagedRuntimeMarker(home: home)")
    configured_cli_probe = source.index("await cli.locateBinary()", guard)
    gateway_probe = source.index(
        'await cli.locateBinary(named: "defenseclaw-gateway")', configured_cli_probe
    )
    payload_verification = source.index(
        'runtimeInstallState = .running("Verifying bundled payload")', gateway_probe
    )
    dependency_boundary = source.index(
        'runtimeInstallState = .running("Locating uv")', payload_verification
    )

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
    guard = source.index(
        "guard let gatewayStageIdentity, let cliStageIdentity,\n"
        "              let venvStageIdentity"
    )
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
        "release-owned resolver asset without --version",
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
        'bash "$d/defenseclaw-upgrade.sh" --yes',
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
    signature_verify = source.index(
        '"Verify release-attested gateway signature and identifier"', gateway_stage
    )
    assert gateway_stage < signature_verify
    gateway_install = source[
        source.index("// ── Gateway binary + CLI link, staged") :
        source.index('runtimeInstallState = .running("Staging DefenseClaw CLI link")', signature_verify)
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
    assert '#"=identifier \"com.cisco.defenseclaw.gateway\""#' in source
    assert '"--verify", "--strict", "-R"' in source
    assert "signatureDisplay" not in source
    assert "== payload.gatewaySHA256" in source
    assert '"Verify staged DefenseClaw gateway"' in source

    build = BUILD_MACOS_RELEASE.read_text(encoding="utf-8")
    verify = VERIFY_MACOS_RELEASE.read_text(encoding="utf-8")
    assert (
        'codesign "${sign_args[@]}" --identifier com.cisco.defenseclaw.gateway'
        in build
    )
    assert '"gateway": {"file": "defenseclaw-gateway", "sha256": gateway_sha}' in build
    assert "outer app signing changed the release-attested gateway bytes" in build
    for script in (build, verify):
        assert 'GATEWAY_REQUIREMENT=\'=identifier "com.cisco.defenseclaw.gateway"\'' in script
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
    team_anchor = (
        "anchor apple generic and certificate leaf[subject.OU]"
        ' = \\"${EXPECTED_TEAM_ID}\\"'
    )

    for script in (build, verify):
        assert team_anchor in script
        assert '[[ "${EXPECTED_TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]]' in script

    base_requirement = 'GATEWAY_REQUIREMENT=\'=identifier "com.cisco.defenseclaw.gateway"\''
    build_base = build.index(base_requirement)
    build_production = build.index('if [[ "${SIGNING_IDENTITY}" != "-" ]]', build_base)
    build_anchor = build.index("GATEWAY_REQUIREMENT+=", build_production)
    assert build_base < build_production < build_anchor

    status_detection = verify.index(
        '[[ "${DMG}" != *-unverified.dmg ]] || DMG_UNVERIFIED=1'
    )
    verify_base = verify.index(base_requirement)
    verify_production = verify.index(
        'if [[ "${DMG_UNVERIFIED}" == "0" ]]', verify_base
    )
    verify_anchor = verify.index("GATEWAY_REQUIREMENT+=", verify_production)
    assert status_detection < verify_base < verify_production < verify_anchor
    assert 'APP_REQUIREMENT="=identifier \\"com.cisco.defenseclaw.macos\\"' in verify
    assert 'codesign --verify --strict -R "${APP_REQUIREMENT}"' in verify


def test_mac_app_runtime_update_is_guidance_only_and_never_runs_bare_cli_upgrade() -> None:
    settings = SETTINGS.read_text(encoding="utf-8")
    app_state = APP_STATE.read_text(encoding="utf-8")

    assert 'cli.run(arguments: ["upgrade", "--yes"])' not in app_state
    assert "Runtime upgrade was not started" in app_state
    assert "no installed files or services were changed" in app_state
    assert "authenticatedRuntimeUpgradeResolverGuidance" in app_state
    assert "authenticated release-asset path" in app_state
    assert "defenseclaw-upgrade.sh" in settings
    assert "checksums" in settings
    assert "docs/CLI.md#upgrade" in settings
    assert "scripts/upgrade.sh resolver" not in app_state
    assert "scripts/upgrade.sh resolver" not in settings
    resolver_source = _source()
    assert "the 0.8.4 bridge" in resolver_source
    assert "rollback, migrations, and health checks" in resolver_source
    assert "Show Upgrade Path" in settings
    assert "The app does not run a bare CLI upgrade" in settings

    registry = COMMAND_REGISTRY.read_text(encoding="utf-8")
    assert "Run CLI upgrade preflight; hard cuts require the release-owned resolver" in registry
    assert 'summary: "Upgrade DefenseClaw"' not in registry
