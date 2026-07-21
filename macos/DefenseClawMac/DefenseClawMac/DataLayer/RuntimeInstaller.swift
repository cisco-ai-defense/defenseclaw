// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Bundled-runtime installer. scripts/build-macos-app-release.sh embeds the
// DefenseClaw release (Developer-ID or ad-hoc signed gateway + wheel +
// manifest) in Contents/Resources/RuntimePayload; this is the native port of
// scripts/install.sh's darwin flow that lays it down — no remote script is
// ever executed. Every mutating step runs through the shared activity store
// so its exact argv, live output, and exit status appear in the Activity
// panel; read-only probes stay silent, matching install.sh.

import CryptoKit
import Foundation

/// The runtime release embedded in the app bundle at build time.
struct RuntimePayload: Sendable {
    static let protectedArtifactMagic = Data(
        "DEFENSECLAW-PROTECTED-ARTIFACT-V1\n".utf8
    )
    static let protectedArtifactXORByte: UInt8 = 0xA5
    var version: String
    var tag: String
    var arch: String
    var gatewayURL: URL
    var gatewaySHA256: String
    var wheelURL: URL
    var wheelSHA256: String
    /// Optional dependency overrides — upstream pyproject's [tool.uv]
    /// override-dependencies (CVE floors + the textual>=8.2.7 pin the
    /// wheel's own scanner constraint would defeat). Applied with
    /// `uv pip install --overrides` to reproduce upstream's resolution.
    var overridesURL: URL?
    var overridesSHA256: String?

    /// Loaded once per launch — the bundle is immutable while running.
    static let bundled: RuntimePayload? = load()

    private static func load() -> RuntimePayload? {
        guard let resources = Bundle.main.resourceURL else { return nil }
        let payloadDir = resources.appendingPathComponent("RuntimePayload")
        let manifestURL = payloadDir.appendingPathComponent("payload-manifest.json")
        guard let data = try? Data(contentsOf: manifestURL),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let version = root["runtime_version"] as? String,
              let gateway = root["gateway"] as? [String: Any],
              let gatewayFile = gateway["file"] as? String,
              let gatewaySHA = gateway["sha256"] as? String,
              let wheel = root["wheel"] as? [String: Any],
              let wheelFile = wheel["file"] as? String,
              let wheelSHA = wheel["sha256"] as? String,
              wheelFile == "defenseclaw-\(version)-2-py3-none-any.dcwheel"
        else { return nil }
        let overrides = root["overrides"] as? [String: Any]
        let overridesFile = overrides?["file"] as? String
        return RuntimePayload(
            version: version,
            tag: (root["runtime_tag"] as? String) ?? version,
            arch: (root["arch"] as? String) ?? "",
            gatewayURL: payloadDir.appendingPathComponent(gatewayFile),
            gatewaySHA256: gatewaySHA,
            wheelURL: payloadDir.appendingPathComponent(wheelFile),
            wheelSHA256: wheelSHA,
            overridesURL: overridesFile.map(payloadDir.appendingPathComponent),
            overridesSHA256: overrides?["sha256"] as? String
        )
    }

    /// Re-hash the payload against its manifest before installing anything.
    /// The bundle seal already covers these files, but the installer is the
    /// last line of defense if the app is running unsealed (dev build, manual
    /// tampering). Returns a failure description, or nil when intact.
    func verifyIntegrity() -> String? {
        guard let gatewayActual = Self.sha256(of: gatewayURL) else {
            return "Bundled gateway is missing or unreadable."
        }
        guard gatewayActual == gatewaySHA256 else {
            return "Bundled gateway does not match its manifest checksum."
        }
        guard let wheelActual = Self.sha256(of: wheelURL) else {
            return "Bundled wheel is missing or unreadable."
        }
        guard wheelActual == wheelSHA256 else {
            return "Bundled wheel does not match its manifest checksum."
        }
        guard Self.protectedPayloadSHA256(of: wheelURL) != nil else {
            return "Bundled wheel is not a valid protected release artifact."
        }
        if let overridesURL {
            guard let overridesSHA256 else {
                return "Bundled dependency overrides are missing a manifest checksum."
            }
            guard let actual = Self.sha256(of: overridesURL), actual == overridesSHA256 else {
                return "Bundled dependency overrides do not match their manifest checksum."
            }
        }
        return nil
    }

    static func sha256(of url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try? handle.read(upToCount: 4 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func protectedPayloadSHA256(of url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard (try? handle.read(upToCount: protectedArtifactMagic.count))
                == protectedArtifactMagic else { return nil }
        var hasher = SHA256()
        var sawPayload = false
        while var chunk = try? handle.read(upToCount: 4 << 20), !chunk.isEmpty {
            sawPayload = true
            chunk.withUnsafeMutableBytes { bytes in
                for index in bytes.indices {
                    bytes[index] ^= protectedArtifactXORByte
                }
            }
            hasher.update(data: chunk)
        }
        guard sawPayload else { return nil }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

enum RuntimeInstallState: Equatable {
    case idle
    case running(String)
    case failed(String)
    case succeeded

    var isRunning: Bool { if case .running = self { true } else { false } }
}

// MARK: - Fresh install

extension AppState {
    private static let installerOrigin = "Runtime Installer"

    /// Lays the bundled runtime down following scripts/install.sh's fresh-install
    /// flow: uv → Python 3.12 → venv → wheel → gateway binary → CLI symlink →
    /// verify. Existing and partial installations must use the release-owned
    /// upgrade resolver so schema policy, bridge selection, rollback custody,
    /// migrations, and health checks cannot be bypassed by the app payload.
    /// The venv is built in a staging path and activated only after the wheel
    /// install succeeds. Configuration happens afterwards through
    /// `defenseclaw init`.
    func installBundledRuntime() async {
        guard !runtimeInstallState.isRunning else { return }
        guard installationMutationsAllowed else {
            runtimeInstallState = .failed(
                installationReadOnlyReason ?? "This installation is read only."
            )
            return
        }
        // `defenseclaw upgrade` mutates the same venv and gateway binary —
        // never run both at once.
        switch runtimeUpgradeState {
        case .checking, .downloading, .installing:
            runtimeInstallState = .failed("A runtime upgrade is in progress — wait for it to finish, then retry.")
            return
        default:
            break
        }
        defer { runtimeInstallRunID = nil }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dataHome = installationContext.homeRoot.path
        let venvDir = installationContext.venvURL.path
        let binDir = home + "/.local/bin"
        let activationJournal = dataHome + "/.fresh-install-activation-journal.json"

        guard let payload = RuntimePayload.bundled else {
            runtimeInstallState = .failed("This build has no bundled runtime payload.")
            return
        }
        guard payload.arch == "arm64" else {
            runtimeInstallState = .failed("Bundled payload is \(payload.arch); this Mac needs arm64. Use the install script instead.")
            return
        }

        // A prior process may have died between the three canonical no-replace
        // moves. Recover the exact, inode-bound plan before the ordinary
        // existing-install gate sees that partial activation.
        do {
            let preserved = try RuntimeInstallFilesystem.recoverFreshInstallActivation(
                journalPath: activationJournal,
                dataHome: dataHome,
                binDir: binDir,
                venvDir: venvDir
            )
            guard preserved.isEmpty else {
                runtimeInstallState = .failed(
                    "Recovered an interrupted fresh install while preserving concurrent state at \(preserved.joined(separator: ", ")). Resolve those paths before retrying."
                )
                return
            }
        } catch {
            runtimeInstallState = .failed(
                "An interrupted fresh install could not be recovered safely: \(error.localizedDescription). No unverified path was removed."
            )
            return
        }

        // This surface is deliberately fresh-install-only. Check every
        // standard managed target lexically (lstat, so dangling symlinks
        // count) to catch incomplete installs that cannot answer `--version`.
        // The read-only binary probes also catch Homebrew, pipx, custom-path,
        // and configured installs outside the standard per-user layout. Keep
        // this gate before locating/bootstraping uv, dependency downloads,
        // process stops, or any filesystem mutation.
        let dataHomeExistedBeforeInstall = RuntimeInstallFilesystem.lexicalPathExists(dataHome)
        if let marker = RuntimeInstallFilesystem.existingManagedRuntimeMarker(home: home) {
            runtimeInstallState = .failed(Self.existingRuntimeRefusal(marker: marker, payload: payload))
            return
        }
        if let marker = RuntimeInstallFilesystem.existingSelectedRuntimeMarker(
            dataHome: dataHome,
            venvDir: venvDir
        ) {
            runtimeInstallState = .failed(Self.existingRuntimeRefusal(marker: marker, payload: payload))
            return
        }
        if let installedCLI = await cli.locateBinary() {
            runtimeInstallState = .failed(
                Self.existingRuntimeRefusal(marker: installedCLI, payload: payload)
            )
            return
        }
        if let installedGateway = await cli.locateBinary(named: "defenseclaw-gateway") {
            runtimeInstallState = .failed(
                Self.existingRuntimeRefusal(marker: installedGateway, payload: payload)
            )
            return
        }

        runtimeInstallState = .running("Verifying bundled payload")
        if let problem = payload.verifyIntegrity() {
            runtimeInstallState = .failed(problem)
            return
        }

        let binDirectoryIdentity: RuntimeInstallFilesystem.PathIdentity
        do {
            let reservations = try RuntimeInstallFilesystem.ensureRealDirectoryTree(
                root: home,
                components: [".local", "bin"]
            )
            guard let reservation = reservations.last else {
                throw RuntimeInstallFilesystem.ActivationError.parentChanged(binDir)
            }
            binDirectoryIdentity = reservation.identity
        } catch {
            runtimeInstallState = .failed(
                "Fresh runtime installation refused an unsafe ~/.local/bin ancestor: \(error.localizedDescription). No existing state was changed."
            )
            return
        }
        let venvCLI = installationContext.runtimeCLIURL.path

        // ── uv ────────────────────────────────────────────────────────────
        runtimeInstallState = .running("Locating uv")
        var uv = await cli.locateBinary(named: "uv")
        if uv == nil, FileManager.default.isExecutableFile(atPath: home + "/.cargo/bin/uv") {
            uv = home + "/.cargo/bin/uv"
        }
        if uv == nil {
            uv = await bootstrapUV(home: home, binDirectoryIdentity: binDirectoryIdentity)
        }
        guard let uv else { return } // bootstrapUV already set the failure state

        // ── Python 3.12 ───────────────────────────────────────────────────
        runtimeInstallState = .running("Ensuring Python 3.12")
        // Expected to miss on Macs without 3.12 (install.sh probes silently
        // too) — a miss is not a failure, so it stays out of Activity.
        let find = await cli.run(binary: uv, arguments: ["python", "find", "3.12"], mutation: false)
        if !find.succeeded {
            runtimeInstallState = .running("Downloading Python 3.12 (network)")
            let install = await installerStep(
                "Install Python 3.12 (uv, ~40 MB download)",
                binary: uv,
                arguments: ["python", "install", "3.12"],
                successEffects: ["Python 3.12 installed (uv-managed)"]
            )
            guard install.succeeded else {
                fail(install, step: "Python 3.12 install")
                return
            }
        }

        // ── venv + wheel, staged (mirrors install.sh install_python_cli,
        // but never destroys a working venv before the network-dependent
        // dependency resolution has succeeded) ────────────────────────────
        let stagingDir = venvDir + ".staging-" + UUID().uuidString
        let dataHomeIdentity: RuntimeInstallFilesystem.PathIdentity
        do {
            if dataHome == home + "/.defenseclaw" {
                let reservations = try RuntimeInstallFilesystem.ensureRealDirectoryTree(
                    root: home,
                    components: [".defenseclaw"]
                )
                guard let reservation = reservations.last else {
                    throw RuntimeInstallFilesystem.ActivationError.parentChanged(dataHome)
                }
                dataHomeIdentity = reservation.identity
            } else {
                dataHomeIdentity = try RuntimeInstallFilesystem.ensureRealDirectoryPath(dataHome)
            }
            let venvParent = URL(fileURLWithPath: venvDir)
                .deletingLastPathComponent().path
            if venvParent != dataHome {
                _ = try RuntimeInstallFilesystem.ensureRealDirectoryPath(venvParent)
            }
        } catch {
            runtimeInstallState = .failed(
                "Fresh runtime installation refused an unsafe selected home or virtual-environment ancestor: \(error.localizedDescription). No existing state was changed."
            )
            return
        }
        let stagingIdentity: RuntimeInstallFilesystem.PathIdentity
        do {
            stagingIdentity = try RuntimeInstallFilesystem.createOwnedDirectory(stagingDir)
        } catch {
            runtimeInstallState = .failed(
                "Could not reserve installer-owned runtime staging: \(error.localizedDescription)"
            )
            return
        }

        runtimeInstallState = .running("Creating Python environment")
        let venv = await installerStep(
            "Create runtime environment (staging)",
            binary: uv,
            // --relocatable: entry-point scripts must survive the staging →
            // .venv rename without baked-in staging shebangs.
            arguments: ["venv", stagingDir, "--clear", "--relocatable", "--python", "3.12"],
            successEffects: ["Virtual environment staged"]
        )
        guard venv.succeeded else {
            RuntimeInstallFilesystem.cleanupFailedFreshInstall(
                stagingDir: stagingDir,
                stagingIdentity: stagingIdentity,
                dataHome: dataHome,
                removeDataHomeIfEmpty: !dataHomeExistedBeforeInstall
            )
            fail(venv, step: "Virtual environment creation")
            return
        }
        guard RuntimeInstallFilesystem.pathIdentity(stagingDir) == stagingIdentity else {
            runtimeInstallState = .failed(
                "Runtime staging was replaced during environment creation; concurrent state was preserved and nothing was activated."
            )
            return
        }

        runtimeInstallState = .running("Materializing authenticated runtime wheel")
        let materializedWheel = dataHome + "/defenseclaw-\(payload.version)-py3-none-any.whl"
        let materializedOverrides = dataHome + "/dependency-overrides-\(payload.version).txt"
        var materializedWheelIdentity: RuntimeInstallFilesystem.PathIdentity?
        var materializedOverridesIdentity: RuntimeInstallFilesystem.PathIdentity?
        do {
            materializedWheelIdentity = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                source: payload.wheelURL.path,
                destination: materializedWheel,
                expectedParentIdentity: dataHomeIdentity,
                mode: 0o600,
                stripPrefix: RuntimePayload.protectedArtifactMagic,
                decodeXORByte: RuntimePayload.protectedArtifactXORByte,
                expectedSourceSHA256: payload.wheelSHA256
            )
            if let overridesURL = payload.overridesURL,
               let overridesSHA256 = payload.overridesSHA256 {
                materializedOverridesIdentity = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                    source: overridesURL.path,
                    destination: materializedOverrides,
                    expectedParentIdentity: dataHomeIdentity,
                    mode: 0o600,
                    expectedSourceSHA256: overridesSHA256
                )
            }
        } catch {
            if let materializedWheelIdentity {
                _ = RuntimeInstallFilesystem.cleanupOwnedPath(
                    materializedWheel,
                    identity: materializedWheelIdentity
                )
            }
            RuntimeInstallFilesystem.cleanupFailedFreshInstall(
                stagingDir: stagingDir,
                stagingIdentity: stagingIdentity,
                dataHome: dataHome,
                removeDataHomeIfEmpty: !dataHomeExistedBeforeInstall
            )
            runtimeInstallState = .failed(
                "Could not materialize the authenticated runtime install inputs privately: \(error.localizedDescription)"
            )
            return
        }

        runtimeInstallState = .running("Installing DefenseClaw CLI \(payload.version) (network: PyPI dependencies)")
        var wheelArguments = ["pip", "install", "--python", stagingDir + "/bin/python"]
        if materializedOverridesIdentity != nil {
            // Upstream's own override-dependencies: without them a fresh
            // resolve honors the scanner's textual<8 cap and the TUI
            // crashes, and the CVE-driven floors are lost.
            wheelArguments += ["--overrides", materializedOverrides]
        }
        wheelArguments.append(materializedWheel)
        let wheel = await installerStep(
            "Install DefenseClaw CLI \(payload.version) (bundled wheel + PyPI dependencies)",
            binary: uv,
            arguments: wheelArguments,
            successEffects: ["DefenseClaw CLI \(payload.version) installed"]
        )
        let wheelCleanupSucceeded = materializedWheelIdentity.map {
            RuntimeInstallFilesystem.cleanupOwnedPath(
                materializedWheel,
                identity: $0
            )
        } ?? false
        let overridesCleanupSucceeded = materializedOverridesIdentity.map {
            RuntimeInstallFilesystem.cleanupOwnedPath(
                materializedOverrides,
                identity: $0
            )
        } ?? true
        guard wheelCleanupSucceeded, overridesCleanupSucceeded else {
            RuntimeInstallFilesystem.cleanupFailedFreshInstall(
                stagingDir: stagingDir,
                stagingIdentity: stagingIdentity,
                dataHome: dataHome,
                removeDataHomeIfEmpty: !dataHomeExistedBeforeInstall
            )
            runtimeInstallState = .failed(
                "Private runtime input cleanup could not prove ownership; installation was not activated."
            )
            return
        }
        guard wheel.succeeded else {
            RuntimeInstallFilesystem.cleanupFailedFreshInstall(
                stagingDir: stagingDir,
                stagingIdentity: stagingIdentity,
                dataHome: dataHome,
                removeDataHomeIfEmpty: !dataHomeExistedBeforeInstall
            )
            if wheel.cancelled {
                runtimeInstallState = .failed("Installation cancelled. No pre-existing runtime was changed; retry when ready.")
            } else {
                runtimeInstallState = .failed(
                    "CLI wheel install failed (exit \(wheel.exitCode)). This step downloads Python dependencies from pypi.org / files.pythonhosted.org — check network or proxy access. No pre-existing runtime was changed; retry after correcting the network issue. See Activity for output."
                )
            }
            return
        }
        let stagedVerify = await installerStep(
            "Verify staged DefenseClaw CLI",
            binary: stagingDir + "/bin/defenseclaw",
            arguments: ["--version"],
            category: "info"
        )
        guard stagedVerify.succeeded,
              UpdateChecker.parseVersion(stagedVerify.output) == payload.version
        else {
            RuntimeInstallFilesystem.cleanupFailedFreshInstall(
                stagingDir: stagingDir,
                stagingIdentity: stagingIdentity,
                dataHome: dataHome,
                removeDataHomeIfEmpty: !dataHomeExistedBeforeInstall
            )
            runtimeInstallState = .failed(
                "Staged CLI did not report the expected version \(payload.version). No pre-existing runtime was changed."
            )
            return
        }

        // ── Gateway binary + CLI link, staged ─────────────────────────────
        // The native no-replace copy re-authenticates the exact opened source
        // descriptor against the bundle manifest. The release build already
        // signed those exact bytes with the fixed gateway identifier; never
        // rewrite the staging inode with the install host's codesign version.
        // All three canonical targets remain absent until every component is
        // staged and ready for no-replace activation.
        runtimeInstallState = .running("Staging gateway \(payload.version)")
        let gatewayDest = binDir + "/defenseclaw-gateway"
        let cliDest = binDir + "/defenseclaw"
        let gatewayStage = gatewayDest + ".install-" + UUID().uuidString
        let cliStage = cliDest + ".install-" + UUID().uuidString
        var gatewayStageIdentity: RuntimeInstallFilesystem.PathIdentity?
        do {
            gatewayStageIdentity = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                source: payload.gatewayURL.path,
                destination: gatewayStage,
                expectedParentIdentity: binDirectoryIdentity,
                mode: 0o755,
                expectedSourceSHA256: payload.gatewaySHA256
            )
        } catch {
            RuntimeInstallFilesystem.cleanupFailedFreshInstall(
                stagingDir: stagingDir,
                stagingIdentity: stagingIdentity,
                dataHome: dataHome,
                removeDataHomeIfEmpty: !dataHomeExistedBeforeInstall
            )
            runtimeInstallState = .failed(
                "Could not stage the authenticated gateway bytes: \(error.localizedDescription)"
            )
            return
        }
        var cliStageIdentity: RuntimeInstallFilesystem.PathIdentity?
        func cleanupKnownStages() {
            if let gatewayStageIdentity {
                RuntimeInstallFilesystem.cleanupOwnedPath(
                    gatewayStage,
                    identity: gatewayStageIdentity
                )
            }
            if let cliStageIdentity {
                RuntimeInstallFilesystem.cleanupOwnedPath(
                    cliStage,
                    identity: cliStageIdentity
                )
            }
            RuntimeInstallFilesystem.cleanupFailedFreshInstall(
                stagingDir: stagingDir,
                stagingIdentity: stagingIdentity,
                dataHome: dataHome,
                removeDataHomeIfEmpty: !dataHomeExistedBeforeInstall
            )
        }
        guard let attestedGatewayIdentity = gatewayStageIdentity else {
            cleanupKnownStages()
            runtimeInstallState = .failed("Release-attested gateway staging identity is unavailable.")
            return
        }
        let signatureVerify = await installerStep(
            "Verify release-attested gateway signature and identifier",
            binary: "/usr/bin/codesign",
            arguments: [
                "--verify", "--strict", "-R",
                #"=identifier "com.cisco.defenseclaw.gateway""#,
                "--verbose=4", gatewayStage,
            ],
            category: "info"
        )
        guard signatureVerify.succeeded,
              RuntimeInstallFilesystem.pathIdentity(binDir) == binDirectoryIdentity,
              RuntimeInstallFilesystem.pathIdentity(gatewayStage) == attestedGatewayIdentity,
              RuntimePayload.sha256(of: URL(fileURLWithPath: gatewayStage))
                == payload.gatewaySHA256
        else {
            cleanupKnownStages()
            runtimeInstallState = .failed(
                "Release-attested gateway signature requirement, parent, or hash verification failed; nothing was activated."
            )
            return
        }
        let stagedGatewayVersion = await installerStep(
            "Verify staged DefenseClaw gateway",
            binary: gatewayStage,
            arguments: ["--version"],
            category: "info"
        )
        guard stagedGatewayVersion.succeeded,
              UpdateChecker.parseVersion(stagedGatewayVersion.output) == payload.version,
              RuntimeInstallFilesystem.pathIdentity(binDir) == binDirectoryIdentity,
              RuntimeInstallFilesystem.pathIdentity(gatewayStage) == attestedGatewayIdentity,
              RuntimePayload.sha256(of: URL(fileURLWithPath: gatewayStage))
                == payload.gatewaySHA256
        else {
            cleanupKnownStages()
            runtimeInstallState = .failed(
                "Staged gateway did not report expected version \(payload.version), or its parent/inode changed; nothing was activated."
            )
            return
        }

        runtimeInstallState = .running("Staging DefenseClaw CLI link")
        do {
            cliStageIdentity = try RuntimeInstallFilesystem.createOwnedSymbolicLink(
                cliStage,
                target: venvDir + "/bin/defenseclaw",
                expectedParentIdentity: binDirectoryIdentity
            )
        } catch {
            cleanupKnownStages()
            runtimeInstallState = .failed(
                "Staged CLI link creation was refused: \(error.localizedDescription). Concurrent state was preserved and nothing was activated."
            )
            return
        }
        guard RuntimeInstallFilesystem.pathIdentity(binDir) == binDirectoryIdentity,
              RuntimeInstallFilesystem.pathIdentity(gatewayStage) == attestedGatewayIdentity,
              RuntimePayload.sha256(of: URL(fileURLWithPath: gatewayStage))
                == payload.gatewaySHA256
        else {
            cleanupKnownStages()
            runtimeInstallState = .failed(
                "Runtime staging changed while creating the CLI link; concurrent state was preserved and nothing was activated."
            )
            return
        }

        guard let gatewayStageIdentity, let cliStageIdentity,
              let venvStageIdentity = RuntimeInstallFilesystem.pathIdentity(stagingDir),
              venvStageIdentity == stagingIdentity
        else {
            // Retire every stage whose inode this attempt captured. The final
            // venv identity check can fail after gateway and CLI staging have
            // succeeded; cleaning only the venv would strand those two known
            // installer-owned entries and make a retry fail closed.
            cleanupKnownStages()
            runtimeInstallState = .failed("Runtime staging identity could not be verified; nothing was activated.")
            return
        }

        runtimeInstallState = .running("Activating complete runtime")
        let activationTargets: [RuntimeInstallFilesystem.ActivationTarget]
        let activation: RuntimeInstallFilesystem.ActivationReceipt
        do {
            activationTargets = try RuntimeInstallFilesystem.prepareActivationTargets([
                (staged: stagingDir, destination: venvDir),
                (staged: gatewayStage, destination: gatewayDest),
                (staged: cliStage, destination: cliDest),
            ])
            // Ensure preparation captured exactly the inodes created by this
            // attempt before entering the no-replace transaction.
            guard activationTargets.map(\.stagedIdentity) == [
                venvStageIdentity, gatewayStageIdentity, cliStageIdentity,
            ] else {
                throw RuntimeInstallFilesystem.ActivationError.missingOrChangedStage(stagingDir)
            }
            activation = try RuntimeInstallFilesystem.activateNoReplace(
                activationTargets,
                journalPath: activationJournal
            )
        } catch {
            _ = RuntimeInstallFilesystem.cleanupOwnedPath(
                stagingDir,
                identity: venvStageIdentity
            )
            _ = RuntimeInstallFilesystem.cleanupOwnedPath(
                gatewayStage,
                identity: gatewayStageIdentity
            )
            _ = RuntimeInstallFilesystem.cleanupOwnedPath(
                cliStage,
                identity: cliStageIdentity
            )
            runtimeInstallState = .failed(
                "Fresh runtime activation was refused: \(error.localizedDescription). Retry after resolving the named concurrent or existing path."
            )
            return
        }

        // ── Verify ────────────────────────────────────────────────────────
        runtimeInstallState = .running("Verifying installation")
        let verify = await installerStep(
            "Verify DefenseClaw CLI",
            binary: venvCLI,
            arguments: ["--version"],
            category: "info",
            successEffects: ["Runtime \(payload.version) installed"],
            suggestedNextAction: "Run Initialize DefenseClaw to create the configuration."
        )
        guard verify.succeeded, let reported = UpdateChecker.parseVersion(verify.output) else {
            let preserved = RuntimeInstallFilesystem.rollbackActivation(activation)
            runtimeInstallState = .failed(
                preserved.isEmpty
                    ? "Installed CLI version check failed (exit \(verify.exitCode)); this attempt was removed and can be retried."
                    : "Installed CLI version check failed and concurrent state was preserved at \(preserved.joined(separator: ", "))."
            )
            return
        }
        guard reported == payload.version else {
            let preserved = RuntimeInstallFilesystem.rollbackActivation(activation)
            runtimeInstallState = .failed(
                preserved.isEmpty
                    ? "Installed CLI reports \(reported), expected \(payload.version); this attempt was removed and can be retried."
                    : "Installed CLI reports \(reported), expected \(payload.version), and concurrent state was preserved at \(preserved.joined(separator: ", "))."
            )
            return
        }
        let gatewayVerify = await installerStep(
            "Verify DefenseClaw gateway",
            binary: gatewayDest,
            arguments: ["--version"],
            category: "info"
        )
        guard gatewayVerify.succeeded,
              UpdateChecker.parseVersion(gatewayVerify.output) == payload.version
        else {
            let preserved = RuntimeInstallFilesystem.rollbackActivation(activation)
            runtimeInstallState = .failed(
                preserved.isEmpty
                    ? "Installed gateway did not report expected version \(payload.version); this attempt was removed and can be retried."
                    : "Installed gateway version check failed and concurrent state was preserved at \(preserved.joined(separator: ", "))."
            )
            return
        }

        do {
            try RuntimeInstallFilesystem.commitActivation(activation)
        } catch {
            let preserved = RuntimeInstallFilesystem.rollbackActivation(activation)
            runtimeInstallState = .failed(
                preserved.isEmpty
                    ? "Runtime health checks passed, but activation could not be committed durably; this attempt was removed and can be retried."
                    : "Runtime health checks passed, but activation commit failed and concurrent state was preserved at \(preserved.joined(separator: ", "))."
            )
            return
        }

        // No restart path belongs here: any pre-existing gateway was refused
        // before mutation, while a true fresh install has no process to stop.
        runtimeInstallState = .succeeded
        await refreshInstalledRuntimeVersion()
        reloadConfig()
    }

    /// One recorded installer step; tracks its runID so the first-run sheet's
    /// Cancel button can interrupt the current step.
    private func installerStep(
        _ title: String,
        binary: String,
        arguments: [String],
        category: String = "setup",
        successEffects: [String] = [],
        suggestedNextAction: String = ""
    ) async -> CLIResult {
        let id = UUID()
        runtimeInstallRunID = id
        return await runCommand(
            runID: id,
            title: title,
            binary: binary,
            arguments: arguments,
            category: category,
            origin: Self.installerOrigin,
            successEffects: successEffects,
            suggestedNextAction: suggestedNextAction
        )
    }

    private func fail(_ result: CLIResult, step: String) {
        runtimeInstallState = result.cancelled
            ? .failed("Installation cancelled during: \(step).")
            : .failed("\(step) failed (exit \(result.exitCode)). See Activity for output.")
    }

    /// Fetch uv from astral-sh GitHub releases as a checksum-verified binary
    /// download — deliberately not `curl | sh` (install.sh's approach) per
    /// the no-remote-scripts policy.
    private func bootstrapUV(
        home: String,
        binDirectoryIdentity: RuntimeInstallFilesystem.PathIdentity
    ) async -> String? {
        runtimeInstallState = .running("Downloading uv (network)")
        let uvVersion = "0.11.28"
        let asset = "uv-aarch64-apple-darwin.tar.gz"
        // Pinned from the immutable astral-sh/uv GitHub release. Updating uv
        // requires reviewing that release and replacing both values together.
        let expectedSHA256 = "33540eb7c883ab857eff79bd5ac2aa31fe27b595abecb4a9c003a2c998447232"
        let base = "https://github.com/astral-sh/uv/releases/download/\(uvVersion)/"
        let temporaryRoot = FileManager.default.temporaryDirectory
        let stageName = "dc-uv-bootstrap-" + UUID().uuidString
        let stage = temporaryRoot.appendingPathComponent(stageName)
        let stageIdentity: RuntimeInstallFilesystem.PathIdentity
        do {
            let reservations = try RuntimeInstallFilesystem.ensureRealDirectoryTree(
                root: temporaryRoot.path,
                components: [stageName]
            )
            guard let reservation = reservations.last else {
                runtimeInstallState = .failed("Could not reserve private uv bootstrap staging.")
                return nil
            }
            stageIdentity = reservation.identity
        } catch {
            runtimeInstallState = .failed(
                "Could not reserve private uv bootstrap staging: \(error.localizedDescription)"
            )
            return nil
        }
        defer {
            _ = RuntimeInstallFilesystem.cleanupOwnedPath(
                stage.path,
                identity: stageIdentity
            )
        }
        let tarball = stage.appendingPathComponent(asset).path

        let fetch = await installerStep(
            "Download pinned uv \(uvVersion) (astral-sh)",
            binary: "/usr/bin/curl",
            arguments: [
                "-fsSL", "--proto", "=https", "--tlsv1.2",
                "--connect-timeout", "15", "--max-time", "300",
                "--retry", "3", "--retry-connrefused",
                "-o", tarball, base + asset,
            ]
        )
        guard fetch.succeeded else {
            runtimeInstallState = fetch.cancelled
                ? .failed("Installation cancelled during: uv download.")
                : .failed("uv download failed (exit \(fetch.exitCode)). Install uv manually (brew install uv) and retry.")
            return nil
        }

        guard let actual = RuntimePayload.sha256(of: URL(fileURLWithPath: tarball)),
              actual == expectedSHA256
        else {
            runtimeInstallState = .failed("uv download failed checksum verification — not installing it.")
            return nil
        }

        let list = await installerStep(
            "Inspect uv archive",
            binary: "/usr/bin/tar",
            arguments: ["-tzf", tarball],
            category: "info"
        )
        let archiveRoot = "uv-aarch64-apple-darwin"
        let entriesAreSafe = list.succeeded && !list.output.split(separator: "\n").isEmpty
            && list.output.split(separator: "\n").allSatisfy { rawEntry in
                let entry = rawEntry.trimmingCharacters(in: .whitespacesAndNewlines)
                let components = entry.split(separator: "/", omittingEmptySubsequences: false)
                return !entry.hasPrefix("/")
                    && !components.contains("..")
                    && (entry == archiveRoot || entry.hasPrefix(archiveRoot + "/"))
            }
        guard entriesAreSafe else {
            runtimeInstallState = .failed("uv archive contains an unexpected or unsafe path — not extracting it.")
            return nil
        }

        let unpack = await installerStep(
            "Unpack uv",
            binary: "/usr/bin/tar",
            arguments: ["-xzf", tarball, "-C", stage.path]
        )
        guard unpack.succeeded else {
            fail(unpack, step: "uv unpack")
            return nil
        }
        let unpackedUV = stage.appendingPathComponent("uv-aarch64-apple-darwin/uv").path
        guard FileManager.default.isExecutableFile(atPath: unpackedUV) else {
            runtimeInstallState = .failed("uv archive did not contain the expected binary.")
            return nil
        }

        let destination = home + "/.local/bin/uv"
        runtimeInstallState = .running("Activating pinned uv")
        do {
            _ = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                source: unpackedUV,
                destination: destination,
                expectedParentIdentity: binDirectoryIdentity,
                mode: 0o755
            )
        } catch {
            runtimeInstallState = .failed(
                "uv activation refused an existing, concurrent, or redirected ~/.local/bin/uv: \(error.localizedDescription). The existing path was preserved."
            )
            return nil
        }
        return destination
    }

    private static func existingRuntimeRefusal(marker: String, payload: RuntimePayload) -> String {
        guard let resolverCommand = authenticatedRuntimeUpgradeResolverCommand(
            releaseTag: payload.tag
        ) else {
            return """
            Bundled runtime installation is fresh-install-only. An existing or partial DefenseClaw runtime was detected at \(marker).

            No installed files or services were changed. The bundled release identifier is not canonical, so no copy/paste upgrade command was produced. Use the authenticated resolver instructions at https://github.com/cisco-ai-defense/defenseclaw/blob/main/docs/CLI.md#upgrade.
            """
        }
        return """
        Bundled runtime installation is fresh-install-only. An existing or partial DefenseClaw runtime was detected at \(marker).

        No installed files or services were changed. Quit DefenseClaw, then authenticate and run the release-owned resolver in Terminal without --version so tested-source policy, the 0.8.4 bridge, rollback, migrations, and health checks remain mandatory (requires cosign):

        \(resolverCommand)
        """
    }

    /// Produce only the runnable, signed-release resolver command shared by
    /// every native-app refusal surface. Returning nil prevents a release tag
    /// from being interpolated into a URL unless it is canonical SemVer.
    static func authenticatedRuntimeUpgradeResolverCommand(releaseTag: String) -> String? {
        let tag = releaseTag.hasPrefix("v") ? String(releaseTag.dropFirst()) : releaseTag
        guard tag.range(
            of: #"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"#,
            options: .regularExpression
        ) != nil else { return nil }
        let assetBase = "https://github.com/cisco-ai-defense/defenseclaw/releases/download/\(tag)"
        return """
        (
          set -eu
          unset VERSION
          umask 077
          command -v cosign >/dev/null
          checksums="$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 '\(assetBase)/checksums.txt')"
          signature="$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 '\(assetBase)/checksums.txt.sig')"
          certificate="$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 '\(assetBase)/checksums.txt.pem')"
          resolver="$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 '\(assetBase)/defenseclaw-upgrade.sh')"
          cosign verify-blob --certificate <(printf '%s\\n' "$certificate") --signature <(printf '%s\\n' "$signature") --certificate-identity 'https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' <(printf '%s\\n' "$checksums")
          line="$(printf '%s\\n' "$checksums" | grep -E '^[0-9a-f]{64}  defenseclaw-upgrade[.]sh$')"
          [ "$(printf '%s\\n' "$line" | wc -l | tr -d ' ')" = 1 ]
          expected="${line%% *}"
          if command -v sha256sum >/dev/null; then
            actual="$(printf '%s\\n' "$resolver" | sha256sum | awk '{print $1}')"
          else
            actual="$(printf '%s\\n' "$resolver" | shasum -a 256 | awk '{print $1}')"
          fi
          [ "$actual" = "$expected" ]
          [ "$(printf '%s\\n' "$resolver" | tail -n 1)" = '# DefenseClaw upgrade resolver complete v1' ]
          bash -n <(printf '%s\\n' "$resolver")
          bash <(printf '%s\\n' "$resolver") --yes
        )
        """
    }
}
