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
              let wheelSHA = wheel["sha256"] as? String
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
        if let overridesURL, let overridesSHA256 {
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
}

enum RuntimeInstallState: Equatable {
    case idle
    case running(String)
    case failed(String)
    case succeeded

    var isRunning: Bool { if case .running = self { true } else { false } }
}

// MARK: - Install / repair

extension AppState {
    private static let installerOrigin = "Runtime Installer"

    /// Lays the bundled runtime down following scripts/install.sh's darwin
    /// flow: uv → Python 3.12 → venv → wheel → gateway binary → CLI symlink →
    /// verify → gateway restart when one was running. Never touches
    /// config.yaml, .env, or audit.db, so the same call serves first install,
    /// upgrade-from-older, and repair. The venv is built in a staging path
    /// and swapped in only after the wheel install succeeds, so a failure
    /// (the dependency download needs PyPI) leaves an existing runtime
    /// working. Configuration happens afterwards through `defenseclaw init`.
    func installBundledRuntime() async {
        guard !runtimeInstallState.isRunning else { return }
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

        guard let payload = RuntimePayload.bundled else {
            runtimeInstallState = .failed("This build has no bundled runtime payload.")
            return
        }
        guard payload.arch == "arm64" else {
            runtimeInstallState = .failed("Bundled payload is \(payload.arch); this Mac needs arm64. Use the install script instead.")
            return
        }

        runtimeInstallState = .running("Verifying bundled payload")
        if let problem = payload.verifyIntegrity() {
            runtimeInstallState = .failed(problem)
            return
        }

        // A ~/.local/bin/defenseclaw symlink resolving outside ~/.defenseclaw
        // is a source-checkout (dev) install — never clobber it.
        if let devTarget = Self.devInstallTarget(home: home) {
            runtimeInstallState = .failed(
                "~/.local/bin/defenseclaw points at \(devTarget) — this looks like a development install. Refusing to overwrite it; remove the symlink first if you want the bundled runtime."
            )
            return
        }

        // Newer-installed guard: the payload only moves versions forward.
        // Only a healthy CLI's answer counts — a broken venv prints a
        // traceback whose paths contain "3.12", which must not be mistaken
        // for a version and block its own repair.
        let venvCLI = home + "/.defenseclaw/.venv/bin/defenseclaw"
        if FileManager.default.isExecutableFile(atPath: venvCLI) {
            let probe = await cli.run(binary: venvCLI, arguments: ["--version"])
            if probe.succeeded,
               let installed = UpdateChecker.parseVersion(probe.output),
               UpdateChecker.isNewer(installed, than: payload.version) {
                runtimeInstallState = .failed(
                    "Installed runtime \(installed) is newer than the bundled \(payload.version). Use Upgrade Runtime (defenseclaw upgrade) or update the Mac app for a newer payload."
                )
                return
            }
        }

        // ── uv ────────────────────────────────────────────────────────────
        runtimeInstallState = .running("Locating uv")
        var uv = await cli.locateBinary(named: "uv")
        if uv == nil, FileManager.default.isExecutableFile(atPath: home + "/.cargo/bin/uv") {
            uv = home + "/.cargo/bin/uv"
        }
        if uv == nil {
            uv = await bootstrapUV(home: home)
        }
        guard let uv else { return } // bootstrapUV already set the failure state

        // ── Python 3.12 ───────────────────────────────────────────────────
        runtimeInstallState = .running("Ensuring Python 3.12")
        // Expected to miss on Macs without 3.12 (install.sh probes silently
        // too) — a miss is not a failure, so it stays out of Activity.
        let find = await cli.run(binary: uv, arguments: ["python", "find", "3.12"])
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
        let venvDir = home + "/.defenseclaw/.venv"
        let stagingDir = venvDir + ".staging"

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
            fail(venv, step: "Virtual environment creation")
            return
        }

        runtimeInstallState = .running("Installing DefenseClaw CLI \(payload.version) (network: PyPI dependencies)")
        var wheelArguments = ["pip", "install", "--python", stagingDir + "/bin/python"]
        if let overridesURL = payload.overridesURL {
            // Upstream's own override-dependencies: without them a fresh
            // resolve honors the scanner's textual<8 cap and the TUI
            // crashes, and the CVE-driven floors are lost.
            wheelArguments += ["--overrides", overridesURL.path]
        }
        wheelArguments.append(payload.wheelURL.path)
        let wheel = await installerStep(
            "Install DefenseClaw CLI \(payload.version) (bundled wheel + PyPI dependencies)",
            binary: uv,
            arguments: wheelArguments,
            successEffects: ["DefenseClaw CLI \(payload.version) installed"]
        )
        guard wheel.succeeded else {
            try? FileManager.default.removeItem(atPath: stagingDir)
            if wheel.cancelled {
                runtimeInstallState = .failed("Installation cancelled. An existing runtime was left untouched.")
            } else {
                runtimeInstallState = .failed(
                    "CLI wheel install failed (exit \(wheel.exitCode)). This step downloads Python dependencies from pypi.org / files.pythonhosted.org — check network or proxy access. An existing runtime was left untouched; see Activity for output."
                )
            }
            return
        }

        runtimeInstallState = .running("Activating new environment")
        for (title, binary, arguments) in [
            ("Remove previous runtime environment", "/bin/rm", ["-rf", venvDir]),
            ("Activate new runtime environment", "/bin/mv", [stagingDir, venvDir]),
        ] {
            let result = await installerStep(title, binary: binary, arguments: arguments)
            guard result.succeeded else {
                fail(result, step: title)
                return
            }
        }

        // ── Gateway binary (mirrors install_gateway, minus the ad-hoc
        // codesign: the bundled gateway already carries the release's
        // Developer ID signature when credentials are configured, or its
        // ad-hoc signature for an explicitly unverified release) ──────────
        runtimeInstallState = .running("Installing gateway \(payload.version)")
        let binDir = home + "/.local/bin"
        let gatewayDest = binDir + "/defenseclaw-gateway"
        for (title, binary, arguments) in [
            ("Prepare ~/.local/bin", "/bin/mkdir", ["-p", binDir]),
            // Unlink first so a running gateway keeps executing its old inode.
            ("Remove previous gateway binary", "/bin/rm", ["-f", gatewayDest]),
            ("Install gateway \(payload.version)", "/bin/cp", [payload.gatewayURL.path, gatewayDest]),
            ("Mark gateway executable", "/bin/chmod", ["755", gatewayDest]),
            ("Link defenseclaw CLI", "/bin/ln", ["-sfh", venvDir + "/bin/defenseclaw", binDir + "/defenseclaw"]),
        ] {
            let result = await installerStep(title, binary: binary, arguments: arguments)
            guard result.succeeded else {
                fail(result, step: title)
                return
            }
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
            fail(verify, step: "Installed CLI version check")
            return
        }
        guard reported == payload.version else {
            runtimeInstallState = .failed("Installed CLI reports \(reported), expected \(payload.version).")
            return
        }

        // ── Restart a live gateway so it runs the new binary (upgrade-in-
        // place parity with `defenseclaw upgrade`); fresh installs have no
        // gateway yet and skip this. ──────────────────────────────────────
        if Self.liveGatewayPID(home: home) != nil {
            runtimeInstallState = .running("Restarting gateway")
            let restart = await installerStep(
                "Restart gateway (\(payload.version))",
                binary: gatewayDest,
                arguments: ["restart"],
                successEffects: ["Gateway restarted on \(payload.version)"]
            )
            guard restart.succeeded else {
                fail(restart, step: "Gateway restart")
                return
            }
        }

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
    private func bootstrapUV(home: String) async -> String? {
        runtimeInstallState = .running("Downloading uv (network)")
        let asset = "uv-aarch64-apple-darwin.tar.gz"
        let base = "https://github.com/astral-sh/uv/releases/latest/download/"
        let stage = FileManager.default.temporaryDirectory.appendingPathComponent("dc-uv-bootstrap")
        try? FileManager.default.removeItem(at: stage)
        try? FileManager.default.createDirectory(at: stage, withIntermediateDirectories: true)
        let tarball = stage.appendingPathComponent(asset).path
        let shaFile = stage.appendingPathComponent(asset + ".sha256").path

        for (title, target, url) in [
            ("Download uv (astral-sh, latest)", tarball, base + asset),
            ("Download uv checksum", shaFile, base + asset + ".sha256"),
        ] {
            let fetch = await installerStep(
                title,
                binary: "/usr/bin/curl",
                arguments: ["-fsSL", "--proto", "=https", "--tlsv1.2", "-o", target, url]
            )
            guard fetch.succeeded else {
                runtimeInstallState = fetch.cancelled
                    ? .failed("Installation cancelled during: uv download.")
                    : .failed("uv download failed (exit \(fetch.exitCode)). Install uv manually (brew install uv) and retry.")
                return nil
            }
        }

        guard let shaLine = try? String(contentsOfFile: shaFile, encoding: .utf8),
              let expected = shaLine.split(separator: " ").first.map(String.init),
              expected.count == 64,
              let actual = RuntimePayload.sha256(of: URL(fileURLWithPath: tarball)),
              actual == expected
        else {
            runtimeInstallState = .failed("uv download failed checksum verification — not installing it.")
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
        for (title, binary, arguments) in [
            ("Prepare ~/.local/bin", "/bin/mkdir", ["-p", home + "/.local/bin"]),
            ("Install uv", "/bin/cp", [unpackedUV, destination]),
            ("Mark uv executable", "/bin/chmod", ["755", destination]),
        ] {
            let result = await installerStep(
                title,
                binary: binary,
                arguments: arguments,
                successEffects: title == "Mark uv executable" ? ["uv installed to ~/.local/bin"] : []
            )
            guard result.succeeded else {
                fail(result, step: title)
                return nil
            }
        }
        return destination
    }

    /// Absolute target of a ~/.local/bin/defenseclaw symlink that resolves to
    /// an existing location outside ~/.defenseclaw — the marker of a dev
    /// (source checkout) install. nil for release installs, broken links, or
    /// no link at all.
    private static func devInstallTarget(home: String) -> String? {
        let link = home + "/.local/bin/defenseclaw"
        guard let destination = try? FileManager.default.destinationOfSymbolicLink(atPath: link) else {
            return nil
        }
        let resolved = destination.hasPrefix("/")
            ? destination
            : home + "/.local/bin/" + destination
        let standardized = (resolved as NSString).standardizingPath
        guard FileManager.default.fileExists(atPath: standardized) else { return nil }
        return standardized.hasPrefix(home + "/.defenseclaw/") ? nil : standardized
    }

    /// PID from ~/.defenseclaw/gateway.pid when that process is alive.
    private static func liveGatewayPID(home: String) -> Int32? {
        let url = URL(fileURLWithPath: home + "/.defenseclaw/gateway.pid")
        guard let data = try? Data(contentsOf: url) else { return nil }
        var pid: Int32?
        if let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
           let value = object["pid"] as? Int {
            pid = Int32(value)
        } else if let text = String(data: data, encoding: .utf8),
                  let value = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)) {
            pid = value
        }
        guard let pid, pid > 0, kill(pid, 0) == 0 else { return nil }
        return pid
    }
}
