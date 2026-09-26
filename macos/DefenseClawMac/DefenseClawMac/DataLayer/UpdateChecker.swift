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

// Release check and installer fetch against the unified Cisco DefenseClaw
// GitHub Releases.
//
// The repo is public: both the release check and the installer download go
// through unauthenticated HTTPS to github.com — no gh CLI, no credentials.
// The app and the runtime ship as one release, and that release's install.sh
// is the only updater: it installs the runtime and swaps this .app bundle,
// rolling back on failure. The app downloads it, verifies it against the
// release's checksums.txt, runs it, and relaunches if the bundle changed.

import CryptoKit
import Foundation

struct ReleaseInfo: Sendable, Equatable {
    var tag: String          // e.g. "1.0.1"
    var version: String      // e.g. "1.0.1"
    var htmlURL: String
}

enum InstallerFetchError: Error, Equatable, LocalizedError {
    case invalidVersion(String)
    case unsupportedVersion(String)
    case downloadFailed(asset: String, reason: String)
    case missingChecksum
    case checksumMismatch
    case stagingFailed(String)
    case signatureInvalid

    var errorDescription: String? {
        switch self {
        case .invalidVersion(let version):
            "\(version) is not a DefenseClaw release version (expected X.Y.Z)."
        case .unsupportedVersion(let version):
            "DefenseClaw \(version) predates the 1.0 installer; install \(UpdateChecker.minimumInstallerVersion) or later."
        case .downloadFailed(let asset, let reason):
            "Could not download \(asset) from the DefenseClaw release: \(reason)"
        case .missingChecksum:
            "The release's checksums.txt has no single entry for install.sh; refusing to run an unverifiable installer."
        case .checksumMismatch:
            "The downloaded install.sh does not match the release's checksums.txt; refusing to run it."
        case .stagingFailed(let reason):
            "Could not save the verified installer: \(reason)"
        case .signatureInvalid:
            "The release signature on checksums.txt did not verify with cosign; refusing to run the installer."
        }
    }
}

/// install.sh progress — one flow for the first-run install and for updates.
enum InstallerState: Equatable {
    case idle
    case downloading(version: String)
    case running(version: String)
    /// install.sh exited 0.
    case installed(version: String)
    /// install.sh exited 3: installed, but a connector needs attention.
    case needsAttention(version: String, detail: String)
    /// Any other outcome. install.sh has already rolled back on its own.
    case failed(version: String, detail: String)

    var isBusy: Bool {
        switch self {
        case .downloading, .running: true
        default: false
        }
    }

    var version: String? {
        switch self {
        case .idle: nil
        case .downloading(let version), .running(let version), .installed(let version),
             .needsAttention(let version, _), .failed(let version, _): version
        }
    }

    /// The installer contract: exit 0 installed, exit 3 installed with a
    /// connector warning, anything else failed. Both carry the last lines.
    static func finished(version: String, exitCode: Int32, cancelled: Bool, output: String) -> InstallerState {
        guard !cancelled else {
            return .failed(
                version: version,
                detail: "The installer was interrupted before it finished. Try again to complete the installation."
            )
        }
        let tail = output.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .suffix(4)
            .joined(separator: "\n")
        switch exitCode {
        case 0:
            return .installed(version: version)
        case 3:
            return .needsAttention(version: version, detail: tail.isEmpty ? "Run defenseclaw doctor for details." : tail)
        default:
            return .failed(version: version, detail: tail.isEmpty ? "install.sh exited \(exitCode)." : tail)
        }
    }
}

actor UpdateChecker {
    static let repo = "cisco-ai-defense/defenseclaw"
    /// Earlier installers predate the app contract (exit 3, DEFENSECLAW_APP_PATH).
    static let minimumInstallerVersion = "1.0.0"

    static var currentVersion: String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "0"
    }

    /// True when `candidate` is a plain release (`X.Y.Z`, optional leading
    /// `v`) whose number is greater than `current`. `current` may carry a
    /// source/build suffix; an equal-number development install is left in
    /// place, and a pre-release or unknown candidate never looks newer.
    static func isNewer(_ candidate: String, than current: String) -> Bool {
        candidate.range(of: #"^v?[0-9]+(\.[0-9]+)+$"#, options: .regularExpression) != nil
            && releaseNumber(candidate, exceeds: current)
    }

    /// Numeric comparison that ignores a source/build suffix on either side.
    /// Unknown versions never compare greater.
    static func releaseNumber(_ version: String, exceeds other: String) -> Bool {
        guard let a = numericVersionComponents(version),
              let b = numericVersionComponents(other) else { return false }
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    private static func numericVersionComponents(_ version: String) -> [Int]? {
        let pattern = #"^v?([0-9]+(?:\.[0-9]+)+)(?:[-+][A-Za-z0-9][A-Za-z0-9.+-]*)?$"#
        guard let expression = try? NSRegularExpression(pattern: pattern),
              let match = expression.firstMatch(in: version, range: NSRange(version.startIndex..., in: version)),
              let range = Range(match.range(at: 1), in: version) else { return nil }
        let parts = version[range].split(separator: ".")
        let numbers = parts.compactMap { Int($0) }
        return numbers.count == parts.count ? numbers : nil
    }

    /// Read only an explicit CLI/gateway version line. Runtime startup can
    /// emit Go/Sonic warnings containing unrelated version numbers first.
    static func parseVersion(_ output: String) -> String? {
        let pattern = #"(?im)^\s*defenseclaw(?:-gateway)?(?:,)?\s+(?:version\s+)?v?([0-9]+(?:\.[0-9]+)+(?:[-+][A-Za-z0-9][A-Za-z0-9.+-]*)?)(?=\s|$)"#
        guard let expression = try? NSRegularExpression(pattern: pattern),
              let match = expression.firstMatch(in: output, range: NSRange(output.startIndex..., in: output)),
              let range = Range(match.range(at: 1), in: output) else { return nil }
        return String(output[range])
    }

    // MARK: - Check

    /// Latest DefenseClaw release. The app and the runtime ship together, so
    /// one lookup covers both; nil means the lookup failed.
    func latestRelease() async -> ReleaseInfo? {
        guard let url = URL(string: "https://api.github.com/repos/\(Self.repo)/releases/latest") else { return nil }
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = dict["tag_name"] as? String
        else { return nil }
        return Self.releaseInfo(from: dict, tag: tag)
    }

    nonisolated static func releaseInfo(from dict: [String: Any], tag: String) -> ReleaseInfo {
        ReleaseInfo(
            tag: tag,
            version: tag.hasPrefix("v") ? String(tag.dropFirst()) : tag,
            htmlURL: (dict["html_url"] as? String) ?? "https://github.com/\(repo)/releases"
        )
    }

    // MARK: - Installer

    /// Download `version`'s install.sh and checksums.txt, verify the script's
    /// SHA-256, and stage both in a private directory. Returns install.sh.
    func fetchInstaller(version: String) async throws -> URL {
        guard Self.isReleaseVersion(version) else { throw InstallerFetchError.invalidVersion(version) }
        guard !Self.isNewer(Self.minimumInstallerVersion, than: version) else {
            throw InstallerFetchError.unsupportedVersion(version)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 120
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let installer = try await Self.download("install.sh", version: version, session: session)
        let checksums = try await Self.download("checksums.txt", version: version, session: session)
        let script = try Self.stageInstaller(installer, checksums: String(decoding: checksums, as: UTF8.self))
        // With cosign installed, check the release signature before trusting
        // checksums.txt, as `defenseclaw upgrade` does. Every release carries
        // the bundle, so a missing one is refused too.
        guard let cosign = Self.installedCosign() else { return script }
        let directory = script.deletingLastPathComponent()
        do {
            let bundle = try await Self.download("checksums.txt.bundle", version: version, session: session)
            try bundle.write(to: directory.appendingPathComponent("checksums.txt.bundle", isDirectory: false))
            try await Task.detached { try Self.verifyReleaseSignature(cosign: cosign, directory: directory) }.value
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
        return script
    }

    /// cosign 2.0 or later where Homebrew and manual installs put it; a GUI
    /// app does not inherit the login shell's PATH.
    nonisolated static func installedCosign(
        candidates: [String] = ["/opt/homebrew/bin/cosign", "/usr/local/bin/cosign"]
    ) -> String? {
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            if let major = cosignMajorVersion(run(path, ["version"]).output), major >= 2 {
                return path
            }
        }
        return nil
    }

    nonisolated static func cosignMajorVersion(_ output: String) -> Int? {
        guard let range = output.range(of: #"GitVersion:\s*v?(\d+)\."#, options: .regularExpression) else { return nil }
        let digits = output[range].drop { !$0.isNumber }.prefix { $0.isNumber }
        return Int(digits)
    }

    /// Verify checksums.txt in `directory` against checksums.txt.bundle, signed
    /// by this repository's release workflow on main.
    nonisolated static func verifyReleaseSignature(cosign: String, directory: URL) throws {
        let signer = "^https://github\\.com/" + repo.replacingOccurrences(of: ".", with: "\\.")
            + "/\\.github/workflows/release\\.yaml@refs/heads/main$"
        let result = run(cosign, [
            "verify-blob",
            "--bundle", directory.appendingPathComponent("checksums.txt.bundle").path,
            "--certificate-identity-regexp", signer,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            directory.appendingPathComponent("checksums.txt").path,
        ])
        guard result.status == 0 else { throw InstallerFetchError.signatureInvalid }
    }

    private nonisolated static func run(_ executable: String, _ arguments: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return (-1, "")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    nonisolated static func isReleaseVersion(_ version: String) -> Bool {
        version.range(
            of: #"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"#,
            options: .regularExpression
        ) != nil
    }

    /// The release's immutable asset URL — never a branch or `latest` URL.
    nonisolated static func releaseAssetURL(_ asset: String, version: String) -> URL? {
        guard isReleaseVersion(version) else { return nil }
        return URL(string: "https://github.com/\(repo)/releases/download/\(version)/\(asset)")
    }

    private static func download(_ asset: String, version: String, session: URLSession) async throws -> Data {
        guard let url = releaseAssetURL(asset, version: version) else {
            throw InstallerFetchError.invalidVersion(version)
        }
        var request = URLRequest(url: url)
        request.setValue("application/octet-stream", forHTTPHeaderField: "Accept")
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw InstallerFetchError.downloadFailed(asset: asset, reason: error.localizedDescription)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        guard status == 200 else {
            throw InstallerFetchError.downloadFailed(asset: asset, reason: "HTTP \(status)")
        }
        return data
    }

    /// The digest checksums.txt (`<sha256>  <name>` lines) records for
    /// `asset`, or nil when the entry is missing, duplicated, or malformed.
    nonisolated static func expectedSHA256(of asset: String, in checksums: String) -> String? {
        let entries = checksums.split(whereSeparator: \.isNewline)
            .map { $0.split(whereSeparator: \.isWhitespace) }
            .filter { $0.count == 2 && $0[1] == asset }
        guard entries.count == 1 else { return nil }
        let digest = entries[0][0].lowercased()
        return digest.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) == nil ? nil : digest
    }

    /// Verify `installer` against checksums.txt, then write both into a fresh
    /// 0700 directory under `parent`. Nothing is written unless verified.
    nonisolated static func stageInstaller(
        _ installer: Data,
        checksums: String,
        in parent: URL = FileManager.default.temporaryDirectory
    ) throws -> URL {
        guard let expected = expectedSHA256(of: "install.sh", in: checksums) else {
            throw InstallerFetchError.missingChecksum
        }
        let actual = SHA256.hash(data: installer).map { String(format: "%02x", $0) }.joined()
        guard actual == expected else { throw InstallerFetchError.checksumMismatch }

        let fileManager = FileManager.default
        let directory = parent.appendingPathComponent(
            "DefenseClaw-installer-" + UUID().uuidString,
            isDirectory: true
        )
        do {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: NSNumber(value: Int16(0o700))]
            )
        } catch {
            throw InstallerFetchError.stagingFailed(error.localizedDescription)
        }
        let script = directory.appendingPathComponent("install.sh", isDirectory: false)
        let files = [
            (script, installer),
            (directory.appendingPathComponent("checksums.txt", isDirectory: false), Data(checksums.utf8)),
        ]
        for (url, contents) in files {
            guard fileManager.createFile(
                atPath: url.path,
                contents: contents,
                attributes: [.posixPermissions: NSNumber(value: Int16(0o600))]
            ) else {
                try? fileManager.removeItem(at: directory)
                throw InstallerFetchError.stagingFailed("could not write \(url.lastPathComponent)")
            }
        }
        return script
    }

    /// A source install from a checkout leaves this marker beside its CLI.
    /// install.sh would replace that runtime, so the app never runs it while
    /// the marker (or anything at its path, including a dangling link) exists.
    nonisolated static func sourceRuntimeMarker(home: String) -> String? {
        let marker = home + "/.local/bin/.defenseclaw-source-root"
        var metadata = stat()
        return lstat(marker, &metadata) == 0 ? marker : nil
    }

    // MARK: - Bundle swap

    /// install.sh replaces the bundle at DEFENSECLAW_APP_PATH, so the folder
    /// holding it must be writable — a mounted disk image or an App
    /// Translocation mount is not.
    nonisolated static func canReplaceBundle(atPath path: String) -> Bool {
        FileManager.default.isWritableFile(
            atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path
        )
    }

    /// The version of the bundle now on disk at `path`, read from Info.plist
    /// directly: Bundle caches the dictionary it loaded at launch.
    nonisolated static func bundleShortVersion(atPath path: String) -> String? {
        let plist = URL(fileURLWithPath: path).appendingPathComponent("Contents/Info.plist", isDirectory: false)
        guard let data = try? Data(contentsOf: plist),
              let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return nil }
        return info["CFBundleShortVersionString"] as? String
    }

    /// Start a detached helper that reopens `bundlePath` after this process
    /// exits. It must WAIT: with this instance still alive, LaunchServices
    /// only activates it instead of launching the replaced bundle. Bounded at
    /// ~30s so a hung teardown still relaunches.
    nonisolated static func relaunchAfterExit(bundlePath: String) throws {
        let helper = Process()
        helper.executableURL = URL(fileURLWithPath: "/bin/sh")
        helper.arguments = ["-c", """
            pid="$1"; target="$2"
            for _ in $(seq 1 150); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
            exec /usr/bin/open "$target"
            """, "defenseclaw-relaunch", "\(ProcessInfo.processInfo.processIdentifier)", bundlePath]
        try helper.run()
    }
}
