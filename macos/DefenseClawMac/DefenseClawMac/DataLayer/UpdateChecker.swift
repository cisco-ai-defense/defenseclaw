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

// Self-update against the unified Cisco DefenseClaw GitHub Releases.
//
// The repo is public: both the release check and the asset download go
// through unauthenticated HTTPS to github.com — no gh CLI, no credentials.
// Install: download the release zip, unpack with ditto, swap the running
// .app bundle in place, strip quarantine, and relaunch.

import AppKit
import Foundation

struct ReleaseInfo: Sendable, Equatable {
    var tag: String          // e.g. "v0.3.1"
    var version: String      // e.g. "0.3.1"
    var assetName: String
    var assetURL: String     // browser_download_url
    var assetSHA256: String  // GitHub asset digest, without "sha256:"
    var htmlURL: String
    var notes: String
}

enum UpgradeState: Equatable {
    case idle
    case checking
    case downloading
    case installing
    /// No mutation failed; the operator must complete an external authenticated action.
    /// Keep human-readable guidance separate from the exact runnable command so
    /// copy actions never put explanatory prose on the operator's pasteboard.
    case actionRequired(guidance: String, command: String)
    case failed(String)
}

actor UpdateChecker {
    static let repo = "cisco-ai-defense/defenseclaw"
    /// The underlying DefenseClaw runtime (CLI + gateway) — upgraded via
    /// `defenseclaw upgrade`, but version-checked against its releases here.
    static let runtimeRepo = "cisco-ai-defense/defenseclaw"

    static var currentVersion: String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "0"
    }

    /// Numeric dotted-version comparison: true when `candidate` > `current`.
    static func isNewer(_ candidate: String, than current: String) -> Bool {
        func components(_ version: String) -> [Int]? {
            let parts = version.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count >= 2 else { return nil }
            let values = parts.compactMap { Int($0) }
            return values.count == parts.count ? values : nil
        }
        guard let a = components(candidate), let b = components(current) else { return false }
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    // MARK: - Check

    /// Latest Mac-app release.
    func latestRelease() async -> ReleaseInfo? {
        await fetchLatest(repo: Self.repo, requireSelfUpdateAsset: true)
    }

    /// Latest DefenseClaw runtime release (upstream repo).
    func latestRuntimeRelease() async -> ReleaseInfo? {
        await fetchLatest(repo: Self.runtimeRepo, requireSelfUpdateAsset: false)
    }

    /// Parse "defenseclaw, version 0.7.0"-style output into "0.7.0".
    static func parseVersion(_ output: String) -> String? {
        let pattern = #"[0-9]+(\.[0-9]+)+"#
        guard let range = output.range(of: pattern, options: .regularExpression) else { return nil }
        return String(output[range])
    }

    private func fetchLatest(repo: String, requireSelfUpdateAsset: Bool) async -> ReleaseInfo? {
        guard let url = URL(string: "https://api.github.com/repos/\(repo)/releases/latest") else { return nil }
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = dict["tag_name"] as? String
        else { return nil }
        return Self.releaseInfo(
            from: dict,
            repo: repo,
            tag: tag,
            requireSelfUpdateAsset: requireSelfUpdateAsset
        )
    }

    nonisolated static func releaseInfo(
        from dict: [String: Any],
        repo: String,
        tag: String,
        requireSelfUpdateAsset: Bool
    ) -> ReleaseInfo? {
        let assets = (dict["assets"] as? [[String: Any]]) ?? []
        let zip = Self.selectSelfUpdateAsset(from: assets)
        if requireSelfUpdateAsset && zip == nil {
            return nil
        }
        return ReleaseInfo(
            tag: tag,
            version: tag.hasPrefix("v") ? String(tag.dropFirst()) : tag,
            assetName: (zip?["name"] as? String) ?? "",
            assetURL: (zip?["browser_download_url"] as? String) ?? "",
            assetSHA256: ((zip?["digest"] as? String) ?? "")
                .replacingOccurrences(of: "sha256:", with: ""),
            htmlURL: (dict["html_url"] as? String) ?? "https://github.com/\(repo)/releases",
            notes: (dict["body"] as? String) ?? ""
        )
    }

    nonisolated static func selectSelfUpdateAsset(from assets: [[String: Any]]) -> [String: Any]? {
        assets.first {
            let name = ($0["name"] as? String) ?? ""
            return name.hasPrefix("DefenseClawMac-")
                && name.contains("-macos-arm64")
                && name.hasSuffix(".zip")
                && !name.contains("-unverified")
        }
    }

    // MARK: - Download + install + restart

    struct ZipArchiveEntry: Equatable {
        var path: String
        var mode: String
    }

    enum ArchiveValidationResult: Equatable {
        case success(appBundleName: String)
        case failure(String)
    }

    /// Downloads the release zip, swaps the current bundle, and relaunches.
    /// Returns an error message, or never returns (the app restarts) on success.
    func downloadAndInstall(_ release: ReleaseInfo, progress: @Sendable @escaping (UpgradeState) -> Void) async -> String? {
        guard Self.isNewer(release.version, than: Self.currentVersion) else {
            return "Refusing to install version \(release.version) over \(Self.currentVersion)."
        }
        guard let assetURL = URL(string: release.assetURL), !release.assetURL.isEmpty else {
            return "The latest release has no downloadable zip asset."
        }
        guard release.assetSHA256.count == 64 else {
            return "The release asset has no SHA-256 digest; refusing to install an unverifiable update."
        }

        progress(.downloading)
        let stage = FileManager.default.temporaryDirectory
            .appendingPathComponent("dc-update-\(release.version)")
        try? FileManager.default.removeItem(at: stage)
        try? FileManager.default.createDirectory(at: stage, withIntermediateDirectories: true)
        let zipPath = stage.appendingPathComponent(release.assetName.isEmpty ? "update.zip" : release.assetName)

        do {
            var request = URLRequest(url: assetURL, timeoutInterval: 30)
            request.setValue("application/octet-stream", forHTTPHeaderField: "Accept")
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = 30
            configuration.timeoutIntervalForResource = 300
            let session = URLSession(configuration: configuration)
            defer { session.invalidateAndCancel() }
            let (tmp, response) = try await session.download(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                return "Download failed (HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1))."
            }
            try? FileManager.default.removeItem(at: zipPath)
            try FileManager.default.moveItem(at: tmp, to: zipPath)
        } catch {
            return "Download failed: \(error.localizedDescription)"
        }
        guard RuntimePayload.sha256(of: zipPath) == release.assetSHA256.lowercased() else {
            return "Downloaded update failed SHA-256 verification."
        }

        progress(.installing)
        // Unpack with ditto (preserves bundle structure + signature).
        let unpackDir = stage.appendingPathComponent("unpacked")
        try? FileManager.default.createDirectory(at: unpackDir, withIntermediateDirectories: true)
        let entries = await Self.listZipEntries(zipPath)
        guard entries.exitCode == 0 else {
            return "Could not inspect update archive: \(entries.output)"
        }
        switch Self.validateUpdateArchive(entries: Self.parseZipEntries(entries.output)) {
        case .success:
            break
        case .failure(let message):
            return "Refusing unsafe update archive: \(message)"
        }
        let unzip = await Self.runProcess("/usr/bin/ditto", ["-xk", zipPath.path, unpackDir.path])
        guard unzip.exitCode == 0 else { return "Unpack failed: \(unzip.output)" }
        let appNames = (try? FileManager.default.contentsOfDirectory(atPath: unpackDir.path))?
            .filter { $0.hasSuffix(".app") } ?? []
        guard appNames.count == 1, let appName = appNames.first else {
            return "The release zip must contain exactly one .app bundle."
        }
        let newApp = unpackDir.appendingPathComponent(appName)

        guard let bundle = Bundle(url: newApp),
              bundle.bundleIdentifier == "com.cisco.defenseclaw.macos",
              (bundle.infoDictionary?["CFBundleShortVersionString"] as? String) == release.version
        else {
            return "The downloaded app has an unexpected bundle identifier or version."
        }
        let runtimePayload = newApp.appendingPathComponent("Contents/Resources/RuntimePayload")
        guard !FileManager.default.fileExists(atPath: runtimePayload.path) else {
            return "The app-only update unexpectedly contains a runtime payload."
        }
        let signature = await Self.runProcess(
            "/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", newApp.path]
        )
        guard signature.exitCode == 0 else {
            return "The downloaded app failed code-signature verification: \(signature.output)"
        }
        let assessment = await Self.runProcess(
            "/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=2", newApp.path]
        )
        guard assessment.exitCode == 0 else {
            return "The downloaded app failed Gatekeeper assessment: \(assessment.output)"
        }

        // Swap the running bundle: move the old aside (the running process keeps
        // executing from the moved inode), copy the new one into place.
        let targetPath = Bundle.main.bundlePath
        let backup = stage.appendingPathComponent("previous.app")
        do {
            try FileManager.default.moveItem(atPath: targetPath, toPath: backup.path)
        } catch {
            return "Could not replace \(targetPath): \(error.localizedDescription)"
        }
        let copy = await Self.runProcess("/usr/bin/ditto", [newApp.path, targetPath])
        if copy.exitCode != 0 {
            let rollback = Self.restoreBackup(backup: backup, targetPath: targetPath)
            return "Install failed: \(copy.output)\(rollback.map { " Rollback also failed: \($0)" } ?? "")"
        }
        let installedSignature = await Self.runProcess(
            "/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", targetPath]
        )
        if installedSignature.exitCode != 0 {
            let rollback = Self.restoreBackup(backup: backup, targetPath: targetPath)
            return "Installed app failed code-signature verification: \(installedSignature.output)\(rollback.map { " Rollback also failed: \($0)" } ?? "")"
        }
        let xattr = await Self.runProcess("/usr/bin/xattr", ["-dr", "com.apple.quarantine", targetPath])
        if xattr.exitCode != 0 {
            let rollback = Self.restoreBackup(backup: backup, targetPath: targetPath)
            return "Could not prepare the installed app for launch: \(xattr.output)\(rollback.map { " Rollback also failed: \($0)" } ?? "")"
        }

        // Relaunch: detached child outlives this process. It must WAIT for
        // this process to fully exit before calling open — with the old
        // instance still alive, LaunchServices sees a running app with the
        // same bundle ID and merely activates it (the moved previous.app
        // backup!) instead of launching the updated bundle. Bounded at ~30s
        // so a hung teardown still eventually relaunches.
        let pid = ProcessInfo.processInfo.processIdentifier
        let relaunch = Process()
        relaunch.executableURL = URL(fileURLWithPath: "/bin/sh")
        relaunch.arguments = ["-c", """
            pid="$1"; target="$2"; stage="$3"
            for _ in $(seq 1 150); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
            /usr/bin/open "$target"
            rc=$?
            /bin/rm -rf "$stage"
            exit $rc
            """, "defenseclaw-relaunch", "\(pid)", targetPath, stage.path]
        do {
            try relaunch.run()
        } catch {
            let rollback = Self.restoreBackup(backup: backup, targetPath: targetPath)
            return "Could not start the app relaunch helper: \(error.localizedDescription)\(rollback.map { " Rollback also failed: \($0)" } ?? "")"
        }

        await MainActor.run { NSApp.terminate(nil) }
        return nil // unreachable in practice
    }

    // MARK: - Process helper

    nonisolated static func validateUpdateArchive(entries: [ZipArchiveEntry]) -> ArchiveValidationResult {
        guard !entries.isEmpty else {
            return .failure("archive is empty")
        }
        var topLevelNames = Set<String>()
        var appBundleName: String?
        for entry in entries {
            let path = entry.path.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let first = path.split(separator: "/", omittingEmptySubsequences: true).first else {
                return .failure("empty archive path")
            }
            guard !path.hasPrefix("/"), !path.hasPrefix("~") else {
                return .failure("unsafe path \(path)")
            }
            let components = path.split(separator: "/", omittingEmptySubsequences: true)
            guard !components.contains("..") else {
                return .failure("unsafe path \(path)")
            }
            guard !entry.mode.hasPrefix("l") && !entry.mode.hasPrefix("h") else {
                return .failure("link entry \(path) is not allowed")
            }
            guard entry.mode.hasPrefix("-") || entry.mode.hasPrefix("d") else {
                return .failure("unsupported archive entry type for \(path)")
            }
            let root = String(first)
            topLevelNames.insert(root)
            if root.hasSuffix(".app") {
                if appBundleName == nil {
                    appBundleName = root
                } else if appBundleName != root {
                    return .failure("archive must contain a single top-level .app bundle")
                }
            }
        }
        guard topLevelNames.count == 1, let appBundleName else {
            return .failure("archive must contain a single top-level .app bundle")
        }
        return .success(appBundleName: appBundleName)
    }

    nonisolated static func parseZipEntries(_ output: String) -> [ZipArchiveEntry] {
        output.split(whereSeparator: \.isNewline).compactMap { rawLine in
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { return nil }
            let fields = line.split(separator: " ", maxSplits: 9, omittingEmptySubsequences: true)
            guard fields.count == 10, fields[0].count == 10 else { return nil }
            return ZipArchiveEntry(path: String(fields[9]), mode: String(fields[0]))
        }
    }

    nonisolated static func listZipEntries(_ zipPath: URL) async -> (exitCode: Int32, output: String) {
        await runProcess("/usr/bin/zipinfo", ["-l", zipPath.path])
    }

    nonisolated static func runProcess(
        _ launchPath: String,
        _ arguments: [String]
    ) async -> (exitCode: Int32, output: String) {
        await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: launchPath)
            process.arguments = arguments
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            let readTask = Task.detached {
                pipe.fileHandleForReading.readDataToEndOfFile()
            }
            process.terminationHandler = { process in
                Task {
                    let data = await readTask.value
                    continuation.resume(returning: (
                        process.terminationStatus,
                        String(data: data, encoding: .utf8) ?? "[process output was not valid UTF-8]"
                    ))
                }
            }
            do {
                try process.run()
            } catch {
                process.terminationHandler = nil
                try? pipe.fileHandleForWriting.close()
                continuation.resume(returning: (
                    126,
                    "failed to launch \(launchPath): \(error.localizedDescription)"
                ))
            }
        }
    }

    nonisolated private static func restoreBackup(backup: URL, targetPath: String) -> String? {
        do {
            if FileManager.default.fileExists(atPath: targetPath) {
                try FileManager.default.removeItem(atPath: targetPath)
            }
            try FileManager.default.moveItem(atPath: backup.path, toPath: targetPath)
            return nil
        } catch {
            return error.localizedDescription
        }
    }
}
