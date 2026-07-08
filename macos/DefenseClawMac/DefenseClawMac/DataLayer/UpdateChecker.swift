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
    var htmlURL: String
    var notes: String
}

enum UpgradeState: Equatable {
    case idle
    case checking
    case downloading
    case installing
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
        let a = candidate.split(separator: ".").map { Int($0) ?? 0 }
        let b = current.split(separator: ".").map { Int($0) ?? 0 }
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
        await fetchLatest(repo: Self.repo)
    }

    /// Latest DefenseClaw runtime release (upstream repo).
    func latestRuntimeRelease() async -> ReleaseInfo? {
        await fetchLatest(repo: Self.runtimeRepo)
    }

    /// Parse "defenseclaw, version 0.7.0"-style output into "0.7.0".
    static func parseVersion(_ output: String) -> String? {
        let pattern = #"[0-9]+(\.[0-9]+)+"#
        guard let range = output.range(of: pattern, options: .regularExpression) else { return nil }
        return String(output[range])
    }

    private func fetchLatest(repo: String) async -> ReleaseInfo? {
        guard let url = URL(string: "https://api.github.com/repos/\(repo)/releases/latest") else { return nil }
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = dict["tag_name"] as? String
        else { return nil }
        let assets = (dict["assets"] as? [[String: Any]]) ?? []
        let appZips = assets.filter {
            let name = ($0["name"] as? String) ?? ""
            return name.hasPrefix("DefenseClawMac-")
                && name.contains("-macos-arm64")
                && name.hasSuffix(".zip")
        }
        // Prefer a Developer ID signed + notarized artifact once release
        // credentials are configured. Until then, releases intentionally use
        // the explicit "unverified" suffix.
        let zip = appZips.first {
            !(($0["name"] as? String) ?? "").contains("-unverified")
        } ?? appZips.first
        return ReleaseInfo(
            tag: tag,
            version: tag.hasPrefix("v") ? String(tag.dropFirst()) : tag,
            assetName: (zip?["name"] as? String) ?? "",
            assetURL: (zip?["browser_download_url"] as? String) ?? "",
            htmlURL: (dict["html_url"] as? String) ?? "https://github.com/\(repo)/releases",
            notes: (dict["body"] as? String) ?? ""
        )
    }

    // MARK: - Download + install + restart

    /// Downloads the release zip, swaps the current bundle, and relaunches.
    /// Returns an error message, or never returns (the app restarts) on success.
    func downloadAndInstall(_ release: ReleaseInfo, progress: @Sendable @escaping (UpgradeState) -> Void) async -> String? {
        guard let assetURL = URL(string: release.assetURL), !release.assetURL.isEmpty else {
            return "The latest release has no downloadable zip asset."
        }

        progress(.downloading)
        let stage = FileManager.default.temporaryDirectory
            .appendingPathComponent("dc-update-\(release.version)")
        try? FileManager.default.removeItem(at: stage)
        try? FileManager.default.createDirectory(at: stage, withIntermediateDirectories: true)
        let zipPath = stage.appendingPathComponent(release.assetName.isEmpty ? "update.zip" : release.assetName)

        do {
            let (tmp, response) = try await URLSession.shared.download(from: assetURL)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                return "Download failed (HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1))."
            }
            try? FileManager.default.removeItem(at: zipPath)
            try FileManager.default.moveItem(at: tmp, to: zipPath)
        } catch {
            return "Download failed: \(error.localizedDescription)"
        }

        progress(.installing)
        // Unpack with ditto (preserves bundle structure + signature).
        let unpackDir = stage.appendingPathComponent("unpacked")
        try? FileManager.default.createDirectory(at: unpackDir, withIntermediateDirectories: true)
        let unzip = Self.runProcess("/usr/bin/ditto", ["-xk", zipPath.path, unpackDir.path])
        guard unzip.exitCode == 0 else { return "Unpack failed: \(unzip.output)" }
        guard let appName = (try? FileManager.default.contentsOfDirectory(atPath: unpackDir.path))?
            .first(where: { $0.hasSuffix(".app") })
        else { return "No .app bundle inside the release zip." }
        let newApp = unpackDir.appendingPathComponent(appName)

        // Swap the running bundle: move the old aside (the running process keeps
        // executing from the moved inode), copy the new one into place.
        let targetPath = Bundle.main.bundlePath
        let backup = stage.appendingPathComponent("previous.app")
        do {
            try FileManager.default.moveItem(atPath: targetPath, toPath: backup.path)
        } catch {
            return "Could not replace \(targetPath): \(error.localizedDescription)"
        }
        let copy = Self.runProcess("/usr/bin/ditto", [newApp.path, targetPath])
        guard copy.exitCode == 0 else {
            // Roll back.
            try? FileManager.default.moveItem(atPath: backup.path, toPath: targetPath)
            return "Install failed: \(copy.output)"
        }
        _ = Self.runProcess("/usr/bin/xattr", ["-dr", "com.apple.quarantine", targetPath])

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
            for _ in $(seq 1 150); do kill -0 \(pid) 2>/dev/null || break; sleep 0.2; done; \
            /usr/bin/open "\(targetPath)"
            """]
        try? relaunch.run()

        await MainActor.run { NSApp.terminate(nil) }
        return nil // unreachable in practice
    }

    // MARK: - Process helper

    nonisolated static func runProcess(_ launchPath: String, _ arguments: [String]) -> (exitCode: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch {
            return (126, "failed to launch \(launchPath): \(error.localizedDescription)")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}
