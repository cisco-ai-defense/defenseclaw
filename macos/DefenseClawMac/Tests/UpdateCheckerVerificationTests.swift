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

import CryptoKit
import Foundation

@main
struct UpdateCheckerVerificationTests {
    static func main() async {
        comparesReleaseVersions()
        buildsImmutableReleaseAssetURLs()
        parsesChecksumEntries()
        stagesInstallerWithMatchingHash()
        refusesInstallerWithWrongHash()
        refusesInstallerWithoutChecksumEntry()
        await refusesUnusableVersionsBeforeDownloading()
        mapsInstallerExitCodes()
        readsBundleVersionFromDisk()
        detectsReplaceableBundleLocations()
        print("Update checker verification tests passed")
    }

    private static let script = Data("#!/bin/bash\necho installing\n".utf8)

    private static var scriptSHA256: String {
        SHA256.hash(data: script).map { String(format: "%02x", $0) }.joined()
    }

    private static func comparesReleaseVersions() {
        expect(UpdateChecker.isNewer("1.0.1", than: "1.0.0"), "patch releases are newer")
        expect(UpdateChecker.isNewer("1.10.0", than: "1.9.9"), "versions compare numerically")
        expect(!UpdateChecker.isNewer("1.0.0", than: "1.0.0"), "a version is not newer than itself")
        expect(!UpdateChecker.isNewer("1.0.0-rc1", than: "0.8.10"), "non-numeric versions never look newer")
        expect(UpdateChecker.parseVersion("defenseclaw, version 1.0.2") == "1.0.2", "CLI version output is parsed")
        let release = UpdateChecker.releaseInfo(
            from: ["html_url": "https://github.com/cisco-ai-defense/defenseclaw/releases/tag/v1.2.3"],
            tag: "v1.2.3"
        )
        expect(release.version == "1.2.3", "a leading v is stripped from the release tag")
        expect(release.htmlURL.hasSuffix("/releases/tag/v1.2.3"), "the release page URL is preserved")
    }

    private static func buildsImmutableReleaseAssetURLs() {
        expect(
            UpdateChecker.releaseAssetURL("install.sh", version: "1.0.0")?.absoluteString
                == "https://github.com/cisco-ai-defense/defenseclaw/releases/download/1.0.0/install.sh",
            "the installer comes from the exact release, not a branch or latest URL"
        )
        for version in ["latest", "v1.0.0", "1.0", "01.0.0", "1.0.0-rc1", "1.0.0/../main", "1.0.0; id"] {
            expect(UpdateChecker.releaseAssetURL("install.sh", version: version) == nil, "rejects version \(version)")
        }
    }

    private static func parsesChecksumEntries() {
        let digest = String(repeating: "a", count: 64)
        let other = String(repeating: "b", count: 64)
        let checksums = """
        \(other)  install.ps1
        \(digest)  install.sh
        \(other)  install.sh.sig
        \(other)  defenseclaw-1.0.0-darwin-arm64.tar.gz
        """
        expect(UpdateChecker.expectedSHA256(of: "install.sh", in: checksums) == digest, "finds the exact install.sh entry")
        expect(
            UpdateChecker.expectedSHA256(of: "install.sh", in: "\(digest.uppercased())  install.sh\r\n") == digest,
            "uppercase digests and CRLF line endings are normalized"
        )
        expect(
            UpdateChecker.expectedSHA256(of: "install.sh", in: "\(digest)  install.sh\n\(other)  install.sh\n") == nil,
            "duplicate entries are ambiguous"
        )
        expect(
            UpdateChecker.expectedSHA256(of: "install.sh", in: "abc123  install.sh\n") == nil,
            "a malformed digest is rejected"
        )
        expect(
            UpdateChecker.expectedSHA256(of: "install.sh", in: "\(digest)  ./install.sh\n\(digest)  my-install.sh\n") == nil,
            "only the flat install.sh name matches"
        )
    }

    private static func stagesInstallerWithMatchingHash() {
        withTemporaryDirectory { parent in
            let checksums = "\(scriptSHA256)  install.sh\n"
            do {
                let staged = try UpdateChecker.stageInstaller(script, checksums: checksums, in: parent)
                let directory = staged.deletingLastPathComponent()
                expect(staged.lastPathComponent == "install.sh", "returns the staged install.sh")
                expect((try? Data(contentsOf: staged)) == script, "stages the verified bytes")
                expect(
                    (try? String(contentsOf: directory.appendingPathComponent("checksums.txt"), encoding: .utf8)) == checksums,
                    "stages checksums.txt beside the installer"
                )
                expect(permissions(of: directory) == 0o700, "the staging directory is private")
                expect(permissions(of: staged) == 0o600, "the staged installer is private")
            } catch {
                fail("a matching installer was refused: \(error)")
            }
        }
    }

    private static func refusesInstallerWithWrongHash() {
        withTemporaryDirectory { parent in
            let wrong = String(repeating: "0", count: 64)
            expectError(.checksumMismatch, "a tampered installer is refused") {
                _ = try UpdateChecker.stageInstaller(script, checksums: "\(wrong)  install.sh\n", in: parent)
            }
            expect(contents(of: parent).isEmpty, "nothing is staged for a tampered installer")
        }
    }

    private static func refusesInstallerWithoutChecksumEntry() {
        withTemporaryDirectory { parent in
            expectError(.missingChecksum, "an installer without a checksum entry is refused") {
                _ = try UpdateChecker.stageInstaller(script, checksums: "\(scriptSHA256)  install.ps1\n", in: parent)
            }
            expect(contents(of: parent).isEmpty, "nothing is staged without a checksum entry")
        }
    }

    private static func refusesUnusableVersionsBeforeDownloading() async {
        let checker = UpdateChecker()
        do {
            _ = try await checker.fetchInstaller(version: "latest")
            fail("a non-release version was fetched")
        } catch let error as InstallerFetchError {
            expect(error == .invalidVersion("latest"), "non-release versions are refused")
        } catch {
            fail("unexpected error: \(error)")
        }
        do {
            _ = try await checker.fetchInstaller(version: "0.8.10")
            fail("a pre-1.0 installer was fetched")
        } catch let error as InstallerFetchError {
            expect(error == .unsupportedVersion("0.8.10"), "installers before the 1.0 contract are refused")
        } catch {
            fail("unexpected error: \(error)")
        }
    }

    private static func mapsInstallerExitCodes() {
        let output = "Downloading assets\nVerifying checksums\n\nInstalled DefenseClaw 1.0.1\n  codex: hooks need attention  \nrun: defenseclaw setup codex\n"
        expect(
            InstallerState.finished(version: "1.0.1", exitCode: 0, cancelled: false, output: output)
                == .installed(version: "1.0.1"),
            "exit 0 is installed"
        )
        expect(
            InstallerState.finished(version: "1.0.1", exitCode: 3, cancelled: false, output: output)
                == .needsAttention(
                    version: "1.0.1",
                    detail: "Verifying checksums\nInstalled DefenseClaw 1.0.1\ncodex: hooks need attention\nrun: defenseclaw setup codex"
                ),
            "exit 3 is installed with the installer's last lines as the warning"
        )
        guard case .failed(_, let detail) = InstallerState.finished(
            version: "1.0.1", exitCode: 1, cancelled: false, output: "rolling back\nerror: gateway did not start\n"
        ) else {
            fail("exit 1 is not a failure")
        }
        expect(detail == "rolling back\nerror: gateway did not start", "failures carry the installer's last lines")
        expect(
            InstallerState.finished(version: "1.0.1", exitCode: 2, cancelled: false, output: "")
                == .failed(version: "1.0.1", detail: "install.sh exited 2."),
            "silent failures name the exit status"
        )
        guard case .failed = InstallerState.finished(version: "1.0.1", exitCode: 0, cancelled: true, output: "") else {
            fail("an interrupted run is not a failure")
        }
        expect(InstallerState.running(version: "1.0.1").isBusy, "a running installer is busy")
        expect(!InstallerState.needsAttention(version: "1.0.1", detail: "").isBusy, "a finished installer is idle")
    }

    private static func readsBundleVersionFromDisk() {
        withTemporaryDirectory { parent in
            let bundle = parent.appendingPathComponent("DefenseClawMac.app")
            let contents = bundle.appendingPathComponent("Contents")
            do {
                try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
                let plist = try PropertyListSerialization.data(
                    fromPropertyList: ["CFBundleShortVersionString": "1.0.1"],
                    format: .xml,
                    options: 0
                )
                try plist.write(to: contents.appendingPathComponent("Info.plist"))
            } catch {
                fail("could not create the bundle fixture: \(error)")
            }
            expect(UpdateChecker.bundleShortVersion(atPath: bundle.path) == "1.0.1", "reads the on-disk bundle version")
            expect(
                UpdateChecker.bundleShortVersion(atPath: parent.appendingPathComponent("Missing.app").path) == nil,
                "a missing bundle has no version"
            )
        }
    }

    private static func detectsReplaceableBundleLocations() {
        withTemporaryDirectory { parent in
            let bundle = parent.appendingPathComponent("DefenseClawMac.app").path
            expect(UpdateChecker.canReplaceBundle(atPath: bundle), "a bundle in a writable folder can be replaced")
            let readOnly = parent.appendingPathComponent("ReadOnly", isDirectory: true)
            do {
                try FileManager.default.createDirectory(
                    at: readOnly,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: NSNumber(value: Int16(0o500))]
                )
            } catch {
                fail("could not create the read-only fixture: \(error)")
            }
            defer {
                try? FileManager.default.setAttributes(
                    [.posixPermissions: NSNumber(value: Int16(0o700))],
                    ofItemAtPath: readOnly.path
                )
            }
            expect(
                !UpdateChecker.canReplaceBundle(atPath: readOnly.appendingPathComponent("DefenseClawMac.app").path),
                "a bundle in a read-only folder (disk image, translocation) cannot be replaced"
            )
        }
    }

    private static func withTemporaryDirectory(_ body: (URL) -> Void) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-update-tests-" + UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        } catch {
            fail("could not create a temporary directory: \(error)")
        }
        defer { try? FileManager.default.removeItem(at: directory) }
        body(directory)
    }

    private static func contents(of directory: URL) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
    }

    private static func permissions(of url: URL) -> Int? {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes?[.posixPermissions] as? NSNumber)?.intValue
    }

    private static func expectError(_ expected: InstallerFetchError, _ label: String, _ body: () throws -> Void) {
        do {
            try body()
            fail("\(label): no error was thrown")
        } catch let error as InstallerFetchError {
            expect(error == expected, "\(label) (got \(error))")
        } catch {
            fail("\(label): unexpected error \(error)")
        }
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else { fail(label) }
    }

    private static func fail(_ label: String) -> Never {
        fputs("FAILED: \(label)\n", stderr)
        exit(1)
    }
}
