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

import Foundation

enum RuntimePayload {
    static func sha256(of _: URL) -> String? {
        nil
    }
}

@main
struct UpdateCheckerSafetyTests {
    static func main() {
        parsesRealZipInfoListing()
        acceptsSingleAppBundleArchive()
        rejectsPathTraversalBeforeExtraction()
        rejectsAbsolutePathsBeforeExtraction()
        rejectsSymlinkEntriesBeforeExtraction()
        rejectsUnexpectedTopLevelFiles()
        rejectsEmptyArchive()
        rejectsTildePrefixedPaths()
        rejectsHardlinkEntries()
        rejectsSpecialFileEntries()
        rejectsMultipleAppBundles()
        rejectsArchiveWithNoAppBundle()
        rejectsEmptyArchivePath()
        print("Update checker safety tests passed")
    }

    private static func parsesRealZipInfoListing() {
        let listing = """
        Archive:  DefenseClawMac-0.8.5-macos-arm64.zip
        Zip file size: 2421636 bytes, number of entries: 3
        drwxr-xr-x  2.1 unx        0 bx        0 stor 26-Jul-08 12:07 DefenseClawMac.app/
        -rw-r--r--  2.1 unx      163 bX       86 defN 26-Jul-08 12:07 DefenseClawMac.app/Contents/Info.plist
        -rw-r--r--  2.1 unx      123 bX       75 defN 26-Jul-08 12:07 DefenseClawMac.app/Contents/Resources/Release Notes.txt
        3 files, 286 bytes uncompressed, 161 bytes compressed:  43.7%
        """
        let entries = UpdateChecker.parseZipEntries(listing)
        expect(entries == [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/", mode: "drwxr-xr-x"),
            UpdateChecker.ZipArchiveEntry(
                path: "DefenseClawMac.app/Contents/Info.plist",
                mode: "-rw-r--r--"
            ),
            UpdateChecker.ZipArchiveEntry(
                path: "DefenseClawMac.app/Contents/Resources/Release Notes.txt",
                mode: "-rw-r--r--"
            ),
        ], "zipinfo headers and footers are ignored and entry paths retain spaces")
        expect(
            UpdateChecker.validateUpdateArchive(entries: entries)
                == .success(appBundleName: "DefenseClawMac.app"),
            "a real zipinfo listing for one app bundle is accepted"
        )
    }

    private static func acceptsSingleAppBundleArchive() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/", mode: "drwxr-xr-x"),
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/MacOS/DefenseClawMac", mode: "-rwxr-xr-x"),
        ])
        expect(result == .success(appBundleName: "DefenseClawMac.app"), "legitimate app archive is accepted")
    }

    private static func rejectsPathTraversalBeforeExtraction() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/../../Library/LaunchAgents/persist.plist", mode: "-rw-r--r--"),
        ])
        expect(result.isFailure(containing: "unsafe path"), "path traversal is rejected")
    }

    private static func rejectsAbsolutePathsBeforeExtraction() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "/tmp/DefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
        ])
        expect(result.isFailure(containing: "unsafe path"), "absolute paths are rejected")
    }

    private static func rejectsSymlinkEntriesBeforeExtraction() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Resources/link", mode: "lrwxr-xr-x"),
        ])
        expect(result.isFailure(containing: "link"), "symlink entries are rejected")
    }

    private static func rejectsUnexpectedTopLevelFiles() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
            UpdateChecker.ZipArchiveEntry(path: "README.txt", mode: "-rw-r--r--"),
        ])
        expect(result.isFailure(containing: "single top-level .app"), "top-level extras are rejected")
    }

    private static func rejectsEmptyArchive() {
        let result = UpdateChecker.validateUpdateArchive(entries: [])
        expect(result.isFailure(containing: "archive is empty"), "empty archive is rejected")
    }

    private static func rejectsTildePrefixedPaths() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "~/Library/LaunchAgents/persist.plist", mode: "-rw-r--r--"),
        ])
        expect(result.isFailure(containing: "unsafe path"), "tilde-prefixed paths are rejected")
    }

    private static func rejectsHardlinkEntries() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Resources/link", mode: "hrwxr-xr-x"),
        ])
        expect(result.isFailure(containing: "link"), "hardlink entries are rejected")
    }

    private static func rejectsSpecialFileEntries() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(
                path: "DefenseClawMac.app/Contents/Resources/device",
                mode: "crw-r--r--"
            ),
        ])
        expect(result.isFailure(containing: "unsupported archive entry"), "special files are rejected")
    }

    private static func rejectsMultipleAppBundles() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
            UpdateChecker.ZipArchiveEntry(path: "OtherDefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
        ])
        expect(result.isFailure(containing: "single top-level .app"), "multiple .app bundles are rejected")
    }

    private static func rejectsArchiveWithNoAppBundle() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac/Contents/Info.plist", mode: "-rw-r--r--"),
        ])
        expect(result.isFailure(containing: "single top-level .app"), "archives without .app bundle are rejected")
    }

    private static func rejectsEmptyArchivePath() {
        let result = UpdateChecker.validateUpdateArchive(entries: [
            UpdateChecker.ZipArchiveEntry(path: "DefenseClawMac.app/Contents/Info.plist", mode: "-rw-r--r--"),
            UpdateChecker.ZipArchiveEntry(path: "", mode: "-rw-r--r--"),
        ])
        expect(result.isFailure(containing: "empty archive path"), "empty archive paths are rejected")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}

private extension UpdateChecker.ArchiveValidationResult {
    func isFailure(containing needle: String) -> Bool {
        if case .failure(let message) = self {
            return message.contains(needle)
        }
        return false
    }
}
