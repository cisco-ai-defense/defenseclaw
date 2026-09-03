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
struct UpdateCheckerVerificationTests {
    static func main() {
        pinsExpectedPublisherRequirement()
        rejectsUnverifiedSelfUpdateAssets()
        selectsVerifiedSelfUpdateAsset()
        rejectsQualifiedAndMismatchedSelfUpdateAssets()
        rejectsNonAppZipAssets()
        allowsRuntimeReleaseWithoutSelfUpdateAsset()
        returnsPopulatedReleaseInfoForAppSelfUpdate()
        selectsDigestBoundRuntimeInstallerAsset()
        rejectsMutableOrUnverifiableRuntimeInstallerAssets()
        print("Update checker verification tests passed")
    }

    private static func pinsExpectedPublisherRequirement() {
        expect(
            UpdateChecker.expectedBundleIdentifier == "com.cisco.defenseclaw.macos",
            "self-update pins the production bundle identifier"
        )
        expect(
            UpdateChecker.expectedCodeRequirement.contains(#"identifier "com.cisco.defenseclaw.macos""#),
            "self-update pins the Cisco bundle identifier in the publisher requirement"
        )
        let requirement = UpdateChecker.expectedCodeRequirement
        expect(requirement.contains("anchor apple generic"), "publisher requirement uses Apple's trust anchor")
        expect(
            requirement.contains(#"identifier "com.cisco.defenseclaw.macos""#),
            "publisher requirement binds the bundle identifier"
        )
        expect(
            requirement.contains(#"identifier "com.cisco.defenseclaw.macos""#),
            "publisher requirement binds the Cisco bundle identifier"
        )
    }

    private static func rejectsUnverifiedSelfUpdateAssets() {
        let assets: [[String: Any]] = [
            [
                "name": "DefenseClawMac-1.2.3-macos-arm64-unverified.zip",
                "browser_download_url": "https://example.test/unverified.zip",
                "digest": "sha256:abc",
            ],
        ]
        expect(
            UpdateChecker.selectSelfUpdateAsset(from: assets, version: "1.2.3") == nil,
            "unverified app zip is not eligible"
        )
    }

    private static func selectsVerifiedSelfUpdateAsset() {
        let assets: [[String: Any]] = [
            [
                "name": "DefenseClawMac-1.2.3-macos-arm64-unverified.zip",
                "browser_download_url": "https://example.test/unverified.zip",
                "digest": "sha256:abc",
            ],
            [
                "name": "DefenseClawMac-1.2.3-macos-arm64.zip",
                "browser_download_url": "https://example.test/verified.zip",
                "digest": "sha256:def",
            ],
        ]
        let selected = UpdateChecker.selectSelfUpdateAsset(from: assets, version: "1.2.3")
        expect(selected?["name"] as? String == "DefenseClawMac-1.2.3-macos-arm64.zip", "verified app zip is selected")
    }

    private static func rejectsQualifiedAndMismatchedSelfUpdateAssets() {
        let assets: [[String: Any]] = [
            ["name": "DefenseClawMac-1.2.3-macos-arm64-preview.zip"],
            ["name": "DefenseClawMac-9.9.9-macos-arm64.zip"],
            ["name": "DefenseClawMac-1.2.3-MACOS-arm64.zip"],
        ]
        expect(
            UpdateChecker.selectSelfUpdateAsset(from: assets, version: "1.2.3") == nil,
            "only the exact versioned canonical app zip is eligible"
        )
    }

    private static func rejectsNonAppZipAssets() {
        let assets: [[String: Any]] = [
            [
                "name": "defenseclaw-1.2.3-py3-none-any.whl",
                "browser_download_url": "https://example.test/runtime.whl",
                "digest": "sha256:abc",
            ],
        ]
        expect(
            UpdateChecker.selectSelfUpdateAsset(from: assets, version: "1.2.3") == nil,
            "runtime assets are not self-update assets"
        )
    }

    private static func allowsRuntimeReleaseWithoutSelfUpdateAsset() {
        let release = UpdateChecker.releaseInfo(
            from: [
                "html_url": "https://github.com/cisco-ai-defense/defenseclaw/releases/tag/v1.2.3",
                "body": "Runtime-only release",
                "assets": [
                    [
                        "name": "defenseclaw-1.2.3-py3-none-any.whl",
                        "browser_download_url": "https://example.test/runtime.whl",
                        "digest": "sha256:abc",
                    ],
                ],
            ],
            repo: "cisco-ai-defense/defenseclaw",
            tag: "v1.2.3",
            requireSelfUpdateAsset: false
        )
        expect(release?.version == "1.2.3", "runtime release metadata is preserved without an app zip")
        expect(release?.assetName == "", "runtime release does not borrow non-app assets")

        let appRelease = UpdateChecker.releaseInfo(
            from: ["assets": []],
            repo: "cisco-ai-defense/defenseclaw",
            tag: "v1.2.3",
            requireSelfUpdateAsset: true
        )
        expect(appRelease == nil, "app self-update still requires a verified app zip")
    }

    private static func returnsPopulatedReleaseInfoForAppSelfUpdate() {
        let release = UpdateChecker.releaseInfo(
            from: [
                "html_url": "https://github.com/cisco-ai-defense/defenseclaw/releases/tag/v1.2.3",
                "body": "App release",
                "assets": [
                    [
                        "name": "DefenseClawMac-1.2.3-macos-arm64.zip",
                        "browser_download_url": "https://example.test/verified.zip",
                        "digest": "sha256:def",
                    ],
                ],
            ],
            repo: "cisco-ai-defense/defenseclaw",
            tag: "v1.2.3",
            requireSelfUpdateAsset: true
        )
        expect(release?.assetName == "DefenseClawMac-1.2.3-macos-arm64.zip", "app release asset name is preserved")
        expect(release?.assetURL == "https://example.test/verified.zip", "app release asset URL is preserved")
        expect(release?.assetSHA256 == "def", "app release digest prefix is stripped")
    }

    private static func selectsDigestBoundRuntimeInstallerAsset() {
        let digest = String(repeating: "a", count: 64)
        let release = UpdateChecker.runtimeInstallerInfo(
            from: [
                "html_url": "https://github.com/cisco-ai-defense/defenseclaw/releases/tag/0.8.10",
                "assets": [[
                    "name": "install.sh",
                    "browser_download_url": "https://github.com/cisco-ai-defense/defenseclaw/releases/download/0.8.10/install.sh",
                    "digest": "sha256:\(digest)",
                ]],
            ],
            tag: "0.8.10"
        )
        expect(release?.tag == "0.8.10", "runtime installer retains the immutable release tag")
        expect(release?.assetSHA256 == digest, "runtime installer retains its release digest")
    }

    private static func rejectsMutableOrUnverifiableRuntimeInstallerAssets() {
        let digest = String(repeating: "b", count: 64)
        let mutable = UpdateChecker.runtimeInstallerInfo(
            from: ["assets": [[
                "name": "install.sh",
                "browser_download_url": "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh",
                "digest": "sha256:\(digest)",
            ]]],
            tag: "0.8.10"
        )
        expect(mutable == nil, "mutable main-branch installer URL is rejected")

        let missingDigest = UpdateChecker.runtimeInstallerInfo(
            from: ["assets": [[
                "name": "install.sh",
                "browser_download_url": "https://github.com/cisco-ai-defense/defenseclaw/releases/download/0.8.10/install.sh",
            ]]],
            tag: "0.8.10"
        )
        expect(missingDigest == nil, "runtime installer without a SHA-256 digest is rejected")

        let wrongTag = UpdateChecker.runtimeInstallerInfo(
            from: ["assets": [[
                "name": "install.sh",
                "browser_download_url": "https://github.com/cisco-ai-defense/defenseclaw/releases/download/0.8.9/install.sh",
                "digest": "sha256:\(digest)",
            ]]],
            tag: "0.8.10"
        )
        expect(wrongTag == nil, "runtime installer URL must match the selected release tag")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
