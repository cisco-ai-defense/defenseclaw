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
        rejectsUnverifiedSelfUpdateAssets()
        selectsVerifiedSelfUpdateAsset()
        rejectsNonAppZipAssets()
        allowsRuntimeReleaseWithoutSelfUpdateAsset()
        returnsPopulatedReleaseInfoForAppSelfUpdate()
        print("Update checker verification tests passed")
    }

    private static func rejectsUnverifiedSelfUpdateAssets() {
        let assets: [[String: Any]] = [
            [
                "name": "DefenseClawMac-1.2.3-macos-arm64-unverified.zip",
                "browser_download_url": "https://example.test/unverified.zip",
                "digest": "sha256:abc",
            ],
        ]
        expect(UpdateChecker.selectSelfUpdateAsset(from: assets) == nil, "unverified app zip is not eligible")
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
        let selected = UpdateChecker.selectSelfUpdateAsset(from: assets)
        expect(selected?["name"] as? String == "DefenseClawMac-1.2.3-macos-arm64.zip", "verified app zip is selected")
    }

    private static func rejectsNonAppZipAssets() {
        let assets: [[String: Any]] = [
            [
                "name": "defenseclaw-1.2.3-py3-none-any.whl",
                "browser_download_url": "https://example.test/runtime.whl",
                "digest": "sha256:abc",
            ],
        ]
        expect(UpdateChecker.selectSelfUpdateAsset(from: assets) == nil, "runtime assets are not self-update assets")
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

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
