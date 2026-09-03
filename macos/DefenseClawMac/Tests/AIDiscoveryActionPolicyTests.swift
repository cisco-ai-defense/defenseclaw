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

@main
enum AIDiscoveryActionPolicyTests {
    static func main() {
        let disabled = AIDiscoveryPrimaryAction.resolve(enabled: false)
        expect(disabled == .enable, "disabled discovery must offer Enable")
        expect(disabled.label == "Enable AI Discovery", "enable action label drifted")
        expect(
            disabled.arguments == ["agent", "discovery", "enable", "--yes"],
            "enable action must use the canonical non-interactive runtime command"
        )

        let enabled = AIDiscoveryPrimaryAction.resolve(enabled: true)
        expect(enabled == .scan, "enabled discovery must offer Scan")
        expect(enabled.label == "Scan Now", "scan action label drifted")
        expect(
            enabled.arguments == ["agent", "discovery", "scan"],
            "scan action must use the canonical runtime command"
        )

        expect(
            AIDiscoveryScanRequestStep.resolve(statusLoaded: false, enabled: false) == .loadStatus,
            "a first-open scan request must wait for status instead of being dropped"
        )
        expect(
            AIDiscoveryScanRequestStep.resolve(statusLoaded: true, enabled: false) == .showDisabled,
            "a disabled status must explain how to enable discovery"
        )
        expect(
            AIDiscoveryScanRequestStep.resolve(statusLoaded: true, enabled: true) == .scan,
            "an enabled status must run the requested scan"
        )

        let disabledBody = #"{"error":"ai discovery disabled"}"#
        expect(
            GatewayErrorBody.userFacingMessage(status: 503, body: disabledBody)
                == "AI Discovery is disabled. Enable it before starting a scan.",
            "canonical disabled response must be actionable"
        )
        expect(
            GatewayErrorBody.userFacingMessage(status: 500, body: disabledBody) == nil,
            "non-503 responses must retain their normal error handling"
        )
        expect(
            GatewayErrorBody.userFacingMessage(status: 503, body: #"{"error":"internal details"}"#) == nil,
            "unknown gateway bodies must not be surfaced"
        )

        print("AI Discovery action policy tests passed")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fputs("FAILED: \(message)\n", stderr)
            exit(1)
        }
    }
}
