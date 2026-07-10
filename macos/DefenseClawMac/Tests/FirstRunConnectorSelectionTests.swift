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
struct FirstRunConnectorSelectionTests {
    static func main() {
        firstDiscoveryPreselectsEverything()
        refreshPreservesExplicitChoices()
        refreshPreselectsOnlyNewConnectors()
        refreshDropsMissingAndUnregisteredActions()
        print("FirstRunConnectorSelectionTests passed")
    }

    private static func firstDiscoveryPreselectsEverything() {
        let selection = reconcile(
            previouslyDetected: [],
            detected: ["codex", "cursor"],
            registered: [],
            action: []
        )
        expect(selection.registered == ["codex", "cursor"], "first discovery preselects detected connectors")
        expect(selection.action.isEmpty, "first discovery does not opt connectors into action mode")
    }

    private static func refreshPreservesExplicitChoices() {
        let selection = reconcile(
            previouslyDetected: ["codex", "cursor"],
            detected: ["codex", "cursor"],
            registered: ["codex"],
            action: ["codex"]
        )
        expect(selection.registered == ["codex"], "refresh preserves an unchecked connector")
        expect(selection.action == ["codex"], "refresh preserves a valid action choice")
    }

    private static func refreshPreselectsOnlyNewConnectors() {
        let selection = reconcile(
            previouslyDetected: ["codex", "cursor"],
            detected: ["codex", "cursor", "claudecode"],
            registered: ["codex"],
            action: ["codex"]
        )
        expect(selection.registered == ["codex", "claudecode"], "refresh preselects only new connectors")
        expect(!selection.registered.contains("cursor"), "refresh keeps a previously unchecked connector unchecked")
        expect(selection.action == ["codex"], "new connectors are not implicitly added to action mode")
    }

    private static func refreshDropsMissingAndUnregisteredActions() {
        let selection = reconcile(
            previouslyDetected: ["codex", "cursor", "stale"],
            detected: ["codex", "cursor"],
            registered: ["codex", "stale"],
            action: ["codex", "cursor", "stale"]
        )
        expect(selection.registered == ["codex"], "missing and unchecked connectors stay unregistered")
        expect(selection.action == ["codex"], "action choices remain a subset of registration")
    }

    private static func reconcile(
        previouslyDetected: [String],
        detected: [String],
        registered: Set<String>,
        action: Set<String>
    ) -> ConnectorDiscoverySelection {
        ConnectorDiscoverySelection.reconciling(
            previouslyDetected: previouslyDetected,
            detected: detected,
            registered: registered,
            action: action
        )
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
