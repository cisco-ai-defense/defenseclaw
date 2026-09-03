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
enum OverviewReadOnlyGuidanceContractTests {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            fputs("Usage: OverviewReadOnlyGuidanceContractTests <repository-root>\n", stderr)
            exit(2)
        }

        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let overview = try source(root, "DefenseClawMac/Features/OverviewView.swift")
        let settings = try source(root, "DefenseClawMac/Features/AppSettingsView.swift")
        let state = try source(root, "DefenseClawMac/App/AppState.swift")

        expect(overview.contains("if let reason = appState.installationReadOnlyReason"),
               "Quick Actions must render the installation lock reason")
        expect(overview.contains("Label(\"State-changing actions disabled: \\(reason)\", systemImage: \"lock.shield\")"),
               "Quick Actions must identify the read-only state")
        expect(overview.contains("Button(\"Review Installation\")"),
               "Quick Actions must provide a visible recovery action")
        expect(overview.contains("appState.selectedSettingsTab = .connection\n                            openSettings()"),
               "Review Installation must open the Connection settings tab")
        expect(overview.contains(".disabled(!appState.installationMutationsAllowed)"),
               "mutation safety gates must remain in place")
        expect(overview.contains(".disabled(doctorRunning || !appState.installationMutationsAllowed)"),
               "Doctor must retain its mutation safety gate")

        expect(state.contains("var selectedSettingsTab: AppSettingsTab = .general"),
               "shared app state must own settings routing")
        expect(settings.contains("TabView(selection: $state.selectedSettingsTab)"),
               "Settings must bind its selected tab")
        expect(settings.contains(".tag(AppSettingsTab.connection)"),
               "Connection settings must have a selectable tag")

        print("OverviewReadOnlyGuidanceContractTests passed")
    }

    private static func source(_ root: URL, _ path: String) throws -> String {
        try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fputs("FAILED: \(message)\n", stderr)
            exit(1)
        }
    }
}
