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
enum ToolbarHelpContractTests {
    private struct Expectation {
        let file: String
        let action: String
        let help: String
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            fputs("Usage: ToolbarHelpContractTests <repository-root>\n", stderr)
            exit(2)
        }

        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let expectations = [
            Expectation(file: "ActivityView.swift", action: #"Label("Run Command", systemImage: "play.circle")"#, help: #".dcQuickHelp("Open Command Palette")"#),
            Expectation(file: "ActivityView.swift", action: #"Label("Clear Completed", systemImage: "trash")"#, help: #".dcQuickHelp("Clear completed commands")"#),
            Expectation(file: "ActivityView.swift", action: #"Label("Refresh", systemImage: "arrow.clockwise")"#, help: #".dcQuickHelp("Refresh mutations")"#),
            Expectation(file: "AlertsView.swift", action: #"Label("Acknowledge Selection", systemImage: "checkmark.circle")"#, help: #".dcQuickHelp("Acknowledge selected alerts")"#),
            Expectation(file: "AlertsView.swift", action: #"Label("Refresh", systemImage: "arrow.clockwise")"#, help: #".dcQuickHelp("Refresh alerts")"#),
            Expectation(file: "AuditView.swift", action: #"Label("Export JSON", systemImage: "square.and.arrow.up")"#, help: #".dcQuickHelp("Export audit events as JSON")"#),
            Expectation(file: "AuditView.swift", action: #"Label("Refresh", systemImage: "arrow.clockwise")"#, help: #".dcQuickHelp("Refresh audit events")"#),
            Expectation(file: "LogsView.swift", action: #"Label("Auto-scroll", systemImage: "arrow.down.to.line")"#, help: #".dcQuickHelp("Follow new log lines")"#),
            Expectation(file: "LogsView.swift", action: #"Label("Reload from disk", systemImage: "arrow.clockwise")"#, help: #".dcQuickHelp("Reload logs from disk")"#),
            Expectation(file: "OverviewView.swift", action: #"Label("Run Health Check", systemImage: "stethoscope")"#, help: #".dcQuickHelp("Run DefenseClaw Doctor")"#),
            Expectation(file: "OverviewView.swift", action: #"Label("Refresh", systemImage: "arrow.clockwise")"#, help: #".dcQuickHelp("Refresh overview")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Rescan All", systemImage: "arrow.triangle.2.circlepath")"#, help: #".dcQuickHelp("Rescan connector inventories")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label(primaryAction.label, systemImage: primaryAction.systemImage)"#, help: #".dcQuickHelp(primaryAction.label)"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Refresh", systemImage: "arrow.clockwise")"#, help: #".dcQuickHelp("Refresh AI Discovery results")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Add Source", systemImage: "plus")"#, help: #".dcQuickHelp("Add Registry Source")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Remove Source", systemImage: "trash")"#, help: #".dcQuickHelp("Remove Selected Source")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Approve", systemImage: "checkmark.seal")"#, help: #".dcQuickHelp("Approve selected registry entry")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Reject", systemImage: "xmark.seal")"#, help: #".dcQuickHelp("Reject selected registry entry")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label(requirementActionLabel, systemImage: "lock.shield")"#, help: #".dcQuickHelp(requirementActionLabel)"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Sync Selected", systemImage: "arrow.triangle.2.circlepath")"#, help: #".dcQuickHelp("Sync selected registry source")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Sync All", systemImage: "arrow.triangle.2.circlepath.circle")"#, help: #".dcQuickHelp("Sync all registry sources")"#),
            Expectation(file: "DiscoverViews.swift", action: #"Label("Refresh", systemImage: "arrow.clockwise")"#, help: #".dcQuickHelp("Refresh registries")"#),
            Expectation(file: "CatalogViews.swift", action: #"Label("Install Skill", systemImage: "square.and.arrow.down")"#, help: #".dcQuickHelp("Install a skill")"#),
            Expectation(file: "CatalogViews.swift", action: #"Label("Set MCP Server", systemImage: "plus")"#, help: #".dcQuickHelp("Scan and add or update an MCP server")"#),
            Expectation(file: "CatalogViews.swift", action: #"Label("Install Plugin", systemImage: "square.and.arrow.down")"#, help: #".dcQuickHelp("Install a plugin")"#),
            Expectation(file: "CatalogViews.swift", action: #"Label("Refresh", systemImage: "arrow.clockwise")"#, help: #".dcQuickHelp("Refresh catalog")"#),
            Expectation(file: "MainWindow.swift", action: #"Label("Command Palette", systemImage: "command")"#, help: #".dcQuickHelp("Command Palette (Command-Shift-P)")"#),
        ]

        var sourceCache: [String: String] = [:]
        for expectation in expectations {
            let source = try sourceCache[expectation.file] ?? {
                let url = root
                    .appendingPathComponent("DefenseClawMac/Features")
                    .appendingPathComponent(expectation.file)
                return try String(contentsOf: url, encoding: .utf8)
            }()
            sourceCache[expectation.file] = source
            expectHelp(expectation, in: source)
        }

        try expectQuickHelpImplementation(at: root)
        try expectStableOverviewToolbarItems(at: root)
        print("ToolbarHelpContractTests passed")
    }

    private static func expectHelp(_ expectation: Expectation, in source: String) {
        guard let helpRange = source.range(of: expectation.help) else {
            fail("\(expectation.file) is missing \(expectation.help)")
        }
        let available = source.distance(from: source.startIndex, to: helpRange.lowerBound)
        let lowerBound = source.index(
            helpRange.lowerBound,
            offsetBy: -min(700, available)
        )
        let nearbySource = source[lowerBound..<helpRange.upperBound]
        guard nearbySource.contains(expectation.action) else {
            fail("\(expectation.file) does not attach \(expectation.help) to \(expectation.action)")
        }
    }

    private static func expectQuickHelpImplementation(at root: URL) throws {
        let url = root.appendingPathComponent("DefenseClawMac/DesignSystem/QuickHoverHelp.swift")
        let source = try String(contentsOf: url, encoding: .utf8)
        let requirements = [
            "static let displayDelay: TimeInterval = 0.15",
            "NSEvent.addLocalMonitorForEvents",
            "toolbar.visibleItems",
            "window.acceptsMouseMovedEvents = true",
            "popover.animates = false",
            "accessibilityHint(Text(text))",
        ]
        for requirement in requirements where !source.contains(requirement) {
            fail("QuickHoverHelp.swift is missing \(requirement)")
        }

        let appURL = root.appendingPathComponent("DefenseClawMac/App/DefenseClawApp.swift")
        let appSource = try String(contentsOf: appURL, encoding: .utf8)
        guard appSource.contains("DCToolbarQuickHelpMonitor.shared.start()") else {
            fail("AppDelegate does not start the toolbar quick-help monitor")
        }
    }

    private static func expectStableOverviewToolbarItems(at root: URL) throws {
        let url = root.appendingPathComponent("DefenseClawMac/Features/OverviewView.swift")
        let source = try String(contentsOf: url, encoding: .utf8)
        guard let toolbarStart = source.range(of: ".toolbar {"),
              let toolbarEnd = source.range(of: ".task { refresh() }", range: toolbarStart.upperBound..<source.endIndex)
        else {
            fail("Overview toolbar source could not be located")
        }
        let toolbar = String(source[toolbarStart.lowerBound..<toolbarEnd.lowerBound])
        let separateItemCount = toolbar.components(separatedBy: "ToolbarItem {").count - 1
        guard separateItemCount == 2,
              toolbar.contains("runDoctor()"),
              toolbar.contains("refresh()")
        else {
            fail("Overview Doctor and Refresh controls must use separate ToolbarItems")
        }
    }

    private static func fail(_ message: String) -> Never {
        fputs("FAILED: \(message)\n", stderr)
        exit(1)
    }
}
