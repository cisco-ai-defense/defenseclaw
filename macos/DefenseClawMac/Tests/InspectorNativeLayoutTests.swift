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

// Opt-in native regression for the macOS split-view constraint-update loop.
// Uses only synthetic events and a separate accessory application; no AppState,
// installed application, gateway, audit database, or user configuration is read.
// The fixture matches Alerts' Table/header/inspector sizing. The fixed branch
// calls the production inspector container; the baseline uses the original
// native inspector with a content-dependent width range.
// The shell runner enforces an external watchdog because a layout loop can
// prevent every timer and task on the application's main thread from progressing.

import AppKit
import SwiftUI

private enum Settings {
    static let arguments = CommandLine.arguments
    static func argument(_ name: String, fallback: String) -> String {
        guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return fallback }
        return arguments[index + 1]
    }
    static let baseline = argument("--variant", fallback: "fixed") == "baseline"
    static let accessibilityInput = argument("--input", fallback: "native") == "accessibility"
    static let width = Double(argument("--width", fallback: "980")) ?? 980
}

private func log(_ message: String) {
    print("PROBE \(Date().timeIntervalSince1970) \(message)")
    fflush(stdout)
}

@MainActor
final class ProbeController: ObservableObject {
    @Published var panel: String? = "Activity"
    @Published var selection = Set<String>()
    @Published var hydrated = false
    @Published var findingsAvailable = false
    @Published var historyCount = 0
    @Published var healthTick = 0
    private var started = false
    private var selectionCount = 0
    private var closeCount = 0
    private var hydrationRequests = 0
    private var hydrationCount = 0
    private var discardedHydrations = 0
    private var visibleInspectorCount = 0
    private var inspectorAppearances = 0

    private var window: NSWindow? {
        NSApp.windows.first { $0.isVisible && $0.canBecomeMain }
    }

    func run() {
        guard !started else { return }
        started = true
        log("START baseline=\(Settings.baseline) accessibility=\(Settings.accessibilityInput)")
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(250))
            resize(to: 1677)
            panel = "Logs"
            try? await Task.sleep(for: .milliseconds(250))
            panel = "Alerts"
            try? await Task.sleep(for: .milliseconds(350))

            if Settings.baseline {
                // Preserve the original compact native-inspector control.
                resize(to: 980)
                for round in 0..<8 {
                    select(row: round % 4)
                    try? await Task.sleep(for: .milliseconds(500))
                    if round % 2 == 1 {
                        select(row: nil)
                        try? await Task.sleep(for: .milliseconds(180))
                    }
                }
                log("BASELINE SURVIVED: this OS did not reproduce the control")
                NSApp.terminate(nil)
                return
            }

            // Reproduce the production failure sequence: clear each AX row,
            // resize, and select adjacent rows while hydration is in flight.
            for width in [1180.0, 980, 1677, 980] {
                select(row: nil)
                resize(to: width)
                try? await Task.sleep(for: .milliseconds(180))
                select(row: 1)
                try? await Task.sleep(for: .milliseconds(400))
                select(row: 2)
                try? await Task.sleep(for: .milliseconds(400))
            }

            // Resize with details open, then invoke the same close action the
            // visible button uses before selecting again.
            for (index, width) in [980.0, 1180, 1677, Settings.width].enumerated() {
                resize(to: width)
                try? await Task.sleep(for: .milliseconds(180))
                closeInspector()
                try? await Task.sleep(for: .milliseconds(180))
                select(row: index % 4)
                try? await Task.sleep(for: .milliseconds(400))
            }
            select(row: 1)
            log("DWELL inspector open for 20 seconds")
            try? await Task.sleep(for: .seconds(20))
            verifyCompletion()
        }
        Task { @MainActor in
            for tick in 1...8 {
                try? await Task.sleep(for: .seconds(5))
                healthTick = tick
                log("PARENT PULSE \(tick)")
            }
        }
    }

    private func resize(to width: Double) {
        guard let window else { fail("missing visible window", code: 92) }
        window.setFrame(
            NSRect(x: window.frame.minX, y: window.frame.minY, width: width, height: 760),
            display: true
        )
        log("RESIZE \(window.frame)")
    }

    private func alertTable(in view: NSView) -> NSTableView? {
        if let table = view as? NSTableView, table.numberOfColumns >= 6 { return table }
        for child in view.subviews {
            if let table = alertTable(in: child) { return table }
        }
        return nil
    }

    private func select(row index: Int?) {
        guard let window, let content = window.contentView,
              let table = alertTable(in: content) else {
            fail("native alert Table unavailable", code: 93)
        }
        window.makeFirstResponder(table)
        if Settings.accessibilityInput {
            // These SwiftUI row objects expose the legacy AX attribute entry
            // point used by accessibility clients, not the modern row setter.
            // The deprecated API is intentional in this test-only control.
            guard let rows = table.accessibilityAttributeValue(.rows) as? [NSObject],
                  rows.count >= 4,
                  rows.allSatisfy({ $0.accessibilityIsAttributeSettable(.selected) }) else {
                fail("native AX row selection unavailable", code: 94)
            }
            if let index {
                rows[index].accessibilitySetValue(NSNumber(value: true), forAttribute: .selected)
            } else {
                for row in rows {
                    row.accessibilitySetValue(NSNumber(value: false), forAttribute: .selected)
                }
            }
            log("AX SELECTION count=\(table.selectedRowIndexes.count)")
        } else if let index {
            table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        } else {
            table.deselectAll(nil)
        }
        guard index.map({ table.selectedRowIndexes.contains($0) }) ?? table.selectedRowIndexes.isEmpty else {
            fail("input did not change native Table selection", code: 95)
        }
        if let index {
            selectionCount += 1
            log("SELECT \(index)")
        } else {
            closeCount += 1
            log("DESELECT")
        }
    }

    func closeInspector() {
        selection = []
        closeCount += 1
        log("CLOSE ACTION")
    }

    func inspectorAppeared() {
        visibleInspectorCount += 1
        inspectorAppearances += 1
        log("DETAILS APPEARED")
    }

    func inspectorDisappeared() {
        visibleInspectorCount -= 1
        log("DETAILS DISAPPEARED")
    }

    func loadDetail() {
        let selected = selection
        hydrated = false
        guard !selected.isEmpty else {
            findingsAvailable = false
            historyCount = 0
            return
        }
        // Match Alerts: retain previous findings/history during a new load;
        // only the full event resets until the next async result arrives.
        hydrationRequests += 1
        let delay = Settings.baseline ? 25 : [50, 800, 2000][hydrationRequests % 3]
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(delay))
            guard self.selection == selected else {
                discardedHydrations += 1
                log("HYDRATE DISCARDED")
                return
            }
            hydrationCount += 1
            hydrated = true
            findingsAvailable = true
            historyCount = 5
            log("HYDRATE APPLIED \(selected.sorted())")
        }
    }

    private func verifyCompletion() {
        guard selectionCount == 13, closeCount == 8, hydrationCount >= 2,
              discardedHydrations >= 1, healthTick >= 4,
              visibleInspectorCount == 1, inspectorAppearances >= 2,
              selection == ["1"], hydrated, findingsAvailable else {
            fail("incomplete sequence selections=\(selectionCount) closes=\(closeCount) hydrated=\(hydrationCount) discarded=\(discardedHydrations) pulses=\(healthTick) visibleDetails=\(visibleInspectorCount) detailAppearances=\(inspectorAppearances)", code: 91)
        }
        guard let window, abs(window.frame.width - Settings.width) < 1,
              let content = window.contentView, let table = alertTable(in: content),
              table.selectedRowIndexes.contains(1) else {
            fail("missing final window, width, or selection", code: 92)
        }
        log("SEQUENCE COMPLETE")
        log("FINAL WINDOW frame=\(window.frame)")
        log("PASS survived")
        NSApp.terminate(nil)
    }

    private func fail(_ message: String, code: Int32) -> Never {
        log("FAIL \(message)")
        exit(code)
    }
}

final class ProbeDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSSetUncaughtExceptionHandler { exception in
            log("EXCEPTION \(exception.name.rawValue): \(exception.reason ?? "nil")")
            log(exception.callStackSymbols.joined(separator: "\n"))
            exit(90)
        }
        NSApp.setActivationPolicy(.accessory)
    }
}

@main
struct DefenseClawLayoutProbe: App {
    @NSApplicationDelegateAdaptor(ProbeDelegate.self) var delegate
    @StateObject private var controller = ProbeController()

    var body: some Scene {
        Window("DefenseClawLayoutProbe", id: "main") {
            MainProbeView(controller: controller)
                .frame(minWidth: 980, minHeight: 640)
                .onAppear { controller.run() }
        }
        .defaultSize(width: Settings.width, height: 760)
    }
}

private struct MainProbeView: View {
    @ObservedObject var controller: ProbeController
    var body: some View {
        NavigationSplitView {
            List(selection: $controller.panel) {
                Section("Monitor") {
                    ForEach(["Overview", "Alerts", "Logs", "Audit", "Activity"], id: \.self) { panel in
                        HStack {
                            Label(panel, systemImage: "shield")
                            if panel == "Overview", controller.healthTick % 2 == 0 {
                                Image(systemName: "exclamationmark.triangle.fill")
                            }
                        }
                        .tag(panel)
                    }
                }
                Section("Discover") { Text("Inventory"); Text("AI Discovery"); Text("Runtime") }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 210)
        } detail: {
            panel
        }
    }
    @ViewBuilder private var panel: some View {
        if controller.panel == "Alerts" {
            AlertsProbeView(controller: controller).navigationTitle("Alerts")
        } else {
            ContentUnavailableView("No \((controller.panel ?? "Activity").lowercased())", systemImage: "tray")
                .navigationTitle(controller.panel ?? "Activity")
        }
    }
}

private struct SyntheticAlert: Identifiable {
    let id: String
    let action: String
    let target: String
    let details: String
    static let rows = (0..<30).map { index in
        SyntheticAlert(id: String(index), action: index % 2 == 0 ? "TOOL_POLICY_BLOCK" : "SCAN_FINDING",
            target: "/Users/synthetic/.local/share/agent/workspace/\(String(repeating: "long-path-segment/", count: index % 4 + 1))example.py",
            details: "decision=block connector=synthetic_tool evaluation_id=synthetic-\(index) rule_ids=[test-policy] max_severity=HIGH metadata=\(String(repeating: "synthetic ", count: index % 4 * 8 + 10))")
    }
}

private struct AlertsProbeView: View {
    @ObservedObject var controller: ProbeController
    @State private var search = ""
    @State private var kind = "all"
    @State private var severity = "All"
    @State private var connector = "All Connectors"
    private var selected: SyntheticAlert? { SyntheticAlert.rows.first { controller.selection.contains($0.id) } }
    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    ForEach(["CRITICAL", "HIGH", "MEDIUM", "LOW"], id: \.self) { severity in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(severity).font(.caption).foregroundStyle(.secondary)
                            Text("10").font(.system(size: 26, weight: .bold, design: .rounded))
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                         .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
                    }
                }
                Picker("Connector", selection: $connector) {
                    ForEach(["All Connectors", "Synthetic Agent", "Synthetic Editor"], id: \.self) { value in
                        Text(value).tag(value)
                    }
                }
                .pickerStyle(.menu)
                .fixedSize()
                HStack {
                    Picker("Severity", selection: $severity) {
                        ForEach(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"], id: \.self) { value in
                            Text(value).tag(value)
                        }
                    }
                    .pickerStyle(.segmented)
                    Spacer()
                    Picker("Kind", selection: $kind) { Text("All kinds").tag("all") }.frame(width: 150)
                }
            }.padding(12)
            Divider()
            Table(SyntheticAlert.rows, selection: $controller.selection) {
                TableColumn("Time") { _ in Text("11:33:19").font(.caption.monospacedDigit()) }.width(76)
                TableColumn("Severity") { _ in Text("HIGH").font(.caption2) }.width(86)
                TableColumn("Kind") { _ in Text("audit").font(.caption) }.width(86)
                TableColumn("Action") { Text($0.action).font(.caption) }.width(min: 90, ideal: 130)
                TableColumn("Target") { Text($0.target).font(.caption).lineLimit(1) }.width(min: 110, ideal: 180)
                TableColumn("Details") { Text($0.details).font(.caption).lineLimit(2) }
                TableColumn("Run") { _ in Text("synthetic-run-identifier").font(.caption2.monospaced()).lineLimit(1) }.width(80)
            }
        }
        .probeInspector(isPresented: Binding(
            get: { selected != nil },
            set: { if !$0 { controller.selection = [] } }
        )) {
            if let selected { inspector(selected) }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search action, target, details")
        .toolbar { Button("Acknowledge Selection", systemImage: "checkmark.circle") {} }
        .onChange(of: controller.selection) { _, _ in controller.loadDetail() }
    }
    private func inspector(_ row: SyntheticAlert) -> some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 10) { inspectorContent(row) }
                .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        }
        .onAppear { controller.inspectorAppeared() }
        .onDisappear { controller.inspectorDisappeared() }
    }
    @ViewBuilder private func inspectorContent(_ row: SyntheticAlert) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text(row.action).font(.headline)
                HStack { Text("HIGH").font(.caption2); Text("Audit").font(.caption) }
            }
            Spacer()
            Button(action: controller.closeInspector) { Image(systemName: "xmark.circle.fill") }.buttonStyle(.borderless)
        }
        KeyValueProbe(pairs: [("Target", row.target), ("Time", "Sep 22, 2026 at 11:33:19 AM"), ("Connector", "synthetic_agent"), ("Run ID", "run-synthetic-0123456789abcdef")])
        Divider()
        Text("Event Details").font(.caption.weight(.semibold))
        KeyValueProbe(pairs: [("Decision", "Block"), ("Evaluation ID", "synthetic-evaluation-0123456789abcdef0123456789abcdef"), ("Rule IDs", "[policy-synthetic-test]"), ("Max Severity", "HIGH")])
        Divider()
        Text("Raw Details").font(.caption.weight(.semibold))
        Text(row.details + (controller.hydrated ? String(repeating: "\nSynthetic hydrated multiline detail with a long token abcdef0123456789abcdef0123456789abcdef0123456789. ", count: 10) : ""))
            .font(.system(.caption, design: .monospaced))
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
            .padding(8).background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            .textSelection(.enabled)
        if controller.findingsAvailable {
            Divider()
            Text("Findings").font(.caption.weight(.semibold))
            ForEach(0..<20, id: \.self) { index in
                VStack(alignment: .leading, spacing: 4) {
                    HStack { Text("HIGH").font(.caption2); Text("Synthetic policy finding \(index)").font(.callout.weight(.medium)) }
                    Text("Synthetic policy details \(String(repeating: "example ", count: index + 4))").font(.caption)
                    Label(row.target, systemImage: "mappin.and.ellipse").font(.caption2).textSelection(.enabled)
                }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
                 .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
        }
        if controller.historyCount > 0 {
            Divider()
            Text("History for This Target").font(.caption.weight(.semibold))
            ForEach(0..<controller.historyCount, id: \.self) { _ in
                HStack { Text("Sep22,11:33").font(.caption2); Text("POLICY_BLOCK").font(.caption).lineLimit(1); Spacer(); Text("HIGH").font(.caption2) }
            }
        }
    }
}

private struct KeyValueProbe: View {
    let pairs: [(String, String)]
    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 5) {
            ForEach(Array(pairs.enumerated()), id: \.offset) { _, pair in
                GridRow {
                    Text(pair.0).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: true, vertical: false)
                    Text(pair.1).font(.caption).frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                }
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

private extension View {
    @ViewBuilder
    func probeInspector<Inspector: View>(
        isPresented: Binding<Bool>,
        @ViewBuilder content: @escaping () -> Inspector
    ) -> some View {
        if Settings.baseline {
            inspector(isPresented: isPresented) {
                if isPresented.wrappedValue {
                    content().inspectorColumnWidth(min: 250, ideal: 320, max: 380)
                }
            }
        } else {
            dcInspector(isPresented: isPresented, content: content)
        }
    }
}
