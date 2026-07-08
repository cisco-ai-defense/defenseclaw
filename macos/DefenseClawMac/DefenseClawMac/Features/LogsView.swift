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

// Logs panel (spec §9.8): four source streams, filter chips (severity /
// action / event type / presets ported from FILTER_PRESETS), live tail.

import SwiftUI

struct LogsView: View {
    @Environment(AppState.self) private var appState
    @State private var stream: LogStream = .gateway
    @State private var preset: LogPreset = .noNoise
    @State private var severityFloor: Severity? = nil
    @State private var actionFilter = "all"
    @State private var eventTypeFilter = "all"
    @State private var search = ""
    @State private var rows: [LogRow] = []
    /// Cached filter output. Filtering up to 20k rows inside `body` stalls the
    /// main thread during trackpad scrolling — recompute only when inputs change.
    @State private var filtered: [LogRow] = []
    @State private var displayRows: [DisplayLogRow] = []
    @State private var selectedRowID: String?
    @State private var autoScroll = true
    /// True while the last row is on screen; auto-scroll only then, so live
    /// tail updates never yank the view away from what the user is reading.
    @State private var isAtBottom = true
    @State private var showRedactionToggle = false

    // Superset of the TUI's Verdicts-stream chips (ACTION_FILTERS: block/alert/
    // confirm/allow; EVENT_TYPE_FILTERS: verdict/judge/lifecycle/error/
    // diagnostic/scan/scan_finding/activity) plus the hook/audit extras the
    // Mac's shared filter serves across all four stream tabs.
    private static let actionOptions = ["all", "block", "alert", "confirm", "allow", "reject", "scan", "hook"]
    private static let eventTypeOptions = ["all", "verdict", "judge", "lifecycle", "error", "diagnostic",
                                           "scan", "scan_finding", "activity", "audit", "hook", "egress",
                                           "skill", "mcp", "plugin"]

    private func applyFilter() {
        let query = search.lowercased()
        filtered = rows.filter { row in
            if !appState.connectorFilterAllows(row.connector) { return false }
            guard preset.matches(row) else { return false }
            if let severityFloor, row.severity < severityFloor { return false }
            if actionFilter != "all", !row.action.lowercased().contains(actionFilter) { return false }
            // "scan" must not swallow "scan_finding" — those are distinct
            // TUI event-type chips; everything else keeps fuzzy matching.
            if eventTypeFilter == "scan" {
                if row.eventType.lowercased() != "scan" { return false }
            } else if eventTypeFilter != "all", !row.eventType.lowercased().contains(eventTypeFilter) {
                return false
            }
            if !query.isEmpty, !row.message.lowercased().contains(query),
               !row.rawJSON.lowercased().contains(query) { return false }
            return true
        }
        displayRows = collapseAdjacentRows(filtered)
        if let selectedRowID, !displayRows.contains(where: { $0.id == selectedRowID }) {
            self.selectedRowID = nil
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            filterBar
            Divider()
            if displayRows.isEmpty {
                DCEmptyState(
                    title: "No log lines",
                    message: rows.isEmpty
                        ? "No data in \(sourceFilename(for: stream)) for the \(stream.title) stream yet."
                        : "Nothing matches the current filters.",
                    systemImage: "text.alignleft"
                )
                .frame(maxHeight: .infinity)
            } else {
                logList
            }
        }
        .inspector(isPresented: inspectorPresented) {
            if let selectedDisplayRow {
                logInspector(selectedDisplayRow)
                    .inspectorColumnWidth(min: 300, ideal: 380)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search log lines")
        .toolbar {
            ToolbarItemGroup {
                Toggle(isOn: $autoScroll) {
                    Label("Auto-scroll", systemImage: "arrow.down.to.line")
                }
                .toggleStyle(.button)
                Button {
                    reload()
                } label: {
                    Label("Reload from disk", systemImage: "arrow.clockwise")
                }
            }
        }
        .task {
            if applyPendingPanelRequest() {
                await load(force: true)
            } else {
                await load()
            }
        }
        .task(id: appState.health.fetchedAt) { await load() } // pulse-fed
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in reload() }
        .onChange(of: preset) { _, _ in applyFilter() }
        .onChange(of: severityFloor) { _, _ in applyFilter() }
        .onChange(of: actionFilter) { _, _ in applyFilter() }
        .onChange(of: eventTypeFilter) { _, _ in applyFilter() }
        .onChange(of: search) { _, _ in applyFilter() }
        .onChange(of: appState.connectorFilter) { _, _ in applyFilter() }
        .onChange(of: appState.logPanelRequest) { _, _ in
            guard applyPendingPanelRequest() else { return }
            Task { await load(force: true) }
        }
        .sheet(isPresented: $showRedactionToggle) {
            RedactionToggleSheet()
                .environment(appState)
        }
    }

    private var filterBar: some View {
        @Bindable var state = appState
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                Picker("Stream", selection: $stream) {
                    ForEach(LogStream.allCases) { s in Text(s.title).tag(s) }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 440)
                .onChange(of: stream) { _, _ in Task { await load(force: true) } }
                Spacer()
                if !appState.config.redactionEnabled {
                    // TUI RAW badge: redaction kill-switch is off.
                    Text("RAW — redaction off")
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(Cisco.orange.opacity(0.18), in: Capsule())
                        .foregroundStyle(Cisco.orange)
                        .help("redaction off - `defenseclaw setup redaction on` to re-enable")
                }
                Button("Redaction…") { showRedactionToggle = true }
                    .controlSize(.small)
                    .help("Toggle the redaction kill-switch (runs defenseclaw setup redaction on|off)")
                ConnectorFilterChip(names: appState.activeConnectorNames, selection: $state.connectorFilter)
            }

            HStack(spacing: 12) {
                FilterChipRow(
                    "Preset",
                    options: [("Preset: all", LogPreset.all)] +
                        LogPreset.allCases.dropFirst().map { ($0.rawValue, $0) },
                    selection: $preset
                )
                Picker("Severity ≥", selection: $severityFloor) {
                    Text("Any severity").tag(Optional<Severity>.none)
                    ForEach([Severity.critical, .high, .medium, .low], id: \.self) {
                        Text("≥ \($0.rawValue)").tag(Optional($0))
                    }
                }
                .frame(width: 150)
                Picker("Action", selection: $actionFilter) {
                    ForEach(Self.actionOptions, id: \.self) { Text($0).tag($0) }
                }
                .frame(width: 120)
                Picker("Event", selection: $eventTypeFilter) {
                    ForEach(Self.eventTypeOptions, id: \.self) { Text($0).tag($0) }
                }
                .frame(width: 120)
                Spacer()
                Text("\(displayRows.count) shown · \(filtered.count) matching · \(rows.count) total")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(10)
    }

    private var logList: some View {
        ScrollViewReader { proxy in
            List(displayRows, selection: $selectedRowID) { item in
                let row = item.row
                HStack(alignment: .top, spacing: 8) {
                    RoundedRectangle(cornerRadius: 1.5)
                        .fill(Cisco.severityColor(row.severity))
                        .frame(width: 3)
                    Text(row.timestamp, format: .dateTime.hour().minute().second())
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 7) {
                            Text(eventLabel(row))
                                .font(.system(.callout, design: .monospaced).weight(.semibold))
                                .foregroundStyle(Cisco.blue)
                            if item.count > 1 {
                                Text("Repeated \(item.count) times")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(.secondary.opacity(0.12), in: Capsule())
                            }
                            Spacer()
                        }
                        Text(item.message)
                            .font(.system(.callout, design: .monospaced))
                            .lineLimit(3)
                            .textSelection(.enabled)
                        if !row.connector.isEmpty,
                           !item.message.localizedCaseInsensitiveContains(row.connector) {
                            Text(row.connector)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .id(item.id)
                .listRowSeparator(.hidden)
                .onAppear { if item.id == displayRows.last?.id { isAtBottom = true } }
                .onDisappear { if item.id == displayRows.last?.id { isAtBottom = false } }
                .contextMenu {
                    Button("Copy Summary") { copyToPasteboard(item.message) }
                    Button("Copy JSON") { copyToPasteboard(row.rawJSON) }
                }
            }
            .listStyle(.plain)
            .onChange(of: displayRows.count) { _, _ in
                // Follow the tail only while the user is already at the bottom —
                // never steal the scroll position mid-read.
                if autoScroll, isAtBottom, let last = displayRows.last {
                    var transaction = Transaction()
                    transaction.disablesAnimations = true
                    withTransaction(transaction) {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }

    private func sourceFilename(for stream: LogStream) -> String {
        switch stream {
        case .gateway:
            ConfigStore.gatewayLogURL.lastPathComponent
        case .watchdog:
            ConfigStore.watchdogLogURL.lastPathComponent
        case .verdicts, .otel:
            ConfigStore.gatewayJSONLURL.lastPathComponent
        }
    }

    private func eventLabel(_ row: LogRow) -> String {
        let parts = [row.eventType, row.action].filter { !$0.isEmpty && $0 != "event" }
        return parts.isEmpty ? row.stream.title : "[\(parts.joined(separator: ":"))]"
    }

    private func collapseAdjacentRows(_ rows: [LogRow]) -> [DisplayLogRow] {
        var result: [DisplayLogRow] = []
        for row in rows {
            let message = humanMessage(row.message)
            if message.count <= 2, preset != .all { continue }
            let displayMessage = message.isEmpty ? "Redacted event payload" : message
            if var previous = result.last,
               previous.message == displayMessage,
               previous.row.eventType == row.eventType,
               previous.row.action == row.action,
               previous.row.connector == row.connector,
               previous.row.severity == row.severity {
                previous.count += 1
                previous.lastTimestamp = row.timestamp
                result[result.count - 1] = previous
            } else {
                result.append(DisplayLogRow(
                    row: row,
                    message: displayMessage,
                    count: 1,
                    lastTimestamp: row.timestamp
                ))
            }
        }
        return result
    }

    private func humanMessage(_ source: String) -> String {
        let patterns = [
            #"^\s*[-–—]?\s*\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\s+"#,
            #"<redacted(?:\s+[^>]*)?>"#,
            #"\b(?:call_id|session|run_id|audit_id|content_hash|payload_hmac|sha(?:256)?|len|body_bytes|request_bytes|response_bytes)=[^\s]+"#,
            #"\b(?:sha|a)=[A-Fa-f0-9]{8,}>"#,
            #"\s+(?:cause|msg)=\s*$"#,
        ]
        let range = { (value: String) in NSRange(value.startIndex..., in: value) }
        var result = source
        for pattern in patterns {
            guard let expression = try? NSRegularExpression(pattern: pattern) else { continue }
            result = expression.stringByReplacingMatches(in: result, range: range(result), withTemplate: "")
        }
        result = result.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return result
    }

    private var selectedDisplayRow: DisplayLogRow? {
        guard let selectedRowID else { return nil }
        return displayRows.first { $0.id == selectedRowID }
    }

    private var inspectorPresented: Binding<Bool> {
        Binding(
            get: { selectedDisplayRow != nil },
            set: { if !$0 { selectedRowID = nil } }
        )
    }

    private func logInspector(_ item: DisplayLogRow) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Event Details").font(.headline)
                Spacer()
                Button { selectedRowID = nil } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.borderless)
                .help("Close Inspector")
            }
            Text(item.message)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
            KeyValueGrid(pairs: [
                ("First", item.row.timestamp.formatted(date: .abbreviated, time: .standard)),
                ("Last", item.lastTimestamp.formatted(date: .abbreviated, time: .standard)),
                ("Stream", item.row.stream.title),
                ("Event", item.row.eventType),
                ("Action", item.row.action),
                ("Severity", item.row.severity.rawValue),
                ("Connector", item.row.connector),
                ("Occurrences", "\(item.count)"),
            ].filter { !$0.1.isEmpty })
            Divider()
            Text("Raw Event").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            ScrollView {
                Text(item.row.rawJSON)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
        }
        .padding(12)
    }

    /// Refreshes from the stream buffer, but only publishes when the tail
    /// actually advanced — pulse ticks with no new lines are free.
    private func load(force: Bool = false) async {
        let fresh = await appState.stream.logBuffers[stream] ?? []
        guard force || fresh.count != rows.count || fresh.last?.id != rows.last?.id else { return }
        rows = fresh
        applyFilter()
    }

    private func reload() {
        Task {
            _ = await appState.stream.reload()
            await load(force: true)
        }
    }

    @discardableResult
    private func applyPendingPanelRequest() -> Bool {
        guard let request = appState.consumeLogPanelRequest() else { return false }
        preset = request.preset
        actionFilter = request.actionFilter
        eventTypeFilter = request.eventTypeFilter
        severityFloor = nil
        search = ""
        stream = request.stream
        autoScroll = true
        return true
    }
}

private struct DisplayLogRow: Identifiable {
    let row: LogRow
    let message: String
    var count: Int
    var lastTimestamp: Date
    var id: String { row.id }
}

/// The TUI's "Redaction kill-switch" consequence modal: current/desired state,
/// the raw-sink warning when disabling, and a two-step danger confirm. Runs
/// `defenseclaw setup redaction on|off --yes` (config.yaml write + gateway
/// restart happen CLI-side).
struct RedactionToggleSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @State private var armed = false
    @State private var running = false

    private var currentlyDisabled: Bool { !appState.config.redactionEnabled }
    private var desired: String { currentlyDisabled ? "on" : "off" }
    private var currentLabel: String {
        currentlyDisabled ? "RAW (full prompts to all sinks)" : "REDACTED (placeholders only)"
    }
    private var desiredLabel: String {
        currentlyDisabled ? "REDACTED (placeholders only)" : "RAW (full prompts to all sinks)"
    }
    private var dangerous: Bool { desired == "off" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Redaction kill-switch").font(.headline)
            VStack(alignment: .leading, spacing: 2) {
                Text("Current state: \(currentLabel)")
                Text("Will become:   \(desiredLabel)")
            }
            .font(.callout.monospaced())
            if dangerous {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Disabling redaction writes RAW content to:")
                    Text("• SQLite audit DB")
                    Text("• Splunk HEC, OTel log exporters, webhooks")
                    Text("• gateway.log and the Logs panel")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                Text("Only proceed if every downstream sink lives in the same trust boundary as this install.")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Cisco.orange)
            } else {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Re-enables redaction; placeholders return on the next sidecar boot.")
                    Text("Existing already-emitted audit rows/events remain as written.")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Text("Runs `defenseclaw setup redaction \(desired) --yes` and restarts the gateway.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
            if armed {
                Text("⚠ danger — click Confirm again to proceed")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Cisco.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(running ? "Running…" : "Confirm") { confirm() }
                    .buttonStyle(.borderedProminent)
                    .tint(dangerous ? Cisco.red : Cisco.green)
                    .disabled(running)
            }
        }
        .padding(16)
        .frame(width: 470)
    }

    private func confirm() {
        // Two-step confirm for the dangerous direction (TUI danger arming).
        if dangerous, !armed {
            armed = true
            return
        }
        running = true
        Task {
            _ = await appState.runCommand(
                title: "setup redaction \(desired)",
                arguments: ["setup", "redaction", desired, "--yes"],
                category: "setup",
                origin: "Logs",
                successEffects: [desired == "on" ? "Redaction re-enabled; gateway restarted"
                                                 : "Redaction DISABLED; raw content flows to sinks"],
                refreshOnSuccess: true
            )
            running = false
            dismiss()
        }
    }
}
