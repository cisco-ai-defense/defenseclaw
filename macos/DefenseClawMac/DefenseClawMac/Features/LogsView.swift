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
    @State private var showRedactionPolicy = false

    // Superset of the TUI's Verdicts-stream chips (ACTION_FILTERS: block/alert/
    // confirm/allow; EVENT_TYPE_FILTERS: verdict/judge/lifecycle/error/
    // diagnostic/scan/scan_finding/activity) plus the hook/audit extras the
    // Mac's shared filter serves across all four stream tabs.
    private static let actionOptions = ["all", "block", "alert", "confirm", "allow", "reject", "scan", "hook"]
    private static let eventTypeOptions = ["all", "verdict", "judge", "lifecycle", "error", "diagnostic",
                                           "scan", "scan_finding", "activity", "audit", "hook", "egress",
                                           "skill", "mcp", "plugin"]
    private static let humanMessageExpressions: [NSRegularExpression] = [
        #"^\s*[-–—]?\s*\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\s+"#,
        #"<redacted(?:\s+[^>]*)?>"#,
        #"\b(?:call_id|session|run_id|audit_id|content_hash|payload_hmac|sha(?:256)?|len|body_bytes|request_bytes|response_bytes)=[^\s]+"#,
        #"\b(?:sha|a)=[A-Fa-f0-9]{8,}>"#,
        #"\s+(?:cause|msg)=\s*$"#,
    ].compactMap { try? NSRegularExpression(pattern: $0) }
    private static let whitespaceExpression = try? NSRegularExpression(pattern: #"\s+"#)

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
        .sheet(isPresented: $showRedactionPolicy) {
            RedactionPolicySheet()
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
                Button("Redaction policy…") { showRedactionPolicy = true }
                    .controlSize(.small)
                    .help("Inspect or apply the v8 redaction policy")
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
            appState.installationContext.gatewayLogURL.lastPathComponent
        case .watchdog:
            appState.installationContext.watchdogLogURL.lastPathComponent
        case .verdicts, .otel:
            appState.installationContext.gatewayJSONLURL.lastPathComponent
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
        let range = { (value: String) in NSRange(value.startIndex..., in: value) }
        var result = source
        for expression in Self.humanMessageExpressions {
            result = expression.stringByReplacingMatches(in: result, range: range(result), withTemplate: "")
        }
        if let expression = Self.whitespaceExpression {
            result = expression.stringByReplacingMatches(in: result, range: range(result), withTemplate: " ")
        }
        result = result.trimmingCharacters(in: .whitespacesAndNewlines)
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
        let installationGeneration = appState.installationGeneration
        let fresh = await appState.stream.logBuffers[stream] ?? []
        guard installationGeneration == appState.installationGeneration else { return }
        guard force || fresh.count != rows.count || fresh.last?.id != rows.last?.id else { return }
        rows = fresh
        applyFilter()
    }

    private func reload() {
        Task {
            let installationGeneration = appState.installationGeneration
            _ = await appState.stream.reload()
            guard installationGeneration == appState.installationGeneration else { return }
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

/// A macOS front end for the canonical v8 redaction CLI. The primary controls
/// cover status and broad profile application; the disclosure below exposes the
/// complete non-interactive policy surface.
struct RedactionPolicySheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @State private var armed = false
    @State private var running = false
    @State private var profile = "sensitive"
    @State private var restart = false
    @State private var statusOutput = ""
    @State private var showAdvanced = false

    private let profiles = ["none", "sensitive", "content", "strict"]
    private var dangerous: Bool { profile == "none" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Redaction policy").font(.headline)
            Text("Current global default: \(appState.config.redactionDefaultProfile.isEmpty ? "unset" : appState.config.redactionDefaultProfile)")
                .font(.callout.monospaced())
            Text("Bucket, destination, and route overrides may be more specific. View status for the canonical effective policy.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Picker("Apply profile everywhere", selection: $profile) {
                ForEach(profiles, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            if dangerous {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Profile none permits raw governed content in generated local SQLite and every configurable destination.")
                    Text("The release-owned managed enterprise destination remains locked.")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                Text("Only proceed if every downstream sink lives in the same trust boundary as this install.")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Cisco.orange)
            } else {
                Text("This replaces every configurable profile override with \(profile); collection and routing stay unchanged.")
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Toggle("Restart gateway after applying", isOn: $restart)
            Text("The CLI previews, validates, backs up, writes atomically, and verifies the effective plan.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
            DisclosureGroup("Show advanced settings", isExpanded: $showAdvanced) {
                RedactionAdvancedEditor(
                    running: $running,
                    output: $statusOutput
                )
                .padding(.top, 8)
            }
            if !statusOutput.isEmpty {
                ScrollView {
                    Text(statusOutput)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 180)
            }
            if armed {
                Text("⚠ danger — click Apply again to proceed")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Cisco.red)
            }
            HStack {
                Button("View status") { inspectStatus() }
                    .disabled(running)
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(running ? "Running…" : "Apply") { confirm() }
                    .buttonStyle(.borderedProminent)
                    .tint(dangerous ? Cisco.red : Cisco.green)
                    .disabled(running || !appState.installationMutationsAllowed)
            }
        }
        .padding(16)
        .frame(width: 560)
        .onAppear {
            if profiles.contains(appState.config.redactionDefaultProfile) {
                profile = appState.config.redactionDefaultProfile
            }
        }
        .onChange(of: profile) { _, _ in armed = false }
    }

    private func inspectStatus() {
        running = true
        Task {
            let result = await appState.runCommand(
                title: "setup redaction status",
                arguments: ["setup", "redaction", "status"],
                mutation: false,
                category: "setup",
                origin: "Logs"
            )
            statusOutput = result.output
            running = false
        }
    }

    private func confirm() {
        // Two-step confirmation for the unredacted profile.
        if dangerous, !armed {
            armed = true
            return
        }
        running = true
        Task {
            var arguments = profile == "none"
                ? ["setup", "redaction", "remove-all", "--yes"]
                : ["setup", "redaction", "apply", "--scope", "all-configurable", "--profile", profile, "--yes"]
            arguments.append(restart ? "--restart" : "--no-restart")
            let result = await appState.runCommand(
                title: "apply redaction profile \(profile)",
                arguments: arguments,
                category: "setup",
                origin: "Logs",
                successEffects: [
                    profile == "none"
                        ? "Redaction removed from configurable projections"
                        : "Redaction profile \(profile) applied to configurable projections"
                ],
                refreshOnSuccess: true
            )
            running = false
            if result.succeeded {
                dismiss()
            } else {
                armed = false
                statusOutput = result.output.isEmpty
                    ? "Command failed with exit \(result.exitCode)."
                    : result.output
            }
        }
    }
}

private enum RedactionAdvancedAction: String, CaseIterable, Identifiable {
    case status = "Inspect effective policy"
    case removeAll = "Remove all configurable redaction"
    case applyAll = "Apply profile everywhere"
    case applyDefaults = "Apply profile to defaults"
    case defaultsSet = "Set global defaults"
    case defaultsReset = "Reset global defaults"
    case bucketList = "List all buckets"
    case bucketSet = "Set bucket policy"
    case bucketReset = "Reset bucket policy"
    case profileList = "List profiles"
    case profileShow = "Show compiled profile"
    case profileSet = "Create or edit custom profile"
    case profileRemove = "Remove custom profile"
    case destinationShow = "Show destination policy"
    case destinationSend = "Set destination send policy"
    case destinationInherit = "Restore destination inheritance"
    case routeList = "List ordered routes"
    case routeAdd = "Add ordered route"
    case routeSet = "Replace ordered route"
    case routeMove = "Move ordered route"
    case routeRemove = "Remove ordered route"

    var id: String { rawValue }

    var isMutation: Bool {
        switch self {
        case .status, .bucketList, .profileList, .profileShow, .destinationShow, .routeList:
            false
        default:
            true
        }
    }

    var supportsJSON: Bool {
        switch self {
        case .status,
             .removeAll,
             .applyAll,
             .applyDefaults,
             .defaultsSet,
             .defaultsReset,
             .bucketSet,
             .bucketReset,
             .profileList,
             .profileShow,
             .profileSet,
             .profileRemove,
             .destinationSend,
             .destinationInherit,
             .routeList,
             .routeAdd,
             .routeSet,
             .routeMove,
             .routeRemove:
            true
        case .bucketList, .destinationShow:
            false
        }
    }
}

/// Complete non-interactive redaction surface for the macOS app. The view
/// builds the same argv accepted by the CLI and defaults every mutation to a
/// canonical dry-run, so platform UI and automation share one policy engine.
private struct RedactionAdvancedEditor: View {
    @Environment(AppState.self) private var appState
    @Binding var running: Bool
    @Binding var output: String

    @State private var action: RedactionAdvancedAction = .status
    @State private var selectedBucket = "compliance.activity"
    @State private var policyProfile = "sensitive"
    @State private var logs = "unchanged"
    @State private var traces = "unchanged"
    @State private var metrics = "unchanged"
    @State private var customProfile = ""
    @State private var extendsProfile = "sensitive"
    @State private var detectors = ""
    @State private var metadataMode = "unchanged"
    @State private var identifierMode = "unchanged"
    @State private var contentMode = "unchanged"
    @State private var reasonMode = "unchanged"
    @State private var evidenceMode = "unchanged"
    @State private var errorMode = "unchanged"
    @State private var pathMode = "unchanged"
    @State private var credentialMode = "unchanged"
    @State private var replacementProfile = ""
    @State private var destination = ""
    @State private var routeName = ""
    @State private var signals = "logs,traces"
    @State private var routeBuckets = "*"
    @State private var sources = ""
    @State private var connectors = ""
    @State private var producerActions = ""
    @State private var eventNames = ""
    @State private var minimumSeverity = "none"
    @State private var routeAction = "send"
    @State private var position = ""
    @State private var dryRun = true
    @State private var emitJSON = false
    @State private var restart = false

    private let buckets = [
        "compliance.activity", "security.finding", "guardrail.evaluation",
        "enforcement.action", "model.io", "tool.activity", "asset.scan",
        "asset.lifecycle", "network.egress", "agent.lifecycle", "ai.discovery",
        "telemetry.ingest", "platform.health", "diagnostic",
    ]
    private let triStates = ["unchanged", "on", "off"]
    private let fieldModes = ["unchanged", "inherit", "preserve", "detect", "whole", "hash", "remove"]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("Action", selection: $action) {
                ForEach(RedactionAdvancedAction.allCases) { item in
                    Text(item.rawValue).tag(item)
                }
            }
            .pickerStyle(.menu)

            ScrollView {
                VStack(alignment: .leading, spacing: 9) {
                    actionFields
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 330)

            if let validationError {
                Text(validationError)
                    .font(.caption)
                    .foregroundStyle(Cisco.orange)
            }

            HStack(spacing: 14) {
                if action.supportsJSON {
                    Toggle("JSON", isOn: $emitJSON)
                }
                if action.isMutation {
                    Toggle("Dry run", isOn: $dryRun)
                    Toggle("Restart", isOn: $restart)
                        .disabled(dryRun)
                }
                Spacer()
                Button(buttonLabel) { runAction() }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        running || validationError != nil ||
                        (action.isMutation && !dryRun && !appState.installationMutationsAllowed)
                    )
            }
            Text(commandPreview)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(3)
        }
        .padding(10)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
        .onChange(of: action) { _, _ in
            resetActionFields()
        }
    }

    private func resetActionFields() {
        // Re-arm safe defaults and clear every action-scoped value so a prior
        // mutation cannot silently carry into a newly selected operation.
        selectedBucket = buckets[0]
        policyProfile = "sensitive"
        logs = "unchanged"
        traces = "unchanged"
        metrics = "unchanged"
        customProfile = ""
        extendsProfile = "sensitive"
        detectors = ""
        metadataMode = "unchanged"
        identifierMode = "unchanged"
        contentMode = "unchanged"
        reasonMode = "unchanged"
        evidenceMode = "unchanged"
        errorMode = "unchanged"
        pathMode = "unchanged"
        credentialMode = "unchanged"
        replacementProfile = ""
        destination = ""
        routeName = ""
        signals = "logs,traces"
        routeBuckets = "*"
        sources = ""
        connectors = ""
        producerActions = ""
        eventNames = ""
        minimumSeverity = "none"
        routeAction = "send"
        position = ""
        dryRun = true
        emitJSON = false
        restart = false
        output = ""
    }

    @ViewBuilder
    private var actionFields: some View {
        switch action {
        case .status, .removeAll, .defaultsReset, .bucketList, .profileList:
            Text(action.rawValue + " requires no additional settings.")
                .font(.caption)
                .foregroundStyle(.secondary)

        case .applyAll, .applyDefaults:
            labeledTextField("Profile", text: $policyProfile, prompt: "built-in or custom profile")

        case .defaultsSet:
            labeledTextField("Profile (blank keeps current)", text: $policyProfile, prompt: "sensitive")
            collectionPickers

        case .bucketSet:
            bucketPicker
            labeledTextField("Profile (blank keeps current; inherit removes override)", text: $policyProfile)
            collectionPickers

        case .bucketReset:
            bucketPicker

        case .profileShow:
            labeledTextField("Profile", text: $customProfile)

        case .profileSet:
            labeledTextField("Custom profile name", text: $customProfile)
            Picker("Extends", selection: $extendsProfile) {
                ForEach(["sensitive", "content", "strict"], id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            labeledTextField("Detector groups (comma-separated; blank keeps current)", text: $detectors,
                             prompt: "pii,credentials,secrets")
            Text("Field-class modes")
                .font(.caption.weight(.semibold))
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                fieldModePicker("metadata", selection: $metadataMode)
                fieldModePicker("identifier", selection: $identifierMode)
                fieldModePicker("content", selection: $contentMode)
                fieldModePicker("reason", selection: $reasonMode)
                fieldModePicker("evidence", selection: $evidenceMode)
                fieldModePicker("error", selection: $errorMode)
                fieldModePicker("path", selection: $pathMode)
                fieldModePicker("credential", selection: $credentialMode)
            }

        case .profileRemove:
            labeledTextField("Custom profile name", text: $customProfile)
            labeledTextField("Replace references with (blank requires unreferenced)", text: $replacementProfile)

        case .destinationShow, .destinationInherit:
            labeledTextField("Destination name", text: $destination)

        case .destinationSend:
            labeledTextField("Destination name", text: $destination)
            labeledTextField("Signals (comma-separated)", text: $signals, prompt: "logs,traces")
            labeledTextField("Buckets (comma-separated or *)", text: $routeBuckets, prompt: "*")
            labeledTextField("Profile (blank inherits)", text: $policyProfile)

        case .routeList:
            labeledTextField("Destination name", text: $destination)

        case .routeAdd, .routeSet:
            labeledTextField("Destination name", text: $destination)
            labeledTextField("Route name", text: $routeName)
            if action == .routeAdd {
                labeledTextField("One-based position (blank appends)", text: $position)
            }
            labeledTextField("Signals (comma-separated)", text: $signals, prompt: "logs,traces")
            labeledTextField("Bucket selectors (blank means any)", text: $routeBuckets)
            labeledTextField("Source selectors", text: $sources)
            labeledTextField("Connector selectors", text: $connectors)
            labeledTextField("Producer-action selectors", text: $producerActions)
            labeledTextField("Event-name selectors", text: $eventNames)
            HStack {
                Picker("Minimum severity", selection: $minimumSeverity) {
                    ForEach(["none", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], id: \.self) {
                        Text($0).tag($0)
                    }
                }
                Picker("Route action", selection: $routeAction) {
                    Text("send").tag("send")
                    Text("drop").tag("drop")
                }
            }
            if routeAction == "send" {
                labeledTextField("Profile (blank inherits)", text: $policyProfile)
            }

        case .routeMove:
            labeledTextField("Destination name", text: $destination)
            labeledTextField("Route name", text: $routeName)
            labeledTextField("One-based position", text: $position)

        case .routeRemove:
            labeledTextField("Destination name", text: $destination)
            labeledTextField("Route name", text: $routeName)
        }
    }

    private var bucketPicker: some View {
        Picker("Bucket", selection: $selectedBucket) {
            ForEach(buckets, id: \.self) { Text($0).tag($0) }
        }
        .pickerStyle(.menu)
    }

    private var collectionPickers: some View {
        HStack {
            triStatePicker("Logs", selection: $logs)
            triStatePicker("Traces", selection: $traces)
            triStatePicker("Metrics", selection: $metrics)
        }
    }

    private func labeledTextField(
        _ label: String,
        text: Binding<String>,
        prompt: String = ""
    ) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption)
            TextField(prompt, text: text)
                .textFieldStyle(.roundedBorder)
        }
    }

    private func triStatePicker(_ label: String, selection: Binding<String>) -> some View {
        Picker(label, selection: selection) {
            ForEach(triStates, id: \.self) { Text($0).tag($0) }
        }
        .pickerStyle(.menu)
    }

    private func fieldModePicker(_ label: String, selection: Binding<String>) -> some View {
        Picker(label, selection: selection) {
            ForEach(fieldModes, id: \.self) { Text($0).tag($0) }
        }
        .pickerStyle(.menu)
    }

    private var validationError: String? {
        let hasCollectionChange = [logs, traces, metrics].contains { $0 != "unchanged" }
        switch action {
        case .applyAll, .applyDefaults:
            return trimmed(policyProfile).isEmpty ? "Enter a built-in or custom profile." : nil
        case .defaultsSet:
            return trimmed(policyProfile).isEmpty && !hasCollectionChange
                ? "Choose a profile or at least one collection change." : nil
        case .bucketSet:
            return trimmed(policyProfile).isEmpty && !hasCollectionChange
                ? "Choose a profile/inherit or at least one collection change." : nil
        case .profileShow, .profileSet, .profileRemove:
            return trimmed(customProfile).isEmpty ? "Enter a profile name." : nil
        case .destinationShow, .destinationInherit, .routeList:
            return trimmed(destination).isEmpty ? "Enter a destination name." : nil
        case .destinationSend:
            if trimmed(destination).isEmpty { return "Enter a destination name." }
            if csv(signals).isEmpty { return "Select at least one signal." }
            return csv(routeBuckets).isEmpty ? "Select at least one bucket or *." : nil
        case .routeAdd, .routeSet:
            if trimmed(destination).isEmpty { return "Enter a destination name." }
            if trimmed(routeName).isEmpty { return "Enter a route name." }
            if csv(signals).isEmpty { return "Select at least one signal." }
            if action == .routeAdd, !trimmed(position).isEmpty,
               (Int(trimmed(position)) ?? 0) < 1 {
                return "Position must be a positive integer."
            }
            return nil
        case .routeMove:
            if trimmed(destination).isEmpty { return "Enter a destination name." }
            if trimmed(routeName).isEmpty { return "Enter a route name." }
            return (Int(trimmed(position)) ?? 0) < 1 ? "Position must be a positive integer." : nil
        case .routeRemove:
            if trimmed(destination).isEmpty { return "Enter a destination name." }
            return trimmed(routeName).isEmpty ? "Enter a route name." : nil
        case .status, .removeAll, .defaultsReset, .bucketList, .bucketReset, .profileList:
            return nil
        }
    }

    private var buttonLabel: String {
        if running { return "Running…" }
        if !action.isMutation { return "Run" }
        return dryRun ? "Preview" : "Apply"
    }

    private var commandPreview: String {
        (["defenseclaw"] + buildArguments()).joined(separator: " ")
    }

    private func buildArguments() -> [String] {
        var arguments = ["setup", "redaction"]
        switch action {
        case .status:
            arguments.append("status")
        case .removeAll:
            arguments.append("remove-all")
        case .applyAll, .applyDefaults:
            arguments += ["apply", "--scope", action == .applyAll ? "all-configurable" : "defaults",
                          "--profile", trimmed(policyProfile)]
        case .defaultsSet:
            arguments += ["defaults", "set"]
            appendProfile(trimmed(policyProfile), inheritFlag: nil, to: &arguments)
            appendCollection(to: &arguments)
        case .defaultsReset:
            arguments += ["defaults", "reset"]
        case .bucketList:
            arguments += ["bucket", "list"]
        case .bucketSet:
            arguments += ["bucket", "set", selectedBucket]
            appendProfile(trimmed(policyProfile), inheritFlag: "--inherit-profile", to: &arguments)
            appendCollection(to: &arguments)
        case .bucketReset:
            arguments += ["bucket", "reset", selectedBucket]
        case .profileList:
            arguments += ["profile", "list"]
        case .profileShow:
            arguments += ["profile", "show", trimmed(customProfile)]
        case .profileSet:
            arguments += ["profile", "set", trimmed(customProfile), "--extends", extendsProfile]
            appendRepeated("--detector", values: csv(detectors), to: &arguments)
            for (name, mode) in fieldModeValues where mode != "unchanged" {
                arguments += ["--field", "\(name)=\(mode)"]
            }
        case .profileRemove:
            arguments += ["profile", "remove", trimmed(customProfile)]
            if !trimmed(replacementProfile).isEmpty {
                arguments += ["--replace-with", trimmed(replacementProfile)]
            }
        case .destinationShow:
            arguments += ["destination", "show", trimmed(destination)]
        case .destinationSend:
            arguments += ["destination", "send", trimmed(destination)]
            appendRepeated("--signal", values: csv(signals), to: &arguments)
            appendRepeated("--bucket", values: csv(routeBuckets), to: &arguments)
            if !trimmed(policyProfile).isEmpty {
                arguments += ["--profile", trimmed(policyProfile)]
            }
        case .destinationInherit:
            arguments += ["destination", "inherit", trimmed(destination)]
        case .routeList:
            arguments += ["route", "list", trimmed(destination)]
        case .routeAdd, .routeSet:
            arguments += ["route", action == .routeAdd ? "add" : "set", trimmed(destination), trimmed(routeName)]
            if action == .routeAdd, !trimmed(position).isEmpty {
                arguments += ["--position", trimmed(position)]
            }
            appendRouteOptions(to: &arguments)
        case .routeMove:
            arguments += ["route", "move", trimmed(destination), trimmed(routeName),
                          "--position", trimmed(position)]
        case .routeRemove:
            arguments += ["route", "remove", trimmed(destination), trimmed(routeName)]
        }
        if action.supportsJSON, emitJSON {
            arguments.append("--json")
        }
        if action.isMutation {
            arguments.append("--yes")
            if dryRun { arguments.append("--dry-run") }
            arguments.append(restart && !dryRun ? "--restart" : "--no-restart")
        }
        return arguments
    }

    private var fieldModeValues: [(String, String)] {
        [
            ("metadata", metadataMode), ("identifier", identifierMode),
            ("content", contentMode), ("reason", reasonMode),
            ("evidence", evidenceMode), ("error", errorMode),
            ("path", pathMode), ("credential", credentialMode),
        ]
    }

    private func appendProfile(_ value: String, inheritFlag: String?, to arguments: inout [String]) {
        guard !value.isEmpty else { return }
        if value == "inherit", let inheritFlag {
            arguments.append(inheritFlag)
        } else {
            arguments += ["--profile", value]
        }
    }

    private func appendCollection(to arguments: inout [String]) {
        for (signal, value) in [("logs", logs), ("traces", traces), ("metrics", metrics)] {
            if value == "on" { arguments.append("--\(signal)") }
            if value == "off" { arguments.append("--no-\(signal)") }
        }
    }

    private func appendRouteOptions(to arguments: inout [String]) {
        appendRepeated("--signal", values: csv(signals), to: &arguments)
        appendRepeated("--bucket", values: csv(routeBuckets), to: &arguments)
        appendRepeated("--source", values: csv(sources), to: &arguments)
        appendRepeated("--connector", values: csv(connectors), to: &arguments)
        appendRepeated("--producer-action", values: csv(producerActions), to: &arguments)
        appendRepeated("--event-name", values: csv(eventNames), to: &arguments)
        if minimumSeverity != "none" {
            arguments += ["--min-severity", minimumSeverity]
        }
        arguments += ["--route-action", routeAction]
        if routeAction == "send", !trimmed(policyProfile).isEmpty {
            arguments += ["--profile", trimmed(policyProfile)]
        }
    }

    private func appendRepeated(_ flag: String, values: [String], to arguments: inout [String]) {
        for value in values { arguments += [flag, value] }
    }

    private func csv(_ value: String) -> [String] {
        value.split(separator: ",").map { trimmed(String($0)) }.filter { !$0.isEmpty }
    }

    private func trimmed(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func runAction() {
        guard validationError == nil else { return }
        let arguments = buildArguments()
        running = true
        Task {
            let result = await appState.runCommand(
                title: action.rawValue,
                arguments: arguments,
                mutation: action.isMutation && !dryRun,
                category: "setup",
                origin: "Logs / Redaction advanced",
                successEffects: action.isMutation && !dryRun ? ["Redaction policy updated and verified"] : [],
                refreshOnSuccess: action.isMutation && !dryRun
            )
            output = result.output.isEmpty
                ? (result.succeeded
                    ? "\(action.rawValue) completed with no output."
                    : "Command failed with exit \(result.exitCode).")
                : result.output
            running = false
        }
    }
}
