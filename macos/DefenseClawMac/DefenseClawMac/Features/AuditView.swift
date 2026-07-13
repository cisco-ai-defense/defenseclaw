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

// Audit panel (spec §9.9): immutable trail with preset filters
// (all/risk/blocks/scans/credentials), paging, detail inspector, JSON export.

import SwiftUI
import UniformTypeIdentifiers

struct AuditView: View {
    @Environment(AppState.self) private var appState
    @State private var events: [AuditEvent] = []
    @State private var preset = "all"
    @State private var search = ""
    @State private var selection = Set<String>()
    @State private var exporterPresented = false
    @State private var exportDocument: AuditExportDocument?
    @State private var correlationTarget = ""
    @State private var correlationRunID = ""
    @State private var relatedEvents: [AuditEvent] = []
    @State private var relatedFindings: [ScanFindingEvent] = []
    @State private var loadTask: Task<Void, Never>?
    @State private var detailTask: Task<Void, Never>?
    @State private var loadGeneration = 0
    @State private var isLoading = false
    @State private var hasMore = true

    private static let pageSize = 200
    private static let presets: [(String, String)] = [
        ("All", "all"), ("Risk", "risk"), ("Blocks", "blocks"),
        ("Scans", "scans"), ("Credentials", "credentials"),
    ]

    /// Loaded rows narrowed by the shared connector filter.
    private var visibleEvents: [AuditEvent] {
        events.filter { event in
            guard appState.connectorFilterAllows(event.connector) else { return false }
            if !correlationTarget.isEmpty, event.target != correlationTarget { return false }
            if !correlationRunID.isEmpty, event.runID != correlationRunID { return false }
            return true
        }
    }

    private var selectedEvent: AuditEvent? {
        visibleEvents.first { selection.contains($0.id) }
    }

    var body: some View {
        @Bindable var state = appState
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    FilterChipRow("Audit View", options: Self.presets, selection: $preset)
                    Spacer()
                    Text("\(visibleEvents.count) events loaded")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                if appState.activeConnectorNames.count > 1 {
                    ConnectorFilterChip(names: appState.activeConnectorNames, selection: $state.connectorFilter)
                }
                if !correlationTarget.isEmpty || !correlationRunID.isEmpty {
                    HStack(spacing: 8) {
                        Label(
                            !correlationTarget.isEmpty ? "Same target: \(correlationTarget)" : "Same run: \(correlationRunID)",
                            systemImage: "line.3.horizontal.decrease.circle.fill"
                        )
                        .font(.caption).foregroundStyle(Cisco.blue).lineLimit(1)
                        Button("Clear Correlation") {
                            correlationTarget = ""
                            correlationRunID = ""
                            selection = []
                        }
                        .controlSize(.small)
                    }
                }
            }
            .padding(10)
            Divider()
            if visibleEvents.isEmpty {
                DCEmptyState(
                    title: "No audit events",
                    message: "Nothing in \(ConfigStore.auditDBURL.path) matches. The gateway writes audit events as it enforces policy.",
                    systemImage: "checklist"
                )
                .frame(maxHeight: .infinity)
            } else {
                table
            }
        }
        .inspector(isPresented: Binding(
            get: { selectedEvent != nil },
            set: { if !$0 { selection = [] } }
        )) {
            if let event = selectedEvent {
                auditInspector(event)
                    .inspectorColumnWidth(min: 360, ideal: 480)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search action, target, details")
        .toolbar {
            ToolbarItemGroup {
                Button {
                    prepareExport()
                } label: {
                    Label("Export JSON", systemImage: "square.and.arrow.up")
                }
                .keyboardShortcut("e", modifiers: .command)
                Button {
                    load(reset: true)
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
        }
        .task {
            if !applyPendingPanelRequest() {
                load(reset: true)
            }
        }
        .onChange(of: preset) { _, _ in load(reset: true) }
        .onChange(of: search) { _, _ in load(reset: true, debounce: true) }
        .onChange(of: appState.auditPresetRequest) { _, _ in
            _ = applyPendingPanelRequest()
        }
        .onChange(of: selection) { _, _ in loadSelectedDetails() }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in load(reset: true) }
        .onDisappear {
            loadTask?.cancel()
            detailTask?.cancel()
        }
        .fileExporter(
            isPresented: $exporterPresented,
            document: exportDocument,
            contentType: .json,
            defaultFilename: "defenseclaw-audit-\(Int(Date().timeIntervalSince1970))"
        ) { _ in }
    }

    private var table: some View {
        Table(visibleEvents, selection: $selection) {
            TableColumn("Time") { e in
                Text(e.timestamp, format: .dateTime.month().day().hour().minute().second())
                    .font(.caption.monospacedDigit())
            }
            .width(130)
            TableColumn("Action") { e in Text(e.action).font(.caption) }
                .width(min: 100, ideal: 140)
            TableColumn("Type") { e in
                Text(e.eventType).font(.caption).foregroundStyle(.secondary)
            }
            .width(70)
            TableColumn("Target") { e in Text(e.target).font(.caption).lineLimit(1) }
                .width(min: 110, ideal: 170)
            TableColumn("Severity") { e in SeverityBadge(severity: e.severity) }
                .width(86)
            TableColumn("Run") { e in
                Text(e.runID).font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(1)
            }
            .width(76)
            TableColumn("Details") { e in
                Text(e.details).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
        }
        .contextMenu(forSelectionType: String.self) { ids in
            Button("Copy Details") {
                let texts = visibleEvents.filter { ids.contains($0.id) }
                    .map { "\($0.timestamp) \($0.action) \($0.target) [\($0.severity.rawValue)] \($0.details)" }
                copyToPasteboard(texts.joined(separator: "\n"))
            }
            Button("Copy Structured JSON") {
                let texts = visibleEvents.filter { ids.contains($0.id) }.map(\.structuredJSON)
                copyToPasteboard(texts.joined(separator: "\n"))
            }
            Divider()
            Button("Show Same Target") {
                guard let event = visibleEvents.first(where: { ids.contains($0.id) }) else { return }
                filterSameTarget(event)
            }
            Button("Show Same Run") {
                guard let event = visibleEvents.first(where: { ids.contains($0.id) }) else { return }
                filterSameRun(event)
            }
            .disabled(!visibleEvents.contains { ids.contains($0.id) && !$0.runID.isEmpty })
        } primaryAction: { _ in }
        .safeAreaInset(edge: .bottom) {
            HStack {
                Spacer()
                Button("Load older events") {
                    load(reset: false)
                }
                .controlSize(.small)
                .disabled(isLoading || !hasMore)
                if isLoading { ProgressView().controlSize(.small) }
                Spacer()
            }
            .padding(6)
            .background(.bar)
        }
    }

    private func auditInspector(_ event: AuditEvent) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(event.action).font(.headline)
                    HStack(spacing: 6) {
                        SeverityBadge(severity: event.severity)
                        Text(event.eventType).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button { selection = [] } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
            }
            HStack {
                Button {
                    filterSameTarget(event)
                } label: { Label("Same Target", systemImage: "scope") }
                .disabled(event.target.isEmpty)
                Button {
                    filterSameRun(event)
                } label: { Label("Same Run", systemImage: "point.3.connected.trianglepath.dotted") }
                .disabled(event.runID.isEmpty)
            }
            .controlSize(.small)

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    KeyValueGrid(pairs: [
                        ("Time", event.timestamp.formatted()),
                        ("Event ID", event.id),
                        ("Target", event.target),
                        ("Actor", event.actor),
                        ("Connector", event.connector),
                        ("Run ID", event.runID),
                    ].filter { !$0.1.isEmpty })

                    let detailPairs = StructuredDetailParser.pairs(event.details)
                    if !detailPairs.isEmpty {
                        Divider()
                        Text("Structured Details").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        KeyValueGrid(pairs: detailPairs)
                    } else if !event.details.isEmpty {
                        Text(event.details).font(.caption).textSelection(.enabled)
                    }

                    if !relatedFindings.isEmpty {
                        Divider()
                        Text("Findings in This Run").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        ForEach(relatedFindings.prefix(10)) { finding in
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    SeverityBadge(severity: finding.severity)
                                    Text(finding.title).font(.caption.weight(.medium))
                                }
                                if !finding.location.isEmpty {
                                    Text(finding.location).font(.caption2.monospaced()).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }

                    if !relatedEvents.isEmpty {
                        Divider()
                        Text("Related Events").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        ForEach(relatedEvents.filter { $0.id != event.id }.prefix(8)) { related in
                            HStack {
                                Text(related.timestamp, format: .dateTime.hour().minute().second())
                                    .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                                Text(related.action).font(.caption).lineLimit(1)
                                Spacer()
                                SeverityBadge(severity: related.severity)
                            }
                        }
                    }

                    if !event.structuredJSON.isEmpty {
                        DisclosureGroup("Structured JSON") {
                            Text(StructuredDetailParser.prettyJSON(event.structuredJSON))
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
            Spacer()
        }
        .padding(12)
    }

    private func filterSameTarget(_ event: AuditEvent) {
        guard !event.target.isEmpty else { return }
        correlationTarget = event.target
        correlationRunID = ""
        selection = []
    }

    private func filterSameRun(_ event: AuditEvent) {
        guard !event.runID.isEmpty else { return }
        correlationRunID = event.runID
        correlationTarget = ""
        selection = []
    }

    private func loadSelectedDetails() {
        detailTask?.cancel()
        guard let event = selectedEvent else {
            relatedEvents = []
            relatedFindings = []
            return
        }
        let selectedID = event.id
        detailTask = Task {
            let freshEvents = await appState.audit.relatedEvents(
                target: event.runID.isEmpty ? event.target : nil,
                runID: event.runID.nonEmpty,
                limit: 12
            )
            let freshFindings = await appState.audit.scanFindings(
                runID: event.runID.nonEmpty,
                target: event.target.nonEmpty,
                limit: 10
            )
            guard !Task.isCancelled, selectedEvent?.id == selectedID else { return }
            relatedEvents = freshEvents
            relatedFindings = freshFindings
        }
    }

    private func load(reset: Bool, debounce: Bool = false) {
        loadTask?.cancel()
        loadGeneration += 1
        let generation = loadGeneration
        let requestedPreset = preset
        let requestedSearch = search
        let offset = reset ? 0 : events.count
        isLoading = true
        loadTask = Task {
            if debounce {
                try? await Task.sleep(for: .milliseconds(200))
                guard !Task.isCancelled else { return }
            }
            var severities: [Severity]? = nil
            var actions: [String]? = nil
            switch requestedPreset {
            case "risk": severities = [.high, .critical]
            case "blocks": actions = ["block", "reject", "enforce", "quarantine"]
            case "scans": actions = ["scan"]
            case "credentials": actions = ["key", "token", "credential", "auth", "rotat"]
            default: break
            }
            let fresh = await appState.audit.recentEvents(
                limit: Self.pageSize,
                offset: offset,
                search: requestedSearch.isEmpty ? nil : requestedSearch,
                severities: severities,
                actionLike: actions
            )
            guard !Task.isCancelled, generation == loadGeneration else { return }
            if reset {
                events = fresh
            } else {
                let existing = Set(events.map(\.id))
                events.append(contentsOf: fresh.filter { !existing.contains($0.id) })
            }
            hasMore = fresh.count == Self.pageSize
            isLoading = false
        }
    }

    private func prepareExport() {
        // Schema identical to the TUI's export (spec §9.9).
        let source = selection.isEmpty ? visibleEvents : visibleEvents.filter { selection.contains($0.id) }
        let payload: [[String: String]] = source.map { e in
            [
                "id": e.id,
                "timestamp": DCDates.iso.string(from: e.timestamp),
                "action": e.action,
                "target": e.target,
                "actor": e.actor,
                "details": e.details,
                "severity": e.severity.rawValue,
                "run_id": e.runID,
            ]
        }
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]) {
            exportDocument = AuditExportDocument(data: data)
            exporterPresented = true
        }
    }

    @discardableResult
    private func applyPendingPanelRequest() -> Bool {
        guard let requested = appState.consumeAuditPresetRequest() else { return false }
        selection = []
        search = ""
        correlationTarget = ""
        correlationRunID = ""
        if preset == requested {
            load(reset: true)
        } else {
            preset = requested
        }
        return true
    }
}

struct AuditExportDocument: FileDocument {
    static let readableContentTypes: [UTType] = [.json]
    var data: Data

    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}
