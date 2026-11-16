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

import AppKit
import SwiftUI

/// Read-only policy inspection and monitoring. Policy changes remain owned
/// by the runtime and are not exposed by this inspector.
struct SandboxInspectorView: View {
    @Environment(AppState.self) private var appState
    let row: SandboxRow
    let overview: AnyView
    private let readOverride: SandboxInspectionStore.Reader?
    @State private var store: SandboxInspectionStore
    @State private var tab: String
    @State private var policyScope = "Effective"
    @State private var selectedPolicyField: String?
    @State private var policySearch = ""
    @State private var query = ""
    @State private var source = "All"
    @State private var severity = "All"
    @State private var decision = "All"
    @State private var timeRange = "Available history"
    @State private var destination: String?
    @State private var selectedEvent: String?
    @State private var selectedRevision: Int?
    @State private var refreshID = 0
    @State private var historyTask: Task<Void, Never>?
    @State private var frozenActivity: [SandboxInspectionEvent]?
    @State private var exportMessage = ""

    init(row: SandboxRow, overview: AnyView = AnyView(EmptyView()), initialTab: String = "Overview",
         initialPolicyScope: String = "Effective", initialRevision: Int? = nil,
         store: SandboxInspectionStore? = nil, readOverride: SandboxInspectionStore.Reader? = nil) {
        self.row = row; self.overview = overview; self.readOverride = readOverride
        _tab = State(initialValue: initialTab)
        _policyScope = State(initialValue: initialPolicyScope)
        _selectedRevision = State(initialValue: initialRevision)
        _store = State(initialValue: store ?? SandboxInspectionStore())
    }

    private var target: SandboxInspectionTarget {
        .init(sandbox: row.name, gateway: appState.sandbox.status.gatewayName,
              workspace: appState.sandbox.status.gatewayWorkspace)
    }
    private var loadKey: String {
        "\(appState.installationContext.homeRoot.path)|\(appState.installationGeneration)|\(target.gateway)|\(target.workspace)|\(target.sandbox)|\(refreshID)"
    }
    private var reader: SandboxInspectionStore.Reader {
        if let readOverride { return { binary, args in await readOverride(binary, args) } }
        let generation = appState.installationGeneration
        let state = appState
        let read = SandboxInspectionStore.reader(cli: state.cli)
        return { binary, args in
            let current = await MainActor.run { state.sandboxInspectionMayRead(generation: generation) }
            guard current else { return CLIResult(exitCode: 75, output: "") }
            return await read(binary, args)
        }
    }
    private var activity: [SandboxInspectionEvent] {
        frozenActivity ?? appState.sandbox.activity.filter { $0.sandbox == row.name }.map(SandboxInspectionEvent.activity)
    }
    private var events: [SandboxInspectionEvent] {
        (activity + (store.sandboxLogs.value ?? []) + (store.gatewayLogs.value ?? []))
            .sorted { ($0.time ?? .distantPast) > ($1.time ?? .distantPast) }
    }
    private var visibleEvents: [SandboxInspectionEvent] {
        let since: Date? = timeRange == "Last 5 minutes" ? Date().addingTimeInterval(-300)
            : timeRange == "Last 15 minutes" ? Date().addingTimeInterval(-900) : nil
        return events.filter { $0.matches(query: query, source: source, severity: severity, decision: decision, since: since) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(row.name, systemImage: "cube.transparent").font(.headline)
                Text("Read-only inspection").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if store.loading { ProgressView().controlSize(.small) }
                Button("Refresh details") { refreshID += 1 }.disabled(store.loading)
            }
            Text("\(target.gateway.isEmpty ? "Gateway unavailable" : target.gateway) · workspace \(target.workspace.isEmpty ? "unavailable" : target.workspace)")
                .font(.caption).foregroundStyle(.secondary)
            if !appState.sandbox.staleNote.isEmpty {
                Label(appState.sandbox.staleNote, systemImage: "exclamationmark.triangle").foregroundStyle(Cisco.orange)
            }
            Picker("Details", selection: $tab) {
                ForEach(["Overview", "Policy", "Network", "Activity & Logs"], id: \.self) { Text($0) }
            }.pickerStyle(.segmented)
            switch tab {
            case "Policy": policyView
            case "Network": networkView
            case "Activity & Logs": monitoringView
            default: overviewView
            }
        }
        .padding(14)
        .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 10))
        .task(id: loadKey) {
            store.invalidate()
            let currentTarget = target
            let read = reader
            await store.refresh(target: currentTarget, read: read)
            var ticks = 0
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(5)) } catch { break }
                guard !Task.isCancelled else { break }
                if !store.paused {
                    ticks += 1
                    if ticks % 6 == 0 { await store.refresh(target: currentTarget, read: read) }
                    else { await store.refreshLogs(read: read) }
                }
            }
        }
        .task(id: selectedRevision) {
            if let selectedRevision { await store.loadRevision(selectedRevision, read: reader) }
        }
        .onDisappear { store.invalidate(); historyTask?.cancel() }
    }

    private var overviewView: some View {
        VStack(alignment: .leading, spacing: 10) {
            overview
            DCCard("Health and policy", systemImage: "heart.text.square") {
                Text("DefenseClaw pack: \(row.policyLabel) · \(row.phase)")
                Text(store.effective.enforcement)
                status(store.effective)
                let failures = activity.filter { $0.severity != "Info" }.prefix(4)
                ForEach(Array(failures)) { event in
                    Label(event.message, systemImage: "exclamationmark.triangle")
                        .font(.callout).foregroundStyle(Cisco.orange).textSelection(.enabled)
                }
                if failures.contains(where: { $0.message.localizedCaseInsensitiveContains("credential") || $0.message.localizedCaseInsensitiveContains("authentication") }) {
                    Text("Provider authentication needs attention. Reconnect to this sandbox and follow the provider’s login flow; host credentials may differ from the sandbox’s credentials.")
                        .font(.caption)
                }
                if row.copyMode { Text("This sandbox works on a project copy. Review and pull its changes to bring work back to the Mac.").font(.caption) }
                Button("Inspect policy") { tab = "Policy" }
            }
        }
    }

    private var policyView: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Picker("Policy layer", selection: $policyScope) {
                    ForEach(["Effective", "Base", "DefenseClaw", "Gateway global", "History"], id: \.self) { Text($0) }
                }.frame(maxWidth: 310)
                TextField("Find policy setting or destination", text: $policySearch)
            }
            switch policyScope {
            case "DefenseClaw":
                Text("Resolved DefenseClaw settings, including their sources and organization constraints. These describe DefenseClaw’s controls, not the complete OpenShell policy.").font(.caption)
                status(store.defense)
                if let rows = store.defense.value { fieldTable(rows, search: policySearch) }
            case "Base":
                Text("OpenShell base policy, before provider-contributed entries.").font(.caption)
                policyDocument(store.base)
            case "Gateway global":
                Text("Gateway-global policy is distinct from DefenseClaw organization policy. A failed read does not establish that no global policy exists.").font(.caption)
                policyDocument(store.global)
            case "History": historyView
            default:
                Text("OpenShell’s effective policy includes provider-contributed rules. Network rules may be dynamic; filesystem and process settings can require a new sandbox.").font(.caption)
                policyDocument(store.effective)
            }
        }
    }

    private func policyDocument(_ result: SandboxInspectionRead<SandboxPolicyDocument>) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            status(result)
            if let doc = result.value {
                Text("\(result.enforcement) · source: \(doc.source) · scope: \(doc.scope)").font(.callout)
                Text("Hash: \(doc.hash)").font(.caption.monospaced()).textSelection(.enabled)
                fieldTable(doc.fields, search: policySearch)
            }
        }
    }

    private var historyView: some View {
        VStack(alignment: .leading, spacing: 8) {
            status(store.history)
            if let history = store.history.value {
                Text("Select a stored revision to compare it with the current base policy. Provider-composed rules are shown separately under Effective.").font(.caption)
                Table(history.revisions, selection: $selectedRevision) {
                    TableColumn("Revision") { Text(String($0.version)) }.width(65)
                    TableColumn("Status", value: \.status)
                    TableColumn("Created") { Text($0.created?.formatted() ?? "Unavailable") }
                    TableColumn("Loaded") { Text($0.loaded?.formatted() ?? "Unverified") }
                }.frame(height: 160)
                if !history.nextPageToken.isEmpty {
                    Button(history.revisions.count >= 200 ? "History limited to 200 revisions" : "Load more revisions") {
                        historyTask?.cancel()
                        historyTask = Task { await store.moreHistory(read: reader) }
                    }.disabled(store.historyLoading || history.revisions.count >= 200)
                }
            }
            if selectedRevision != nil {
                status(store.revision)
                Text("Current base:").font(.caption)
                status(store.base)
                if let old = store.revision.value, let current = store.base.value {
                    let changes = SandboxInspectionDecoding.difference(old.fields, current.fields)
                    Text("Stored revision \(old.version.map(String.init) ?? "?") → current base · \(changes.count) changed fields")
                    fieldTable(changes, search: policySearch)
                }
            }
        }
    }

    private var networkView: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField("Filter destinations and network rules", text: $query)
            status(store.destinations)
            if let rows = store.destinations.value {
                let shown = rows.filter { query.isEmpty || $0.host.localizedCaseInsensitiveContains(query) }
                Table(shown, selection: $destination) { TableColumn("Observed destination", value: \.host) }.frame(height: 130)
                if rows.isEmpty { Text("No destinations recorded for this sandbox. This does not prove that every connection was observed.").font(.caption) }
                if let selected = rows.first(where: { $0.id == destination }) {
                    fieldTable(selected.fields)
                    let matches = activity.filter { $0.host == selected.host }
                    ForEach(Array(matches.prefix(8))) { event in Text("\(event.decision): \(event.message)").font(.caption) }
                    Button("Find this host in policy") { policySearch = selected.host; policyScope = "Effective"; tab = "Policy" }
                }
            }
            Divider()
            Text("Effective OpenShell network permissions").font(.headline)
            status(store.effective)
            if let doc = store.effective.value {
                fieldTable(doc.fields.filter { $0.key.hasPrefix("network_") }, search: query)
            }
            Text("Destination observations and policy permissions are separate. A permitted destination is not evidence that a connection occurred.").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var monitoringView: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                TextField("Search messages, destinations, or rules", text: $query)
                Button(store.paused ? "Resume" : "Pause") {
                    if store.paused { frozenActivity = nil } else { frozenActivity = activity }
                    store.paused.toggle()
                }
                Button("Export redacted diagnostics…", action: export)
            }
            HStack {
                Picker("Source", selection: $source) {
                    ForEach(["All", "DefenseClaw", "OpenShell sandbox", "OpenShell gateway"], id: \.self) { Text($0) }
                }
                Picker("Severity", selection: $severity) { ForEach(["All", "Info", "Warning", "Error"], id: \.self) { Text($0) } }
                Picker("Decision", selection: $decision) { ForEach(["All", "Allowed", "Blocked", "Unblocked", "Other"], id: \.self) { Text($0) } }
                Picker("Time", selection: $timeRange) { ForEach(["Available history", "Last 5 minutes", "Last 15 minutes"], id: \.self) { Text($0) } }
            }.controlSize(.small)
            Text("OpenShell: last 15 minutes, up to 200 lines per source, refreshed every 5 seconds. DefenseClaw: retained activity buffer. Time filters exclude events without timestamps. \(store.paused ? "Paused." : "")")
                .font(.caption).foregroundStyle(.secondary)
            HStack { Text("Sandbox logs:"); status(store.sandboxLogs); Text("Gateway logs:"); status(store.gatewayLogs) }.font(.caption)
            Table(visibleEvents, selection: $selectedEvent) {
                TableColumn("Time") { Text($0.time?.formatted(date: .omitted, time: .standard) ?? "Unknown") }.width(80)
                TableColumn("Source", value: \.source).width(125)
                TableColumn("Severity", value: \.severity).width(65)
                TableColumn("Decision", value: \.decision).width(65)
                TableColumn("Message", value: \.message)
            }.frame(height: 300)
            Text("\(visibleEvents.count) of \(events.count) available events").font(.caption)
            if let event = events.first(where: { $0.id == selectedEvent }) {
                Text(event.message).font(.callout.monospaced()).textSelection(.enabled)
                if !event.host.isEmpty || !event.rule.isEmpty {
                    Button("Inspect related policy") { policySearch = event.rule.isEmpty ? event.host : event.rule; policyScope = event.source == "DefenseClaw" ? "DefenseClaw" : "Effective"; tab = "Policy" }
                }
            }
            if !exportMessage.isEmpty { Text(exportMessage).font(.caption) }
        }
    }

    private func status<T>(_ read: SandboxInspectionRead<T>) -> some View {
        Text(read.note).font(.caption).foregroundStyle(read.error.isEmpty ? Color.secondary : Cisco.orange).textSelection(.enabled)
    }
    private func fieldTable(_ rows: [SandboxInspectionField], search: String = "") -> some View {
        let shown = rows.filter { search.isEmpty || ($0.key + " " + $0.value + " " + $0.source).localizedCaseInsensitiveContains(search) }
        return VStack(alignment: .leading, spacing: 4) {
            Table(shown, selection: $selectedPolicyField) {
                TableColumn("Setting / rule", value: \.key)
                TableColumn("Value") { Text($0.value).textSelection(.enabled) }
                TableColumn("Source", value: \.source).width(min: 80, ideal: 160)
            }.frame(height: min(380, max(110, CGFloat(shown.count * 26 + 30))))
            if let selected = shown.first(where: { $0.id == selectedPolicyField }) {
                Text(selected.key).font(.caption.monospaced()).textSelection(.enabled)
                Text(selected.value).font(.callout).textSelection(.enabled)
                if !selected.source.isEmpty { Text("Source: " + selected.source).font(.caption).textSelection(.enabled) }
            }
            if shown.isEmpty { Text(rows.isEmpty ? "No fields returned for this section." : "No matching fields.").font(.caption) }
        }
    }
    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "sandbox-diagnostics.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try SandboxDiagnosticsExport.data(target: target, events: visibleEvents,
                sandboxLogStatus: store.sandboxLogs.note, gatewayLogStatus: store.gatewayLogs.note)
            try data.write(to: url, options: .atomic)
            exportMessage = "Exported the redacted, filtered events."
        } catch { exportMessage = "Could not write the diagnostic export." }
    }
}
