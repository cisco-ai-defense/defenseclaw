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

import SwiftUI

private enum ActivityTab: String, CaseIterable, Identifiable {
    case commands = "Commands"
    case mutations = "Mutations"
    var id: String { rawValue }
}

struct ActivityView: View {
    @Environment(AppState.self) private var appState
    @State private var tab: ActivityTab = .commands
    @State private var mutations: [ActivityMutation] = []
    @State private var search = ""
    @State private var selectedMutation: ActivityMutation?
    @State private var mutationLoadGeneration = 0

    private var commandEntries: [CommandActivityEntry] {
        appState.activity.entries.filter { entry in
            search.isEmpty || "\(entry.title) \(entry.command) \(entry.category) \(entry.origin) \(entry.output)"
                .localizedCaseInsensitiveContains(search)
        }
    }

    private var filteredMutations: [ActivityMutation] {
        mutations.filter { mutation in
            guard appState.connectorFilterAllows(mutation.connector) else { return false }
            guard !search.isEmpty else { return true }
            return "\(mutation.actor) \(mutation.action) \(mutation.targetType) \(mutation.targetID) \(mutation.reason)"
                .localizedCaseInsensitiveContains(search)
        }
    }

    private var selectedCommand: CommandActivityEntry? {
        guard let id = appState.activity.selectedID else { return nil }
        return appState.activity.entries.first { $0.id == id }
    }

    var body: some View {
        @Bindable var activity = appState.activity
        @Bindable var state = appState
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                Picker("Activity", selection: $tab) {
                    ForEach(ActivityTab.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 320)
                if tab == .mutations, appState.activeConnectorNames.count > 1 {
                    ConnectorFilterChip(names: appState.activeConnectorNames, selection: $state.connectorFilter)
                }
            }
            .padding(10)
            Divider()
            if tab == .commands { commandContent(selection: $activity.selectedID) }
            else { mutationContent }
        }
        .inspector(isPresented: inspectorPresented) {
            if tab == .commands, let entry = selectedCommand {
                commandInspector(entry)
                    .inspectorColumnWidth(min: 340, ideal: 460)
            } else if let mutation = selectedMutation {
                mutationInspector(mutation)
                    .inspectorColumnWidth(min: 320, ideal: 420)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search activity")
        .toolbar {
            ToolbarItemGroup {
                if tab == .commands {
                    Button {
                        appState.commandPalettePresented = true
                    } label: {
                        Label("Run Command", systemImage: "play.circle")
                    }
                    Button {
                        appState.activity.clearCompleted()
                    } label: {
                        Label("Clear Completed", systemImage: "trash")
                    }
                    .disabled(!appState.activity.entries.contains { !$0.status.isActive })
                } else {
                    Button { Task { await loadMutations() } } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
            }
        }
        .task { await loadMutations() }
        .task(id: appState.health.fetchedAt) { await loadMutations() }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in
            Task { await loadMutations() }
        }
    }

    @ViewBuilder
    private func commandContent(selection: Binding<UUID?>) -> some View {
        if commandEntries.isEmpty {
            DCEmptyState(
                title: "No commands run yet",
                message: "Commands started from setup, catalogs, diagnostics, onboarding, and the command palette appear here with live output.",
                systemImage: "terminal"
            )
        } else {
            Table(commandEntries, selection: selection) {
                TableColumn("Started") { entry in
                    Text(entry.startedAt, format: .dateTime.month().day().hour().minute().second())
                        .font(.caption.monospacedDigit())
                }
                .width(126)
                TableColumn("Command") { entry in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(entry.title).font(.caption.weight(.medium)).lineLimit(1)
                        Text(entry.command).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                TableColumn("Status") { entry in
                    Label(entry.statusLabel, systemImage: statusIcon(entry.status))
                        .font(.caption)
                        .foregroundStyle(statusColor(entry.status))
                }
                .width(100)
                TableColumn("Duration") { entry in
                    Text(durationLabel(entry.duration)).font(.caption.monospacedDigit())
                }
                .width(72)
                TableColumn("Side Effects") { entry in
                    Text(entry.sideEffects.isEmpty ? "—" : entry.sideEffects.joined(separator: " · "))
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                .width(min: 130, ideal: 200)
            }
        }
    }

    @ViewBuilder
    private var mutationContent: some View {
        if filteredMutations.isEmpty {
            DCEmptyState(
                title: "No mutations",
                message: "Gateway configuration mutations and policy changes appear here from gateway.jsonl and the audit database.",
                systemImage: "clock.arrow.circlepath"
            )
        } else {
            Table(filteredMutations, selection: Binding(
                get: { selectedMutation?.id },
                set: { id in selectedMutation = filteredMutations.first { $0.id == id } }
            )) {
                TableColumn("Time") { mutation in
                    Text(mutation.timestamp, format: .dateTime.month().day().hour().minute())
                        .font(.caption.monospacedDigit())
                }
                .width(110)
                TableColumn("Actor") { mutation in Text(mutation.actor).font(.caption) }.width(90)
                TableColumn("Action") { mutation in Text(mutation.action).font(.caption) }.width(min: 100, ideal: 140)
                TableColumn("Target") { mutation in
                    Text(mutation.targetType.isEmpty ? mutation.targetID : "\(mutation.targetType)/\(mutation.targetID)")
                        .font(.caption).lineLimit(1)
                }
                TableColumn("Version Change") { mutation in
                    Text(mutation.versionFrom.isEmpty && mutation.versionTo.isEmpty ? "—" : "\(mutation.versionFrom) to \(mutation.versionTo)")
                        .font(.caption2.monospaced()).foregroundStyle(.secondary)
                }
                .width(110)
                TableColumn("Reason") { mutation in
                    Text(mutation.reason).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
            }
        }
    }

    private var inspectorPresented: Binding<Bool> {
        Binding(
            get: { tab == .commands ? selectedCommand != nil : selectedMutation != nil },
            set: { shown in
                if !shown {
                    if tab == .commands { appState.activity.selectedID = nil }
                    else { selectedMutation = nil }
                }
            }
        )
    }

    private func commandInspector(_ entry: CommandActivityEntry) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(entry.title).font(.headline)
                Spacer()
                if entry.status == .running {
                    Button(role: .destructive) {
                        appState.activity.cancel(entry.id)
                    } label: {
                        Label("Cancel", systemImage: "stop.fill")
                    }
                    .controlSize(.small)
                } else if entry.status == .cancelling {
                    Button(role: .destructive) {} label: {
                        Label("Cancelling…", systemImage: "stop.fill")
                    }
                    .controlSize(.small)
                    .disabled(true)
                } else if entry.status == .finishing {
                    Button {} label: {
                        Label("Finishing…", systemImage: "hourglass")
                    }
                    .controlSize(.small)
                    .disabled(true)
                }
                Button { appState.activity.selectedID = nil } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Close command details")
            }
            KeyValueGrid(pairs: [
                ("Status", entry.statusLabel),
                ("Started", entry.startedAt.formatted()),
                ("Duration", durationLabel(entry.duration)),
                ("Origin", entry.origin),
                ("Category", entry.category),
                ("Side effects", entry.sideEffects.joined(separator: ", ")),
                ("Next", entry.suggestedNextAction),
            ].filter { !$0.1.isEmpty })
            Text(entry.command)
                .font(.caption.monospaced())
                .textSelection(.enabled)
            Divider()
            HStack {
                Text("Output").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                Button {
                    copyToPasteboard(entry.output)
                } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(.borderless)
                .help("Copy Output")
                .accessibilityLabel("Copy command output")
            }
            ScrollView {
                Text(entry.output.isEmpty ? emptyOutputLabel(entry.status) : entry.output)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Spacer()
        }
        .padding(12)
    }

    private func mutationInspector(_ mutation: ActivityMutation) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(mutation.action).font(.headline)
                Spacer()
                Button { selectedMutation = nil } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Close mutation details")
            }
            KeyValueGrid(pairs: [
                ("Actor", mutation.actor),
                ("Target", "\(mutation.targetType)/\(mutation.targetID)"),
                ("When", mutation.timestamp.formatted()),
                ("Reason", mutation.reason.isEmpty ? "—" : mutation.reason),
            ])
            DiffView(before: mutation.beforeJSON, after: mutation.afterJSON)
            Spacer()
        }
        .padding(12)
    }

    private func loadMutations() async {
        mutationLoadGeneration += 1
        let generation = mutationLoadGeneration
        let installationGeneration = appState.installationGeneration
        let fromDB = await appState.audit.activityEvents(limit: 500)
        guard !Task.isCancelled,
              installationGeneration == appState.installationGeneration else { return }
        let fromStream = await appState.stream.activity
        var seen = Set<String>()
        var merged: [ActivityMutation] = []
        for mutation in (fromDB + fromStream).sorted(by: { $0.timestamp > $1.timestamp }) {
            let key = "\(mutation.timestamp.timeIntervalSince1970)-\(mutation.action)-\(mutation.targetID)"
            if seen.insert(key).inserted { merged.append(mutation) }
        }
        guard !Task.isCancelled,
              generation == mutationLoadGeneration,
              installationGeneration == appState.installationGeneration else { return }
        if merged.map(\.id) != mutations.map(\.id) { mutations = merged }
    }

    private func statusIcon(_ status: CommandActivityStatus) -> String {
        switch status {
        case .running: "hourglass"
        case .cancelling: "stop.circle"
        case .finishing: "hourglass.circle"
        case .succeeded: "checkmark.circle.fill"
        case .failed: "xmark.circle.fill"
        case .cancelled: "stop.circle.fill"
        }
    }

    private func statusColor(_ status: CommandActivityStatus) -> Color {
        switch status {
        case .running: Cisco.blue
        case .cancelling: Cisco.orange
        case .finishing: .secondary
        case .succeeded: Cisco.green
        case .failed: Cisco.red
        case .cancelled: .secondary
        }
    }

    private func emptyOutputLabel(_ status: CommandActivityStatus) -> String {
        switch status {
        case .running: "Waiting for output..."
        case .cancelling: "Stopping command..."
        case .finishing: "Finalizing output..."
        case .succeeded, .failed, .cancelled: "No output"
        }
    }

    private func durationLabel(_ duration: TimeInterval) -> String {
        if duration < 1 { return String(format: "%.0f ms", duration * 1_000) }
        if duration < 60 { return String(format: "%.1f s", duration) }
        return String(format: "%d:%02d", Int(duration) / 60, Int(duration) % 60)
    }
}
