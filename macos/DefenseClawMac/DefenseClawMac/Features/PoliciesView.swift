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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

struct PoliciesView: View {
    @Environment(AppState.self) private var appState
    @State private var snapshot: PolicyCatalogSnapshot?
    @State private var viewID = "posture"
    @State private var scope = "global"
    @State private var selection: String?
    @State private var search = ""
    @State private var loading = false
    @State private var running = false
    @State private var error: String?
    @State private var output = ""
    @State private var pending: PolicyCatalogAction?
    @State private var acknowledgeWeaker = false
    @State private var loadedGeneration = -1
    @State private var loadedSignature = ""

    private var catalog: PolicyCatalogView? { snapshot?.view(viewID, scope: scope) }
    private var rows: [PolicyCatalogRow] { catalog?.rows.filter { $0.matches(search) } ?? [] }
    private var selected: PolicyCatalogRow? { rows.first { $0.id == selection } }
    private var current: Bool {
        loadedGeneration == appState.installationGeneration
            && loadedSignature == appState.installationContext.diskSignature && error == nil
            && catalog?.error.isEmpty == true
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Picker("View", selection: $viewID) {
                    ForEach(Array(zip(PolicyCatalogView.identifiers, PolicyCatalogView.titles)), id: \.0) { id, title in
                        Text(title).tag(id)
                    }
                }.frame(maxWidth: 300)
                if ["optin", "families"].contains(viewID) {
                    Picker("Scope", selection: $scope) {
                        ForEach(snapshot?.scopes ?? ["global"], id: \.self) { Text($0).tag($0) }
                    }.frame(maxWidth: 240)
                }
                Spacer()
                if loading { ProgressView().controlSize(.small) }
                Button("Refresh") { Task { await load() } }.disabled(loading || running)
            }
            Text(viewID == "policies"
                 ? "The active policy uses global guardrail levels; inactive policy changes take effect on activation."
                 : "Levels apply to tool calls, prompts, completions and LLM traffic, including inherited values.")
                .font(.caption).foregroundStyle(.secondary)
            if let message = error ?? catalog?.error, !message.isEmpty {
                Label(message, systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(Cisco.orange).textSelection(.enabled)
            }
            if rows.isEmpty {
                DCEmptyState(title: loading ? "Loading policies" : (search.isEmpty ? "No rows" : "No matching rows"),
                             message: catalog?.empty ?? "The policy catalog has not been loaded. Refresh to retry.",
                             systemImage: "shield.lefthalf.filled")
            } else {
                // Use a native selectable table and keep all runtime columns in its
                // summary. The detail exposes untruncated values and consequences.
                Table(rows, selection: $selection) {
                    TableColumn("Name / scope") { row in
                        Text(row.cells.prefix(2).joined(separator: " ")).font(.callout.weight(.medium))
                    }.width(min: 160, ideal: 220)
                    TableColumn("Effective settings") { row in
                        Text(summary(row)).font(.caption).lineLimit(2)
                    }
                }
                if let row = selected {
                    HStack {
                        ForEach(actionGroups(row), id: \.self) { group in
                            Menu(group) {
                                ForEach(row.actions.filter { $0.group == group && $0.allowed }) { action in
                                    Button(action.title) {
                                        acknowledgeWeaker = false
                                        pending = action
                                    }
                                    .disabled(action.mutation && !appState.installationMutationsAllowed)
                                }
                            }
                        }
                    }.disabled(running || loading || !current)
                    ScrollView {
                        Text(row.detail).font(.callout.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(minHeight: 110, maxHeight: 240)
                }
            }
            if !output.isEmpty {
                DisclosureGroup("Last command output (also in Activity)") {
                    ScrollView { Text(output).font(.caption.monospaced()).textSelection(.enabled) }
                        .frame(maxHeight: 150)
                }
            }
        }
        .padding(16)
        .searchable(text: $search, prompt: "Search policy settings and details")
        .task(id: appState.installationGeneration) { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in Task { await load() } }
        .onChange(of: viewID) { _, _ in selection = nil }
        .onChange(of: scope) { _, _ in selection = nil }
        .sheet(item: $pending) { action in
            VStack(alignment: .leading, spacing: 16) {
                Text(action.title).font(.headline)
                ScrollView { Text(action.consequence).textSelection(.enabled) }.frame(maxHeight: 240)
                Text((["defenseclaw"] + action.arguments).map(ShellQuoting.quote).joined(separator: " "))
                    .font(.caption.monospaced()).textSelection(.enabled)
                if action.weaker {
                    Label("This reduces protection", systemImage: "exclamationmark.shield")
                        .foregroundStyle(Cisco.red)
                    Toggle("I understand and want to reduce protection", isOn: $acknowledgeWeaker)
                }
                HStack {
                    Button("Cancel") { pending = nil }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button(action.mutation ? "Apply change" : "Validate") { execute(action) }
                        .disabled(!current || !action.allowed || running
                                  || (action.weaker && !acknowledgeWeaker)
                                  || (action.mutation && !appState.installationMutationsAllowed))
                }
            }.padding(20).frame(width: 560)
        }
    }

    private func summary(_ row: PolicyCatalogRow) -> String {
        zip(catalog?.columns ?? [], row.cells).map { "\($0): \($1)" }.joined(separator: " · ")
    }

    private func actionGroups(_ row: PolicyCatalogRow) -> [String] {
        var seen = Set<String>()
        return row.actions.map(\.group).filter { seen.insert($0).inserted }
    }

    private func load() async {
        guard !loading else { return }
        loading = true
        defer { loading = false }
        let generation = appState.installationGeneration
        let signature = appState.installationContext.diskSignature
        if loadedGeneration != generation {
            snapshot = nil
            selection = nil
            pending = nil
        }
        do {
            let fresh = try await PolicyCatalog.load(using: appState.cli)
            guard generation == appState.installationGeneration,
                  signature == appState.installationContext.diskSignature else { return }
            snapshot = fresh
            if !fresh.scopes.contains(scope) { scope = fresh.scopes.first ?? "global" }
            loadedGeneration = generation
            loadedSignature = signature
            error = nil
        } catch {
            guard generation == appState.installationGeneration else { return }
            self.error = error.localizedDescription
        }
    }

    private func execute(_ action: PolicyCatalogAction) {
        guard current, action.allowed, !running,
              !action.weaker || acknowledgeWeaker,
              !action.mutation || appState.installationMutationsAllowed else { return }
        pending = nil
        running = true
        Task {
            defer { running = false }
            if let validation = action.validationArguments {
                let checked = await appState.runCommand(title: "Validate selected rule pack", arguments: validation,
                                                        mutation: false, category: "policy", origin: "Policies")
                let payload = checked.output.data(using: .utf8).flatMap {
                    (try? JSONSerialization.jsonObject(with: $0)) as? [String: Any]
                }
                guard checked.succeeded, payload?["valid"] as? Bool == true else {
                    output = "Rule pack was not changed because validation did not pass.\n" + checked.output
                    return
                }
            }
            guard current else {
                output = "The installation or policy changed during validation. Refresh and review the action again."
                return
            }
            let result = await appState.runCommand(title: action.title, arguments: action.arguments,
                                                  mutation: action.mutation, category: "policy", origin: "Policies",
                                                  refreshOnSuccess: action.mutation)
            output = result.output.isEmpty ? "Exit \(result.exitCode)" : result.output
            await load()
        }
    }
}
