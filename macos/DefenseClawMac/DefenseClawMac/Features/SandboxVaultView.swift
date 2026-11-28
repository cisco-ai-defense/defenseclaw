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

// The Vault card of the Sandboxes panel (Preview): the TUI's Vault tab.
// The list comes from `defenseclaw sandbox vault list --json` (never a
// value); each change runs `defenseclaw sandbox vault ...` through the app's
// runner, so it lands in Activity. A value is typed in a SecureField, moved
// out of view state before the command starts, and sent on standard input.

import SwiftUI

struct SandboxVaultCard: View {
    @Environment(AppState.self) private var appState
    @State private var store = SandboxVaultStore()
    @State private var selection: SandboxVaultEntry.ID?
    @State private var editor: SandboxVaultEditor?
    @State private var confirmRemove: SandboxVaultEntry?
    @State private var confirmCaptured: SandboxVaultEntry?

    private var managed: Bool { appState.sandbox.status.adminConfigured }
    private var changesAllowed: Bool { appState.installationMutationsAllowed && !store.busy }
    private var entries: [SandboxVaultEntry] { store.list?.entries ?? [] }
    private var selected: SandboxVaultEntry? {
        guard let selection else { return nil }
        return entries.first { $0.id == selection }
    }

    var body: some View {
        DCCard("Vault (Preview)", systemImage: "key") {
            Text(SandboxVault.aboutText)
                .font(.caption)
                .foregroundStyle(.secondary)
            content
            if let message = store.message {
                Label(message, systemImage: store.messageFailed ? "exclamationmark.triangle" : "checkmark.circle")
                    .font(.callout)
                    .foregroundStyle(store.messageFailed ? Cisco.orange : Cisco.green)
                    .textSelection(.enabled)
            }
            if !appState.installationMutationsAllowed {
                Text(appState.installationReadOnlyReason ?? "This installation is read only.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            actions
        }
        .task(id: appState.installationGeneration) {
            store.reset()
            selection = nil
            await store.refresh(read: reader, managed: managed)
        }
        .sheet(item: $editor) { editor in
            SandboxVaultEditorSheet(editor: editor) { change, value in
                Task { await store.perform(change, value: value, run: runner, read: reader, managed: managed) }
            }
        }
        .confirmationDialog(
            "Remove \(confirmRemove?.name ?? "") from your vault?",
            isPresented: Binding(get: { confirmRemove != nil }, set: { if !$0 { confirmRemove = nil } }),
            presenting: confirmRemove
        ) { entry in
            Button("Remove", role: .destructive) {
                Task { await store.perform(.remove(name: entry.name), run: runner, read: reader, managed: managed) }
            }
        } message: { entry in
            Text("Sandboxes started from now on cannot use \(entry.name); running ones keep it until they stop. "
                + "Revoke it with its issuer if it may have leaked.")
        }
        .confirmationDialog(
            "Is \(confirmCaptured?.name ?? "") your own secret?",
            isPresented: Binding(get: { confirmCaptured != nil }, set: { if !$0 { confirmCaptured = nil } }),
            presenting: confirmCaptured
        ) { entry in
            Button("Confirm") {
                Task { await store.perform(.confirm(name: entry.name), run: runner, read: reader, managed: managed) }
            }
        } message: { entry in
            Text(SandboxVault.confirmText(entry))
        }
    }

    @ViewBuilder
    private var content: some View {
        if !store.error.isEmpty {
            Label(store.error, systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(Cisco.orange)
                .textSelection(.enabled)
        }
        if let list = store.list {
            if list.entries.isEmpty {
                Text(SandboxVault.emptyText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                Text(list.summary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Table(list.entries, selection: $selection) {
                    TableColumn("Name", value: \.name)
                    TableColumn("Host", value: \.hostText)
                    TableColumn("Status") { entry in
                        Text(entry.statusText)
                            .foregroundStyle(Self.tint(entry.status))
                            .help(entry.attention)
                    }
                    TableColumn("Source", value: \.sourceText)
                    TableColumn("Last used") { entry in Text(entry.lastUsedText()) }
                    TableColumn("Uses") { entry in Text("\(entry.useCount)").monospacedDigit() }
                }
                .frame(minHeight: 110, idealHeight: 160)
                if let selected {
                    Text(selected.detailText)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    if !selected.attention.isEmpty {
                        Text(selected.attention)
                            .font(.caption)
                            .foregroundStyle(Self.tint(selected.status))
                    }
                }
            }
        } else if store.error.isEmpty {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Reading the vault…").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var actions: some View {
        HStack(spacing: 8) {
            Button("Confirm…") { if let selected, selected.unconfirmed { confirmCaptured = selected } }
                .disabled(!(selected?.unconfirmed ?? false) || !changesAllowed)
                .help("Confirm a secret captured from a sandbox is one you gave the agent. \(SandboxVault.confirmCaution)")
            Button {
                editor = .add
            } label: {
                Label("Add…", systemImage: "plus")
            }
            .disabled(!changesAllowed)
            .help("Add a secret bound to one host. The value is hidden and goes to the vault on standard input.")
            Button("Replace value…") { if let selected { editor = .replace(selected.name) } }
                .disabled(selected == nil || !changesAllowed)
                .help("Paste a new value (after you rotate it).")
            Button("Set host…") { if let selected { editor = .bind(selected.name, current: selected.target) } }
                .disabled(selected == nil || !changesAllowed)
                .help("Set the only host the value may be sent to.")
            Button("Rename…") { if let selected { editor = .rename(selected.name) } }
                .disabled(selected == nil || !changesAllowed)
                .help("Rename the variable the sandbox sees.")
            Button("Remove…", role: .destructive) { confirmRemove = selected }
                .disabled(selected == nil || !changesAllowed)
            Spacer()
            if store.busy || store.loading { ProgressView().controlSize(.small) }
            Button {
                Task { await store.refresh(read: reader, managed: managed) }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(store.loading)
        }
        .controlSize(.small)
    }

    static func tint(_ status: String) -> Color {
        switch status {
        case "ready": return Cisco.green
        case "exposed": return Cisco.red
        default: return Cisco.orange
        }
    }

    /// Read-only list reads: the app's runner, bounded, and only while the
    /// installation they started under is current.
    private var reader: SandboxVaultStore.Reader {
        let generation = appState.installationGeneration
        let state = appState
        let read = SandboxInspectionStore.reader(cli: state.cli)
        return { arguments in
            let current = await MainActor.run { state.sandboxInspectionMayRead(generation: generation) }
            guard current else { return CLIResult(exitCode: 75, output: "") }
            return await read("defenseclaw", arguments)
        }
    }

    /// Changes run as Sandboxes commands, so each lands in Activity. The
    /// value travels only as standard input. The row keeps the exit status
    /// and a redacted line, never the output (confirm prints the last 4
    /// characters of the value).
    private var runner: SandboxVaultStore.Runner {
        let state = appState
        return { title, arguments, standardInput in
            await state.runCommand(
                title: title, arguments: arguments, standardInput: standardInput,
                mutation: true, category: "sandbox", origin: "Sandboxes",
                outputSummary: SandboxVault.activityOutput
            )
        }
    }
}

struct SandboxVaultEditorSheet: View {
    let editor: SandboxVaultEditor
    /// Called with the change and, for add and replace, the value. The
    /// sheet's own copy of the value is cleared before this is called.
    let submit: (SandboxVaultChange, String?) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var host = ""
    @State private var newName = ""
    @State private var value = ""

    private var change: SandboxVaultChange { editor.change(name: name, host: host, newName: newName) }
    private var problem: String? {
        if let problem = change.problem { return problem }
        return editor.asksValue ? SandboxVault.valueProblem(value) : nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(editor.title).font(.headline)
            Form {
                if editor.asksName {
                    TextField("Name", text: $name, prompt: Text("STRIPE_API_KEY"))
                    Text("The variable the sandbox sees: letters, digits and _.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if editor.asksNewName {
                    TextField("New name", text: $newName)
                }
                if editor.asksHost {
                    TextField("Host", text: $host, prompt: Text("api.stripe.com"))
                    Text("The only host the value may be sent to (host or host:port).")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if editor.asksValue {
                    SecureField("Value", text: $value)
                    Text("Hidden here; it goes to the vault on standard input and is never shown again.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if let problem, edited {
                Text(problem).font(.caption).foregroundStyle(Cisco.orange)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) {
                    value = ""
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button(editor.asksValue ? "Save to vault" : "Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(problem != nil)
            }
        }
        .padding(20)
        .frame(minWidth: 420)
        .onAppear {
            if case .bind(_, let current) = editor { host = current }
        }
        .onDisappear { value = "" }
    }

    /// Whether anything was typed yet (no complaint on an empty form).
    private var edited: Bool { !name.isEmpty || !host.isEmpty || !newName.isEmpty || !value.isEmpty }

    private func save() {
        guard problem == nil else { return }
        let change = self.change
        let secret: String? = editor.asksValue ? value : nil
        value = ""
        dismiss()
        submit(change, secret)
    }
}
