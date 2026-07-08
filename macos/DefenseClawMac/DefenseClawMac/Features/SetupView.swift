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

// Setup panel (spec §9.13): TUI setup workflows as data-driven native forms,
// each ending in a review step that shows the exact `defenseclaw setup …`
// command before applying via CLIRunner. Plus a typed config editor whose
// section catalog is dumped from the installed runtime (self-updating on
// runtime upgrades) and whose saves go through the runtime's own writer.

import SwiftUI

// MARK: - Wizard model (data-driven; one table per wizard)

struct WizardField: Identifiable {
    enum Kind {
        case text(placeholder: String)
        case secure(placeholder: String)
        case choice(options: [String])
        case bool       // click-style paired flag: --key / --no-key
        case flagOnly   // bare flag: emit --key when on, nothing when off
    }

    let key: String          // CLI flag name, e.g. "provider" → --provider=
    let label: String
    let kind: Kind
    var defaultValue: String = ""
    /// Only shown when (other field key, required value) matches — ports _SETUP_DRIVER_FLAGS.
    var visibleWhen: (key: String, equals: [String])? = nil
    /// Optional second condition, ANDed with visibleWhen (e.g. action==setup
    /// AND connector is a proxy connector).
    var visibleWhen2: (key: String, equals: [String])? = nil
    var help: String = ""

    var id: String { key }
}

struct WizardDefinition: Identifiable {
    let id: String
    let title: String
    let icon: String
    let blurb: String
    /// Verb prefix, e.g. ["setup", "llm"] or ["setup"] (+ commandField) or ["agent", "discovery"].
    let baseArgs: [String]
    /// Field whose VALUE becomes the next positional argument (the subcommand),
    /// optionally renamed via commandMap — e.g. connector "claudecode" → "claude-code".
    var commandField: String? = nil
    var commandMap: [String: String] = [:]
    /// Append --yes (only where the CLI supports -y/--yes).
    var appendYes: Bool = false
    /// Append --non-interactive (setup llm / guardrail style commands, which
    /// otherwise treat flags as prompt pre-fills and still prompt — aborting
    /// without a TTY).
    var appendNonInteractive: Bool = false
    /// True for subcommands with no flags — they only run as interactive
    /// terminal wizards, so the sheet offers Copy Command instead of Apply.
    var interactiveOnly: Bool = false
    /// When set, this wizard applies via the gateway instead of the CLI:
    /// each non-empty field becomes PATCH /config/patch on
    /// "<prefix>.<field key>" — mirroring the TUI's config-editor sections.
    var configPatchPrefix: String? = nil
    /// Optional exact argv builder for setup areas whose command shape is
    /// conditional or emits follow-up commands. The Bool requests masked
    /// secret values for review display.
    var commandBuilder: (([String: String], Bool) -> [[String]])? = nil
    /// Field delivered through stdin instead of argv (currently `keys set`).
    var secretInputField: String? = nil
    /// Optional form validation. Returning a message keeps Review disabled and
    /// surfaces the same requirement before invoking the CLI.
    var validation: (([String: String]) -> String?)? = nil
    /// Optional live-config prefill: values derived from config.yaml override
    /// static defaults so an untouched apply never resets current posture.
    var liveDefaults: ((YAMLNode) -> [String: String])? = nil
    let fields: [WizardField]
}

// MARK: - Setup panel

struct SetupView: View {
    @Environment(AppState.self) private var appState
    @State private var activeWizard: WizardDefinition?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Setup Areas").font(.title3.weight(.semibold))
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 230), spacing: 12)], spacing: 12) {
                    ForEach(TUIWizards.all) { wizard in
                        Button {
                            activeWizard = wizard
                        } label: {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Image(systemName: wizard.icon)
                                        .font(.title3)
                                        .foregroundStyle(Cisco.blue)
                                    Text(wizard.title).font(.headline)
                                    Spacer()
                                }
                                Text(wizard.blurb)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .multilineTextAlignment(.leading)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .padding(12)
                            .frame(height: 92)
                            .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 10))
                        }
                        .buttonStyle(.plain)
                    }
                }

                Divider().padding(.vertical, 4)

                Text("Config Editor").font(.title3.weight(.semibold))
                Text("Typed, sectioned config.yaml editor generated from the installed runtime's own catalog — new runtime settings appear here automatically. Changes are diff-reviewed, saved through the runtime's config writer, and queue a gateway restart.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                ConfigEditorView()
            }
            .padding(16)
        }
        .sheet(item: $activeWizard) { wizard in
            WizardSheet(wizard: wizard)
                .environment(appState)
        }
    }
}

// MARK: - Wizard sheet

struct WizardSheet: View {
    let wizard: WizardDefinition
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var values: [String: String] = [:]
    @State private var revealedSecrets: Set<String> = []
    @State private var phase: Phase = .form
    @State private var output = ""
    @State private var exitCode: Int32?
    @State private var confirmConnectorReplacement = false

    enum Phase { case form, review, running, done }

    private var visibleFields: [WizardField] {
        wizard.fields.filter { field in
            matches(field.visibleWhen) && matches(field.visibleWhen2)
        }
    }

    private func matches(_ condition: (key: String, equals: [String])?) -> Bool {
        guard let condition else { return true }
        let current = values[condition.key] ?? ""
        if condition.equals == ["*nonempty*"] { return !current.isEmpty }
        return condition.equals.contains(current)
    }

    /// The exact CLI invocation, shown verbatim in review (parity requirement).
    /// Booleans render click-style (--flag / --no-flag); the commandField value
    /// becomes a positional subcommand (mapped, e.g. claudecode → claude-code).
    private func buildArguments(maskSecrets: Bool) -> [String] {
        var args = wizard.baseArgs
        if let commandField = wizard.commandField {
            let value = values[commandField] ?? ""
            if !value.isEmpty { args.append(wizard.commandMap[value] ?? value) }
        }
        for field in visibleFields where field.key != wizard.commandField {
            let value = values[field.key] ?? ""
            switch field.kind {
            case .bool:
                args.append(value == "yes" ? "--\(field.key)" : "--no-\(field.key)")
            case .flagOnly:
                if value == "yes" { args.append("--\(field.key)") }
            case .secure:
                guard !value.isEmpty else { continue }
                args.append("--\(field.key)=\(maskSecrets ? "••••••" : value)")
            default:
                guard !value.isEmpty else { continue }
                args.append("--\(field.key)=\(value)")
            }
        }
        if wizard.appendYes { args.append("--yes") }
        if wizard.appendNonInteractive { args.append("--non-interactive") }
        return args
    }

    private func buildCommands(maskSecrets: Bool) -> [[String]] {
        if let commandBuilder = wizard.commandBuilder {
            return commandBuilder(values, maskSecrets)
        }
        return [buildArguments(maskSecrets: maskSecrets)]
    }

    private var cliCommands: [[String]] { buildCommands(maskSecrets: false) }

    private var validationMessage: String? {
        wizard.validation?(values)
    }

    private var replacesConnectorRoster: Bool {
        wizard.id == "connector"
            && (values["action"] == "batch"
                || (values["action"] == "setup" && values["replace"] == "yes"))
    }

    /// Gateway-applied wizards: one PATCH /config/patch per non-empty field.
    private var patchOperations: [(path: String, value: String, secure: Bool)] {
        guard let prefix = wizard.configPatchPrefix else { return [] }
        return visibleFields.compactMap { field in
            let value = values[field.key] ?? ""
            guard !value.isEmpty else { return nil }
            if case .secure = field.kind {
                return ("\(prefix).\(field.key)", value, true)
            }
            return ("\(prefix).\(field.key)", value, false)
        }
    }

    private var displayCommand: String {
        if wizard.configPatchPrefix != nil {
            guard !patchOperations.isEmpty else { return "(no fields set — nothing to apply)" }
            return patchOperations
                .map { "PATCH /config/patch  \($0.path) = \($0.secure ? "••••••" : $0.value)" }
                .joined(separator: "\n")
        }
        let commands = buildCommands(maskSecrets: true)
        guard !commands.isEmpty else { return "(no changes selected — nothing to apply)" }
        return commands
            .map { (["defenseclaw"] + $0).joined(separator: " ") }
            .joined(separator: "\n")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: wizard.icon).foregroundStyle(Cisco.blue)
                Text("Setup: \(wizard.title)").font(.headline)
                Spacer()
                Button { dismiss() } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
            }
            Text(wizard.blurb).font(.caption).foregroundStyle(.secondary)

            switch phase {
            case .form: formBody
            case .review: reviewBody
            case .running, .done: runBody
            }
        }
        .padding(18)
        .frame(width: 560, height: 480)
        .onAppear {
            for field in wizard.fields where values[field.key] == nil {
                values[field.key] = field.defaultValue
            }
            // Live-config prefill outranks static defaults (never downgrade
            // current posture on an untouched apply).
            if let liveDefaults = wizard.liveDefaults {
                for (key, value) in liveDefaults(appState.config.raw) where !value.isEmpty {
                    values[key] = value
                }
            }
            // TUI parity: the connector wizard preselects the configured
            // claw.mode connector, not a hardcoded default.
            if wizard.id == "connector",
               let configured = (appState.config.connectorMode ?? appState.config.connectorName)?
                   .trimmingCharacters(in: .whitespaces).lowercased(),
               TUIWizards.connectors.contains(configured) {
                values["connector"] = configured
            }
            if wizard.interactiveOnly { phase = .review } // nothing to fill in
        }
        .alert("Replace the connector roster?", isPresented: $confirmConnectorReplacement) {
            Button("Cancel", role: .cancel) {}
            Button("Replace Connectors", role: .destructive) { apply() }
        } message: {
            Text("This removes the other configured connectors from the active DefenseClaw roster. Their local agent files may remain installed until separately removed.")
        }
    }

    private var formBody: some View {
        VStack(alignment: .leading) {
            Form {
                ForEach(visibleFields) { field in
                    fieldRow(field)
                    if !field.help.isEmpty {
                        Text(field.help).font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            if let validationMessage {
                Label(validationMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(Cisco.red)
            }
            Spacer()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Review →") { phase = .review }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(Cisco.blue)
                    .disabled(validationMessage != nil)
            }
        }
    }

    @ViewBuilder
    private func fieldRow(_ field: WizardField) -> some View {
        let binding = Binding(
            get: { values[field.key] ?? "" },
            set: { values[field.key] = $0 }
        )
        switch field.kind {
        case .text(let placeholder):
            TextField(field.label, text: binding, prompt: Text(placeholder))
        case .secure(let placeholder):
            HStack {
                if revealedSecrets.contains(field.key) {
                    TextField(field.label, text: binding, prompt: Text(placeholder))
                } else {
                    SecureField(field.label, text: binding, prompt: Text(placeholder))
                }
                Button {
                    if revealedSecrets.contains(field.key) { revealedSecrets.remove(field.key) }
                    else { revealedSecrets.insert(field.key) }
                } label: {
                    Image(systemName: revealedSecrets.contains(field.key) ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help("Toggle secret visibility")
            }
        case .choice(let options):
            Picker(field.label, selection: binding) {
                ForEach(options, id: \.self) { Text($0).tag($0) }
            }
        case .bool, .flagOnly:
            Toggle(field.label, isOn: Binding(
                get: { (values[field.key] ?? "") == "yes" },
                set: { values[field.key] = $0 ? "yes" : "no" }
            ))
        }
    }

    private var reviewBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Review").font(.subheadline.weight(.semibold))
            Text(wizard.configPatchPrefix != nil
                 ? "These values apply through the gateway (PATCH /config/patch), exactly like the TUI's config-editor section:"
                 : wizard.interactiveOnly
                 ? "This subcommand is an interactive terminal wizard (it takes no flags). Copy it and run it in your terminal:"
                 : "This exact command will run (matching the terminal TUI’s behavior):")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(displayCommand)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 8))
            if replacesConnectorRoster {
                Label(
                    "This command replaces the active connector roster. Use normal Setup to add a connector without removing its peers.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.caption)
                .foregroundStyle(Cisco.red)
            }
            KeyValueGrid(pairs: visibleFields.compactMap { field in
                let value = values[field.key] ?? ""
                guard !value.isEmpty else { return nil }
                if case .secure = field.kind { return (field.label, "••••••") }
                return (field.label, value)
            })
            Spacer()
            HStack {
                if !wizard.interactiveOnly {
                    Button("← Back") { phase = .form }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                if wizard.interactiveOnly {
                    Button("Copy Command") {
                        let command = buildCommands(maskSecrets: false).first ?? wizard.baseArgs
                        copyToPasteboard((["defenseclaw"] + command).joined(separator: " "))
                        dismiss()
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(Cisco.blue)
                } else {
                    if replacesConnectorRoster {
                        Button("Replace Connectors", role: .destructive) {
                            confirmConnectorReplacement = true
                        }
                        .keyboardShortcut(.defaultAction)
                    } else {
                        Button("Apply") { apply() }
                            .keyboardShortcut(.defaultAction)
                            .buttonStyle(.borderedProminent)
                            .tint(Cisco.blue)
                            .disabled(wizard.configPatchPrefix != nil && !appState.gatewayReachable)
                            .help(wizard.configPatchPrefix != nil && !appState.gatewayReachable
                                  ? "Gateway offline — config patches need the gateway running."
                                  : "")
                    }
                }
            }
        }
    }

    private var runBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                if phase == .running {
                    ProgressView().controlSize(.small)
                    Text("Applying…").font(.subheadline)
                } else if exitCode == 0 {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Cisco.green)
                    Text("Applied successfully").font(.subheadline.weight(.semibold))
                } else {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(Cisco.red)
                    Text("Failed (exit \(exitCode ?? -1))").font(.subheadline.weight(.semibold))
                }
            }
            ScrollView {
                Text(output.isEmpty ? "…" : output)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 8))
            Spacer()
            HStack {
                Spacer()
                Button(phase == .done ? "Close" : "Dismiss") {
                    dismiss()
                    if exitCode == 0 { appState.reloadConfig() }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func apply() {
        phase = .running
        output = ""
        if wizard.configPatchPrefix != nil {
            applyPatches()
            return
        }
        Task {
            let commands = cliCommands
            guard !commands.isEmpty else {
                output = "Nothing to apply."
                exitCode = 0
                phase = .done
                return
            }
            var finalCode: Int32 = 0
            for (index, arguments) in commands.enumerated() {
                if commands.count > 1 {
                    output += "$ defenseclaw \(arguments.joined(separator: " "))\n"
                }
                let secret = index == 0 ? wizard.secretInputField.flatMap { key in
                    visibleFields.contains(where: { $0.key == key }) ? values[key] : nil
                } : nil
                let result = await appState.runCommand(
                    title: wizard.title,
                    binary: "defenseclaw",
                    arguments: arguments,
                    standardInput: secret,
                    category: "setup",
                    origin: "Setup",
                    refreshOnSuccess: true
                )
                if let entry = appState.activity.entries.first(where: { $0.id == appState.activity.selectedID }) {
                    output += entry.output
                }
                if output.isEmpty { output = result.output }
                finalCode = result.exitCode
                if !result.succeeded { break }
            }
            exitCode = finalCode
            phase = .done
        }
    }

    private func applyPatches() {
        let operations = patchOperations
        guard !operations.isEmpty else {
            output = "Nothing to apply — all fields are empty."
            exitCode = 1
            phase = .done
            return
        }
        Task {
            var failures = 0
            for op in operations {
                do {
                    let value = dcCoerceConfigValue(op.value, forPath: op.path)
                    try await appState.gateway.patchConfig(path: op.path, value: value)
                    output += "✓ \(op.path)\n"
                } catch {
                    failures += 1
                    output += "✗ \(op.path): \(error.localizedDescription)\n"
                }
            }
            exitCode = failures == 0 ? 0 : Int32(failures)
            phase = .done
            if failures == 0 { appState.reloadConfig() }
        }
    }
}

// MARK: - Config editor

/// Sectioned typed config editor (TUI Setup config sections parity): a
/// section list, kind-aware field controls with validation, a diff-review
/// save sheet with masked secrets, and a queued-gateway-restart banner.
/// Writes go through PATCH /config/patch per changed key.
struct ConfigEditorView: View {
    @Environment(AppState.self) private var appState
    @State private var selectedSection: String? = "General"
    @State private var original: [String: String] = [:]
    @State private var edited: [String: String] = [:]
    @State private var showDiff = false
    @State private var status: String?
    @State private var statusOK = true
    @State private var restartQueued = false
    @State private var saving = false
    /// Sections dumped from the installed runtime's own catalog — new
    /// runtime features appear here on upgrade with no Mac code changes.
    @State private var dynamicSections: [ConfigEditorSection]?
    @State private var uncatalogued: ConfigEditorSection?
    @State private var catalogSource = "loading…"
    @State private var fieldSearch = ""

    private var sections: [ConfigEditorSection] {
        var all = dynamicSections
            ?? ConfigEditorCatalog.sections(activeConnectors: appState.activeConnectorNames)
        if let uncatalogued { all.append(uncatalogued) }
        return all
    }

    /// Fields matching the cross-section search, with their section names.
    private var searchMatches: [(section: String, field: ConfigEditorField)] {
        let query = fieldSearch.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return [] }
        return sections.flatMap { section in
            section.fields.filter { field in
                field.interactive &&
                "\(field.label) \(field.key) \(field.hint)".localizedCaseInsensitiveContains(query)
            }.map { (section.name, $0) }
        }
    }

    private var currentSection: ConfigEditorSection? {
        sections.first { $0.name == selectedSection }
    }

    /// Every changed key across all sections, in catalog order.
    private var diffEntries: [ConfigDiffEntry] {
        sections.flatMap(\.fields).compactMap { field in
            guard field.interactive, let after = edited[field.key],
                  after != (original[field.key] ?? "") else { return nil }
            return ConfigDiffEntry(
                key: field.key,
                before: original[field.key] ?? "",
                after: after,
                secret: field.secret
            )
        }
    }

    /// First validation error among the changed fields (blocks Review & Save).
    private var firstValidationError: String? {
        for field in sections.flatMap(\.fields) where field.interactive {
            guard let value = edited[field.key], value != (original[field.key] ?? "") else { continue }
            let result = ConfigFieldValidation.validate(field, value: value)
            if result.isError { return "\(field.label): \(result.message)" }
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if restartQueued {
                HStack(spacing: 8) {
                    Label("Config saved — restart queued. Changes take effect after the gateway restarts.",
                          systemImage: "clock.arrow.circlepath")
                        .font(.caption)
                        .foregroundStyle(Cisco.orange)
                    Button("Restart Gateway Now") { restartGateway() }
                        .controlSize(.small)
                    Button("Dismiss") { restartQueued = false }
                        .controlSize(.small)
                        .buttonStyle(.borderless)
                    Spacer()
                }
                .padding(8)
                .background(Cisco.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
            }
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search all settings (label, key, or hint)", text: $fieldSearch)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 380)
                if !fieldSearch.isEmpty {
                    Button("Clear") { fieldSearch = "" }
                        .controlSize(.small)
                }
                Spacer()
                Text(catalogSource)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                Button {
                    loadCatalog()
                } label: {
                    Label("Reload Catalog", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
                .help("Re-dump the section catalog from the installed runtime")
            }
            if fieldSearch.isEmpty {
                HStack(alignment: .top, spacing: 0) {
                    List(sections, selection: $selectedSection) { section in
                        HStack {
                            Text(section.name)
                            Spacer()
                            if sectionHasEdits(section) {
                                Circle().fill(Cisco.orange).frame(width: 6, height: 6)
                            }
                        }
                        .tag(section.name)
                    }
                    .listStyle(.sidebar)
                    .frame(width: 190)
                    Divider()
                    sectionForm
                }
                // Embedded in the Setup tab's ScrollView, so the sidebar List
                // needs an explicit height or it collapses to zero.
                .frame(height: 520)
            } else {
                // Cross-section search results as a flat list.
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        if searchMatches.isEmpty {
                            Text("No settings match “\(fieldSearch)”.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .padding(.top, 12)
                        }
                        ForEach(Array(searchMatches.enumerated()), id: \.offset) { _, match in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(match.section)
                                    .font(.caption2)
                                    .foregroundStyle(Cisco.blue)
                                    .frame(width: 130, alignment: .leading)
                                    .lineLimit(1)
                                fieldRow(match.field)
                            }
                        }
                    }
                    .padding(.trailing, 8)
                }
                .frame(height: 520)
            }
            HStack {
                if let error = firstValidationError {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(Cisco.red)
                } else if let status {
                    Label(status, systemImage: statusOK ? "checkmark.circle" : "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(statusOK ? Cisco.green : Cisco.red)
                }
                Spacer()
                Button("Revert") { edited = [:]; status = nil }
                    .disabled(diffEntries.isEmpty)
                Button("Review \(diffEntries.count) Change\(diffEntries.count == 1 ? "" : "s")…") {
                    showDiff = true
                }
                .buttonStyle(.borderedProminent)
                .tint(Cisco.blue)
                .disabled(diffEntries.isEmpty || firstValidationError != nil || saving)
                .help("Review the pending config changes before saving (writes config.yaml via the DefenseClaw runtime)")
            }
        }
        .task { loadCatalog() }
        .sheet(isPresented: $showDiff) {
            ConfigDiffSheet(entries: diffEntries, saving: saving) { save in
                if save { applyChanges() } else { showDiff = false }
            }
        }
    }

    @ViewBuilder
    private var sectionForm: some View {
        if let section = currentSection {
            VStack(alignment: .leading, spacing: 6) {
                Text(section.summary).font(.caption).foregroundStyle(.secondary)
                if !section.help.isEmpty {
                    Text(section.help).font(.caption2).foregroundStyle(.tertiary)
                }
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(section.fields) { field in
                            fieldRow(field)
                        }
                    }
                    .padding(.trailing, 8)
                }
            }
            .padding(.leading, 12)
        } else {
            DCEmptyState(title: "Select a section", message: "", systemImage: "slider.horizontal.3")
        }
    }

    @ViewBuilder
    private func fieldRow(_ field: ConfigEditorField) -> some View {
        if field.kind == .header {
            HStack {
                Text(field.label)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Cisco.blue)
                if !headerDisplayValue(field).isEmpty {
                    Text(headerDisplayValue(field))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.top, 6)
        } else {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(field.label)
                    .font(.callout)
                    .frame(width: 210, alignment: .leading)
                    .help(field.key)
                fieldControl(field)
                Spacer(minLength: 0)
            }
            .help(field.hint)
            let value = currentValue(field.key)
            let validation = ConfigFieldValidation.validate(field, value: value)
            if !validation.severity.isEmpty, value != (original[field.key] ?? "") {
                Text(validation.message)
                    .font(.caption2)
                    .foregroundStyle(validation.isError ? Cisco.red : Cisco.orange)
                    .padding(.leading, 220)
            }
        }
    }

    @ViewBuilder
    private func fieldControl(_ field: ConfigEditorField) -> some View {
        switch field.kind {
        case .bool:
            Toggle("", isOn: Binding(
                get: { currentValue(field.key) == "true" },
                set: { edited[field.key] = $0 ? "true" : "false" }
            ))
            .toggleStyle(.switch)
            .controlSize(.small)
            .labelsHidden()
        case .choice:
            Picker("", selection: Binding(
                get: { currentValue(field.key) },
                set: { edited[field.key] = $0 }
            )) {
                ForEach(field.options, id: \.self) { option in
                    Text(option.isEmpty ? "(inherit)" : option).tag(option)
                }
                // Keep an off-catalog current value selectable rather than
                // silently coercing it.
                if !field.options.contains(currentValue(field.key)) {
                    Text(currentValue(field.key).isEmpty ? "(unset)" : currentValue(field.key))
                        .tag(currentValue(field.key))
                }
            }
            .labelsHidden()
            .frame(maxWidth: 260, alignment: .leading)
        case .password:
            SecureField("(unchanged)", text: Binding(
                get: { edited[field.key] ?? "" },
                set: { edited[field.key] = $0 }
            ))
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: 260)
            .help("Value is write-only here; the stored secret is never displayed.")
        default:
            TextField("", text: Binding(
                get: { currentValue(field.key) },
                set: { edited[field.key] = $0 }
            ))
            .textFieldStyle(.roundedBorder)
            .font(.callout.monospaced())
            .frame(maxWidth: 320)
        }
    }

    // MARK: Data plumbing

    private func currentValue(_ key: String) -> String {
        edited[key] ?? original[key] ?? ""
    }

    private func headerDisplayValue(_ field: ConfigEditorField) -> String {
        if !field.headerValue.isEmpty { return field.headerValue }
        guard !field.key.isEmpty else { return "" }
        let value = original[field.key] ?? ""
        return value.isEmpty ? "(unset)" : value
    }

    private func sectionHasEdits(_ section: ConfigEditorSection) -> Bool {
        section.fields.contains { field in
            guard field.interactive, let after = edited[field.key] else { return false }
            return after != (original[field.key] ?? "")
        }
    }

    /// Load the section catalog + on-disk values. Prefers the runtime's own
    /// catalog (self-updating on runtime upgrades); falls back to the static
    /// built-in port. Secrets stay out of `original` (write-only fields) so
    /// they can never echo into the UI. Keys in config.yaml that neither
    /// catalog describes land in the "Other (uncatalogued)" section.
    private func loadCatalog() {
        Task {
            let cfg = await appState.configStore.reload()
            var values: [String: String] = [:]
            var active: [ConfigEditorSection]
            if let dynamic = await DynamicConfigCatalog.load(using: appState.cli) {
                dynamicSections = dynamic.sections
                values = dynamic.values
                active = dynamic.sections
                let version = appState.installedRuntimeVersion.map { " \($0)" } ?? ""
                catalogSource = "runtime catalog\(version) · \(dynamic.sections.count) sections"
            } else {
                dynamicSections = nil
                active = ConfigEditorCatalog.sections(activeConnectors: appState.activeConnectorNames)
                catalogSource = "built-in catalog (runtime dump unavailable)"
                for field in active.flatMap(\.fields) where !field.key.isEmpty {
                    if field.kind == .password { continue }
                    values[field.key] = Self.displayValue(cfg.raw[field.key])
                }
            }
            let known = Set(active.flatMap(\.fields).map(\.key).filter { !$0.isEmpty })
            if let extra = DynamicConfigCatalog.uncataloguedSection(raw: cfg.raw, knownKeys: known) {
                uncatalogued = extra.section
                values.merge(extra.values) { current, _ in current }
            } else {
                uncatalogued = nil
            }
            original = values
            edited = [:]
        }
    }

    /// YAML node → editor display string (lists join with ", ", TUI _value()).
    private static func displayValue(_ node: YAMLNode?) -> String {
        switch node {
        case .scalar(let s): return s
        case .sequence(let items):
            return items.compactMap(\.string).joined(separator: ", ")
        default: return ""
        }
    }

    /// The TUI's exact save path: apply every changed key through the
    /// installed runtime's own `apply_config_field` (typed coercion, CSV
    /// lists, tristates, judge hook-connector list surgery) and `cfg.save()`.
    /// Changes travel as JSON on stdin — secrets never touch argv. The
    /// gateway's /config/patch endpoint is NOT used (POST-only legacy RPC
    /// that fails against real gateways).
    private static let applyScript = """
    import json, sys
    from defenseclaw import config as dc_config
    from defenseclaw.tui.services.setup_state import apply_config_field
    changes = json.load(sys.stdin)
    cfg = dc_config.load()
    for key, value in changes.items():
        apply_config_field(cfg, key, str(value))
    cfg.save()
    print(f"applied {len(changes)} change(s) to config.yaml")
    """

    private var runtimePython: String {
        FileManager.default.homeDirectoryForCurrentUser.path + "/.defenseclaw/.venv/bin/python"
    }

    private func applyChanges() {
        let entries = diffEntries
        guard !entries.isEmpty else { return }
        guard FileManager.default.isExecutableFile(atPath: runtimePython) else {
            showDiff = false
            status = "DefenseClaw runtime not found at ~/.defenseclaw/.venv — cannot write config."
            statusOK = false
            return
        }
        saving = true
        let payload = Dictionary(uniqueKeysWithValues: entries.map { ($0.key, $0.after) })
        guard let json = try? JSONSerialization.data(withJSONObject: payload),
              let stdin = String(data: json, encoding: .utf8) else {
            saving = false
            showDiff = false
            status = "Could not encode the pending changes."
            statusOK = false
            return
        }
        Task {
            let result = await appState.runCommand(
                title: "Save \(entries.count) config change\(entries.count == 1 ? "" : "s")",
                binary: runtimePython,
                arguments: ["-c", Self.applyScript],
                standardInput: stdin,
                category: "setup",
                origin: "Config editor",
                successEffects: ["config.yaml updated; gateway restart queued"],
                refreshOnSuccess: true
            )
            saving = false
            showDiff = false
            if result.succeeded {
                status = "Saved \(entries.count) change\(entries.count == 1 ? "" : "s"); restart queued."
                statusOK = true
                restartQueued = true
                appState.reloadConfig()
                loadCatalog()
            } else {
                // cfg.save() runs after all applies, so a failure means
                // nothing was written.
                status = "Save failed — no changes were written. \(result.output.suffix(160))"
                statusOK = false
            }
        }
    }

    private func restartGateway() {
        Task {
            _ = await appState.runCommand(
                title: "Restart gateway",
                binary: "defenseclaw-gateway",
                arguments: ["restart"],
                category: "daemon",
                origin: "Config editor",
                successEffects: ["Gateway restarted with the saved config"],
                refreshOnSuccess: true
            )
            restartQueued = false
        }
    }
}

/// The TUI's "Review Config Changes" modal: every pending key with
/// before/after (secrets masked), Cancel / Save and queue restart.
private struct ConfigDiffSheet: View {
    let entries: [ConfigDiffEntry]
    let saving: Bool
    let onDecision: (Bool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Review Config Changes").font(.headline)
            if entries.isEmpty {
                Text("No pending changes.").font(.caption).foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(entries) { entry in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.secret ? "\(entry.key) (masked)" : entry.key)
                                    .font(.caption.weight(.semibold).monospaced())
                                Text("before: \(entry.secret ? "••••••" : displayTruncated(entry.before))")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                                Text("after:  \(entry.secret ? "••••••" : displayTruncated(entry.after))")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(Cisco.green)
                            }
                        }
                    }
                }
                .frame(minHeight: 120, maxHeight: 320)
            }
            HStack {
                Spacer()
                Button("Cancel") { onDecision(false) }
                    .keyboardShortcut(.cancelAction)
                Button(saving ? "Saving…" : "Save and queue restart") { onDecision(true) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(Cisco.green)
                    .disabled(entries.isEmpty || saving)
            }
        }
        .padding(16)
        .frame(width: 560)
    }

    private func displayTruncated(_ value: String) -> String {
        let display = value.isEmpty ? "(empty)" : value
        return display.count <= 72 ? display : String(display.prefix(71)) + "…"
    }
}
// MARK: - Shared helpers

/// Coerce a string value typed into a wizard or config-editor field to the
/// YAML scalar the gateway expects — int for *_ms / *_seconds keys, bool for
/// "true"/"false". Wizard apply and direct config editor share this so the
/// two write paths never drift on type-handling.
fileprivate func dcCoerceConfigValue(_ raw: String, forPath path: String) -> Any {
    let pathLower = path.lowercased()
    if (pathLower.hasSuffix("_ms") || pathLower.hasSuffix("_seconds")),
       let intValue = Int(raw) {
        return intValue
    }
    switch raw.lowercased() {
    case "true": return true
    case "false": return false
    default: return raw
    }
}
