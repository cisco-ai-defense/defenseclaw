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

// MARK: - Skills

struct SkillsView: View {
    @Environment(AppState.self) private var appState
    @State private var items: [SkillItem] = []
    @State private var search = ""
    @State private var error: String?
    @State private var loaded = false
    @State private var invocation: CatalogInvocation?
    @State private var showingInstall = false

    private var filtered: [SkillItem] {
        filter(items.filter { appState.connectorFilterAllows($0.connector) }) {
            "\($0.name) \($0.skillDescription) \($0.connector) \($0.status) \($0.verdict)"
        }
    }

    var body: some View {
        CatalogContainer(error: $error, isEmpty: loaded && filtered.isEmpty,
                         emptyMessage: "No skills were reported by `defenseclaw skill list --json`.") {
            Table(filtered) {
                TableColumn("Status") { item in CatalogStatusLabel(status: item.status, verdict: item.verdict) }
                    .width(105)
                TableColumn("Name", value: \.name)
                TableColumn("Description") { item in
                    Text(item.skillDescription).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                TableColumn("Scan") { item in CatalogScanLabel(scan: item.scan) }.width(120)
                TableColumn("Connector", value: \.connector).width(90)
                TableColumn("Source") { item in SourceText(item.source) }
                TableColumn("") { item in
                    CatalogActionMenu(actions: CatalogActions.skills(item)) { action in
                        invocation = CatalogActions.invocation(action, skill: item)
                    }
                }
                .width(34)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search skills")
        .toolbar {
            ToolbarItem { CatalogConnectorChip() }
            ToolbarItem {
                Button { showingInstall = true } label: {
                    Label("Install Skill", systemImage: "square.and.arrow.down")
                }
            }
            RefreshButton { await load() }
        }
        .task { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in Task { await load() } }
        .sheet(item: $invocation) { command in
            CatalogCommandSheet(invocation: command) { Task { await load() } }
                .environment(appState)
        }
        .sheet(isPresented: $showingInstall) {
            CatalogInstallSheet(resource: "skill", connectors: appState.configuredConnectors()) { command in
                showingInstall = false
                DispatchQueue.main.async { invocation = command }
            }
        }
    }

    private func load() async {
        do {
            items = try await CatalogCLI.skills(using: appState.cli)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        loaded = true
    }

    private func filter<T>(_ values: [T], text: (T) -> String) -> [T] {
        search.isEmpty ? values : values.filter { text($0).localizedCaseInsensitiveContains(search) }
    }
}

// MARK: - MCPs

struct MCPsView: View {
    @Environment(AppState.self) private var appState
    @State private var items: [MCPItem] = []
    @State private var search = ""
    @State private var error: String?
    @State private var loaded = false
    @State private var invocation: CatalogInvocation?
    @State private var showingSetForm = false

    private var filtered: [MCPItem] {
        let scoped = items.filter { appState.connectorFilterAllows($0.connector) }
        return search.isEmpty ? scoped : scoped.filter {
            "\($0.name) \($0.endpoint) \($0.connector) \($0.status) \($0.verdict)"
                .localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        CatalogContainer(error: $error, isEmpty: loaded && filtered.isEmpty,
                         emptyMessage: "No MCP servers were reported by `defenseclaw mcp list --json`.") {
            Table(filtered) {
                TableColumn("Status") { item in CatalogStatusLabel(status: item.status, verdict: item.verdict) }
                    .width(105)
                TableColumn("Name", value: \.name)
                TableColumn("Transport", value: \.transport).width(80)
                TableColumn("Command / URL") { item in
                    Text(item.endpoint).font(.caption.monospaced()).lineLimit(1)
                }
                TableColumn("Scan") { item in CatalogScanLabel(scan: item.scan) }.width(120)
                TableColumn("Connector", value: \.connector).width(90)
                TableColumn("") { item in
                    CatalogActionMenu(actions: CatalogActions.mcps(item)) { action in
                        invocation = CatalogActions.invocation(action, mcp: item)
                    }
                }
                .width(34)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search MCPs")
        .toolbar {
            ToolbarItem { CatalogConnectorChip() }
            ToolbarItem {
                Button { showingSetForm = true } label: {
                    Label("Set MCP Server", systemImage: "plus")
                }
                .help("Scan and add or update an MCP server")
            }
            RefreshButton { await load() }
        }
        .task { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in Task { await load() } }
        .sheet(isPresented: $showingSetForm) {
            MCPSetSheet(connectors: appState.configuredConnectors()) { command in
                showingSetForm = false
                DispatchQueue.main.async { invocation = command }
            }
        }
        .sheet(item: $invocation) { command in
            CatalogCommandSheet(invocation: command) { Task { await load() } }
                .environment(appState)
        }
    }

    private func load() async {
        do {
            items = try await CatalogCLI.mcps(using: appState.cli)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        loaded = true
    }
}

// MARK: - Plugins

struct PluginsView: View {
    @Environment(AppState.self) private var appState
    @State private var items: [PluginItem] = []
    @State private var search = ""
    @State private var error: String?
    @State private var loaded = false
    @State private var invocation: CatalogInvocation?
    @State private var showingInstall = false

    private var filtered: [PluginItem] {
        let scoped = items.filter { appState.connectorFilterAllows($0.connector) }
        return search.isEmpty ? scoped : scoped.filter {
            "\($0.name) \($0.connector) \($0.status) \($0.verdict) \($0.source)"
                .localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        CatalogContainer(error: $error, isEmpty: loaded && filtered.isEmpty,
                         emptyMessage: "No plugins were reported by `defenseclaw plugin list --json`.") {
            Table(filtered) {
                TableColumn("Status") { item in CatalogStatusLabel(status: item.status, verdict: item.verdict) }
                    .width(105)
                TableColumn("Name", value: \.name)
                TableColumn("Version", value: \.version).width(80)
                TableColumn("Origin", value: \.category).width(90)
                TableColumn("Scan") { item in CatalogScanLabel(scan: item.scan) }.width(120)
                TableColumn("Connector", value: \.connector).width(90)
                TableColumn("Source") { item in SourceText(item.source) }
                TableColumn("") { item in
                    CatalogActionMenu(actions: CatalogActions.plugins(item)) { action in
                        invocation = CatalogActions.invocation(action, plugin: item)
                    }
                }
                .width(34)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search plugins")
        .toolbar {
            ToolbarItem { CatalogConnectorChip() }
            ToolbarItem {
                Button { showingInstall = true } label: {
                    Label("Install Plugin", systemImage: "square.and.arrow.down")
                }
            }
            RefreshButton { await load() }
        }
        .task { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in Task { await load() } }
        .sheet(item: $invocation) { command in
            CatalogCommandSheet(invocation: command) { Task { await load() } }
                .environment(appState)
        }
        .sheet(isPresented: $showingInstall) {
            CatalogInstallSheet(resource: "plugin", connectors: appState.configuredConnectors()) { command in
                showingInstall = false
                DispatchQueue.main.async { invocation = command }
            }
        }
    }

    private func load() async {
        do {
            items = try await CatalogCLI.plugins(using: appState.cli)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        loaded = true
    }
}

// MARK: - Tools

struct ToolsView: View {
    @Environment(AppState.self) private var appState
    @State private var items: [ToolItem] = []
    @State private var search = ""
    @State private var error: String?
    @State private var loaded = false
    @State private var invocation: CatalogInvocation?

    private var filtered: [ToolItem] {
        // Tools special-case (TUI): an untagged override row stays visible
        // under any connector filter iff its scope is empty (global rows apply
        // everywhere); source-scoped untagged rows show only under All.
        let scoped = items.filter { item in
            if appState.connectorFilterAllows(item.connector) { return true }
            return item.connector.isEmpty && item.scope.isEmpty
        }
        return search.isEmpty ? scoped : scoped.filter {
            "\($0.name) \($0.summary) \($0.connector) \($0.scope) \($0.status)"
                .localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        CatalogContainer(error: $error, isEmpty: loaded && filtered.isEmpty,
                         emptyMessage: "No tool policy rows. Unblocked tools do not appear in this table.") {
            Table(filtered) {
                TableColumn("Status") { item in CatalogStatusLabel(status: item.status, verdict: "") }.width(90)
                TableColumn("Tool", value: \.name)
                TableColumn("Reason") { item in
                    Text(item.summary).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                TableColumn("Scope", value: \.scope).width(90)
                TableColumn("Connector", value: \.connector).width(90)
                TableColumn("") { item in
                    CatalogActionMenu(actions: CatalogActions.tools(item)) { action in
                        invocation = CatalogActions.invocation(action, tool: item)
                    }
                }
                .width(34)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search tools")
        .toolbar {
            ToolbarItem { CatalogConnectorChip() }
            RefreshButton { await load() }
        }
        .task { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in Task { await load() } }
        .sheet(item: $invocation) { command in
            CatalogCommandSheet(invocation: command) { Task { await load() } }
                .environment(appState)
        }
    }

    private func load() async {
        do {
            let cliItems = try await CatalogCLI.tools(using: appState.cli)
            items = cliItems.isEmpty ? await appState.audit.toolOverrideRows() : cliItems
            error = nil
        } catch {
            let fallback = await appState.audit.toolOverrideRows()
            items = fallback
            self.error = fallback.isEmpty ? error.localizedDescription : nil
        }
        loaded = true
    }
}

/// Toolbar connector-scope picker shared by the four catalog panels — the
/// same control the signal panels use; hides itself on single-connector
/// installs like the TUI chip.
private struct CatalogConnectorChip: View {
    @Environment(AppState.self) private var appState
    var body: some View {
        @Bindable var state = appState
        ConnectorFilterChip(names: appState.activeConnectorNames, selection: $state.connectorFilter)
    }
}

// MARK: - Actions

private struct CatalogActionMenu: View {
    let actions: [CatalogResourceAction]
    let perform: (CatalogResourceAction) -> Void

    var body: some View {
        Menu {
            ForEach(actions) { action in
                Button(role: action.destructive ? .destructive : nil) {
                    perform(action)
                } label: {
                    Label(action.label, systemImage: action.systemImage)
                }
                .help(action.detail)
            }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help("Actions")
    }
}

private struct CatalogCommandSheet: View {
    let invocation: CatalogInvocation
    let onComplete: () -> Void

    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @State private var phase: Phase = .ready
    @State private var output = ""
    @State private var exitCode: Int32?

    private enum Phase { case ready, running, done }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: invocation.destructive ? "exclamationmark.triangle.fill" : "terminal")
                    .foregroundStyle(invocation.destructive ? Cisco.red : Cisco.blue)
                Text(invocation.title).font(.headline)
                Spacer()
                Button { dismiss() } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
            }

            Text(invocation.detail).font(.callout).foregroundStyle(.secondary)
            Text(invocation.displayCommand)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 8))

            if phase != .ready {
                HStack {
                    if phase == .running { ProgressView().controlSize(.small) }
                    if phase == .done {
                        Image(systemName: exitCode == 0 ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(exitCode == 0 ? Cisco.green : Cisco.red)
                    }
                    Text(statusText).font(.subheadline.weight(.semibold))
                }
                ScrollView {
                    Text(output.isEmpty ? "Waiting for output…" : output)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(8)
                .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 8))
            } else if invocation.requiresConfirmation {
                Label(invocation.destructive
                      ? "This action changes or removes files. Review the command before continuing."
                      : "This action changes DefenseClaw policy or connector configuration.",
                      systemImage: "exclamationmark.shield")
                    .font(.caption)
                    .foregroundStyle(invocation.destructive ? Cisco.red : Cisco.orange)
            }

            Spacer()
            HStack {
                Spacer()
                if phase == .ready {
                    Button("Cancel") { dismiss() }
                    Button(invocation.destructive ? "Run Destructive Action" : "Run") { run() }
                        .buttonStyle(.borderedProminent)
                        .tint(invocation.destructive ? Cisco.red : Cisco.blue)
                        .keyboardShortcut(.defaultAction)
                } else if phase == .done {
                    Button("Close") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(18)
        .frame(width: 640, height: 440)
        .task {
            if !invocation.requiresConfirmation && phase == .ready { run() }
        }
    }

    private var statusText: String {
        switch phase {
        case .ready: "Ready"
        case .running: "Running…"
        case .done where exitCode == 0: "Completed"
        case .done: "Failed (exit \(exitCode ?? -1))"
        }
    }

    private func run() {
        guard phase == .ready else { return }
        phase = .running
        Task {
            let result = await appState.runCommand(
                title: invocation.title,
                arguments: invocation.arguments,
                category: "catalog",
                origin: "Catalog",
                refreshOnSuccess: true
            )
            if let entry = appState.activity.entries.first(where: { $0.id == appState.activity.selectedID }) {
                output = entry.output
            }
            exitCode = result.exitCode
            if output.isEmpty { output = result.output }
            phase = .done
            if result.succeeded { onComplete() }
        }
    }
}

private struct MCPSetSheet: View {
    let connectors: [String]
    let onReview: (CatalogInvocation) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var command = ""
    @State private var commandArguments = ""
    @State private var url = ""
    @State private var transport = "stdio"
    @State private var connector = "all"
    @State private var skipScan = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Set MCP Server").font(.headline)
            Text("DefenseClaw scans the server before writing it to the selected connector configuration.")
                .font(.caption).foregroundStyle(.secondary)
            Form {
                TextField("Name", text: $name)
                TextField("Command", text: $command, prompt: Text("npx, uvx, node…"))
                TextField("Arguments", text: $commandArguments, prompt: Text("JSON array or comma-separated"))
                TextField("URL", text: $url, prompt: Text("https://…"))
                Picker("Transport", selection: $transport) {
                    Text("stdio").tag("stdio")
                    Text("sse").tag("sse")
                }
                Picker("Connector", selection: $connector) {
                    Text("All configured connectors").tag("all")
                    ForEach(connectors, id: \.self) { Text($0).tag($0) }
                }
                Toggle("Skip security scan", isOn: $skipScan)
            }
            .formStyle(.grouped)
            Spacer()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Review") { onReview(invocation) }
                    .buttonStyle(.borderedProminent)
                    .tint(Cisco.blue)
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || (command.isEmpty && url.isEmpty))
            }
        }
        .padding(18)
        .frame(width: 520, height: 430)
    }

    private var invocation: CatalogInvocation {
        var args = ["mcp", "set", name]
        if !command.isEmpty { args += ["--command", command] }
        if !commandArguments.isEmpty { args += ["--args", commandArguments] }
        if !url.isEmpty { args += ["--url", url] }
        args += ["--transport", transport]
        if connector != "all" { args += ["--connector", connector] }
        if skipScan { args.append("--skip-scan") }
        return CatalogInvocation(title: "Set MCP server \(name)", arguments: args,
                                 detail: "Scan and write this MCP server to connector configuration.",
                                 requiresConfirmation: true, destructive: false)
    }
}

private struct CatalogInstallSheet: View {
    let resource: String
    let connectors: [String]
    let onReview: (CatalogInvocation) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var target = ""
    @State private var connector = "all"
    @State private var force = false
    @State private var applyPolicy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Install \(resource.capitalized)").font(.headline)
            Text(resource == "skill"
                 ? "Install and scan a skill from ClawHub."
                 : "Install and scan a plugin from a path, package, ClawHub URI, or URL.")
                .font(.caption).foregroundStyle(.secondary)
            Form {
                TextField(resource == "skill" ? "Skill name" : "Name or source path", text: $target)
                Picker("Connector", selection: $connector) {
                    Text("All configured connectors").tag("all")
                    ForEach(connectors, id: \.self) { Text($0).tag($0) }
                }
                Toggle("Overwrite an existing installation", isOn: $force)
                Toggle("Apply configured enforcement policy after scanning", isOn: $applyPolicy)
            }
            .formStyle(.grouped)
            Spacer()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Review") { onReview(invocation) }
                    .buttonStyle(.borderedProminent)
                    .tint(Cisco.blue)
                    .keyboardShortcut(.defaultAction)
                    .disabled(target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(18)
        .frame(width: 500, height: 330)
    }

    private var invocation: CatalogInvocation {
        var args = [resource, "install", target]
        if connector != "all" { args += ["--connector", connector] }
        if force { args.append("--force") }
        if applyPolicy { args.append("--action") }
        return CatalogInvocation(
            title: "Install \(resource) \(target)",
            arguments: args,
            detail: "DefenseClaw installs the resource, scans it, and reports its admission decision.",
            requiresConfirmation: true,
            destructive: force
        )
    }
}

// MARK: - Shared chrome

private struct CatalogStatusLabel: View {
    let status: String
    let verdict: String

    var body: some View {
        let decision = verdict.lowercased()
        // Raw roster state outranks the verdict (CLI _skill_status_display):
        // a disabled/blocked item stays "disabled"/"blocked" even when an
        // install=allow action would compute an "allowed" verdict.
        let rawState = status.lowercased()
        let value = ["disabled", "blocked", "quarantined"].contains(rawState)
            ? status
            : (!verdict.isEmpty && verdict != "-" && decision != "clean" ? verdict : (status.nonEmpty ?? "unknown"))
        Label(value.capitalized, systemImage: icon(value))
            .font(.caption)
            .foregroundStyle(color(value))
            .lineLimit(1)
            .help(verdict.isEmpty || verdict == "-" ? "Runtime status: \(status)" : "Runtime: \(status) · Verdict: \(verdict)")
    }

    private func color(_ value: String) -> Color {
        switch EntityState.classify(value) {
        case .active: Cisco.green
        case .blocked: Cisco.red
        case .warn, .quarantined: Cisco.orange
        case .disabled: .secondary
        }
    }

    private func icon(_ value: String) -> String {
        switch EntityState.classify(value) {
        case .active: "checkmark.circle.fill"
        case .blocked: "xmark.octagon.fill"
        case .warn: "exclamationmark.triangle.fill"
        case .quarantined: "shippingbox.fill"
        case .disabled: "pause.circle"
        }
    }
}

private struct CatalogScanLabel: View {
    let scan: CatalogScanState?

    var body: some View {
        if let scan {
            Label(scan.summary, systemImage: scan.clean ? "checkmark.shield" : "exclamationmark.shield.fill")
                .font(.caption)
                .foregroundStyle(scan.clean ? Cisco.green : severityColor(scan.maxSeverity))
                .lineLimit(1)
                .help(scan.target)
        } else {
            Text("Not scanned").font(.caption).foregroundStyle(.secondary)
        }
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity.uppercased() {
        case "CRITICAL": Cisco.red
        case "HIGH": Cisco.orange
        case "MEDIUM": Cisco.yellow
        default: .secondary
        }
    }
}

private struct SourceText: View {
    let source: String
    init(_ source: String) { self.source = source }

    var body: some View {
        Text(source.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
            .font(.caption.monospaced())
            .foregroundStyle(.secondary)
            .lineLimit(1)
    }
}

private struct CatalogContainer<Content: View>: View {
    @Binding var error: String?
    let isEmpty: Bool
    let emptyMessage: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            if let error {
                HStack {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(Cisco.red)
                    Spacer()
                    Button { self.error = nil } label: { Image(systemName: "xmark") }
                        .buttonStyle(.borderless)
                }
                .padding(8)
                .background(Cisco.red.opacity(0.08))
            }
            if isEmpty {
                DCEmptyState(title: "Nothing here", message: emptyMessage, systemImage: "tray")
                    .frame(maxHeight: .infinity)
            } else {
                content
            }
        }
    }
}

struct RefreshButton: ToolbarContent {
    let action: () async -> Void
    var body: some ToolbarContent {
        ToolbarItem {
            Button { Task { await action() } } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
        }
    }
}
