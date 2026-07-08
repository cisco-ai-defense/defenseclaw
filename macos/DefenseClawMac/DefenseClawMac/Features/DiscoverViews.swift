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

// Discover panels (spec §9.7, §9.11, §9.12): Inventory, AI Discovery, Registries.

import SwiftUI
import Charts

// MARK: - Inventory

/// Toolbar connector-scope picker for the Inventory panel — same shared
/// filter as the catalogs and signal panels; hidden on single-connector.
private struct InventoryConnectorChip: View {
    @Environment(AppState.self) private var appState
    var body: some View {
        @Bindable var state = appState
        ConnectorFilterChip(names: appState.activeConnectorNames, selection: $state.connectorFilter)
    }
}

struct InventoryView: View {
    @Environment(AppState.self) private var appState
    @State private var tab = "Summary"
    @State private var items: [InventoryItem] = []
    @State private var summaries: [InventoryConnectorSummary] = []
    @State private var search = ""
    @State private var statusFilter = "all"
    @State private var selectedID: String?
    @State private var scanning = false
    @State private var error: String?
    @State private var warning: String?
    @State private var lastScan: Date?

    private var category: InventoryCategory? {
        InventoryCategory.allCases.first { $0.rawValue == tab }
    }

    private var filtered: [InventoryItem] {
        guard let category else { return [] }
        return items.filter { item in
            guard item.category == category else { return false }
            guard appState.connectorFilterAllows(item.connector) else { return false }
            let state = "\(item.status) \(item.verdict) \(item.detail)".lowercased()
            if statusFilter != "all", !state.contains(statusFilter) { return false }
            guard !search.isEmpty else { return true }
            let fields = item.fields.map { "\($0.label) \($0.value)" }.joined(separator: " ")
            return "\(item.name) \(item.path) \(item.connector) \(fields)"
                .localizedCaseInsensitiveContains(search)
        }
    }

    /// Summary rows honoring the shared filter — a selected connector shows
    /// its own snapshot only (TUI _summary_inventory behavior).
    private var scopedSummaries: [InventoryConnectorSummary] {
        summaries.filter { appState.connectorFilterAllows($0.connector) }
    }

    /// Items visible under the shared filter (for the Summary stat cards and
    /// segmented tab counts).
    private var scopedItems: [InventoryItem] {
        items.filter { appState.connectorFilterAllows($0.connector) }
    }

    private var selectedItem: InventoryItem? {
        guard let selectedID else { return nil }
        return items.first { $0.id == selectedID }
    }

    private var statusOptions: [(String, String)] {
        switch category {
        case .skills: [("All", "all"), ("Eligible", "eligible"), ("Warning", "warning"), ("Blocked", "blocked")]
        case .plugins: [("All", "all"), ("Loaded", "loaded"), ("Disabled", "disabled"), ("Blocked", "blocked")]
        default: [("All", "all")]
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 8) {
                Picker("View", selection: $tab) {
                    Text("Summary").tag("Summary")
                    ForEach(InventoryCategory.allCases) { category in
                        Text("\(category.rawValue) (\(scopedItems.filter { $0.category == category }.count))")
                            .tag(category.rawValue)
                    }
                }
                .pickerStyle(.segmented)
                HStack {
                    if category != nil, statusOptions.count > 1 {
                        FilterChipRow("Status", options: statusOptions, selection: $statusFilter)
                    }
                    if let lastScan {
                        Text("Last scan: \(DCDates.relative(lastScan))")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        StaleBadge(date: lastScan)
                    }
                    Spacer()
                    if scanning { ProgressView().controlSize(.small) }
                }
            }
            .padding(10)
            Divider()
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(Cisco.red)
                    .padding(6)
            }
            if let warning {
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(Cisco.orange)
                    .padding(6)
            }
            if tab == "Summary" {
                summaryView
            } else if filtered.isEmpty {
                DCEmptyState(
                    title: scanning ? "Scanning..." : "No \(tab.lowercased()) inventoried",
                    message: scanning
                        ? "Running `defenseclaw aibom scan` across every active connector."
                        : "Inventory comes from `defenseclaw aibom scan --json`, the same per-connector bill of materials the TUI shows. Use Rescan to run it.",
                    systemImage: "shippingbox"
                )
                .frame(maxHeight: .infinity)
            } else {
                Table(filtered, selection: $selectedID) {
                    TableColumn("Name", value: \.name)
                    TableColumn("Version", value: \.version).width(70)
                    TableColumn("Connector") { item in
                        Text(item.connector.isEmpty ? "—" : item.connector)
                            .font(.caption)
                            .foregroundStyle(Cisco.blue)
                    }
                    .width(90)
                    TableColumn("Verdict") { item in
                        if item.verdict.isEmpty || item.verdict == "unscanned" {
                            Text(item.verdict.isEmpty ? "—" : item.verdict)
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        } else {
                            StatePill(raw: item.verdict)
                        }
                    }
                    .width(100)
                    TableColumn("Status") { item in
                        Text(item.status.isEmpty ? "—" : item.status)
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .width(86)
                    TableColumn("Path / Source") { item in
                        Text(item.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                            .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    }
                    TableColumn("Detail") { item in
                        Text(item.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
        }
        .inspector(isPresented: Binding(
            get: { selectedItem != nil },
            set: { if !$0 { selectedID = nil } }
        )) {
            if let item = selectedItem {
                inventoryInspector(item)
                    .inspectorColumnWidth(min: 320, ideal: 400)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search inventory")
        .toolbar {
            ToolbarItemGroup {
                InventoryConnectorChip()
                Button {
                    scan()
                } label: {
                    Label("Rescan All", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(scanning)
            }
        }
        .task { if items.isEmpty { scan() } }
        .onChange(of: tab) {
            statusFilter = "all"
            selectedID = nil
        }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in scan() }
    }

    private var summaryView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                StatCard(title: "Total Items", value: "\(scopedItems.count)", tint: Cisco.blue)
                StatCard(title: "Tools", value: "\(scopedItems.filter { $0.category == .tools }.count)", tint: Cisco.green)
                StatCard(title: "Connectors", value: "\(scopedSummaries.count)", tint: .secondary)
                StatCard(title: "Errors", value: "\(scopedSummaries.reduce(0) { $0 + $1.errors })",
                         tint: scopedSummaries.contains { $0.errors > 0 } ? Cisco.red : .secondary)
            }
            if scopedSummaries.isEmpty {
                DCEmptyState(
                    title: scanning ? "Scanning inventory..." : "No inventory snapshot",
                    message: "Run Rescan All to collect the per-connector AIBOM summary.",
                    systemImage: "shippingbox"
                )
            } else {
                Table(scopedSummaries) {
                    TableColumn("Connector", value: \.connector)
                    TableColumn("Total") { Text("\($0.total)") }.width(55)
                    TableColumn("Skills") { Text("\($0.counts[.skills, default: 0])") }.width(55)
                    TableColumn("Plugins") { Text("\($0.counts[.plugins, default: 0])") }.width(58)
                    TableColumn("MCPs") { Text("\($0.counts[.mcps, default: 0])") }.width(50)
                    TableColumn("Agents") { Text("\($0.counts[.agents, default: 0])") }.width(55)
                    TableColumn("Tools") { Text("\($0.counts[.tools, default: 0])") }.width(50)
                    TableColumn("Models") { Text("\($0.counts[.providers, default: 0])") }.width(55)
                    TableColumn("Memory") { Text("\($0.counts[.memories, default: 0])") }.width(55)
                    TableColumn("Source") { summary in
                        Text(summary.home.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                            .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
        }
        .padding(12)
    }

    private func inventoryInspector(_ item: InventoryItem) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.name).font(.headline)
                    Text(item.category.rawValue).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button { selectedID = nil } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
            }
            KeyValueGrid(pairs: [
                ("Connector", item.connector),
                ("Status", item.status),
                ("Verdict", item.verdict),
                ("Version", item.version),
                ("Source", item.path),
            ].filter { !$0.1.isEmpty })
            Divider()
            Text("Inventory Fields").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            ScrollView {
                KeyValueGrid(pairs: item.fields.map { ($0.label, $0.value) }.filter { !$0.1.isEmpty })
            }
            Spacer()
        }
        .padding(12)
    }

    /// The TUI's Inventory data source: `defenseclaw aibom scan --json` emits
    /// one document per active connector with skills / plugins / mcp / agents /
    /// model_providers / memory arrays (each row carrying scan verdicts).
    private func scan() {
        guard !scanning else { return }
        scanning = true
        appState.scanInFlight = true
        error = nil
        warning = nil
        Task {
            let result = await appState.runCommand(
                title: "Scan inventory",
                arguments: ["aibom", "scan", "--json"],
                category: "scan",
                origin: "Inventory",
                successEffects: ["Inventory snapshot refreshed"]
            )
            defer {
                scanning = false
                appState.scanInFlight = false
            }
            guard result.succeeded else {
                error = "aibom scan failed (exit \(result.exitCode)). \(String(result.output.suffix(200)))"
                return
            }
            guard let parsed = InventoryOutputParser.parse(result.output) else {
                error = "Could not parse `aibom scan --json` output."
                return
            }
            items = parsed.documents.flatMap(Self.rows(from:))
            summaries = parsed.documents.map(Self.summary(from:))
            warning = parsed.diagnostics.nonEmpty
            lastScan = Date()
        }
    }

    /// Map one per-connector aibom document into inventory rows.
    private static func rows(from doc: [String: Any]) -> [InventoryItem] {
        let connector = (doc["connector"] as? String) ?? ""

        func str(_ r: [String: Any], _ keys: String...) -> String {
            for key in keys {
                if let v = r[key] as? String, !v.isEmpty { return v }
            }
            return ""
        }
        func verdict(_ r: [String: Any]) -> (verdict: String, detail: String) {
            (str(r, "policy_verdict"), str(r, "policy_detail"))
        }
        func fields(_ r: [String: Any]) -> [InventoryField] {
            r.keys.sorted().compactMap { key in
                guard let value = r[key], !(value is NSNull) else { return nil }
                return InventoryField(label: Self.fieldLabel(key), value: Self.displayValue(value))
            }
        }
        func rows(_ key: String, _ category: InventoryCategory,
                  _ map: ([String: Any]) -> InventoryItem) -> [InventoryItem] {
            ((doc[key] as? [[String: Any]]) ?? []).map(map)
        }

        return rows("skills", .skills) { r in
            let v = verdict(r)
            let flags = [(r["eligible"] as? Bool) == true ? "eligible" : "not ready",
                         (r["bundled"] as? Bool) == true ? "bundled" : ""]
            return InventoryItem(
                category: .skills, name: str(r, "id", "name"), version: str(r, "version"),
                path: str(r, "path", "source"),
                detail: (flags.filter { !$0.isEmpty } + [v.detail]).filter { !$0.isEmpty }.joined(separator: " · "),
                connector: connector, verdict: v.verdict, status: str(r, "status"), fields: fields(r)
            )
        }
        + rows("plugins", .plugins) { r in
            let v = verdict(r)
            return InventoryItem(
                category: .plugins, name: str(r, "name", "id"), version: str(r, "version"),
                path: str(r, "path", "origin"),
                detail: [str(r, "status"), v.detail].filter { !$0.isEmpty }.joined(separator: " · "),
                connector: connector, verdict: v.verdict, status: str(r, "status"), fields: fields(r)
            )
        }
        + rows("mcp", .mcps) { r in
            let v = verdict(r)
            return InventoryItem(
                category: .mcps, name: str(r, "id", "name"), version: "",
                path: str(r, "command", "url"),
                detail: [str(r, "source"), v.detail].filter { !$0.isEmpty }.joined(separator: " · "),
                connector: connector, verdict: v.verdict, status: str(r, "status"), fields: fields(r)
            )
        }
        + rows("agents", .agents) { r in
            let v = verdict(r)
            return InventoryItem(
                category: .agents, name: str(r, "id", "name"), version: str(r, "version"),
                path: str(r, "path", "source"),
                detail: [str(r, "description"), v.detail].filter { !$0.isEmpty }.joined(separator: " · "),
                connector: connector, verdict: v.verdict, status: str(r, "status"), fields: fields(r)
            )
        }
        + rows("tools", .tools) { r in
            let v = verdict(r)
            return InventoryItem(
                category: .tools, name: str(r, "name", "id"), version: str(r, "version"),
                path: str(r, "source", "command"), detail: str(r, "description", "signature"),
                connector: connector, verdict: v.verdict, status: str(r, "status"), fields: fields(r)
            )
        }
        + rows("model_providers", .providers) { r in
            InventoryItem(
                category: .providers, name: str(r, "name", "id"), version: "",
                path: str(r, "base_url"),
                detail: [str(r, "source"),
                         (r["api_key_present"] as? Bool) == true ? "key present" : "no key"]
                    .filter { !$0.isEmpty }.joined(separator: " · "),
                connector: connector, status: str(r, "status"), fields: fields(r)
            )
        }
        + rows("memory", .memories) { r in
            InventoryItem(
                category: .memories, name: str(r, "id", "name"), version: "",
                path: str(r, "path", "source"),
                detail: str(r, "description", "detail", "kind"),
                connector: connector, status: str(r, "status"), fields: fields(r)
            )
        }
    }

    private static func summary(from doc: [String: Any]) -> InventoryConnectorSummary {
        func arrayCount(_ key: String) -> Int { (doc[key] as? [Any])?.count ?? 0 }
        let summary = doc["summary"] as? [String: Any]
        let errors: Int = {
            if let value = summary?["errors"] as? Int { return value }
            return (doc["errors"] as? [Any])?.count ?? 0
        }()
        let connector = (doc["connector"] as? String) ?? (doc["claw_mode"] as? String) ?? "default"
        let configFiles = doc["connector_config_files"] as? [String]
        return InventoryConnectorSummary(
            connector: connector,
            version: (doc["version"] as? String) ?? "",
            generatedAt: (doc["generated_at"] as? String) ?? "",
            home: (doc["connector_home"] as? String) ?? (doc["claw_home"] as? String) ?? "",
            config: configFiles?.first ?? (doc["openclaw_config"] as? String) ?? "",
            live: (doc["live"] as? Bool) ?? false,
            errors: errors,
            counts: [
                .skills: arrayCount("skills"), .plugins: arrayCount("plugins"), .mcps: arrayCount("mcp"),
                .agents: arrayCount("agents"), .tools: arrayCount("tools"),
                .providers: arrayCount("model_providers"), .memories: arrayCount("memory"),
            ]
        )
    }

    private static func fieldLabel(_ key: String) -> String {
        key.split(separator: "_").map { $0.capitalized }.joined(separator: " ")
    }

    private static func displayValue(_ value: Any) -> String {
        if let text = value as? String { return text }
        if let number = value as? NSNumber { return number.stringValue }
        if JSONSerialization.isValidJSONObject(value),
           let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
           let text = String(data: data, encoding: .utf8) {
            return text
        }
        return String(describing: value)
    }
}

// MARK: - AI Discovery

struct AIDiscoveryView: View {
    @Environment(AppState.self) private var appState
    @State private var snapshot = AIUsageSnapshot()
    @State private var search = ""
    @State private var selected: AIDiscoveryRow?
    @State private var scanning = false
    @State private var error: String?

    /// Grouped rows (one per product), filtered like the TUI's _apply_filter:
    /// substring match across state/product/vendor/component/version/bands/categories/detectors.
    private var filtered: [AIDiscoveryRow] {
        let rows = snapshot.rows
        guard !search.isEmpty else { return rows }
        let query = search.lowercased()
        return rows.filter { row in
            let haystack = ([row.state, row.product, row.vendor, row.ecosystem, row.component,
                             row.version, row.identityBand, row.presenceBand]
                            + row.categories + row.detectors).joined(separator: " ").lowercased()
            return haystack.contains(query)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header parity with the TUI: "active=56, files=0".
            HStack(spacing: 12) {
                StatCard(title: "Active Signals", value: "\(snapshot.activeSignals > 0 ? snapshot.activeSignals : snapshot.totalDetected)")
                StatCard(title: "Files Scanned", value: "\(snapshot.filesScanned)", tint: .secondary)
                StatCard(title: "Avg Confidence", value: "\(Int(snapshot.averageConfidence * 100))%",
                         tint: snapshot.averageConfidence > 0.8 ? Cisco.green : Cisco.orange)
                StatCard(title: "Last Scan", value: DCDates.relative(snapshot.lastScan), tint: .secondary)
            }
            .padding(12)
            Divider()
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(Cisco.red).padding(6)
            }
            if filtered.isEmpty {
                DCEmptyState(
                    title: "No AI components",
                    message: "Run a scan to detect AI SDKs and frameworks on this machine (POST /api/v1/ai-usage/scan).",
                    systemImage: "sparkle.magnifyingglass"
                )
                .frame(maxHeight: .infinity)
            } else {
                discoveryTable
            }
        }
        .inspector(isPresented: .constant(selected != nil)) {
            if let row = selected {
                rowInspector(row)
                    .inspectorColumnWidth(min: 320, ideal: 400)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Filter products")
        .toolbar {
            ToolbarItemGroup {
                Button {
                    scan()
                } label: {
                    Label("Scan Now", systemImage: "wand.and.rays")
                }
                .disabled(scanning || !appState.gatewayReachable)
                Button {
                    Task { await load() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
        }
        .task { await load() }
        // Pulse-fed retry: a transient gateway failure (restart mid-fetch,
        // token rotation) must not freeze the panel on a stale error.
        .task(id: appState.health.fetchedAt) { if error != nil { await load() } }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in Task { await load() } }
        .onReceive(NotificationCenter.default.publisher(for: .dcScanAIDiscovery)) { _ in
            guard !scanning, appState.gatewayReachable else { return }
            scan()
        }
    }

    private var rowSelection: Binding<String?> {
        Binding<String?>(
            get: { selected?.id },
            set: { (id: String?) in selected = filtered.first { $0.id == id } }
        )
    }

    /// Column set mirrors the TUI: State · Categories · Product · Component ·
    /// Version · Vendor · Detectors · Count · Identity · Presence.
    private var discoveryTable: some View {
        Table(filtered, selection: rowSelection) {
            TableColumn("State") { (r: AIDiscoveryRow) in
                StatePill(raw: r.state)
            }
            .width(80)
            TableColumn("Categories") { (r: AIDiscoveryRow) in
                Text(AIDiscoveryGrouping.csvTruncated(r.categories))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            .width(min: 130, ideal: 190)
            TableColumn("Product") { (r: AIDiscoveryRow) in
                Text(r.product).font(.callout.weight(.medium))
            }
            .width(min: 110, ideal: 150)
            TableColumn("Component") { (r: AIDiscoveryRow) in
                Text(r.component).font(.caption)
            }
            .width(90)
            TableColumn("Version") { (r: AIDiscoveryRow) in
                Text(r.version.isEmpty ? "—" : r.version).font(.caption)
            }
            .width(70)
            TableColumn("Vendor") { (r: AIDiscoveryRow) in
                Text(r.vendor).font(.caption)
            }
            .width(90)
            TableColumn("Detectors") { (r: AIDiscoveryRow) in
                Text(AIDiscoveryGrouping.csvTruncated(r.detectors))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            .width(min: 130, ideal: 190)
            TableColumn("Count") { (r: AIDiscoveryRow) in
                Text("\(r.count)").font(.caption.monospacedDigit())
            }
            .width(46)
            TableColumn("Identity") { (r: AIDiscoveryRow) in
                Text(AIDiscoveryGrouping.formatConfidence(score: r.identityScore, band: r.identityBand))
                    .font(.caption).foregroundStyle(.secondary)
            }
            .width(90)
            TableColumn("Presence") { (r: AIDiscoveryRow) in
                Text(AIDiscoveryGrouping.formatConfidence(score: r.presenceScore, band: r.presenceBand))
                    .font(.caption).foregroundStyle(.secondary)
            }
            .width(90)
        }
    }

    private func rowInspector(_ row: AIDiscoveryRow) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(row.vendor.isEmpty ? row.product : "\(row.vendor) / \(row.product)")
                    .font(.headline)
                Spacer()
                Button { selected = nil } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
            }
            KeyValueGrid(pairs: [
                ("State", row.state),
                ("Signals", "\(row.count)"),
                ("Version", row.version.isEmpty ? "—" : row.version),
                ("Categories", row.categories.joined(separator: ", ")),
                ("Detectors", row.detectors.joined(separator: ", ")),
                ("Identity", AIDiscoveryGrouping.formatConfidence(score: row.identityScore, band: row.identityBand)),
                ("Presence", AIDiscoveryGrouping.formatConfidence(score: row.presenceScore, band: row.presenceBand)),
                ("Last active", DCDates.relative(row.lastActive)),
            ].filter { !$0.1.isEmpty })
            Divider()
            Text("Signals").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(row.signals.enumerated()), id: \.offset) { _, signal in
                        VStack(alignment: .leading, spacing: 1) {
                            HStack {
                                Text(signal.detector.isEmpty ? "detector?" : signal.detector)
                                    .font(.caption.weight(.medium))
                                Spacer()
                                ConfidenceGauge(value: signal.confidence)
                            }
                            Text([signal.category, signal.source,
                                  signal.lastSeen.map { "seen \(DCDates.relative($0))" } ?? ""]
                                .filter { !$0.isEmpty }.joined(separator: " · "))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        .padding(6)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
            Spacer()
        }
        .padding(12)
    }

    private func load() async {
        guard appState.gatewayReachable else { return }
        do {
            snapshot = try await appState.gateway.aiUsage()
            error = nil
        } catch { self.error = error.localizedDescription }
    }

    private func scan() {
        scanning = true
        appState.scanInFlight = true
        Task {
            do {
                try await appState.gateway.aiScan()
                await load()
                error = nil
            } catch { self.error = "Scan failed: \(error.localizedDescription)" }
            scanning = false
            appState.scanInFlight = false
        }
    }
}

// MARK: - Registries

private enum RegistryTab: String, CaseIterable, Identifiable {
    case sources = "Sources"
    case entries = "Entries"
    case approved = "Approved"

    var id: String { rawValue }
}

struct RegistriesView: View {
    @Environment(AppState.self) private var appState
    @State private var snapshot = RegistrySnapshot()
    @State private var tab: RegistryTab = .sources
    @State private var selectedSourceID: String?
    @State private var selectedEntryID: String?
    @State private var search = ""
    @State private var registryRequiredByType: [String: Bool] = [:]
    @State private var registryDataDirectory = ConfigStore.dataDirectory
    @State private var running = false
    @State private var error: String?
    @State private var status: String?
    @State private var sourcePendingRemoval: RegistrySource?
    @State private var entryPendingRejection: RegistryEntry?
    @State private var showingAddSource = false

    private var filteredSources: [RegistrySource] {
        guard !search.isEmpty else { return snapshot.sources }
        let query = search.lowercased()
        return snapshot.sources.filter {
            "\($0.id) \($0.kind) \($0.content) \($0.url) \($0.lastStatus)"
                .lowercased().contains(query)
        }
    }

    private var filteredEntries: [RegistryEntry] {
        let approvedOnly = tab == .approved
        return snapshot.entries.filter { entry in
            if approvedOnly && !entry.approved { return false }
            guard !search.isEmpty else { return true }
            let query = search.lowercased()
            return "\(entry.sourceID) \(entry.name) \(entry.type) \(entry.status) \(entry.severity) \(entry.location)"
                .lowercased().contains(query)
        }
    }

    private var selectedSource: RegistrySource? {
        snapshot.sources.first { $0.id == selectedSourceID }
    }

    private var selectedEntry: RegistryEntry? {
        snapshot.entries.first { $0.id == selectedEntryID }
    }

    private var selectedSourceForSync: String? {
        selectedSource?.id ?? selectedEntry?.sourceID
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("Registry view", selection: $tab) {
                ForEach(RegistryTab.allCases) { tab in
                    Text(tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 420)
            .padding(10)

            if let error {
                messageBanner(error, systemImage: "exclamationmark.triangle", tint: Cisco.red)
            } else if let status {
                messageBanner(status, systemImage: "checkmark.circle", tint: Cisco.green)
            }

            Divider()
            registryContent
        }
        .searchable(text: $search, placement: .toolbar, prompt: tab == .sources ? "Search sources" : "Search entries")
        .inspector(isPresented: inspectorPresented) {
            inspectorContent
                .inspectorColumnWidth(min: 320, ideal: 400)
        }
        .toolbar {
            ToolbarItemGroup {
                if tab == .sources {
                    Button {
                        showingAddSource = true
                    } label: {
                        Label("Add Source", systemImage: "plus")
                    }
                    .help("Add Registry Source")

                    Button(role: .destructive) {
                        sourcePendingRemoval = selectedSource
                    } label: {
                        Label("Remove Source", systemImage: "trash")
                    }
                    .disabled(selectedSource == nil || running)
                    .help("Remove Selected Source")
                } else {
                    Button {
                        if let entry = selectedEntry { approve(entry) }
                    } label: {
                        Label("Approve", systemImage: "checkmark.seal")
                    }
                    .disabled(selectedEntry == nil || running)

                    Button(role: .destructive) {
                        entryPendingRejection = selectedEntry
                    } label: {
                        Label("Reject", systemImage: "xmark.seal")
                    }
                    .disabled(selectedEntry == nil || running)

                    Button {
                        if let entry = selectedEntry { toggleRequirement(for: entry) }
                    } label: {
                        Label(requirementActionLabel, systemImage: "lock.shield")
                    }
                    .disabled(!selectedEntrySupportsRequirement || running)
                    .help(requirementActionLabel)
                }

                Button {
                    syncSelected()
                } label: {
                    Label("Sync Selected", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(running || selectedSourceForSync == nil)

                Button {
                    syncAll()
                } label: {
                    Label("Sync All", systemImage: "arrow.triangle.2.circlepath.circle")
                }
                .disabled(running || snapshot.sources.isEmpty)

                Button {
                    Task { await load() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(running)
            }
        }
        .task { await load() }
        .onChange(of: tab) { _, _ in
            search = ""
            selectedSourceID = nil
            selectedEntryID = nil
        }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in Task { await load() } }
        .sheet(isPresented: $showingAddSource) {
            AddRegistrySourceSheet { draft in
                addSource(draft)
            }
        }
        .confirmationDialog(
            "Remove registry source \(sourcePendingRemoval?.id ?? "")?",
            isPresented: Binding(
                get: { sourcePendingRemoval != nil },
                set: { if !$0 { sourcePendingRemoval = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Remove Source", role: .destructive) {
                if let source = sourcePendingRemoval { remove(source) }
                sourcePendingRemoval = nil
            }
            Button("Cancel", role: .cancel) { sourcePendingRemoval = nil }
        } message: {
            Text("The source, its cache, and policy rules promoted from it will be removed.")
        }
        .confirmationDialog(
            "Reject \(entryPendingRejection?.name ?? "")?",
            isPresented: Binding(
                get: { entryPendingRejection != nil },
                set: { if !$0 { entryPendingRejection = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Reject Entry", role: .destructive) {
                if let entry = entryPendingRejection { reject(entry) }
                entryPendingRejection = nil
            }
            Button("Cancel", role: .cancel) { entryPendingRejection = nil }
        } message: {
            Text("Rejected entries remain blocked during future registry syncs.")
        }
    }

    @ViewBuilder
    private var registryContent: some View {
        switch tab {
        case .sources:
            if filteredSources.isEmpty {
                DCEmptyState(
                    title: "No registry sources",
                    message: search.isEmpty ? "Add a source to begin." : "No sources match the current search.",
                    systemImage: "books.vertical"
                )
                .frame(maxHeight: .infinity)
            } else {
                sourcesTable
            }
        case .entries, .approved:
            if filteredEntries.isEmpty {
                DCEmptyState(
                    title: tab == .approved ? "No approved entries" : "No registry entries",
                    message: search.isEmpty ? "Sync a source to populate this view." : "No entries match the current search.",
                    systemImage: tab == .approved ? "checkmark.seal" : "list.bullet.rectangle"
                )
                .frame(maxHeight: .infinity)
            } else {
                entriesTable
            }
        }
    }

    private var sourcesTable: some View {
        Table(filteredSources, selection: $selectedSourceID) {
            TableColumn("ID", value: \.id)
            TableColumn("Kind", value: \.kind).width(90)
            TableColumn("Content", value: \.content).width(70)
            TableColumn("On") { source in
                Toggle("", isOn: Binding(
                    get: { source.enabled },
                    set: { toggleSource(source, to: $0) }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.mini)
                .disabled(running)
            }
            .width(44)
            TableColumn("Last Sync") { source in
                Text(relativeTimestamp(source.lastSync))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(90)
            TableColumn("Status") { source in
                Text(source.indexError ?? (source.lastStatus.isEmpty ? "—" : source.lastStatus))
                    .font(.caption)
                    .foregroundStyle(source.indexError == nil ? Color.secondary : Cisco.red)
                    .lineLimit(1)
            }
            TableColumn("Entries") { source in Text("\(source.entryCount)").monospacedDigit() }.width(56)
            TableColumn("Clean") { source in Text("\(source.cleanCount)").monospacedDigit() }.width(48)
            TableColumn("Warn") { source in Text("\(source.warningCount)").monospacedDigit() }.width(44)
            TableColumn("Block / Error") { source in
                Text("\(source.blockedCount) / \(source.errorCount)").monospacedDigit()
                    .foregroundStyle(source.blockedCount > 0 || source.errorCount > 0 ? Cisco.red : Color.secondary)
            }
            .width(82)
        }
    }

    private var entriesTable: some View {
        Table(filteredEntries, selection: $selectedEntryID) {
            TableColumn("Source", value: \.sourceID).width(110)
            TableColumn("Name", value: \.name)
            TableColumn("Type", value: \.type).width(70)
            TableColumn("Status") { entry in StatePill(raw: entry.status.isEmpty ? "unknown" : entry.status) }
                .width(90)
            TableColumn("Severity") { entry in
                Text(entry.severity.isEmpty ? "—" : entry.severity.uppercased())
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(severityColor(entry.severity))
            }
            .width(80)
            TableColumn("Review") { entry in
                Text(entry.approvalMarker)
                    .font(.caption)
                    .foregroundStyle(entry.approved ? Cisco.green : entry.rejected ? Cisco.red : Color.secondary)
            }
            .width(82)
            TableColumn("Location") { entry in
                Text(entry.location).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }

    private var inspectorPresented: Binding<Bool> {
        Binding(
            get: { selectedSource != nil || selectedEntry != nil },
            set: { presented in
                if !presented {
                    selectedSourceID = nil
                    selectedEntryID = nil
                }
            }
        )
    }

    @ViewBuilder
    private var inspectorContent: some View {
        if let source = selectedSource {
            VStack(alignment: .leading, spacing: 12) {
                inspectorHeader(source.id)
                KeyValueGrid(pairs: [
                    ("Kind", source.kind),
                    ("Content", source.content),
                    ("Enabled", source.enabled ? "yes" : "no"),
                    ("URL", source.url.isEmpty ? "—" : source.url),
                    ("Last Sync", source.lastSync.isEmpty ? "never" : source.lastSync),
                    ("Status", source.indexError ?? (source.lastStatus.isEmpty ? "—" : source.lastStatus)),
                    ("Fetched", source.fetchedAt.isEmpty ? "—" : source.fetchedAt),
                    ("Publisher", source.publisher.isEmpty ? "—" : source.publisher),
                    ("Entries", "\(source.entryCount)"),
                    ("Verdicts", "\(source.cleanCount) clean, \(source.warningCount) warning, \(source.blockedCount) blocked, \(source.errorCount) error"),
                    ("Cache", cachePath(for: source)),
                ])
                Spacer()
            }
            .padding(12)
        } else if let entry = selectedEntry {
            VStack(alignment: .leading, spacing: 12) {
                inspectorHeader(entry.name)
                KeyValueGrid(pairs: [
                    ("Source", entry.sourceID),
                    ("Type", entry.type),
                    ("Status", entry.status.isEmpty ? "—" : entry.status),
                    ("Severity", entry.severity.isEmpty ? "—" : entry.severity.uppercased()),
                    ("Findings", "\(entry.findings)"),
                    ("Approved", entry.approved ? "yes" : "no"),
                    ("Rejected", entry.rejected ? "yes" : "no"),
                    ("Transport", entry.transport.isEmpty ? "—" : entry.transport),
                    ("Command", entry.command.isEmpty ? "—" : entry.command),
                    ("Arguments", entry.arguments.isEmpty ? "—" : entry.arguments.joined(separator: " ")),
                    ("Location", entry.location.isEmpty ? "—" : entry.location),
                ])
                Spacer()
            }
            .padding(12)
        }
    }

    private func inspectorHeader(_ title: String) -> some View {
        HStack {
            Text(title).font(.headline).lineLimit(1)
            Spacer()
            Button {
                selectedSourceID = nil
                selectedEntryID = nil
            } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.borderless)
            .help("Close Inspector")
        }
    }

    private func messageBanner(_ text: String, systemImage: String, tint: Color) -> some View {
        HStack(spacing: 6) {
            Image(systemName: systemImage)
            Text(text).lineLimit(2)
            Spacer()
            Button {
                error = nil
                status = nil
            } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
            .help("Dismiss")
        }
        .font(.caption)
        .foregroundStyle(tint)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    private func load() async {
        let config = await appState.configStore.reload()
        registryDataDirectory = RegistryStore.dataDirectory(for: config)
        snapshot = RegistryStore.load(config: config)
        registryRequiredByType = config.registryRequiredByType
        if let selected = selectedSourceID, !snapshot.sources.contains(where: { $0.id == selected }) {
            selectedSourceID = nil
        }
        if let selected = selectedEntryID, !snapshot.entries.contains(where: { $0.id == selected }) {
            selectedEntryID = nil
        }
    }

    private func syncSelected() {
        guard let sourceID = selectedSourceForSync else { return }
        run(RegistryCLIArguments.sync(sourceID: sourceID), success: "Synced \(sourceID).")
    }

    private func syncAll() {
        run(RegistryCLIArguments.syncAll, success: "Synced all enabled sources.")
    }

    private func approve(_ entry: RegistryEntry) {
        run(RegistryCLIArguments.approve(entry), success: "Approved \(entry.name).")
    }

    private func toggleSource(_ source: RegistrySource, to enabled: Bool) {
        run(
            RegistryCLIArguments.setSourceEnabled(sourceID: source.id, enabled: enabled),
            success: "\(enabled ? "Enabled" : "Disabled") \(source.id)."
        )
    }

    private func reject(_ entry: RegistryEntry) {
        run(RegistryCLIArguments.reject(entry), success: "Rejected \(entry.name).")
    }

    private func toggleRequirement(for entry: RegistryEntry) {
        guard ["skill", "mcp"].contains(entry.type) else { return }
        let required = registryRequiredByType[entry.type] ?? false
        run(
            RegistryCLIArguments.setRequired(type: entry.type, required: !required),
            success: "Registry is now \(required ? "optional" : "required") for \(entry.type) entries."
        )
    }

    private func remove(_ source: RegistrySource) {
        run(RegistryCLIArguments.remove(sourceID: source.id), success: "Removed \(source.id).")
    }

    private func addSource(_ draft: RegistrySourceDraft) {
        let arguments = RegistryCLIArguments.add(
            sourceID: draft.normalizedID,
            kind: draft.kind,
            content: draft.content,
            url: draft.url.trimmingCharacters(in: .whitespacesAndNewlines),
            authEnv: draft.authEnv.trimmingCharacters(in: .whitespacesAndNewlines),
            enabled: draft.enabled
        )
        run(arguments, success: "Added \(draft.normalizedID).")
    }

    private func run(_ arguments: [String], success successMessage: String) {
        guard !running else { return }
        running = true
        error = nil
        status = nil
        Task {
            let result = await appState.runCommand(
                title: arguments.prefix(3).joined(separator: " "),
                arguments: arguments,
                category: "registry",
                origin: "Registries",
                refreshOnSuccess: true
            )
            if result.succeeded {
                status = successMessage
                appState.reloadConfig()
            } else {
                let detail = String(result.output.suffix(400)).trimmingCharacters(in: .whitespacesAndNewlines)
                error = detail.isEmpty
                    ? "Registry command failed with exit \(result.exitCode)."
                    : "Registry command failed: \(detail)"
            }
            await load()
            running = false
        }
    }

    private var selectedEntrySupportsRequirement: Bool {
        guard let entry = selectedEntry else { return false }
        return ["skill", "mcp"].contains(entry.type)
    }

    private var requirementActionLabel: String {
        guard let entry = selectedEntry, selectedEntrySupportsRequirement else { return "Require Registry" }
        return registryRequiredByType[entry.type] == true ? "Make Registry Optional" : "Require Registry"
    }

    private func relativeTimestamp(_ raw: String) -> String {
        guard let date = DCDates.parse(raw) else { return raw.isEmpty ? "never" : raw }
        return DCDates.relative(date)
    }

    private func cachePath(for source: RegistrySource) -> String {
        (try? RegistryStore.indexURL(dataDirectory: registryDataDirectory, sourceID: source.id).path) ?? "unsafe source ID"
    }

    private func severityColor(_ raw: String) -> Color {
        guard let severity = Severity(rawValue: raw.uppercased()) else { return .secondary }
        return Cisco.severityColor(severity)
    }
}

private struct RegistrySourceDraft {
    static let kinds = ["clawhub", "smithery", "skills_sh", "http_yaml", "http_json", "git", "file"]
    static let contentTypes = ["skill", "mcp", "both"]

    var id = ""
    var kind = "http_yaml"
    var content = "skill"
    var url = ""
    var authEnv = ""
    var enabled = true

    var normalizedID: String { id.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
    var requiresURL: Bool { ["http_yaml", "http_json", "git", "file"].contains(kind) }
    var validID: Bool {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-_")
        return (2...64).contains(normalizedID.count)
            && RegistryStore.isSafeSourceID(normalizedID)
            && normalizedID.unicodeScalars.allSatisfy(allowed.contains)
    }
    var isValid: Bool {
        validID && (!requiresURL || !url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    }
}

private struct AddRegistrySourceSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var draft = RegistrySourceDraft()
    let onAdd: (RegistrySourceDraft) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add Registry Source").font(.headline)
            Form {
                TextField("Source ID", text: $draft.id, prompt: Text("corp-skills"))
                Picker("Kind", selection: $draft.kind) {
                    ForEach(RegistrySourceDraft.kinds, id: \.self) { Text($0).tag($0) }
                }
                Picker("Content", selection: $draft.content) {
                    ForEach(RegistrySourceDraft.contentTypes, id: \.self) { Text($0).tag($0) }
                }
                TextField("URL or path", text: $draft.url)
                TextField("Authentication environment variable", text: $draft.authEnv)
                Toggle("Enabled", isOn: $draft.enabled)
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Add") {
                    onAdd(draft)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!draft.isValid)
            }
        }
        .padding(18)
        .frame(width: 500)
    }
}
