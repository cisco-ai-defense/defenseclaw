import SwiftUI
import DefenseClawKit

/// Read-only inventory of discovered Skills, MCP servers, and plugins with
/// status, last-scan, search, and a tile/table layout. Actions (block/allow/
/// scan) are tracked separately (REM-105).
struct InventoryView: View {
    @State private var category: InventoryCategory = .skill
    @State private var skills: [Skill] = []
    @State private var mcpServers: [MCPServer] = []
    @State private var plugins: [Plugin] = []
    @State private var isLoading = false
    @State private var loadError: String?
    @State private var filter = ""
    @State private var layout: ListLayoutMode = .table
    @State private var selectedID: String?

    private let sidecar = SidecarClient()
    private let commandRunner = LocalCommandRunner()

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
        }
        .frame(minWidth: 760, minHeight: 480)
        .task { await load() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Inventory")
                        .font(.title2.weight(.semibold))
                    Text("Skills, MCP servers, and plugins discovered by DefenseClaw.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task { await load() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(isLoading)
            }

            HStack(spacing: 10) {
                Picker("Category", selection: $category) {
                    ForEach(InventoryCategory.allCases) { cat in
                        Text("\(cat.label) (\(count(cat)))").tag(cat)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 380)

                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Filter \(category.label.lowercased())", text: $filter)
                        .textFieldStyle(.plain)
                    if !filter.isEmpty {
                        Button {
                            filter = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))

                ListLayoutToggle(mode: $layout)
            }
        }
        .padding(18)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    @ViewBuilder
    private var content: some View {
        if isLoading && items.isEmpty {
            ProgressView("Loading inventory…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let loadError, items.isEmpty {
            ContentUnavailableView(
                "Inventory unavailable",
                systemImage: "exclamationmark.triangle",
                description: Text(loadError)
            )
        } else {
            HSplitView {
                listColumn
                    .frame(minWidth: 420)
                detailColumn
                    .frame(minWidth: 300, idealWidth: 340)
            }
        }
    }

    private var listColumn: some View {
        ScrollView {
            if filtered.isEmpty {
                ContentUnavailableView(
                    filter.isEmpty ? "No \(category.label.lowercased()) discovered" : "No matches",
                    systemImage: category.systemImage,
                    description: Text(filter.isEmpty
                        ? "Nothing reported by the gateway yet."
                        : "No \(category.label.lowercased()) match “\(filter)”.")
                )
                .frame(maxWidth: .infinity, minHeight: 220)
            } else {
                switch layout {
                case .tile:
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 240), spacing: 12)], spacing: 12) {
                        ForEach(filtered) { item in
                            InventoryCard(item: item, isSelected: selectedID == item.id)
                                .contentShape(Rectangle())
                                .onTapGesture { selectedID = item.id }
                        }
                    }
                    .padding(14)
                case .table:
                    LazyVStack(spacing: 0) {
                        ForEach(filtered) { item in
                            InventoryRow(item: item, isSelected: selectedID == item.id)
                                .contentShape(Rectangle())
                                .onTapGesture { selectedID = item.id }
                            Divider()
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }

    private var detailColumn: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let item = selectedItem {
                InventoryDetail(item: item)
            } else {
                ContentUnavailableView(
                    "Select an item",
                    systemImage: "square.stack.3d.up",
                    description: Text("Status, path, and last-scan details appear here.")
                )
            }
            Spacer()
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Data

    private var items: [InventoryItem] {
        switch category {
        case .skill:
            return skills.map { skill in
                InventoryItem(
                    id: "skill:\(skill.id)",
                    title: skill.name,
                    subtitle: skill.path ?? "No path reported",
                    path: skill.path ?? skill.name,
                    badge: catalogBadge(blocked: skill.blocked, quarantined: skill.quarantined, enabled: skill.enabled),
                    isBlocked: skill.blocked || skill.quarantined,
                    statusReason: catalogReason(blocked: skill.blocked, quarantined: skill.quarantined, enabled: skill.enabled),
                    lastScan: skill.lastScan
                )
            }
        case .mcp:
            return mcpServers.map { server in
                InventoryItem(
                    id: "mcp:\(server.id)",
                    title: server.name,
                    subtitle: server.command ?? server.url,
                    path: server.url.isEmpty ? server.name : server.url,
                    badge: server.blocked ? "Blocked" : (server.isRunning ? "Running" : "Configured"),
                    isBlocked: server.blocked,
                    statusReason: server.blocked ? "Blocked by policy or allowlist." : nil,
                    lastScan: server.lastScan
                )
            }
        case .plugin:
            return plugins.map { plugin in
                InventoryItem(
                    id: "plugin:\(plugin.id)",
                    title: plugin.name,
                    subtitle: plugin.pluginDescription ?? plugin.path ?? plugin.source ?? "Plugin",
                    path: plugin.path ?? plugin.id,
                    badge: catalogBadge(blocked: plugin.blocked, quarantined: plugin.quarantined, enabled: plugin.enabled),
                    isBlocked: plugin.blocked || plugin.quarantined,
                    statusReason: catalogReason(blocked: plugin.blocked, quarantined: plugin.quarantined, enabled: plugin.enabled),
                    lastScan: plugin.lastScan
                )
            }
        }
    }

    private var filtered: [InventoryItem] {
        let query = filter.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return items }
        return items.filter { item in
            item.title.lowercased().contains(query)
                || item.subtitle.lowercased().contains(query)
                || item.badge.lowercased().contains(query)
        }
    }

    private var selectedItem: InventoryItem? {
        items.first { $0.id == selectedID }
    }

    private func count(_ category: InventoryCategory) -> Int {
        switch category {
        case .skill: return skills.count
        case .mcp: return mcpServers.count
        case .plugin: return plugins.count
        }
    }

    private func load() async {
        isLoading = true
        var messages: [String] = []
        do { skills = try await sidecar.skills() } catch let err { messages.append("Skills: \(err.localizedDescription)") }
        do { mcpServers = try await sidecar.mcpServers() } catch let err { messages.append("MCP servers: \(err.localizedDescription)") }
        do { plugins = try await loadPlugins() } catch let err { messages.append("Plugins: \(err.localizedDescription)") }
        loadError = messages.isEmpty ? nil : messages.joined(separator: "\n")
        isLoading = false
    }

    private func loadPlugins() async throws -> [Plugin] {
        let result = try await commandRunner.run("defenseclaw", arguments: ["plugin", "list", "--json"])
        guard result.exitCode == 0 else { return [] }
        let output = result.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard output.first == "[" || output.first == "{" else { return [] }
        let decoder = JSONDecoder()
        if let decoded = try? decoder.decode([Plugin].self, from: Data(output.utf8)) {
            return decoded
        }
        return (try? decoder.decode(InventoryPluginResponse.self, from: Data(output.utf8)))?.items ?? []
    }
}

private enum InventoryCategory: String, CaseIterable, Identifiable {
    case skill
    case mcp
    case plugin

    var id: String { rawValue }

    var label: String {
        switch self {
        case .skill: return "Skills"
        case .mcp: return "MCP Servers"
        case .plugin: return "Plugins"
        }
    }

    var systemImage: String {
        switch self {
        case .skill: return "wand.and.stars"
        case .mcp: return "server.rack"
        case .plugin: return "shippingbox"
        }
    }
}

private struct InventoryItem: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let path: String
    let badge: String
    let isBlocked: Bool
    let statusReason: String?
    let lastScan: ScanSummary?
}

private struct InventoryPluginResponse: Decodable {
    let items: [Plugin]

    private enum CodingKeys: String, CodingKey {
        case plugins, items, data
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        items = try container.decodeIfPresent([Plugin].self, forKey: .plugins)
            ?? container.decodeIfPresent([Plugin].self, forKey: .items)
            ?? container.decodeIfPresent([Plugin].self, forKey: .data)
            ?? []
    }
}

private struct InventoryRow: View {
    let item: InventoryItem
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                Text(item.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            CatalogStatusPill(badge: item.badge)
            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Color.accentColor)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(isSelected ? Color.accentColor.opacity(0.12) : Color.clear)
    }
}

private struct InventoryCard: View {
    let item: InventoryItem
    let isSelected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(item.title)
                .font(.callout.weight(.semibold))
                .lineLimit(1)
            Text(item.subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
            HStack {
                CatalogStatusPill(badge: item.badge)
                Spacer()
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(Color.accentColor)
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 92, alignment: .topLeading)
        .background(isSelected ? Color.accentColor.opacity(0.14) : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isSelected ? Color.accentColor.opacity(0.7) : Color(nsColor: .separatorColor).opacity(0.35), lineWidth: 0.8)
        )
    }
}

private struct InventoryDetail: View {
    let item: InventoryItem

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(item.title)
                    .font(.headline)
                    .lineLimit(1)
                Spacer()
                CatalogStatusPill(badge: item.badge)
            }
            row("Path", item.path)
            if !item.subtitle.isEmpty, item.subtitle != item.path {
                row("Detail", item.subtitle)
            }
            if let reason = item.statusReason {
                row("Status", reason, emphasize: item.isBlocked)
            }
            row("Last scan", item.lastScan.map(scanText) ?? "Not scanned yet")
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private func row(_ label: String, _ value: String, emphasize: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(emphasize ? .red : .primary)
                .textSelection(.enabled)
        }
    }

    private func scanText(_ scan: ScanSummary) -> String {
        var parts = ["\(scan.severity.rawValue) · \(scan.findingCount) finding(s)"]
        if let scannedAt = scan.scannedAt {
            parts.append(scannedAt.formatted(date: .abbreviated, time: .shortened))
        }
        return parts.joined(separator: " · ")
    }
}
