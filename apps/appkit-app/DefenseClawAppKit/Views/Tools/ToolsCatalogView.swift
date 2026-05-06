import SwiftUI
import DefenseClawKit

struct ToolsCatalogView: View {
    @State private var tools: [ToolEntry] = []
    @State private var isLoading = false
    @State private var error: String?
    @State private var selectedTool: ToolEntry?
    @State private var inspectResult: [String: AnyCodable]?
    @State private var searchText = ""

    private let sidecarClient = SidecarClient()

    private var filteredTools: [ToolEntry] {
        if searchText.isEmpty { return tools }
        let q = searchText.lowercased()
        return tools.filter {
            $0.name.lowercased().contains(q) ||
            ($0.description?.lowercased().contains(q) ?? false) ||
            ($0.source?.lowercased().contains(q) ?? false) ||
            ($0.group?.lowercased().contains(q) ?? false)
        }
    }

    private var groupedTools: [(String, [ToolEntry])] {
        let grouped = Dictionary(grouping: filteredTools) { $0.group ?? $0.source ?? "Other" }
        return grouped.sorted { $0.key < $1.key }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 12) {
                Image(systemName: "wrench.and.screwdriver")
                    .foregroundStyle(.teal)
                Text("Tools Catalog")
                    .font(.headline)

                if !tools.isEmpty {
                    Text("\(tools.count)")
                        .font(.caption2)
                        .fontWeight(.medium)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.teal.opacity(0.15))
                        .foregroundStyle(.teal)
                        .clipShape(Capsule())
                }

                Spacer()

                // Search
                HStack(spacing: 4) {
                    Image(systemName: "magnifyingglass")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("Filter tools...", text: $searchText)
                        .textFieldStyle(.plain)
                        .font(.caption)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color(nsColor: .controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .frame(maxWidth: 200)

                Button {
                    Task { await loadTools() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
                .help("Refresh tools catalog")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            if let error {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                    Text(error)
                        .font(.caption)
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.red.opacity(0.06))
            }

            if isLoading {
                Spacer()
                ProgressView("Loading tools...")
                Spacer()
            } else if tools.isEmpty {
                Spacer()
                VStack(spacing: 12) {
                    Image(systemName: "wrench.and.screwdriver")
                        .font(.system(size: 36))
                        .foregroundStyle(.tertiary)
                    Text("No tools available")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Text("Tools will appear here when the sidecar is connected to a gateway.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                }
                .padding()
                Spacer()
            } else {
                List {
                    ForEach(groupedTools, id: \.0) { group, groupTools in
                        Section {
                            ForEach(groupTools) { tool in
                                ToolRow(
                                    tool: tool,
                                    isSelected: selectedTool?.id == tool.id,
                                    inspectResult: selectedTool?.id == tool.id ? inspectResult : nil,
                                    onInspect: { Task { await inspectTool(tool) } }
                                )
                            }
                        } header: {
                            HStack(spacing: 6) {
                                Text(group)
                                    .font(.caption)
                                    .fontWeight(.semibold)
                                    .foregroundStyle(.secondary)
                                Text("\(groupTools.count)")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                }
            }
        }
        .frame(minWidth: 600, minHeight: 400)
        .onAppear {
            Task { await loadTools() }
        }
    }

    private func loadTools() async {
        isLoading = true
        error = nil
        do {
            tools = try await sidecarClient.toolsCatalog()
            await MainActor.run { isLoading = false }
        } catch {
            await MainActor.run {
                self.error = error.localizedDescription
                isLoading = false
            }
        }
    }

    private func inspectTool(_ tool: ToolEntry) async {
        selectedTool = tool
        inspectResult = nil
        do {
            let result = try await sidecarClient.inspectTool(name: tool.name)
            await MainActor.run { inspectResult = result }
        } catch {
            await MainActor.run {
                self.error = "Inspect failed: \(error.localizedDescription)"
            }
        }
    }
}

// MARK: - Tool Row

private struct ToolRow: View {
    let tool: ToolEntry
    let isSelected: Bool
    let inspectResult: [String: AnyCodable]?
    let onInspect: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: toolIcon)
                    .font(.caption)
                    .foregroundStyle(sourceColor)
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 2) {
                    Text(tool.name)
                        .font(.system(.body, design: .monospaced, weight: .medium))
                    if let source = tool.source {
                        Text(source)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }

                Spacer()

                if tool.blocked == true {
                    Text("Blocked")
                        .font(.caption2)
                        .fontWeight(.medium)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.red.opacity(0.12))
                        .foregroundStyle(.red)
                        .clipShape(Capsule())
                }

                Button("Inspect", action: onInspect)
                    .controlSize(.small)
                    .buttonStyle(.bordered)
            }

            if let desc = tool.description, !desc.isEmpty {
                Text(desc)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            if isSelected, let result = inspectResult {
                ScrollView {
                    Text(formatResult(result))
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 200)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color(nsColor: .separatorColor).opacity(0.5), lineWidth: 0.5)
                )
            }
        }
        .padding(.vertical, 4)
    }

    private var toolIcon: String {
        switch tool.source?.lowercased() {
        case "builtin": return "hammer.fill"
        case "skill": return "wand.and.stars"
        case "mcp": return "server.rack"
        default: return "wrench"
        }
    }

    private var sourceColor: Color {
        switch tool.source?.lowercased() {
        case "builtin": return .blue
        case "skill": return .purple
        case "mcp": return .teal
        default: return .gray
        }
    }

    private func formatResult(_ result: [String: AnyCodable]) -> String {
        var output = ""
        for (key, value) in result.sorted(by: { $0.key < $1.key }) {
            output += "\(key): \(value)\n"
        }
        return output.isEmpty ? "No data" : output
    }
}
