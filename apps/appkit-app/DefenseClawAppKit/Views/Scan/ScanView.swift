import Foundation
import SwiftUI
import DefenseClawKit

struct ScanView: View {
    @State private var scanType = ScanTarget.skill
    @State private var targetPath = ""
    @State private var selectedTargetID: String?
    @State private var isScanning = false
    @State private var isLoadingTargets = false
    @State private var results: [Finding] = []
    @State private var error: String?
    @State private var targetLoadMessage: String?
    @State private var hasRunScan = false
    @State private var lastRunTarget = ""
    @State private var skills: [Skill] = []
    @State private var mcpServers: [MCPServer] = []
    @State private var plugins: [Plugin] = []
    @State private var codeTargets = ScanTargetItem.defaultCodeTargets()

    private let commandRunner = LocalCommandRunner()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                scanForm
                resultsCard
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            await loadTargets()
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Security Scans")
                    .font(.system(.largeTitle, weight: .semibold))
                Text("Choose a discovered skill, MCP server, plugin, or code path and run the matching DefenseClaw scanner.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button {
                Task { await loadTargets() }
            } label: {
                Label("Refresh Targets", systemImage: "arrow.clockwise")
            }
            .disabled(isLoadingTargets)
        }
    }

    private var scanForm: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Picker("Scan Type", selection: $scanType) {
                    ForEach(ScanTarget.allCases) { target in
                        Label(target.label, systemImage: target.systemImage)
                            .tag(target)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 480)
                .onChange(of: scanType) { _, _ in
                    selectedTargetID = nil
                }

                Spacer()

                Button {
                    runScan()
                } label: {
                    if isScanning {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Label("Run Scan", systemImage: "play.fill")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(targetPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isScanning)
            }

            targetCatalog

            VStack(alignment: .leading, spacing: 6) {
                Text("Target")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                TextField(scanType.placeholder, text: $targetPath)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            }

            if let error {
                ScanErrorBanner(message: error)
            } else if let targetLoadMessage {
                ScanNoticeBanner(message: targetLoadMessage)
            } else if targetPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                Text("Select a target above or enter a path manually.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(18)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(nsColor: .separatorColor).opacity(0.45), lineWidth: 0.5)
        )
    }

    private var targetCatalog: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Available \(scanType.pluralLabel)", systemImage: scanType.systemImage)
                    .font(.headline)
                Spacer()
                if isLoadingTargets {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Text("\(targetItems.count)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }

            if targetItems.isEmpty {
                ContentUnavailableView(
                    "No \(scanType.pluralLabel.lowercased()) discovered",
                    systemImage: scanType.systemImage,
                    description: Text(scanType.emptyDescription)
                )
                .frame(maxWidth: .infinity, minHeight: 110)
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 230), spacing: 12)], spacing: 12) {
                    ForEach(targetItems) { item in
                        ScanTargetCard(
                            item: item,
                            isSelected: selectedTargetID == item.id
                        )
                        .contentShape(Rectangle())
                        .onTapGesture {
                            select(item)
                        }
                    }
                }
            }
        }
        .padding(14)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor).opacity(0.35), lineWidth: 0.5)
        )
    }

    private var targetItems: [ScanTargetItem] {
        switch scanType {
        case .skill:
            return skills.map { skill in
                ScanTargetItem(
                    id: "skill:\(skill.id)",
                    kind: .skill,
                    title: skill.name,
                    subtitle: skill.path ?? "No path reported",
                    target: skill.path ?? skill.name,
                    badge: skill.enabled ? "Enabled" : "Disabled",
                    isBlocked: skill.blocked || skill.quarantined
                )
            }
        case .mcp:
            return mcpServers.map { server in
                ScanTargetItem(
                    id: "mcp:\(server.id)",
                    kind: .mcp,
                    title: server.name,
                    subtitle: server.command ?? server.url,
                    target: server.url.isEmpty ? server.name : server.url,
                    badge: server.isRunning ? "Running" : "Configured",
                    isBlocked: server.blocked
                )
            }
        case .plugin:
            return plugins.map { plugin in
                ScanTargetItem(
                    id: "plugin:\(plugin.id)",
                    kind: .plugin,
                    title: plugin.name,
                    subtitle: plugin.pluginDescription ?? plugin.path ?? plugin.source ?? "Plugin",
                    target: plugin.path ?? plugin.id,
                    badge: plugin.enabled ? "Enabled" : "Disabled",
                    isBlocked: plugin.blocked || plugin.quarantined
                )
            }
        case .code:
            return codeTargets
        }
    }

    private var resultsCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Findings", systemImage: "list.bullet.rectangle")
                    .font(.headline)
                if !results.isEmpty {
                    Text("\(results.count)")
                        .font(.caption2)
                        .fontWeight(.medium)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.blue.opacity(0.14))
                        .foregroundStyle(.blue)
                        .clipShape(Capsule())
                }
                Spacer()
            }

            if isScanning {
                HStack(spacing: 10) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Scanning \(targetPath)...")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 140)
            } else if results.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: hasRunScan ? "checkmark.shield" : "magnifyingglass")
                        .font(.system(size: 34))
                        .foregroundStyle(hasRunScan ? .green : .secondary)
                    Text(hasRunScan ? "No findings found" : "No scan has run yet")
                        .font(.headline)
                    Text(hasRunScan
                         ? "\(lastRunTarget) completed without reported findings."
                         : "Choose a target and run a scan to populate this table.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, minHeight: 180)
            } else {
                VStack(spacing: 0) {
                    ScanResultsHeader()
                    Divider()
                    ForEach(results) { finding in
                        ScanFindingRow(finding: finding)
                        Divider()
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color(nsColor: .separatorColor).opacity(0.45), lineWidth: 0.5)
                )
            }
        }
        .padding(18)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(nsColor: .separatorColor).opacity(0.45), lineWidth: 0.5)
        )
    }

    private func select(_ item: ScanTargetItem) {
        scanType = item.kind
        selectedTargetID = item.id
        targetPath = item.target
        error = nil
    }

    private func loadTargets() async {
        isLoadingTargets = true
        targetLoadMessage = nil
        var messages: [String] = []
        let client = SidecarClient()

        do {
            skills = try await client.skills()
        } catch {
            skills = []
            messages.append("Skills: \(error.localizedDescription)")
        }

        do {
            mcpServers = try await client.mcpServers()
        } catch {
            mcpServers = []
            messages.append("MCP servers: \(error.localizedDescription)")
        }

        do {
            plugins = try await loadPlugins()
        } catch {
            plugins = []
            messages.append("Plugins: \(error.localizedDescription)")
        }

        codeTargets = ScanTargetItem.defaultCodeTargets()
        targetLoadMessage = messages.isEmpty ? nil : "Some targets could not be loaded.\n" + messages.joined(separator: "\n")
        isLoadingTargets = false
    }

    private func loadPlugins() async throws -> [Plugin] {
        let result = try await commandRunner.run("defenseclaw", arguments: ["plugin", "list", "--json"])
        guard result.exitCode == 0 else {
            throw ScanCommandError.failed(result.combinedOutput)
        }

        let output = result.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard output.first == "[" || output.first == "{" else {
            return []
        }

        let decoder = JSONDecoder()
        if let items = try? decoder.decode([Plugin].self, from: Data(output.utf8)) {
            return items
        }
        return try decoder.decode(PluginListResponse.self, from: Data(output.utf8)).items
    }

    private func runScan() {
        let target = targetPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else {
            error = "Choose a \(scanType.label.lowercased()) target before running a scan."
            return
        }

        isScanning = true
        error = nil
        results = []
        lastRunTarget = target

        Task {
            let client = SidecarClient()
            do {
                let scanResult: ScanResult
                switch scanType {
                case .skill:
                    scanResult = try await client.scanSkill(path: target)
                case .mcp:
                    scanResult = try await client.scanMCP(url: target)
                case .plugin:
                    scanResult = try await runPluginScan(target: target)
                case .code:
                    scanResult = try await client.scanCode(path: target)
                }
                await MainActor.run {
                    results = scanResult.findings
                    hasRunScan = true
                    isScanning = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    hasRunScan = true
                    isScanning = false
                }
            }
        }
    }

    private func runPluginScan(target: String) async throws -> ScanResult {
        let result = try await commandRunner.run("defenseclaw", arguments: ["plugin", "scan", target, "--json"])
        guard result.exitCode == 0 else {
            throw ScanCommandError.failed(result.combinedOutput)
        }

        let output = result.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = output.data(using: .utf8), !data.isEmpty else {
            throw ScanCommandError.failed("Plugin scan returned no JSON output.")
        }

        let decoder = JSONDecoder()
        if let envelope = try? decoder.decode(LocalScanResultEnvelope.self, from: data) {
            return envelope.result
        }
        return try decoder.decode(ScanResult.self, from: data)
    }
}

private struct PluginListResponse: Decodable {
    let items: [Plugin]

    private enum CodingKeys: String, CodingKey {
        case plugins
        case items
        case data
    }

    init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        if let decoded = try? single.decode([Plugin].self) {
            items = decoded
            return
        }

        let container = try decoder.container(keyedBy: CodingKeys.self)
        items = try container.decodeIfPresent([Plugin].self, forKey: .plugins)
            ?? container.decodeIfPresent([Plugin].self, forKey: .items)
            ?? container.decodeIfPresent([Plugin].self, forKey: .data)
            ?? []
    }
}

private struct LocalScanResultEnvelope: Decodable {
    let result: ScanResult

    private enum CodingKeys: String, CodingKey {
        case result
        case data
    }

    init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        if let decoded = try? single.decode(ScanResult.self) {
            result = decoded
            return
        }

        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let decoded = try container.decodeIfPresent(ScanResult.self, forKey: .result)
            ?? container.decodeIfPresent(ScanResult.self, forKey: .data) {
            result = decoded
            return
        }

        throw DecodingError.keyNotFound(
            CodingKeys.result,
            DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Expected scan result or result envelope")
        )
    }
}

private enum ScanCommandError: LocalizedError {
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .failed(let output):
            return output.isEmpty ? "Command failed without output." : output
        }
    }
}

private struct ScanTargetItem: Identifiable {
    let id: String
    let kind: ScanTarget
    let title: String
    let subtitle: String
    let target: String
    let badge: String
    let isBlocked: Bool

    static func defaultCodeTargets() -> [ScanTargetItem] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidates: [(String, URL, String)] = [
            ("DefenseClaw runtime", home.appendingPathComponent(".defenseclaw", isDirectory: true), "Config, policies, and runtime files"),
            ("OpenClaw home", home.appendingPathComponent(".openclaw", isDirectory: true), "Agent config, skills, MCPs, and plugins")
        ]

        return candidates
            .filter { FileManager.default.fileExists(atPath: $0.1.path) }
            .map { name, url, subtitle in
                ScanTargetItem(
                    id: "code:\(url.path)",
                    kind: .code,
                    title: name,
                    subtitle: subtitle,
                    target: url.path,
                    badge: "Folder",
                    isBlocked: false
                )
            }
    }
}

private struct ScanTargetCard: View {
    let item: ScanTargetItem
    let isSelected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: item.kind.systemImage)
                    .foregroundStyle(item.isBlocked ? .red : .accentColor)
                    .frame(width: 18)

                VStack(alignment: .leading, spacing: 3) {
                    Text(item.title)
                        .font(.callout.weight(.semibold))
                        .lineLimit(1)
                    Text(item.subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                Spacer(minLength: 4)
            }

            HStack(spacing: 8) {
                Text(item.badge)
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(item.isBlocked ? .red : .secondary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background((item.isBlocked ? Color.red : Color.secondary).opacity(0.12), in: Capsule())
                Spacer()
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(Color.accentColor)
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 104, alignment: .topLeading)
        .background(isSelected ? Color.accentColor.opacity(0.14) : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isSelected ? Color.accentColor.opacity(0.7) : Color(nsColor: .separatorColor).opacity(0.35), lineWidth: 0.8)
        )
    }
}

private struct ScanErrorBanner: View {
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            VStack(alignment: .leading, spacing: 3) {
                Text("Scan failed")
                    .font(.caption.weight(.semibold))
                Text(message)
                    .font(.caption)
                    .textSelection(.enabled)
            }
            .foregroundStyle(.red)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct ScanNoticeBanner: View {
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Spacer()
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}

private enum ScanTarget: String, CaseIterable, Identifiable {
    case skill
    case mcp
    case plugin
    case code

    var id: String { rawValue }

    var label: String {
        switch self {
        case .skill: return "Skill"
        case .mcp: return "MCP"
        case .plugin: return "Plugin"
        case .code: return "Code"
        }
    }

    var pluralLabel: String {
        switch self {
        case .skill: return "Skills"
        case .mcp: return "MCP Servers"
        case .plugin: return "Plugins"
        case .code: return "Code Paths"
        }
    }

    var systemImage: String {
        switch self {
        case .skill: return "wand.and.stars"
        case .mcp: return "server.rack"
        case .plugin: return "shippingbox"
        case .code: return "chevron.left.forwardslash.chevron.right"
        }
    }

    var placeholder: String {
        switch self {
        case .skill: return "Path to skill directory or manifest"
        case .mcp: return "MCP server URL or target"
        case .plugin: return "Plugin name or directory path"
        case .code: return "Path to source tree"
        }
    }

    var emptyDescription: String {
        switch self {
        case .skill:
            return "Run setup or connect the gateway so DefenseClaw can discover local skills."
        case .mcp:
            return "Run setup or connect OpenClaw so DefenseClaw can read configured MCP servers."
        case .plugin:
            return "No plugins were returned by defenseclaw plugin list --json."
        case .code:
            return "Enter a source path manually, or initialize DefenseClaw/OpenClaw to show common folders."
        }
    }
}

private struct ScanResultsHeader: View {
    var body: some View {
        HStack(spacing: 12) {
            Text("Severity")
                .frame(width: 100, alignment: .leading)
            Text("Rule")
                .frame(width: 180, alignment: .leading)
            Text("Description")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.caption)
        .fontWeight(.semibold)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct ScanFindingRow: View {
    let finding: Finding

    var body: some View {
        HStack(spacing: 12) {
            HStack(spacing: 6) {
                Circle()
                    .fill(severityColor)
                    .frame(width: 8, height: 8)
                Text(finding.severity.rawValue.uppercased())
                    .fontWeight(.semibold)
                    .foregroundStyle(severityColor)
            }
            .frame(width: 100, alignment: .leading)

            Text(finding.rule)
                .frame(width: 180, alignment: .leading)
                .foregroundStyle(.secondary)

            Text(finding.description)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private var severityColor: Color {
        switch finding.severity {
        case .critical:
            return .red
        case .high:
            return .orange
        case .medium:
            return .yellow
        case .low:
            return .blue
        case .info:
            return .green
        case .none:
            return .secondary
        }
    }
}
