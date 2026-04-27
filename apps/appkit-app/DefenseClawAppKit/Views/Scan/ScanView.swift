import SwiftUI
import DefenseClawKit

struct ScanView: View {
    @State private var scanType = ScanTarget.skill
    @State private var targetPath = ""
    @State private var isScanning = false
    @State private var results: [Finding] = []
    @State private var error: String?

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
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Security Scans")
                .font(.system(.largeTitle, weight: .semibold))
            Text("Run DefenseClaw scanners against skills, MCP servers, and source paths from the main console.")
                .font(.callout)
                .foregroundStyle(.secondary)
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
                .frame(width: 360)

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

            TextField(scanType.placeholder, text: $targetPath)
                .textFieldStyle(.roundedBorder)

            if let error {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }

            HStack(spacing: 10) {
                ScanHint(label: "Skill", value: "Local skill directory or manifest")
                ScanHint(label: "MCP", value: "Server URL or command target")
                ScanHint(label: "Code", value: "Repository or source path")
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
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 34))
                        .foregroundStyle(.secondary)
                    Text("No findings to show")
                        .font(.headline)
                    Text("Run a scan to populate this table.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
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

    private func runScan() {
        isScanning = true
        error = nil
        results = []

        Task {
            let client = SidecarClient()
            do {
                let scanResult: ScanResult
                switch scanType {
                case .skill:
                    scanResult = try await client.scanSkill(path: targetPath)
                case .mcp:
                    scanResult = try await client.scanMCP(url: targetPath)
                case .code:
                    scanResult = try await client.scanCode(path: targetPath)
                }
                await MainActor.run {
                    results = scanResult.findings
                    isScanning = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    isScanning = false
                }
            }
        }
    }
}

private enum ScanTarget: String, CaseIterable, Identifiable {
    case skill
    case mcp
    case code

    var id: String { rawValue }

    var label: String {
        switch self {
        case .skill: return "Skill"
        case .mcp: return "MCP"
        case .code: return "Code"
        }
    }

    var systemImage: String {
        switch self {
        case .skill: return "wand.and.stars"
        case .mcp: return "server.rack"
        case .code: return "chevron.left.forwardslash.chevron.right"
        }
    }

    var placeholder: String {
        switch self {
        case .skill: return "Path to skill directory or manifest"
        case .mcp: return "MCP server URL or target"
        case .code: return "Path to source tree"
        }
    }
}

private struct ScanHint: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.caption)
                .fontWeight(.semibold)
            Text(value)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
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
