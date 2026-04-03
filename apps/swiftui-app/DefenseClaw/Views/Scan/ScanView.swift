import SwiftUI
import DefenseClawKit

struct ScanView: View {
    @State private var scanType = "skill"
    @State private var targetPath = ""
    @State private var isScanning = false
    @State private var results: [Finding] = []
    @State private var error: String?

    private let scanTypes = ["skill", "mcp", "aibom"]

    var body: some View {
        VStack(spacing: 16) {
            Form {
                Picker("Scan Type", selection: $scanType) {
                    ForEach(scanTypes, id: \.self) { type in
                        Text(type.uppercased()).tag(type)
                    }
                }

                TextField("Target Path", text: $targetPath)

                Button("Scan") {
                    runScan()
                }
                .disabled(targetPath.isEmpty || isScanning)
            }
            .padding()

            if let error = error {
                Text("Error: \(error)")
                    .foregroundStyle(.red)
                    .padding()
            }

            if isScanning {
                ProgressView("Scanning...")
                    .padding()
            }

            if !results.isEmpty {
                List(results) { finding in
                    ScanFindingRow(finding: finding)
                }
            }

            Spacer()
        }
        .navigationTitle("Scan")
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
                case "skill":
                    scanResult = try await client.scanSkill(path: targetPath)
                case "mcp":
                    scanResult = try await client.scanMCP(url: targetPath)
                case "aibom":
                    scanResult = try await client.scanCode(path: targetPath)
                default:
                    scanResult = try await client.scanSkill(path: targetPath)
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

struct ScanFindingRow: View {
    let finding: Finding

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(severityColor)
                .frame(width: 10, height: 10)

            VStack(alignment: .leading, spacing: 4) {
                Text(finding.description)
                    .font(.body)

                Text(finding.rule)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Text(finding.severity.rawValue)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundStyle(severityColor)
        }
        .padding(.vertical, 4)
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
            return .gray
        }
    }
}
