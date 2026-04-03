import SwiftUI
import DefenseClawKit

struct DiagnosticsView: View {
    @State private var diagnosticsOutput = ""
    @State private var isRunning = false

    var body: some View {
        VStack(spacing: 16) {
            HStack {
                Text("System Diagnostics")
                    .font(.headline)

                Spacer()

                Button("Run Diagnostics") {
                    runDiagnostics()
                }
                .disabled(isRunning)
            }

            ScrollView {
                Text(diagnosticsOutput.isEmpty ? "Click 'Run Diagnostics' to check system health" : diagnosticsOutput)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color(nsColor: .textBackgroundColor))
                    .cornerRadius(8)
            }
        }
        .padding()
    }

    private func runDiagnostics() {
        isRunning = true
        diagnosticsOutput = "Running diagnostics...\n"

        Task {
            let client = SidecarClient()

            do {
                let health = try await client.health()
                await MainActor.run {
                    diagnosticsOutput += "\n✓ Sidecar Gateway: Running\n"
                    diagnosticsOutput += "  Started: \(health.startedAt)\n"
                    diagnosticsOutput += "  Uptime: \(health.uptimeMs)ms\n"
                    diagnosticsOutput += "  Gateway: \(health.gateway.state)\n"
                    diagnosticsOutput += "  Guardrail: \(health.guardrail.state)\n"
                }
            } catch {
                await MainActor.run {
                    diagnosticsOutput += "\n✗ Sidecar Gateway: Not running\n"
                    diagnosticsOutput += "  Error: \(error.localizedDescription)\n"
                }
            }

            // Check config
            let manager = ConfigManager()
            do {
                let config = try manager.load()
                await MainActor.run {
                    diagnosticsOutput += "\n✓ Configuration: Loaded\n"
                    diagnosticsOutput += "  Gateway: \(config.gateway?.host ?? "unknown"):\(config.gateway?.port ?? 0)\n"
                    diagnosticsOutput += "  Guardrail: \(config.guardrail?.enabled == true ? "Enabled" : "Disabled")\n"
                }
            } catch {
                await MainActor.run {
                    diagnosticsOutput += "\n✗ Configuration: Error loading\n"
                    diagnosticsOutput += "  Error: \(error.localizedDescription)\n"
                }
            }

            await MainActor.run {
                diagnosticsOutput += "\n✓ Diagnostics complete\n"
                isRunning = false
            }
        }
    }
}
