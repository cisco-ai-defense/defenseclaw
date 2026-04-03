import SwiftUI
import DefenseClawKit

struct SettingsView: View {
    var body: some View {
        TabView {
            GatewaySettingsView()
                .tabItem {
                    Label("Gateway", systemImage: "network")
                }

            GuardrailSettingsView()
                .tabItem {
                    Label("Guardrails", systemImage: "shield")
                }

            DiagnosticsView()
                .tabItem {
                    Label("Diagnostics", systemImage: "stethoscope")
                }
        }
        .frame(width: 600, height: 500)
    }
}

struct GatewaySettingsView: View {
    @State private var gatewayURL = "http://localhost:8888"
    @State private var autoStart = true

    var body: some View {
        Form {
            Section("Gateway Configuration") {
                TextField("Gateway URL", text: $gatewayURL)
                Toggle("Auto-start Gateway", isOn: $autoStart)
            }

            HStack {
                Spacer()
                Button("Save") {
                    // Save settings
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }
}

struct GuardrailSettingsView: View {
    @State private var enableSkillScanning = true
    @State private var enableMCPScanning = true
    @State private var blockOnCritical = true

    var body: some View {
        Form {
            Section("Scanning") {
                Toggle("Enable Skill Scanning", isOn: $enableSkillScanning)
                Toggle("Enable MCP Scanning", isOn: $enableMCPScanning)
            }

            Section("Enforcement") {
                Toggle("Block on Critical Findings", isOn: $blockOnCritical)
            }

            HStack {
                Spacer()
                Button("Save") {
                    // Save settings
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }
}

struct DiagnosticsView: View {
    @State private var logs = "Loading diagnostics..."

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("System Diagnostics")
                .font(.headline)

            ScrollView {
                Text(logs)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color(nsColor: .textBackgroundColor))
                    .cornerRadius(8)
            }

            HStack {
                Button("Refresh") {
                    refreshDiagnostics()
                }
                Spacer()
                Button("Export Logs") {
                    // Export logs
                }
            }
        }
        .padding()
        .onAppear {
            refreshDiagnostics()
        }
    }

    private func refreshDiagnostics() {
        logs = """
        DefenseClaw Diagnostics
        =====================
        Gateway: Running
        Health Check: OK
        Active Sessions: 0
        """
    }
}
