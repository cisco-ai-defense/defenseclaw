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

            ScannersSettingsView()
                .tabItem {
                    Label("Scanners", systemImage: "magnifyingglass")
                }

            IntegrationsSettingsView()
                .tabItem {
                    Label("Integrations", systemImage: "link")
                }

            EnforcementSettingsView()
                .tabItem {
                    Label("Enforcement", systemImage: "exclamationmark.triangle")
                }

            SandboxSettingsView()
                .tabItem {
                    Label("Sandbox", systemImage: "cube")
                }

            DiagnosticsView()
                .tabItem {
                    Label("Diagnostics", systemImage: "stethoscope")
                }
        }
        .frame(width: 600, height: 500)
    }
}
