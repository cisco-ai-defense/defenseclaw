import SwiftUI

struct ProtectionView: View {
    @State private var selection = ProtectionTab.guardrails

    var body: some View {
        TabView(selection: $selection) {
            GuardrailSettingsView()
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .tabItem {
                    Label("Guardrails", systemImage: "shield")
                }
                .tag(ProtectionTab.guardrails)

            EnforcementView()
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .tabItem {
                    Label("Enforcement", systemImage: "lock.shield")
                }
                .tag(ProtectionTab.enforcement)

            ConfigFilesView(
                title: "Advanced Configuration",
                subtitle: "Edit DefenseClaw, OpenClaw, coding-agent, scanner, and observability config files. Policy files stay in the Policy section.",
                emptyMessage: "No config files found"
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .tabItem {
                    Label("Advanced Config", systemImage: "doc.text.magnifyingglass")
                }
                .tag(ProtectionTab.advancedConfig)
        }
        .frame(minWidth: 980, idealWidth: 1120, minHeight: 650, idealHeight: 760)
    }
}

private enum ProtectionTab: Hashable {
    case guardrails
    case enforcement
    case advancedConfig
}

struct OperationsView: View {
    var body: some View {
        TabView {
            DiagnosticsView()
                .tabItem {
                    Label("Diagnostics", systemImage: "stethoscope")
                }

            LogsView()
                .tabItem {
                    Label("Logs", systemImage: "terminal")
                }

            GatewaySettingsView()
                .tabItem {
                    Label("Services", systemImage: "network")
                }
        }
        .frame(minWidth: 980, idealWidth: 1120, minHeight: 650, idealHeight: 760)
    }
}

struct AdvancedView: View {
    @State private var selection = AdvancedTab.overview

    var body: some View {
        TabView(selection: $selection) {
            SettingsOverviewView(
                openSetup: { (NSApp.delegate as? AppDelegate)?.showSetup() },
                openConfig: { selection = .config },
                openGateway: { selection = .services },
                openGuardrails: { (NSApp.delegate as? AppDelegate)?.showProtection() },
                openEnforcement: { (NSApp.delegate as? AppDelegate)?.showProtection() },
                openScanners: { selection = .scanners },
                openDiagnostics: { (NSApp.delegate as? AppDelegate)?.showOperations() },
                openPolicy: { (NSApp.delegate as? AppDelegate)?.showPolicy() },
                openAlerts: { (NSApp.delegate as? AppDelegate)?.showAlerts() },
                openLogs: { (NSApp.delegate as? AppDelegate)?.showOperations() }
            )
            .tabItem {
                Label("Overview", systemImage: "square.grid.2x2")
            }
            .tag(AdvancedTab.overview)

            ConfigFilesView()
                .tabItem {
                    Label("Config Files", systemImage: "doc.text.magnifyingglass")
                }
                .tag(AdvancedTab.config)

            ScannersView()
                .tabItem {
                    Label("Scanner Settings", systemImage: "magnifyingglass")
                }
                .tag(AdvancedTab.scanners)

            GatewaySettingsView()
                .tabItem {
                    Label("Gateway", systemImage: "network")
                }
                .tag(AdvancedTab.services)

            ToolsCatalogView()
                .tabItem {
                    Label("Tools", systemImage: "wrench.and.screwdriver")
                }
                .tag(AdvancedTab.tools)
        }
        .frame(minWidth: 980, idealWidth: 1120, minHeight: 650, idealHeight: 760)
    }
}

private enum AdvancedTab: Hashable {
    case overview
    case config
    case scanners
    case services
    case tools
}
