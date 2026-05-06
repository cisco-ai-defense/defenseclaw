import SwiftUI
import DefenseClawKit

struct StatusBarPopover: View {
    @Environment(\.dismiss) private var dismiss
    let appViewModel: AppViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundStyle(.blue)
                Text("DefenseClaw")
                    .font(.headline)
                Spacer()
                statusIndicator
            }

            Divider()

            Text(statusSummary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button {
                route(.home)
            } label: {
                Label("Open Console", systemImage: "rectangle.split.2x1")
            }
            .buttonStyle(.borderedProminent)

            VStack(spacing: 6) {
                HStack(spacing: 6) {
                    navButton("Setup", "wand.and.stars", .setup)
                    navButton("Protect", "shield.checkered", .protection)
                }
                HStack(spacing: 6) {
                    navButton("Alerts", "bell.badge", .alerts)
                    navButton("Scans", "magnifyingglass", .scan)
                }
                HStack(spacing: 6) {
                    navButton("Policy", "doc.text.magnifyingglass", .policy)
                    navButton("Ops", "stethoscope", .operations)
                }
                HStack(spacing: 6) {
                    navButton("Advanced", "slider.horizontal.3", .advanced)
                }
            }

            Divider()

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding()
        .frame(width: 280)
    }

    private var statusIndicator: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(appViewModel.isHealthy ? Color.green : Color.red)
                .frame(width: 8, height: 8)
            Text(appViewModel.isHealthy ? "Running" : "Offline")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private var statusSummary: String {
        guard let health = appViewModel.healthSnapshot else {
            return "The local helper is not reachable. Open the console for diagnostics and logs."
        }
        if health.isGatewayConnected {
            return "Gateway connected. Guardrails and operator views are available in the main console."
        }
        return "Helper is running, but the gateway is still \(health.gateway.state.rawValue)."
    }

    private func navButton(_ title: String, _ systemImage: String, _ section: OperatorSection) -> some View {
        Button {
            route(section)
        } label: {
            Label(title, systemImage: systemImage)
                .frame(maxWidth: .infinity)
        }
    }

    private func route(_ section: OperatorSection) {
        dismiss()
        guard let appDelegate = NSApp.delegate as? AppDelegate else { return }
        switch section {
        case .home:
            appDelegate.showHome()
        case .setup:
            appDelegate.showSetup()
        case .protection:
            appDelegate.showProtection()
        case .scan:
            appDelegate.showScan()
        case .policy:
            appDelegate.showPolicy()
        case .alerts:
            appDelegate.showAlerts()
        case .operations:
            appDelegate.showOperations()
        case .advanced:
            appDelegate.showAdvanced()
        }
    }
}
