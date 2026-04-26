import SwiftUI
import DefenseClawKit

struct StatusBarPopover: View {
    @Environment(\.dismiss) private var dismiss
    let appViewModel: AppViewModel

    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Text("DefenseClaw")
                    .font(.headline)
                Spacer()
                statusIndicator
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Sessions: \(appViewModel.sessions.count)")
                    .font(.caption)

                if let index = appViewModel.activeSessionIndex {
                    Text("Active: Session \(index + 1)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("No active session")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Divider()

            Button("New Session...") {
                appViewModel.showNewSessionSheet = true
                NSApplication.shared.activate(ignoringOtherApps: true)
                if let window = NSApplication.shared.windows.first(where: { $0.isVisible }) {
                    window.makeKeyAndOrderFront(nil)
                }
            }

            Button("Open Window") {
                NSApplication.shared.activate(ignoringOtherApps: true)
                if let window = NSApplication.shared.windows.first(where: { $0.isVisible }) {
                    window.makeKeyAndOrderFront(nil)
                }
            }

            Divider()

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding()
        .frame(width: 250)
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
}
