import SwiftUI
import DefenseClawKit

/// Alerts window — matches the DefenseClaw TUI alerts panel layout:
/// Table with SEVERITY | TIME | ACTION | TARGET columns,
/// selected-row highlight, and detail modal on click.
struct AlertsView: View {
    @State private var alerts: [DefenseClawKit.Alert] = []
    @State private var selectedAlert: DefenseClawKit.Alert?
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var pollingTask: Task<Void, Never>?

    private let sidecarClient = SidecarClient()

    var body: some View {
        VStack(spacing: 0) {
            // Header bar — matches TUI tab bar style
            HStack {
                Text("ALERTS")
                    .font(.system(.headline, design: .monospaced))
                    .fontWeight(.bold)
                    .foregroundStyle(Color(nsColor: .systemBlue))

                Spacer()

                Text("\(alerts.count) alert\(alerts.count == 1 ? "" : "s")")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)

                Button {
                    Task { await loadAlerts() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color(nsColor: .controlBackgroundColor))

            Divider()

            if alerts.isEmpty && !isLoading {
                Spacer()
                Text("No alerts. All clear.")
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer()
            } else {
                // Column header — matches TUI: SEVERITY | TIME | ACTION | TARGET
                HStack(spacing: 0) {
                    Text("SEVERITY")
                        .frame(width: 90, alignment: .leading)
                    Text("TIME")
                        .frame(width: 140, alignment: .leading)
                    Text("ACTION")
                        .frame(width: 160, alignment: .leading)
                    Text("TARGET")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.system(.caption, design: .monospaced))
                .fontWeight(.bold)
                .foregroundStyle(Color(nsColor: .systemBlue))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Color(nsColor: .controlBackgroundColor))

                Divider()

                // Alert rows — TUI-style table
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(alerts) { alert in
                            AlertTableRow(
                                alert: alert,
                                isSelected: selectedAlert?.id == alert.id
                            )
                            .contentShape(Rectangle())
                            .onTapGesture {
                                withAnimation(.easeInOut(duration: 0.15)) {
                                    if selectedAlert?.id == alert.id {
                                        selectedAlert = nil
                                    } else {
                                        selectedAlert = alert
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Status bar — matches TUI status bar
            HStack {
                Text("showing 1-\(alerts.count) of \(alerts.count)")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer()
                if let sel = selectedAlert {
                    Text("selected: \(sel.action)")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 4)
            .background(Color(nsColor: .windowBackgroundColor).opacity(0.8))
        }
        .frame(minWidth: 600, minHeight: 400)
        .sheet(item: $selectedAlert) { alert in
            AlertDetailModal(alert: alert) {
                selectedAlert = nil
            }
        }
        .task {
            await loadAlerts()
            pollingTask = Task {
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(5))
                    await loadAlerts()
                }
            }
        }
        .onDisappear {
            pollingTask?.cancel()
        }
    }

    private func loadAlerts() async {
        do {
            let fetched = try await sidecarClient.alerts()
            await MainActor.run {
                alerts = fetched
                errorMessage = ""
            }
        } catch {
            await MainActor.run {
                errorMessage = error.localizedDescription
            }
        }
    }
}

// MARK: - Table Row (TUI-style)

struct AlertTableRow: View {
    let alert: DefenseClawKit.Alert
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 0) {
            Text(alert.severity.rawValue.uppercased())
                .foregroundStyle(severityColor)
                .fontWeight(.bold)
                .frame(width: 90, alignment: .leading)

            Text(formatTimestamp(alert.timestamp))
                .frame(width: 140, alignment: .leading)

            Text(truncate(alert.action, max: 20))
                .frame(width: 160, alignment: .leading)

            Text(truncate(alert.target, max: 30))
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.system(.caption, design: .monospaced))
        .padding(.horizontal, 12)
        .padding(.vertical, 5)
        .background(isSelected ? Color(nsColor: .selectedContentBackgroundColor).opacity(0.3) : Color.clear)
    }

    private func formatTimestamp(_ date: Date) -> String {
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd HH:mm"
        return fmt.string(from: date)
    }

    private func truncate(_ s: String, max: Int) -> String {
        if s.count > max { return String(s.prefix(max - 3)) + "..." }
        return s
    }

    private var severityColor: Color {
        switch alert.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .secondary
        case .none: return .secondary
        }
    }
}

// MARK: - Detail Modal (matches TUI detail modal)

struct AlertDetailModal: View {
    let alert: DefenseClawKit.Alert
    let onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Alert: \(alert.action)")
                .font(.system(.headline, design: .monospaced))
                .fontWeight(.bold)
                .foregroundStyle(Color(nsColor: .systemBlue))

            Divider()

            detailRow("Severity:", alert.severity.rawValue.uppercased(), color: severityColor)
            detailRow("Action:", alert.action)
            detailRow("Target:", alert.target)
            detailRow("Details:", alert.details)
            detailRow("Actor:", alert.actor)
            detailRow("Timestamp:", formatTimestamp(alert.timestamp))

            Spacer()

            HStack {
                Text("press esc or enter to close")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.tertiary)
                Spacer()
                Button("Close") { onDismiss() }
                    .keyboardShortcut(.return, modifiers: [])
                    .keyboardShortcut(.escape, modifiers: [])
            }
        }
        .padding(20)
        .frame(width: 500, height: 300)
    }

    private func detailRow(_ label: String, _ value: String, color: Color? = nil) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.system(.caption, design: .monospaced))
                .fontWeight(.bold)
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .trailing)

            if let color {
                Text(value)
                    .font(.system(.caption, design: .monospaced))
                    .fontWeight(.bold)
                    .foregroundStyle(color)
            } else {
                Text(value)
                    .font(.system(.caption, design: .monospaced))
            }

            Spacer()
        }
    }

    private func formatTimestamp(_ date: Date) -> String {
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return fmt.string(from: date)
    }

    private var severityColor: Color {
        switch alert.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info, .none: return .secondary
        }
    }
}
