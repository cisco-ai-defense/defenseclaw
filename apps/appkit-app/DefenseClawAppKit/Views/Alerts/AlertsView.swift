import SwiftUI
import DefenseClawKit

struct AlertsView: View {
    @State private var alerts: [DefenseClawKit.Alert] = []
    @State private var selectedAlert: DefenseClawKit.Alert?
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var searchText = ""
    @State private var severityFilter = "All"
    @State private var lastRefresh: Date?
    @State private var pollingTask: Task<Void, Never>?

    private let sidecarClient = SidecarClient()
    private let severityOptions = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    private var filteredAlerts: [DefenseClawKit.Alert] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return alerts.filter { alert in
            let matchesSeverity = severityFilter == "All" || alert.severity.rawValue == severityFilter
            guard matchesSeverity else {
                return false
            }
            guard !query.isEmpty else {
                return true
            }
            return [
                alert.severity.rawValue,
                alert.action,
                alert.target,
                alert.details,
                alert.actor
            ].contains { $0.lowercased().contains(query) }
        }
        .sorted { $0.timestamp > $1.timestamp }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            HSplitView {
                alertsList
                    .frame(minWidth: 520)

                detailPane
                    .frame(minWidth: 320, idealWidth: 380)
            }

            Divider()
            statusBar
        }
        .frame(minWidth: 720, minHeight: 480)
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

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Alerts")
                        .font(.title2.weight(.semibold))
                    Text("Active sidecar alerts with policy, guardrail, scanner, and enforcement context.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                summaryChip(label: "Active", value: "\(alerts.count)", color: alerts.isEmpty ? .green : .orange)
                summaryChip(label: "Shown", value: "\(filteredAlerts.count)", color: .blue)

                Button {
                    Task { await loadAlerts() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(isLoading)
            }

            HStack(spacing: 10) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Search action, target, details, actor", text: $searchText)
                        .textFieldStyle(.plain)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))

                Picker("Severity", selection: $severityFilter) {
                    ForEach(severityOptions, id: \.self) { severity in
                        Text(severity).tag(severity)
                    }
                }
                .frame(width: 150)

                if !errorMessage.isEmpty {
                    Label("Sidecar error", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .font(.caption.weight(.semibold))
                } else if let lastRefresh {
                    Text("Updated \(lastRefresh.formatted(date: .omitted, time: .standard))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(18)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var alertsList: some View {
        VStack(spacing: 0) {
            tableHeader
            Divider()

            if isLoading && alerts.isEmpty {
                ProgressView("Loading alerts...")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if !errorMessage.isEmpty && alerts.isEmpty {
                errorState
            } else if filteredAlerts.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(filteredAlerts) { alert in
                            AlertTableRow(
                                alert: alert,
                                isSelected: selectedAlert?.id == alert.id
                            )
                            .contentShape(Rectangle())
                            .onTapGesture {
                                selectedAlert = selectedAlert?.id == alert.id ? nil : alert
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }

    private var tableHeader: some View {
        HStack(spacing: 0) {
            Text("SEVERITY")
                .frame(width: 94, alignment: .leading)
            Text("TIME")
                .frame(width: 138, alignment: .leading)
            Text("ACTION")
                .frame(width: 170, alignment: .leading)
            Text("TARGET")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.system(.caption, design: .monospaced).weight(.semibold))
        .foregroundStyle(Color.accentColor)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var detailPane: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let selectedAlert {
                AlertDetailPanel(alert: selectedAlert) {
                    self.selectedAlert = nil
                }
            } else {
                ContentUnavailableView(
                    "Select an alert",
                    systemImage: "bell.badge",
                    description: Text("Alert details, redacted payloads, actor, and timestamps appear here.")
                )
            }

            Spacer()
        }
        .padding(18)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var errorState: some View {
        VStack(spacing: 14) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.largeTitle)
                .foregroundStyle(.orange)
            Text("Alerts could not be loaded")
                .font(.headline)
            Text(errorMessage)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .textSelection(.enabled)
            HStack {
                Button {
                    (NSApp.delegate as? AppDelegate)?.showSettings()
                } label: {
                    Label("Open Diagnostics", systemImage: "stethoscope")
                }
                Button {
                    (NSApp.delegate as? AppDelegate)?.showLogs()
                } label: {
                    Label("Open Logs", systemImage: "doc.text.magnifyingglass")
                }
            }
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "checkmark.shield")
                .font(.largeTitle)
                .foregroundStyle(.green)
            Text(alerts.isEmpty ? "No active alerts reported by the sidecar" : "No alerts match the current filters")
                .font(.headline)
            Text(alerts.isEmpty
                 ? "This is the active-alert view. Historical audit events and dismissed alerts are available in Audit and Logs."
                 : "Clear search or severity filters to return to the full active-alert list.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            HStack {
                Button {
                    (NSApp.delegate as? AppDelegate)?.showLogs()
                } label: {
                    Label("Open Logs", systemImage: "doc.text")
                }
                Button {
                    (NSApp.delegate as? AppDelegate)?.showPolicy()
                } label: {
                    Label("Review Policy", systemImage: "checklist.checked")
                }
            }
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var statusBar: some View {
        HStack {
            Text("showing \(filteredAlerts.count) of \(alerts.count)")
            Spacer()
            if isLoading {
                ProgressView()
                    .controlSize(.small)
                Text("refreshing")
            } else if !errorMessage.isEmpty {
                Text("sidecar unavailable")
                    .foregroundStyle(.orange)
            } else {
                Text("polling every 5 seconds")
            }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private func summaryChip(label: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.headline.monospacedDigit())
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .frame(minWidth: 68, alignment: .leading)
        .background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
    }

    private func loadAlerts() async {
        await MainActor.run {
            isLoading = true
        }

        do {
            let fetched = try await sidecarClient.alerts()
            await MainActor.run {
                alerts = fetched
                if let selectedAlert,
                   !fetched.contains(where: { $0.id == selectedAlert.id }) {
                    self.selectedAlert = nil
                }
                errorMessage = ""
                lastRefresh = Date()
                isLoading = false
            }
        } catch {
            await MainActor.run {
                errorMessage = error.localizedDescription
                lastRefresh = Date()
                isLoading = false
            }
        }
    }
}

private struct AlertTableRow: View {
    let alert: DefenseClawKit.Alert
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 0) {
            Text(alert.severity.rawValue)
                .foregroundStyle(severityColor)
                .fontWeight(.semibold)
                .frame(width: 94, alignment: .leading)

            Text(formatTimestamp(alert.timestamp))
                .frame(width: 138, alignment: .leading)

            Text(alert.action)
                .frame(width: 170, alignment: .leading)
                .lineLimit(1)

            Text(alert.target)
                .frame(maxWidth: .infinity, alignment: .leading)
                .lineLimit(1)
        }
        .font(.system(.caption, design: .monospaced))
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(isSelected ? Color.accentColor.opacity(0.14) : Color.clear)
    }

    private func formatTimestamp(_ date: Date) -> String {
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd HH:mm"
        return fmt.string(from: date)
    }

    private var severityColor: Color {
        switch alert.severity {
        case .critical:
            return .red
        case .high:
            return .orange
        case .medium:
            return .yellow
        case .low:
            return .blue
        case .info, .none:
            return .secondary
        }
    }
}

private struct AlertDetailPanel: View {
    let alert: DefenseClawKit.Alert
    let onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Alert Details", systemImage: "bell.badge")
                    .font(.headline)
                Spacer()
                Button {
                    onDismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }

            detailRow("Severity", alert.severity.rawValue, color: severityColor)
            detailRow("Action", alert.action)
            detailRow("Target", alert.target)
            detailRow("Actor", alert.actor)
            detailRow("Timestamp", alert.timestamp.formatted(date: .abbreviated, time: .standard))

            VStack(alignment: .leading, spacing: 6) {
                Text("Details")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(alert.details.isEmpty ? "No details supplied" : alert.details)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            }

            Spacer()
        }
    }

    @ViewBuilder
    private func detailRow(_ label: String, _ value: String, color: Color? = nil) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(color ?? .primary)
                .textSelection(.enabled)
        }
    }

    private var severityColor: Color {
        switch alert.severity {
        case .critical:
            return .red
        case .high:
            return .orange
        case .medium:
            return .yellow
        case .low:
            return .blue
        case .info, .none:
            return .secondary
        }
    }
}
