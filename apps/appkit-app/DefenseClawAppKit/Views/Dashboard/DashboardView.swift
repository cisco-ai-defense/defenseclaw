import SwiftUI
import DefenseClawKit

struct DashboardView: View {
    @State private var health: HealthSnapshot?
    @State private var alerts: [DefenseClawKit.Alert] = []
    @State private var skills: [Skill] = []
    @State private var mcpServers: [MCPServer] = []
    private let sidecarClient = SidecarClient()

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                headerSection
                healthSection
                HStack(alignment: .top, spacing: 16) {
                    alertsSection
                    inventorySection
                }
                quickActionsSection
            }
            .padding(24)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            await refresh()
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("DefenseClaw")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                Text("Agent Governance Dashboard")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            HStack(spacing: 8) {
                Circle()
                    .fill(health != nil ? Color.green : Color.red)
                    .frame(width: 10, height: 10)
                Text(health != nil ? "Sidecar Running" : "Sidecar Offline")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
        }
    }

    // MARK: - Health

    private var healthSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Subsystem Health")
                    .font(.headline)
                Spacer()
                if let h = health {
                    Text("Uptime: \(formatUptime(h.uptimeMs))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button {
                    Task { await refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
            }

            if let h = health {
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                ], spacing: 12) {
                    SubsystemCard(name: "Gateway", health: h.gateway)
                    SubsystemCard(name: "Watcher", health: h.watcher)
                    SubsystemCard(name: "API", health: h.api)
                    SubsystemCard(name: "Guardrail", health: h.guardrail)
                    SubsystemCard(name: "Telemetry", health: h.telemetry)
                    SubsystemCard(name: "Splunk", health: h.splunk)
                }
            } else {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                    Text("Cannot reach sidecar at 127.0.0.1:18970")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding()
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Alerts

    private var alertsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Recent Alerts")
                .font(.headline)

            if alerts.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.shield")
                        .font(.title)
                        .foregroundStyle(.green)
                    Text("No alerts")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 80)
            } else {
                ForEach(alerts.prefix(5)) { alert in
                    HStack(spacing: 8) {
                        Circle()
                            .fill(severityColor(alert.severity))
                            .frame(width: 8, height: 8)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(alert.message.isEmpty ? alert.action : alert.message)
                                .font(.caption)
                                .lineLimit(1)
                            Text(alert.target)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(alert.severity.rawValue)
                            .font(.caption2)
                            .fontWeight(.semibold)
                            .foregroundStyle(severityColor(alert.severity))
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Inventory

    private var inventorySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Inventory")
                .font(.headline)

            HStack(spacing: 24) {
                VStack(spacing: 4) {
                    Text("\(skills.count)")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text("Skills")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                VStack(spacing: 4) {
                    Text("\(mcpServers.count)")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text("MCP Servers")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 80)

            if !skills.isEmpty {
                Divider()
                ForEach(skills.prefix(3)) { skill in
                    HStack {
                        Image(systemName: skill.blocked ? "xmark.circle.fill" : "checkmark.circle.fill")
                            .foregroundStyle(skill.blocked ? .red : .green)
                            .font(.caption)
                        Text(skill.name)
                            .font(.caption)
                            .lineLimit(1)
                        Spacer()
                    }
                }
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Quick Actions

    private var quickActionsSection: some View {
        HStack(spacing: 12) {
            ActionButton(icon: "magnifyingglass", title: "Scan", subtitle: "Run security scan") {
                if let delegate = NSApp.delegate as? AppDelegate {
                    delegate.showScan()
                }
            }
            ActionButton(icon: "doc.text", title: "Policies", subtitle: "View & reload") {
                if let delegate = NSApp.delegate as? AppDelegate {
                    delegate.showPolicy()
                }
            }
            ActionButton(icon: "gearshape", title: "Settings", subtitle: "Configure gateway") {
                if let delegate = NSApp.delegate as? AppDelegate {
                    delegate.showSettings()
                }
            }
        }
    }

    // MARK: - Helpers

    private func refresh() async {
        do {
            health = try await sidecarClient.health()
        } catch {
            health = nil
        }
        do {
            alerts = try await sidecarClient.alerts()
        } catch {
            alerts = []
        }
        do {
            skills = try await sidecarClient.skills()
        } catch {
            skills = []
        }
        do {
            mcpServers = try await sidecarClient.mcpServers()
        } catch {
            mcpServers = []
        }
    }

    private func formatUptime(_ ms: Int64) -> String {
        let seconds = Int(ms / 1000)
        let hours = seconds / 3600
        let minutes = (seconds % 3600) / 60
        let secs = seconds % 60
        if hours > 0 {
            return "\(hours)h \(minutes)m"
        } else if minutes > 0 {
            return "\(minutes)m \(secs)s"
        }
        return "\(secs)s"
    }

    private func severityColor(_ severity: Severity) -> Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .green
        case .none: return .gray
        }
    }
}

// MARK: - Subviews

struct SubsystemCard: View {
    let name: String
    let health: SubsystemHealth

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(stateColor)
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(name)
                    .font(.caption)
                    .fontWeight(.semibold)
                Text(health.state.rawValue)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(10)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var stateColor: Color {
        switch health.state {
        case .running: return .green
        case .starting, .reconnecting: return .yellow
        case .disabled, .stopped: return .gray
        case .error: return .red
        }
    }
}

struct ActionButton: View {
    let icon: String
    let title: String
    let subtitle: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                Text(title)
                    .font(.callout)
                    .fontWeight(.semibold)
                Text(subtitle)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 80)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
    }
}
