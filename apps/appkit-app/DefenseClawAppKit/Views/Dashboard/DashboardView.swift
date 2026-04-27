import SwiftUI
import DefenseClawKit

/// Main operator dashboard. This is intentionally not a chat surface: it is the
/// app's control-plane home for health, posture, inventory, and workflows.
struct DashboardView: View {
    @State private var viewModel = DashboardViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                metrics

                HStack(alignment: .top, spacing: 16) {
                    healthCard
                        .frame(minWidth: 360)

                    VStack(spacing: 16) {
                        postureCard
                        recentAlertsCard
                    }
                    .frame(minWidth: 360)
                }

                workflowCard
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            await viewModel.start()
        }
        .onDisappear {
            viewModel.stop()
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 32, weight: .semibold))
                .foregroundStyle(.blue)
                .frame(width: 54, height: 54)
                .background(Color.blue.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 12))

            VStack(alignment: .leading, spacing: 5) {
                Text("DefenseClaw Control Plane")
                    .font(.system(.largeTitle, weight: .semibold))
                Text("Health, guardrails, policy, scans, alerts, tools, and logs in one operator console.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 8) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(viewModel.statusColor)
                        .frame(width: 9, height: 9)
                    Text(viewModel.statusText)
                        .font(.callout)
                        .fontWeight(.medium)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(Color(nsColor: .controlBackgroundColor))
                .clipShape(Capsule())

                Button {
                    Task { await viewModel.refreshAll() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
            }
        }
    }

    private var metrics: some View {
        LazyVGrid(
            columns: [GridItem(.adaptive(minimum: 180), spacing: 12)],
            alignment: .leading,
            spacing: 12
        ) {
            MetricTile(
                title: "Active Alerts",
                value: "\(viewModel.alerts.count)",
                subtitle: viewModel.alerts.isEmpty ? "No active findings" : "Needs review",
                systemImage: "bell.badge",
                tint: viewModel.alerts.isEmpty ? .green : .orange
            )

            MetricTile(
                title: "Skills",
                value: viewModel.skillsMetricValue,
                subtitle: viewModel.skillsMetricSubtitle,
                systemImage: "wand.and.stars",
                tint: .purple
            )

            MetricTile(
                title: "MCP Servers",
                value: viewModel.mcpMetricValue,
                subtitle: viewModel.mcpMetricSubtitle,
                systemImage: "server.rack",
                tint: .teal
            )

            MetricTile(
                title: "Tools",
                value: "\(viewModel.tools.count)",
                subtitle: viewModel.tools.isEmpty ? "Gateway catalog unavailable" : "Runtime catalog",
                systemImage: "wrench.and.screwdriver",
                tint: .blue
            )

            MetricTile(
                title: "Enforcement",
                value: viewModel.enforcementMetricValue,
                subtitle: viewModel.enforcementMetricSubtitle,
                systemImage: "lock.shield",
                tint: .red
            )
        }
    }

    private var healthCard: some View {
        DashboardCard(title: "Subsystem Health", systemImage: "heart.text.square", tint: .green) {
            if let health = viewModel.health {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("Uptime")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(formatUptime(health.uptimeMs))
                            .fontWeight(.medium)
                    }
                    .font(.caption)

                    Divider()

                    VStack(spacing: 8) {
                        SubsystemRow(name: "Gateway", health: health.gateway)
                        SubsystemRow(name: "Watcher", health: health.watcher)
                        SubsystemRow(name: "API", health: health.api)
                        SubsystemRow(name: "Guardrail", health: health.guardrail)
                        SubsystemRow(name: "Telemetry", health: health.telemetry)
                        SubsystemRow(name: "Sinks", health: health.splunk)
                        if let sandbox = health.sandbox {
                            SubsystemRow(name: "Sandbox", health: sandbox)
                        }
                    }
                }
            } else {
                OfflineStateView(
                    title: "Sidecar offline",
                    message: viewModel.errorMessage ?? "The local helper is not reachable yet.",
                    systemImage: "exclamationmark.triangle.fill",
                    tint: .orange
                )
            }
        }
    }

    private var postureCard: some View {
        DashboardCard(title: "Protection Posture", systemImage: "shield.checkered", tint: .blue) {
            VStack(alignment: .leading, spacing: 10) {
                PostureRow(
                    title: "Gateway",
                    value: viewModel.gatewayPostureText,
                    stateColor: viewModel.gatewayPostureColor
                )
                PostureRow(
                    title: "Guardrail",
                    value: viewModel.guardrailPostureText,
                    stateColor: viewModel.guardrailPostureColor
                )
                PostureRow(
                    title: "Scanner Coverage",
                    value: viewModel.scannerCoverageText,
                    stateColor: viewModel.scannerCoverageColor
                )
                PostureRow(
                    title: "Policy",
                    value: viewModel.policySummary,
                    stateColor: viewModel.policySummaryColor
                )

                Divider()

                HStack {
                    Button {
                        (NSApp.delegate as? AppDelegate)?.showSettings()
                    } label: {
                        Label("Settings", systemImage: "slider.horizontal.3")
                    }
                    Button {
                        (NSApp.delegate as? AppDelegate)?.showPolicy()
                    } label: {
                        Label("Policy", systemImage: "doc.text.magnifyingglass")
                    }
                }
                .controlSize(.small)
            }
        }
    }

    private var recentAlertsCard: some View {
        DashboardCard(title: "Recent Alerts", systemImage: "bell.badge", tint: .orange) {
            if viewModel.alerts.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    Text("No active alerts")
                        .foregroundStyle(.secondary)
                }
                .font(.callout)
            } else {
                VStack(spacing: 8) {
                    ForEach(viewModel.alerts.prefix(5)) { alert in
                        AlertSummaryRow(alert: alert)
                    }

                    if viewModel.alerts.count > 5 {
                        Button("View all \(viewModel.alerts.count) alerts") {
                            (NSApp.delegate as? AppDelegate)?.showAlerts()
                        }
                        .buttonStyle(.link)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
    }

    private var workflowCard: some View {
        DashboardCard(title: "Operator Workflows", systemImage: "rectangle.grid.2x2", tint: .indigo) {
            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 210), spacing: 12)],
                alignment: .leading,
                spacing: 12
            ) {
                WorkflowButton(
                    title: "Settings",
                    subtitle: "Gateway, guardrail, scanners",
                    systemImage: "slider.horizontal.3",
                    tint: .blue
                ) {
                    (NSApp.delegate as? AppDelegate)?.showSettings()
                }
                WorkflowButton(
                    title: "Run Scans",
                    subtitle: "Skills, MCP servers, code paths",
                    systemImage: "magnifyingglass",
                    tint: .teal
                ) {
                    (NSApp.delegate as? AppDelegate)?.showScan()
                }
                WorkflowButton(
                    title: "Policy",
                    subtitle: "View, reload, evaluate",
                    systemImage: "doc.text.magnifyingglass",
                    tint: .indigo
                ) {
                    (NSApp.delegate as? AppDelegate)?.showPolicy()
                }
                WorkflowButton(
                    title: "Alerts",
                    subtitle: "Audit findings and severity",
                    systemImage: "bell.badge",
                    tint: .orange
                ) {
                    (NSApp.delegate as? AppDelegate)?.showAlerts()
                }
                WorkflowButton(
                    title: "Tools",
                    subtitle: "Runtime catalog and inspection",
                    systemImage: "wrench.and.screwdriver",
                    tint: .purple
                ) {
                    (NSApp.delegate as? AppDelegate)?.showTools()
                }
                WorkflowButton(
                    title: "Logs",
                    subtitle: "Local app log stream",
                    systemImage: "terminal",
                    tint: .green
                ) {
                    (NSApp.delegate as? AppDelegate)?.showLogs()
                }
            }
        }
    }

    private func formatUptime(_ ms: Int64) -> String {
        let seconds = Int(ms / 1000)
        let hours = seconds / 3600
        let minutes = (seconds % 3600) / 60
        let secs = seconds % 60
        if hours > 0 { return "\(hours)h \(minutes)m" }
        if minutes > 0 { return "\(minutes)m \(secs)s" }
        return "\(secs)s"
    }
}

@MainActor
@Observable
final class DashboardViewModel {
    var health: HealthSnapshot?
    var alerts: [DefenseClawKit.Alert] = []
    var skills: [Skill] = []
    var mcpServers: [MCPServer] = []
    var tools: [ToolEntry] = []
    var blockedCount = 0
    var allowedCount = 0
    var policySummary = "Not loaded"
    var errorMessage: String?
    var skillsError: String?
    var mcpError: String?
    var toolsError: String?
    var blockedError: String?
    var allowedError: String?

    private let sidecarClient = SidecarClient()
    private let log = AppLogger.shared
    private var pollingTask: Task<Void, Never>?

    var statusText: String {
        guard let health else { return "Sidecar Offline" }
        return health.isHealthy ? "Sidecar Running" : "Attention Needed"
    }

    var statusColor: Color {
        guard let health else { return .red }
        return health.isHealthy ? .green : .orange
    }

    var blockedSkillsCount: Int {
        skills.filter(\.blocked).count
    }

    var runningMCPCount: Int {
        mcpServers.filter(\.isRunning).count
    }

    var scannedSkillsCount: Int {
        skills.filter { $0.lastScan != nil }.count
    }

    var skillsMetricValue: String {
        skillsError == nil ? "\(skills.count)" : "!"
    }

    var skillsMetricSubtitle: String {
        if let skillsError { return "Load failed: \(shortError(skillsError))" }
        if skills.isEmpty { return "No runtime skills reported" }
        return "\(blockedSkillsCount) blocked"
    }

    var mcpMetricValue: String {
        mcpError == nil ? "\(mcpServers.count)" : "!"
    }

    var mcpMetricSubtitle: String {
        if let mcpError { return "Load failed: \(shortError(mcpError))" }
        if mcpServers.isEmpty { return "No MCP servers configured" }
        return "\(runningMCPCount) running"
    }

    var enforcementMetricValue: String {
        blockedError == nil && allowedError == nil ? "\(blockedCount + allowedCount)" : "!"
    }

    var enforcementMetricSubtitle: String {
        if let blockedError { return "Blocked failed: \(shortError(blockedError))" }
        if let allowedError { return "Allowed failed: \(shortError(allowedError))" }
        if blockedCount + allowedCount == 0 { return "No explicit overrides" }
        return "\(blockedCount) blocked, \(allowedCount) allowed"
    }

    var scannerCoverageText: String {
        if let skillsError { return "Skills unavailable: \(shortError(skillsError))" }
        if skills.isEmpty { return "No runtime skills reported" }
        if scannedSkillsCount == 0 { return "\(skills.count) skills, scan state pending" }
        return "\(scannedSkillsCount) of \(skills.count) scanned"
    }

    var scannerCoverageColor: Color {
        if skillsError != nil { return .red }
        if scannedSkillsCount > 0 { return .green }
        return skills.isEmpty ? .secondary : .orange
    }

    var gatewayPostureText: String {
        guard let health else { return "Offline" }
        switch health.gateway.state {
        case .running: return "Connected"
        case .starting: return "Starting"
        case .reconnecting: return "Sidecar running, gateway reconnecting"
        case .stopped: return "Stopped"
        case .error: return "Error"
        case .disabled: return "Disabled"
        }
    }

    var gatewayPostureColor: Color {
        guard let health else { return .red }
        return color(for: health.gateway.state)
    }

    var guardrailPostureText: String {
        guard let health else { return "Unknown" }
        switch health.guardrail.state {
        case .running: return "Enabled"
        case .disabled: return "Disabled"
        default: return health.guardrail.state.rawValue.capitalized
        }
    }

    var guardrailPostureColor: Color {
        guard let health else { return .secondary }
        return color(for: health.guardrail.state)
    }

    var policySummaryColor: Color {
        policySummary == "Loaded" ? .green : .secondary
    }

    func start() async {
        pollingTask?.cancel()
        await refreshAll()
        pollingTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                await self?.refreshAll()
            }
        }
    }

    func stop() {
        pollingTask?.cancel()
        pollingTask = nil
    }

    func refreshAll() async {
        do {
            health = try await sidecarClient.health()
            errorMessage = nil
        } catch {
            health = nil
            errorMessage = error.localizedDescription
            log.warn("dashboard", "Health poll failed", details: "\(error.localizedDescription)")
        }

        do { alerts = try await sidecarClient.alerts() } catch { alerts = [] }
        do {
            skills = try await sidecarClient.skills()
            skillsError = nil
            log.info("dashboard", "Skills loaded", details: "count=\(skills.count)")
        } catch {
            skills = []
            skillsError = error.localizedDescription
            log.warn("dashboard", "Skills load failed", details: error.localizedDescription)
        }
        do {
            mcpServers = try await sidecarClient.mcpServers()
            mcpError = nil
            log.info("dashboard", "MCP servers loaded", details: "count=\(mcpServers.count)")
        } catch {
            mcpServers = []
            mcpError = error.localizedDescription
            log.warn("dashboard", "MCP load failed", details: error.localizedDescription)
        }
        do {
            tools = try await sidecarClient.toolsCatalog()
            toolsError = nil
        } catch {
            tools = []
            toolsError = error.localizedDescription
            log.warn("dashboard", "Tools load failed", details: error.localizedDescription)
        }

        do {
            let blocked = try await sidecarClient.blockedList()
            blockedCount = blocked.count
            blockedError = nil
            log.info("dashboard", "Blocked enforcement loaded", details: "count=\(blocked.count)")
        } catch {
            blockedCount = 0
            blockedError = error.localizedDescription
            log.warn("dashboard", "Blocked enforcement load failed", details: error.localizedDescription)
        }

        do {
            let allowed = try await sidecarClient.allowedList()
            allowedCount = allowed.count
            allowedError = nil
            log.info("dashboard", "Allowed enforcement loaded", details: "count=\(allowed.count)")
        } catch {
            allowedCount = 0
            allowedError = error.localizedDescription
            log.warn("dashboard", "Allowed enforcement load failed", details: error.localizedDescription)
        }

        do {
            _ = try await sidecarClient.policyShow()
            policySummary = "Loaded"
        } catch {
            policySummary = "Unavailable"
        }
    }

    private func color(for state: SubsystemState) -> Color {
        switch state {
        case .running: return .green
        case .starting, .reconnecting: return .yellow
        case .disabled, .stopped: return .secondary
        case .error: return .red
        }
    }

    private func shortError(_ error: String) -> String {
        let cleaned = error.replacingOccurrences(of: "\n", with: " ")
        if cleaned.count <= 42 { return cleaned }
        return String(cleaned.prefix(39)) + "..."
    }
}

private struct DashboardCard<Content: View>: View {
    let title: String
    let systemImage: String
    let tint: Color
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: systemImage)
                    .foregroundStyle(tint)
                    .frame(width: 18)
                Text(title)
                    .font(.headline)
                Spacer()
            }

            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(nsColor: .separatorColor).opacity(0.5), lineWidth: 0.5)
        )
    }
}

private struct MetricTile: View {
    let title: String
    let value: String
    let subtitle: String
    let systemImage: String
    let tint: Color

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 38, height: 38)
                .background(tint.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 9))

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.title3)
                    .fontWeight(.semibold)
                Text(subtitle)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }

            Spacer(minLength: 0)
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(nsColor: .separatorColor).opacity(0.45), lineWidth: 0.5)
        )
    }
}

private struct PostureRow: View {
    let title: String
    let value: String
    let stateColor: Color

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(stateColor)
                .frame(width: 7, height: 7)
            Text(title)
                .font(.callout)
            Spacer()
            Text(value)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }
}

private struct AlertSummaryRow: View {
    let alert: DefenseClawKit.Alert

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(severityColor)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                Text(alert.action)
                    .font(.callout)
                    .lineLimit(1)
                Text(alert.target)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            Text(alert.severity.rawValue.uppercased())
                .font(.caption2)
                .fontWeight(.semibold)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(severityColor.opacity(0.12))
                .foregroundStyle(severityColor)
                .clipShape(Capsule())
        }
    }

    private var severityColor: Color {
        switch alert.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .green
        case .none: return .secondary
        }
    }
}

private struct WorkflowButton: View {
    let title: String
    let subtitle: String
    let systemImage: String
    let tint: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: systemImage)
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(tint)
                    .frame(width: 36, height: 36)
                    .background(tint.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 8))

                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.callout)
                        .fontWeight(.medium)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(12)
            .frame(maxWidth: .infinity)
            .background(Color(nsColor: .windowBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 9))
            .overlay(
                RoundedRectangle(cornerRadius: 9)
                    .stroke(Color(nsColor: .separatorColor).opacity(0.45), lineWidth: 0.5)
            )
        }
        .buttonStyle(.plain)
    }
}

private struct OfflineStateView: View {
    let title: String
    let message: String
    let systemImage: String
    let tint: Color

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: systemImage)
                .foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.callout)
                    .fontWeight(.medium)
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct SubsystemRow: View {
    let name: String
    let health: SubsystemHealth

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(stateColor)
                .frame(width: 7, height: 7)
                .shadow(color: stateColor.opacity(0.35), radius: 2)
            Text(name)
                .font(.callout)
            Spacer()
            Text(health.state.rawValue)
                .font(.caption2)
                .fontWeight(.medium)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(stateColor.opacity(0.12))
                .foregroundStyle(stateColor)
                .clipShape(Capsule())
        }
    }

    private var stateColor: Color {
        switch health.state {
        case .running: return .green
        case .starting, .reconnecting: return .yellow
        case .disabled, .stopped: return .secondary
        case .error: return .red
        }
    }
}
