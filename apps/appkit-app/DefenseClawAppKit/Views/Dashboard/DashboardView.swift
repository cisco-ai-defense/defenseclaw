import SwiftUI
import DefenseClawKit

/// Main dashboard: left chat panel + right governance panel.
/// Automatically creates an AgentSession on appear so the chat
/// interface is always visible — even when the gateway is offline.
struct DashboardView: View {
    @Environment(AppViewModel.self) private var appViewModel
    @State private var viewModel: DashboardViewModel

    init() {
        self._viewModel = State(initialValue: DashboardViewModel())
    }

    var body: some View {
        HSplitView {
            // Left: Chat
            VStack(spacing: 0) {
                chatHeader
                Divider()
                chatMessages
                Divider()
                chatInput
            }
            .frame(minWidth: 450)

            // Right: Governance + Health
            governancePanel
                .frame(minWidth: 280, idealWidth: 340, maxWidth: 420)
        }
        .task {
            await viewModel.setup(appViewModel: appViewModel)
        }
    }

    // MARK: - Chat Header

    private var chatHeader: some View {
        HStack(spacing: 10) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 16))
                .foregroundStyle(
                    LinearGradient(
                        colors: [.blue, .indigo],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            Text("DefenseClaw")
                .font(.headline)
            Spacer()
            HStack(spacing: 6) {
                Circle()
                    .fill(gatewayStatusColor)
                    .frame(width: 8, height: 8)
                    .shadow(color: gatewayStatusColor.opacity(0.5), radius: 3)
                Text(gatewayStatusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(Capsule())
            .overlay(
                Capsule()
                    .stroke(Color(nsColor: .separatorColor).opacity(0.5), lineWidth: 0.5)
            )
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Chat Messages

    private var chatMessages: some View {
        ScrollView {
            ScrollViewReader { proxy in
                LazyVStack(alignment: .leading, spacing: 12) {
                    if viewModel.messages.isEmpty {
                        VStack(spacing: 16) {
                            Image(systemName: "shield.checkered")
                                .font(.system(size: 52))
                                .foregroundStyle(
                                    LinearGradient(
                                        colors: [.blue.opacity(0.6), .indigo.opacity(0.4)],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                            Text("DefenseClaw Agent")
                                .font(.title2)
                                .fontWeight(.semibold)
                            Text("Send a message to interact with your AI agent\nthrough the OpenClaw gateway.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                                .lineSpacing(2)
                            if !viewModel.isConnected {
                                HStack(spacing: 6) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.orange)
                                    Text("Gateway is offline — messages will be sent when it reconnects")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.orange.opacity(0.08))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.top, 80)
                    } else {
                        ForEach(viewModel.messages) { message in
                            MessageBubble(message: message, viewModel: viewModel.sessionViewModel!)
                                .id(message.id)
                        }
                    }
                }
                .padding()
                .onChange(of: viewModel.messages.count) { _, _ in
                    if let last = viewModel.messages.last {
                        withAnimation {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Chat Input

    private var canSend: Bool {
        !viewModel.inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var chatInput: some View {
        VStack(spacing: 0) {
            HStack(alignment: .bottom, spacing: 8) {
                ChatTextView(
                    text: $viewModel.inputText,
                    placeholder: "Send a message... (Enter to send, Shift+Enter for new line)",
                    onSubmit: {
                        if canSend {
                            viewModel.sendMessage()
                        }
                    }
                )
                .frame(minHeight: 36, maxHeight: 100)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                )

                if viewModel.isStreaming {
                    Button {
                        viewModel.stopStreaming()
                    } label: {
                        Image(systemName: "stop.circle.fill")
                            .font(.system(size: 24))
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.borderless)
                    .help("Stop response")
                } else {
                    Button {
                        viewModel.sendMessage()
                    } label: {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.system(size: 24))
                            .foregroundStyle(canSend ? Color.accentColor : Color.gray.opacity(0.4))
                    }
                    .buttonStyle(.borderless)
                    .disabled(!canSend)
                    .help("Send message")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Governance Panel

    private var governancePanel: some View {
        VStack(spacing: 0) {
            // Panel header
            HStack {
                Image(systemName: "shield.checkered")
                    .foregroundStyle(.blue)
                    .font(.caption)
                Text("Governance")
                    .font(.headline)
                Spacer()
                Button {
                    Task { await viewModel.refreshAll() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
                .help("Refresh all")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            ScrollView {
                VStack(spacing: 12) {
                    healthCard
                    alertsCard
                    skillsCard
                    mcpCard
                    quickActionsCard
                }
                .padding(12)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var healthCard: some View {
        SidebarCard(title: "Subsystem Health", icon: "heart.text.square", iconColor: .green) {
            if let h = viewModel.health {
                VStack(spacing: 6) {
                    if let uptime = formatUptime(h.uptimeMs) as String? {
                        HStack {
                            Text("Uptime")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                            Spacer()
                            Text(uptime)
                                .font(.caption2)
                                .fontWeight(.medium)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.bottom, 2)
                    }
                    SubsystemRow(name: "Gateway", health: h.gateway)
                    SubsystemRow(name: "Watcher", health: h.watcher)
                    SubsystemRow(name: "API", health: h.api)
                    SubsystemRow(name: "Guardrail", health: h.guardrail)
                    SubsystemRow(name: "Telemetry", health: h.telemetry)
                    SubsystemRow(name: "Sinks", health: h.splunk)
                    if let sandbox = h.sandbox {
                        SubsystemRow(name: "Sandbox", health: sandbox)
                    }
                }
            } else {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.caption)
                    Text("Sidecar offline")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var alertsCard: some View {
        SidebarCard(title: "Alerts", icon: "bell.badge", iconColor: .orange, badge: viewModel.alerts.isEmpty ? nil : "\(viewModel.alerts.count)") {
            if viewModel.alerts.isEmpty {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                        .font(.caption)
                    Text("No active alerts")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                ForEach(viewModel.alerts.prefix(5)) { alert in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(severityColor(alert.severity))
                            .frame(width: 6, height: 6)
                        Text(alert.message.isEmpty ? alert.action : alert.message)
                            .font(.caption)
                            .lineLimit(1)
                        Spacer()
                        Text(alert.severity.rawValue)
                            .font(.caption2)
                            .fontWeight(.medium)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(severityColor(alert.severity).opacity(0.12))
                            .foregroundStyle(severityColor(alert.severity))
                            .clipShape(Capsule())
                    }
                }
                if viewModel.alerts.count > 5 {
                    Button("View All \(viewModel.alerts.count) Alerts") {
                        (NSApp.delegate as? AppDelegate)?.showAlerts()
                    }
                    .font(.caption2)
                    .buttonStyle(.borderless)
                }
            }
        }
    }

    private var skillsCard: some View {
        SidebarCard(title: "Skills", icon: "wand.and.stars", iconColor: .purple, badge: viewModel.skills.isEmpty ? nil : "\(viewModel.skills.count)") {
            if viewModel.skills.isEmpty {
                Text("No skills discovered")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.skills.prefix(5)) { skill in
                    HStack(spacing: 6) {
                        Image(systemName: skill.blocked ? "xmark.circle.fill" : "checkmark.circle.fill")
                            .foregroundStyle(skill.blocked ? .red : .green)
                            .font(.caption2)
                        Text(skill.name)
                            .font(.caption)
                            .lineLimit(1)
                        Spacer()
                        Button {
                            Task { await viewModel.toggleSkill(skill) }
                        } label: {
                            Text(skill.blocked ? "Enable" : "Disable")
                                .font(.caption2)
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
        }
    }

    private var mcpCard: some View {
        SidebarCard(title: "MCP Servers", icon: "server.rack", iconColor: .teal, badge: viewModel.mcpServers.isEmpty ? nil : "\(viewModel.mcpServers.count)") {
            if viewModel.mcpServers.isEmpty {
                Text("No MCP servers")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.mcpServers.prefix(5)) { server in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(server.blocked ? Color.red : Color.green)
                            .frame(width: 6, height: 6)
                        Text(server.name)
                            .font(.caption)
                            .lineLimit(1)
                        Spacer()
                        Button {
                            Task { await viewModel.toggleMCP(server) }
                        } label: {
                            Text(server.blocked ? "Enable" : "Disable")
                                .font(.caption2)
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
        }
    }

    private var quickActionsCard: some View {
        SidebarCard(title: "Quick Actions", icon: "bolt.fill", iconColor: .yellow) {
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                QuickActionButton(title: "Alerts", icon: "bell", color: .orange) {
                    (NSApp.delegate as? AppDelegate)?.showAlerts()
                }
                QuickActionButton(title: "Scan", icon: "magnifyingglass", color: .blue) {
                    (NSApp.delegate as? AppDelegate)?.showScan()
                }
                QuickActionButton(title: "Policies", icon: "doc.text", color: .indigo) {
                    (NSApp.delegate as? AppDelegate)?.showPolicy()
                }
                QuickActionButton(title: "Tools", icon: "wrench.and.screwdriver", color: .teal) {
                    (NSApp.delegate as? AppDelegate)?.showTools()
                }
                QuickActionButton(title: "Settings", icon: "gearshape", color: .gray) {
                    (NSApp.delegate as? AppDelegate)?.showSettings()
                }
                QuickActionButton(title: "Logs", icon: "doc.text.magnifyingglass", color: .green) {
                    (NSApp.delegate as? AppDelegate)?.showLogs()
                }
            }
        }
    }

    // MARK: - Helpers

    private var gatewayStatusColor: Color {
        guard let h = viewModel.health else { return .red }
        switch h.gateway.state {
        case .running: return .green
        case .reconnecting: return .yellow
        case .starting: return .yellow
        default: return .red
        }
    }

    private var gatewayStatusText: String {
        guard let h = viewModel.health else { return "Sidecar Offline" }
        switch h.gateway.state {
        case .running: return "Gateway Connected"
        case .reconnecting: return "Sidecar Running (no gateway server)"
        case .starting: return "Gateway Starting..."
        default: return "Gateway \(h.gateway.state.rawValue)"
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

// MARK: - DashboardViewModel

@Observable
class DashboardViewModel {
    var inputText = ""
    var health: HealthSnapshot?
    var alerts: [DefenseClawKit.Alert] = []
    var skills: [Skill] = []
    var mcpServers: [MCPServer] = []
    var sessionViewModel: SessionViewModel?
    var sidecarStatus = "Connecting..."

    private var session: AgentSession?
    private let sidecarClient = SidecarClient()
    private var pollingTask: Task<Void, Never>?
    private let log = AppLogger.shared

    var messages: [ChatMessage] {
        session?.messages ?? []
    }

    var isConnected: Bool {
        session?.isConnected ?? false
    }

    var isStreaming: Bool {
        messages.last?.isStreaming == true
    }

    @MainActor
    func setup(appViewModel: AppViewModel) async {
        // Create a session (it will try to connect to gateway)
        if session == nil {
            let s = AgentSession()
            session = s
            sessionViewModel = SessionViewModel(session: s)
            // Try connecting — if gateway is offline, session stays in disconnected state
            try? await s.connect()

            // Also set on appViewModel so tab strip can see it
            appViewModel.sessions = [s]
            appViewModel.activeSessionIndex = 0
        }

        // Start health polling
        pollingTask?.cancel()
        pollingTask = Task {
            while !Task.isCancelled {
                await refreshAll()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    func sendMessage() {
        guard !inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        let text = inputText
        inputText = ""
        session?.sendMessage(text)
    }

    func stopStreaming() {
        session?.cancelStream()
    }

    @MainActor
    func refreshAll() async {
        do {
            health = try await sidecarClient.health()
            sidecarStatus = "Connected"
        } catch {
            health = nil
            sidecarStatus = "Sidecar offline: \(error.localizedDescription)"
            log.warn("dashboard", "Health poll failed", details: "\(error.localizedDescription)")
        }
        do { alerts = try await sidecarClient.alerts() } catch { alerts = [] }
        do { skills = try await sidecarClient.skills() } catch { skills = [] }
        do { mcpServers = try await sidecarClient.mcpServers() } catch { mcpServers = [] }
    }

    @MainActor
    func toggleSkill(_ skill: Skill) async {
        do {
            if skill.blocked {
                try await sidecarClient.enableSkill(key: skill.id)
            } else {
                try await sidecarClient.disableSkill(key: skill.id)
            }
            await refreshAll()
        } catch {
            log.error("dashboard", "Toggle skill failed", details: "\(error)")
        }
    }

    @MainActor
    func toggleMCP(_ server: MCPServer) async {
        do {
            if server.blocked {
                try await sidecarClient.enablePlugin(key: server.id)
            } else {
                try await sidecarClient.disablePlugin(key: server.id)
            }
            await refreshAll()
        } catch {
            log.error("dashboard", "Toggle MCP failed", details: "\(error)")
        }
    }
}

// MARK: - Subviews

struct SubsystemRow: View {
    let name: String
    let health: SubsystemHealth

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(stateColor)
                .frame(width: 7, height: 7)
                .shadow(color: stateColor.opacity(0.4), radius: 2)
            Text(name)
                .font(.caption)
            Spacer()
            Text(health.state.rawValue)
                .font(.caption2)
                .fontWeight(.medium)
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(stateColor.opacity(0.1))
                .foregroundStyle(stateColor)
                .clipShape(Capsule())
        }
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

struct QuickActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 14))
                    .foregroundStyle(color)
                Text(title)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(color.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(color.opacity(0.1), lineWidth: 0.5)
            )
        }
        .buttonStyle(.plain)
    }
}
