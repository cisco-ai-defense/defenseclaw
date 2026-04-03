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
        HStack {
            Text("DefenseClaw")
                .font(.headline)
            Spacer()
            HStack(spacing: 6) {
                Circle()
                    .fill(viewModel.isConnected ? Color.green : Color.orange)
                    .frame(width: 8, height: 8)
                Text(viewModel.isConnected ? "Gateway Connected" : "Gateway Offline")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    // MARK: - Chat Messages

    private var chatMessages: some View {
        ScrollView {
            ScrollViewReader { proxy in
                LazyVStack(alignment: .leading, spacing: 12) {
                    if viewModel.messages.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "shield.checkered")
                                .font(.system(size: 48))
                                .foregroundStyle(.tertiary)
                            Text("Agent Chat")
                                .font(.title2)
                                .fontWeight(.semibold)
                            Text("Send a message to interact with your AI agent through the OpenClaw gateway.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                            if !viewModel.isConnected {
                                Label("Gateway is offline — messages will be sent when it reconnects", systemImage: "exclamationmark.triangle")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                                    .padding(.top, 4)
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

    private var chatInput: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextEditor(text: $viewModel.inputText)
                .frame(minHeight: 36, maxHeight: 100)
                .padding(4)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                )

            if viewModel.isStreaming {
                Button {
                    viewModel.stopStreaming()
                } label: {
                    Image(systemName: "stop.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.red)
                }
                .buttonStyle(.borderless)
            } else {
                Button {
                    viewModel.sendMessage()
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title2)
                        .foregroundStyle(Color.accentColor)
                }
                .buttonStyle(.borderless)
                .disabled(viewModel.inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    // MARK: - Governance Panel

    private var governancePanel: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Health section
                healthSection

                Divider()

                // Alerts section
                alertsSection

                Divider()

                // Skills section
                skillsSection

                Divider()

                // MCP Servers section
                mcpSection

                Divider()

                // Quick Actions
                quickActionsSection
            }
            .padding()
        }
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var healthSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Subsystem Health")
                    .font(.headline)
                Spacer()
                if let h = viewModel.health {
                    Text(formatUptime(h.uptimeMs))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button {
                    Task { await viewModel.refreshAll() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
            }

            if let h = viewModel.health {
                VStack(spacing: 6) {
                    SubsystemRow(name: "Gateway", health: h.gateway)
                    SubsystemRow(name: "Watcher", health: h.watcher)
                    SubsystemRow(name: "API", health: h.api)
                    SubsystemRow(name: "Guardrail", health: h.guardrail)
                    SubsystemRow(name: "Telemetry", health: h.telemetry)
                    SubsystemRow(name: "Splunk", health: h.splunk)
                    if let sandbox = h.sandbox {
                        SubsystemRow(name: "Sandbox", health: sandbox)
                    }
                }
            } else {
                Label("Sidecar offline", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
    }

    private var alertsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Alerts")
                .font(.subheadline)
                .fontWeight(.semibold)

            if viewModel.alerts.isEmpty {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.shield")
                        .foregroundStyle(.green)
                    Text("No alerts")
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
                            .foregroundStyle(severityColor(alert.severity))
                    }
                }
            }
        }
    }

    private var skillsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Skills (\(viewModel.skills.count))")
                .font(.subheadline)
                .fontWeight(.semibold)

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
                    }
                }
            }
        }
    }

    private var mcpSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MCP Servers (\(viewModel.mcpServers.count))")
                .font(.subheadline)
                .fontWeight(.semibold)

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
                    }
                }
            }
        }
    }

    private var quickActionsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Quick Actions")
                .font(.subheadline)
                .fontWeight(.semibold)

            HStack(spacing: 8) {
                Button {
                    (NSApp.delegate as? AppDelegate)?.showScan()
                } label: {
                    Label("Scan", systemImage: "magnifyingglass")
                        .font(.caption)
                }

                Button {
                    (NSApp.delegate as? AppDelegate)?.showPolicy()
                } label: {
                    Label("Policies", systemImage: "doc.text")
                        .font(.caption)
                }

                Button {
                    (NSApp.delegate as? AppDelegate)?.showSettings()
                } label: {
                    Label("Settings", systemImage: "gearshape")
                        .font(.caption)
                }
            }
        }
    }

    // MARK: - Helpers

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

    private var session: AgentSession?
    private let sidecarClient = SidecarClient()
    private var pollingTask: Task<Void, Never>?

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
        do { health = try await sidecarClient.health() } catch { health = nil }
        do { alerts = try await sidecarClient.alerts() } catch { alerts = [] }
        do { skills = try await sidecarClient.skills() } catch { skills = [] }
        do { mcpServers = try await sidecarClient.mcpServers() } catch { mcpServers = [] }
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
                .frame(width: 8, height: 8)
            Text(name)
                .font(.caption)
            Spacer()
            Text(health.state.rawValue)
                .font(.caption2)
                .foregroundStyle(.secondary)
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
