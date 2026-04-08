import Foundation
import DefenseClawKit

@Observable
class SessionViewModel {
    var session: AgentSession
    var inputText = ""
    var governanceAlerts: [DefenseClawKit.Alert] = []
    var skills: [Skill] = []
    var mcpServers: [MCPServer] = []

    private let sidecarClient = SidecarClient()
    private let log = AppLogger.shared

    init(session: AgentSession) {
        self.session = session
    }

    func sendMessage() {
        guard !inputText.isEmpty else { return }
        let text = inputText
        inputText = ""
        session.sendMessage(text)
    }

    @MainActor
    func approveExec(requestId: String) {
        session.resolveApproval(requestId: requestId, approved: true)
    }

    @MainActor
    func denyExec(requestId: String) {
        session.resolveApproval(requestId: requestId, approved: false)
    }

    func stopStreaming() {
        session.cancelStream()
    }

    @MainActor
    func refreshGovernance() async {
        do {
            governanceAlerts = try await sidecarClient.alerts()
            skills = try await sidecarClient.skills()
            mcpServers = try await sidecarClient.mcpServers()
        } catch {
            log.warn("session", "Governance refresh failed", details: "\(error)")
        }
    }

    var tabTitle: String {
        if let lastMessage = session.messages.last(where: { $0.role == .user }) {
            let text = lastMessage.textContent
            return String(text.prefix(30))
        }
        return "Chat"
    }
}
