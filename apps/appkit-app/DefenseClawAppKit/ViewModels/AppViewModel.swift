import SwiftUI
import DefenseClawKit

@Observable
class AppViewModel {
    var sessions: [AgentSession] = []
    var activeSessionIndex: Int?
    var healthSnapshot: HealthSnapshot?
    var showNewSessionSheet = false

    private var pollingTask: Task<Void, Never>?
    private let sidecarClient = SidecarClient()

    init() {
        startPolling()
    }

    deinit {
        pollingTask?.cancel()
    }

    func startPolling() {
        pollingTask = Task {
            while !Task.isCancelled {
                await checkHealth()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    @MainActor
    func checkHealth() async {
        do {
            healthSnapshot = try await sidecarClient.health()
        } catch {
            healthSnapshot = nil
        }
    }

    @MainActor
    func addSession(workspace: String, agentName: String) async throws {
        let session = AgentSession()
        try await session.connect()
        sessions.append(session)
        activeSessionIndex = sessions.count - 1
        showNewSessionSheet = false
    }

    var activeSession: AgentSession? {
        guard let index = activeSessionIndex, sessions.indices.contains(index) else { return nil }
        return sessions[index]
    }

    var isHealthy: Bool {
        healthSnapshot?.isHealthy ?? false
    }
}
