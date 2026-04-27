import SwiftUI
import DefenseClawKit

@Observable
class AppViewModel {
    var healthSnapshot: HealthSnapshot?

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

    var isHealthy: Bool {
        healthSnapshot?.isHealthy ?? false
    }
}
