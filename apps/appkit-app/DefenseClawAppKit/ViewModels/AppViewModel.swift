import SwiftUI
import DefenseClawKit

@Observable
class AppViewModel {
    var healthSnapshot: HealthSnapshot?
    var firstRunCompleted: Bool

    private var pollingTask: Task<Void, Never>?
    private let sidecarClient = SidecarClient()
    private static let firstRunCompletionKey = "com.cisco.defenseclaw.firstRunCompleted.v2"

    init() {
        let arguments = ProcessInfo.processInfo.arguments
        let forceFirstRun = arguments.contains("--qa-first-run")
        let qaSectionRequested = arguments.contains("--qa-section") || arguments.contains { $0.hasPrefix("--qa-section=") }

        if forceFirstRun {
            firstRunCompleted = false
        } else if qaSectionRequested {
            firstRunCompleted = true
        } else {
            firstRunCompleted = UserDefaults.standard.bool(forKey: Self.firstRunCompletionKey)
        }

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

    func completeFirstRun() {
        UserDefaults.standard.set(true, forKey: Self.firstRunCompletionKey)
        firstRunCompleted = true
    }

    func resetFirstRun() {
        UserDefaults.standard.set(false, forKey: Self.firstRunCompletionKey)
        firstRunCompleted = false
    }
}
