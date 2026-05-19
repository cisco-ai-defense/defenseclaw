import SwiftUI
import DefenseClawKit

struct FirstRunSetupView: View {
    let navigation: OperatorNavigationModel
    let appViewModel: AppViewModel

    @State private var isChecking = false

    private var backendState: FirstRunStepState {
        if appViewModel.healthSnapshot == nil {
            return .warning
        }
        return appViewModel.isHealthy ? .complete : .warning
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                header

                HStack(alignment: .top, spacing: 18) {
                    readinessCard
                        .frame(minWidth: 380, maxWidth: 460)
                    setupPathCard
                        .frame(minWidth: 460)
                }

                actionBar
            }
            .padding(34)
            .frame(maxWidth: 1120, alignment: .leading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            await refreshHealth()
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 18) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 38, weight: .semibold))
                .foregroundStyle(.blue)
                .frame(width: 72, height: 72)
                .background(Color.blue.opacity(0.12), in: RoundedRectangle(cornerRadius: 16))

            VStack(alignment: .leading, spacing: 6) {
                Text("Set up DefenseClaw")
                    .font(.largeTitle.weight(.semibold))
                Text("The macOS app installs, configures, and verifies the local backend before you use the operator console.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var readinessCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Ready Check", systemImage: "checklist")
                .font(.title3.weight(.semibold))

            FirstRunStepRow(
                title: "Local backend",
                detail: backendDetail,
                systemImage: "server.rack",
                state: backendState
            )
            FirstRunStepRow(
                title: "Config and bundled policies",
                detail: "Initialized in ~/.defenseclaw and ready for setup.",
                systemImage: "doc.text",
                state: .complete
            )
            FirstRunStepRow(
                title: "Secrets",
                detail: "Add a DefenseClaw LLM key in Setup, or explicitly skip for local-only diagnostics.",
                systemImage: "key",
                state: .needed
            )
            FirstRunStepRow(
                title: "Protection mode",
                detail: "Start in observe mode, then move to action mode when policy is tuned.",
                systemImage: "shield.checkered",
                state: .needed
            )

            Button {
                Task { await refreshHealth() }
            } label: {
                if isChecking {
                    Label("Checking", systemImage: "hourglass")
                } else {
                    Label("Run Ready Check", systemImage: "arrow.clockwise")
                }
            }
            .disabled(isChecking)
        }
        .padding(18)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(nsColor: .separatorColor).opacity(0.55), lineWidth: 0.5)
        )
    }

    private var setupPathCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Guided Setup Path", systemImage: "wand.and.stars")
                .font(.title3.weight(.semibold))

            Text("You only have to finish essentials before entering the console. The rest appears as guided setup tasks, not a wall of YAML fields.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 210), spacing: 12)], spacing: 12) {
                FirstRunFlowTile("LLM & Agents", "Provider, model, key reference, Codex/Claude/OpenClaw hooks.", "brain.head.profile", .blue)
                FirstRunFlowTile("Gateway", "Local helper, API bind, watcher, and OpenClaw connection.", "network", .teal)
                FirstRunFlowTile("Scanners", "Skill, MCP, plugin, and CodeGuard readiness.", "magnifyingglass", .purple)
                FirstRunFlowTile("Guardrail", "Observe/action mode, judge settings, regex rules.", "shield", .green)
                FirstRunFlowTile("Policy", "Suppressions, firewall, Rego, YAML and JSON editors.", "doc.text.magnifyingglass", .indigo)
                FirstRunFlowTile("Integrations", "Splunk, Datadog, OTel, Slack, PagerDuty, Webex.", "waveform.path.ecg", .orange)
            }
        }
        .padding(18)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(nsColor: .separatorColor).opacity(0.55), lineWidth: 0.5)
        )
    }

    private var actionBar: some View {
        HStack(spacing: 12) {
            Button {
                navigation.selection = .setup
                appViewModel.completeFirstRun()
            } label: {
                Label("Start Guided Setup", systemImage: "wand.and.stars")
            }
            .buttonStyle(.borderedProminent)

            Button {
                navigation.selection = .home
                appViewModel.completeFirstRun()
            } label: {
                Label("Enter Console", systemImage: "rectangle.split.2x1")
            }

            Button {
                navigation.selection = .operations
                appViewModel.completeFirstRun()
            } label: {
                Label("Open Diagnostics", systemImage: "stethoscope")
            }

            Spacer()

            Button("Skip for now") {
                navigation.selection = .home
                appViewModel.completeFirstRun()
            }
            .foregroundStyle(.secondary)
        }
    }

    private var backendDetail: String {
        guard let health = appViewModel.healthSnapshot else {
            return "The local backend is not reachable yet. Use Setup or Diagnostics to install or repair it."
        }
        if health.isHealthy {
            return "Sidecar is running and reporting healthy subsystem status."
        }
        return "Sidecar responded, but one or more subsystems need attention."
    }

    @MainActor
    private func refreshHealth() async {
        isChecking = true
        await appViewModel.checkHealth()
        isChecking = false
    }
}

private enum FirstRunStepState {
    case complete
    case warning
    case needed

    var color: Color {
        switch self {
        case .complete: return .green
        case .warning: return .orange
        case .needed: return .blue
        }
    }

    var icon: String {
        switch self {
        case .complete: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .needed: return "circle.dotted"
        }
    }
}

private struct FirstRunStepRow: View {
    let title: String
    let detail: String
    let systemImage: String
    let state: FirstRunStepState

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: systemImage)
                .foregroundStyle(state.color)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(title)
                        .font(.headline)
                    Image(systemName: state.icon)
                        .foregroundStyle(state.color)
                        .font(.caption)
                }
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
        .padding(12)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct FirstRunFlowTile: View {
    let title: String
    let subtitle: String
    let systemImage: String
    let tint: Color

    init(_ title: String, _ subtitle: String, _ systemImage: String, _ tint: Color) {
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.tint = tint
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: systemImage)
                .foregroundStyle(tint)
            Text(title)
                .font(.headline)
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(3)
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 118, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }
}
