import SwiftUI

enum OperatorSection: String, CaseIterable, Identifiable {
    case home
    case settings
    case scan
    case policy
    case alerts
    case tools
    case logs

    var id: String { rawValue }

    var title: String {
        switch self {
        case .home: return "Home"
        case .settings: return "Settings"
        case .scan: return "Scans"
        case .policy: return "Policy"
        case .alerts: return "Alerts"
        case .tools: return "Tools"
        case .logs: return "Logs"
        }
    }

    var subtitle: String {
        switch self {
        case .home: return "Health and posture"
        case .settings: return "Gateway, guardrail, enforcement"
        case .scan: return "Skills, MCPs, plugins, code"
        case .policy: return "Policy viewer and evaluator"
        case .alerts: return "Audit and findings"
        case .tools: return "Runtime tool catalog"
        case .logs: return "Application and gateway logs"
        }
    }

    var systemImage: String {
        switch self {
        case .home: return "shield.lefthalf.filled"
        case .settings: return "slider.horizontal.3"
        case .scan: return "magnifyingglass"
        case .policy: return "doc.text.magnifyingglass"
        case .alerts: return "bell.badge"
        case .tools: return "wrench.and.screwdriver"
        case .logs: return "terminal"
        }
    }
}

@Observable
final class OperatorNavigationModel {
    var selection: OperatorSection = .home
}

struct OperatorConsoleView: View {
    let navigation: OperatorNavigationModel

    private var selection: Binding<OperatorSection?> {
        Binding(
            get: { navigation.selection },
            set: { newValue in
                if let newValue {
                    navigation.selection = newValue
                }
            }
        )
    }

    var body: some View {
        NavigationSplitView {
            List(selection: selection) {
                Section("DefenseClaw") {
                    ForEach(OperatorSection.allCases) { section in
                        OperatorSidebarRow(section: section)
                            .tag(section)
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 220, ideal: 260, max: 320)
        } detail: {
            detailView
                .navigationTitle(navigation.selection.title)
        }
        .frame(minWidth: 1040, minHeight: 720)
    }

    @ViewBuilder
    private var detailView: some View {
        switch navigation.selection {
        case .home:
            DashboardView()
        case .settings:
            SettingsView()
        case .scan:
            ScanView()
        case .policy:
            PolicyView()
        case .alerts:
            AlertsView()
        case .tools:
            ToolsCatalogView()
        case .logs:
            LogsView()
        }
    }
}

private struct OperatorSidebarRow: View {
    let section: OperatorSection

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: section.systemImage)
                .foregroundStyle(.secondary)
                .frame(width: 16)

            VStack(alignment: .leading, spacing: 2) {
                Text(section.title)
                    .lineLimit(1)
                Text(section.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }
}
