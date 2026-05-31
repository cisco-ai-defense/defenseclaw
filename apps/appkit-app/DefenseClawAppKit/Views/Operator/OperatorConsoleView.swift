import SwiftUI

enum OperatorSection: String, CaseIterable, Identifiable {
    case home
    case setup
    case protection
    case scan
    case inventory
    case policy
    case alerts
    case operations
    case advanced

    var id: String { rawValue }

    var title: String {
        switch self {
        case .home: return "Home"
        case .setup: return "Setup"
        case .protection: return "Protection"
        case .scan: return "Scans"
        case .inventory: return "Inventory"
        case .policy: return "Policy"
        case .alerts: return "Alerts"
        case .operations: return "Operations"
        case .advanced: return "Advanced"
        }
    }

    var subtitle: String {
        switch self {
        case .home: return "Health and posture"
        case .setup: return "Wizards and integrations"
        case .protection: return "Guardrails and enforcement"
        case .scan: return "Skills, MCPs, plugins, code"
        case .inventory: return "Installed skills, MCPs, and plugins"
        case .policy: return "Rich policy editors"
        case .alerts: return "Audit and findings"
        case .operations: return "Diagnostics, logs, services"
        case .advanced: return "Raw files and tools"
        }
    }

    var systemImage: String {
        switch self {
        case .home: return "shield.lefthalf.filled"
        case .setup: return "wand.and.stars"
        case .protection: return "shield.checkered"
        case .scan: return "magnifyingglass"
        case .inventory: return "square.stack.3d.up"
        case .policy: return "doc.text.magnifyingglass"
        case .alerts: return "bell.badge"
        case .operations: return "stethoscope"
        case .advanced: return "slider.horizontal.3"
        }
    }
}

@Observable
final class OperatorNavigationModel {
    var selection: OperatorSection = .home
}

struct OperatorConsoleView: View {
    @Environment(AppViewModel.self) private var appViewModel
    let navigation: OperatorNavigationModel
    @State private var sidebarCompact = false

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
        Group {
            if appViewModel.firstRunCompleted {
                NavigationSplitView {
                    List(selection: selection) {
                        Section {
                            ForEach(OperatorSection.allCases) { section in
                                OperatorSidebarRow(section: section, compact: sidebarCompact)
                                    .tag(section)
                            }
                        } header: {
                            if !sidebarCompact {
                                Text("DefenseClaw")
                            }
                        }
                    }
                    .listStyle(.sidebar)
                    .navigationSplitViewColumnWidth(sidebarCompact ? 64 : 260)
                    .toolbar {
                        ToolbarItem(placement: .navigation) {
                            Button {
                                withAnimation(.easeInOut(duration: 0.15)) { sidebarCompact.toggle() }
                            } label: {
                                Image(systemName: "sidebar.left")
                            }
                            .help(sidebarCompact ? "Show sidebar labels" : "Collapse sidebar to icons")
                        }
                    }
                } detail: {
                    detailView
                        .navigationTitle(navigation.selection.title)
                }
                .background(
                    GeometryReader { geo in
                        Color.clear
                            .onChange(of: geo.size.width) { _, width in
                                updateSidebarCompaction(for: width)
                            }
                            .onAppear { updateSidebarCompaction(for: geo.size.width) }
                    }
                )
            } else {
                FirstRunSetupView(navigation: navigation, appViewModel: appViewModel)
            }
        }
        .frame(minWidth: 800, minHeight: 720)
    }

    /// Auto-collapse the sidebar to an icon rail when the window is too narrow
    /// to show it docked alongside the detail content (instead of overlaying).
    private func updateSidebarCompaction(for width: CGFloat) {
        let shouldCompact = width < 980
        if shouldCompact != sidebarCompact {
            withAnimation(.easeInOut(duration: 0.15)) {
                sidebarCompact = shouldCompact
            }
        }
    }

    @ViewBuilder
    private var detailView: some View {
        switch navigation.selection {
        case .home:
            DashboardView()
        case .setup:
            SetupView()
        case .protection:
            ProtectionView()
        case .scan:
            ScanView()
        case .inventory:
            InventoryView()
        case .policy:
            PolicyView()
        case .alerts:
            AlertsView()
        case .operations:
            OperationsView()
        case .advanced:
            AdvancedView()
        }
    }
}

private struct OperatorSidebarRow: View {
    let section: OperatorSection
    var compact: Bool = false

    var body: some View {
        if compact {
            HStack {
                Spacer(minLength: 0)
                Image(systemName: section.systemImage)
                    .foregroundStyle(.secondary)
                    .frame(width: 22)
                Spacer(minLength: 0)
            }
            .padding(.vertical, 6)
            .help(section.title)
        } else {
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
}
