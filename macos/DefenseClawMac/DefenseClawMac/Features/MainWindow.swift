// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Main window (spec §5.2): sidebar grouped Monitor / Govern / Discover / Configure.

import SwiftUI

struct MainWindow: View {
    @Environment(AppState.self) private var appState
    @Environment(\.openWindow) private var openWindow
    @SceneStorage("main.selectedPanel") private var selectedPanelRaw = PanelID.overview.rawValue

    private let groups: [(String, [PanelID])] = [
        ("Monitor", [.overview, .alerts, .logs, .audit, .activity]),
        ("Govern", [.skills, .mcps, .plugins, .tools]),
        ("Discover", [.inventory, .aiDiscovery, .aiRuntime, .registries]),
        ("Configure", [.setup]),
    ]

    var body: some View {
        // Keep sidebar visibility under NavigationSplitView/user control.
        // Coupling it to inspector lifecycle events can create a re-entrant
        // AppKit constraint pass while SwiftUI is inserting the inspector.
        NavigationSplitView {
            List(selection: selectedPanelBinding) {
                ForEach(groups, id: \.0) { group in
                    Section(group.0) {
                        ForEach(group.1) { panel in
                            Label {
                                HStack {
                                    Text(panel.title)
                                    Spacer()
                                    badge(for: panel)
                                }
                            } icon: {
                                Image(systemName: panel.systemImage)
                            }
                            .tag(panel)
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 210)
        } detail: {
            panelView(selectedPanel)
                .navigationTitle(selectedPanel.title)
        }
        .overlay(alignment: .top) {
            VStack(spacing: 6) {
                if let err = appState.lastGatewayError, case .unauthorized = err {
                    tokenBanner
                }
                if appState.availableUpdate != nil, !appState.updateBannerDismissed {
                    updateBanner
                }
            }
        }
        // A real (writable) binding so the environment DismissAction works —
        // dismissal is remembered for this launch only, never faked as
        // installDetected (that flag means "config.yaml exists" and feeds
        // guardrail notices).
        .sheet(isPresented: Binding(
            get: { !appState.installDetected && !appState.firstRunDismissed },
            set: { if !$0 { appState.firstRunDismissed = true } }
        )) {
            FirstRunView()
                .environment(appState)
        }
        .sheet(isPresented: commandPaletteBinding) {
            CommandPaletteView()
                .environment(appState)
        }
        .toolbar {
            ToolbarItem {
                Button { appState.commandPalettePresented = true } label: {
                    Label("Command Palette", systemImage: "command")
                }
                .dcQuickHelp("Command Palette (Command-Shift-P)")
            }
        }
        .onAppear {
            // Deep links/menu actions may select a panel before SwiftUI
            // restores SceneStorage. Preserve that explicit selection; only
            // restore SceneStorage when AppState is still at its default.
            if appState.selectedPanel != .overview || selectedPanelRaw == PanelID.overview.rawValue {
                selectedPanelRaw = appState.selectedPanel.rawValue
            } else {
                appState.selectedPanel = selectedPanel
            }
            AppDelegate.recreateMainWindow = { openWindow(id: "main") }
        }
        .onChange(of: appState.selectedPanel) { _, panel in
            if panel != selectedPanel {
                selectedPanelRaw = panel.rawValue
            }
        }
    }

    private var selectedPanel: PanelID {
        PanelID(rawValue: selectedPanelRaw) ?? .overview
    }

    private var selectedPanelBinding: Binding<PanelID> {
        Binding(
            get: { selectedPanel },
            set: { panel in
                selectedPanelRaw = panel.rawValue
                appState.selectedPanel = panel
            }
        )
    }

    private var commandPaletteBinding: Binding<Bool> {
        Binding(
            get: { appState.commandPalettePresented },
            set: { appState.commandPalettePresented = $0 }
        )
    }

    @ViewBuilder
    private func badge(for panel: PanelID) -> some View {
        switch panel {
        // Badge = all severity-bearing alerts (C/H/M/L) — same definition as
        // the Overview Findings tile so the two numbers always agree.
        case .alerts where appState.unackedAlerts.contains(where: { $0.severity > .info }):
            Text("\(appState.unackedAlerts.filter { $0.severity > .info }.count)")
                .font(.caption2.weight(.bold))
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(Cisco.red, in: Capsule())
                .foregroundStyle(.white)
        case .overview:
            if case .degraded = appState.menuBarState {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.caption2)
                    .foregroundStyle(Cisco.orange)
            }
        default:
            EmptyView()
        }
    }

    @ViewBuilder
    private func panelView(_ panel: PanelID) -> some View {
        switch panel {
        case .overview: OverviewView()
        case .alerts: AlertsView()
        case .logs: LogsView()
        case .audit: AuditView()
        case .activity: ActivityView()
        case .skills: SkillsView()
        case .mcps: MCPsView()
        case .plugins: PluginsView()
        case .tools: ToolsView()
        case .inventory: InventoryView()
        case .aiDiscovery: AIDiscoveryView()
        case .aiRuntime: AIRuntimeView()
        case .registries: RegistriesView()
        case .setup: SetupView()
        }
    }

    /// One banner for the app and the runtime: the release's install.sh
    /// updates both, then the app restarts if its bundle was replaced.
    private var updateBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.down.circle.fill")
            VStack(alignment: .leading, spacing: 1) {
                Text("DefenseClaw \(appState.availableUpdate?.version ?? "") is available")
                    .font(.callout.weight(.semibold))
                Text(updateStatusText)
                    .font(.caption2)
                    .opacity(0.85)
                    .lineLimit(4)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if appState.installerState.isBusy {
                ProgressView().controlSize(.small).padding(.leading, 4)
            } else {
                if appState.relaunchPending {
                    Button("Restart Now") { appState.relaunch() }
                        .controlSize(.small)
                } else if let update = appState.availableUpdate {
                    Button(updateFailed ? "Try Again" : (appState.updateRestartsApp ? "Update & Restart" : "Update Runtime")) {
                        Task { await appState.runReleaseInstaller(version: update.version) }
                    }
                    .controlSize(.small)
                    .keyboardShortcut("u", modifiers: [.command, .shift])
                    .disabled(!appState.installationMutationsAllowed)
                }
                if let url = appState.availableUpdate.flatMap({ URL(string: $0.htmlURL) }) {
                    Link("Release notes", destination: url)
                        .font(.caption)
                }
                Button { appState.updateBannerDismissed = true } label: {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Dismiss update")
            }
        }
        .padding(10)
        .background(Cisco.blue.opacity(0.95), in: RoundedRectangle(cornerRadius: 8))
        .foregroundStyle(.white)
        .padding(.top, 6)
    }

    /// Installer progress for this update — not for a first-run install of
    /// the app's own version, which the first-run sheet reports.
    private var bannerInstallerState: InstallerState {
        appState.installerState.version == appState.availableUpdate?.version ? appState.installerState : .idle
    }

    private var updateFailed: Bool {
        if case .failed = bannerInstallerState { return true }
        return false
    }

    private var updateStatusText: String {
        switch bannerInstallerState {
        case .downloading:
            return "Downloading and verifying the release installer…"
        case .running:
            return "Installing; progress is in Activity…"
        case .needsAttention(_, let detail):
            return "Installed, but a connector needs attention: \(detail)"
        case .failed(_, let detail):
            return "Update failed: \(detail)"
        case .installed, .idle:
            if appState.relaunchPending { return "Installed. Restart DefenseClaw to finish the update." }
            return "Installed: app \(UpdateChecker.currentVersion), runtime \(appState.installedRuntimeVersion ?? "not detected"). ⌘⇧U updates both."
        }
    }

    private var tokenBanner: some View {
        HStack {
            Image(systemName: "key.slash")
            Text("Gateway token rejected — config.yaml token may have been rotated.")
                .font(.callout)
            Button("Reload Config") { appState.reloadConfig() }
                .controlSize(.small)
        }
        .padding(10)
        .background(Cisco.orange.opacity(0.92), in: RoundedRectangle(cornerRadius: 8))
        .foregroundStyle(.black)
        .padding(.top, 6)
    }
}
