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
        ("Discover", [.inventory, .aiDiscovery, .registries]),
        ("Configure", [.setup]),
    ]

    var body: some View {
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
                if appState.availableRuntimeUpdate != nil, !appState.runtimeBannerDismissed {
                    runtimeUpdateBanner
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
                .help("Command Palette (Command-Shift-P)")
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
        case .registries: RegistriesView()
        case .setup: SetupView()
        }
    }

    private var updateBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.down.circle.fill")
            VStack(alignment: .leading, spacing: 1) {
                Text("DefenseClaw for macOS \(appState.availableUpdate?.tag ?? "") is available")
                    .font(.callout.weight(.semibold))
                Text(upgradeStatusText)
                    .font(.caption2)
                    .opacity(0.85)
            }
            switch appState.upgradeState {
            case .downloading, .installing:
                ProgressView().controlSize(.small).padding(.leading, 4)
            default:
                Button("Upgrade & Restart") { appState.performUpgrade() }
                    .controlSize(.small)
                    .keyboardShortcut("u", modifiers: [.command, .shift])
                if let url = appState.availableUpdate.flatMap({ URL(string: $0.htmlURL) }) {
                    Link("Release notes", destination: url)
                        .font(.caption)
                }
                Button { appState.updateBannerDismissed = true } label: {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Dismiss app update")
            }
        }
        .padding(10)
        .background(Cisco.blue.opacity(0.95), in: RoundedRectangle(cornerRadius: 8))
        .foregroundStyle(.white)
        .padding(.top, 6)
    }

    private var upgradeStatusText: String {
        switch appState.upgradeState {
        case .idle, .checking: "Mac app update — installed: \(UpdateChecker.currentVersion). ⌘⇧U upgrades this app and restarts it."
        case .downloading: "Downloading release…"
        case .installing: "Installing and restarting…"
        case .actionRequired(let guidance, _): "Action required: \(guidance)"
        case .failed(let why): "Upgrade failed: \(why)"
        }
    }

    /// Distinct from the Mac-app banner: runtime mutation must happen through
    /// the release-owned latest-mode resolver outside this app.
    private var runtimeUpdateBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: "server.rack")
                .foregroundStyle(Cisco.green)
            VStack(alignment: .leading, spacing: 1) {
                Text("DefenseClaw runtime \(appState.availableRuntimeUpdate?.tag ?? "") is available")
                    .font(.callout.weight(.semibold))
                Text(runtimeStatusText)
                    .font(.caption2)
                    .foregroundStyle(isRuntimeFailed ? Cisco.red : .secondary)
                    .lineLimit(isRuntimeFailed || isRuntimeActionRequired ? 4 : 1)
                    .fixedSize(horizontal: false, vertical: true)
            }
            switch appState.runtimeUpgradeState {
            case .checking, .installing, .downloading:
                ProgressView().controlSize(.small).padding(.leading, 4)
            case .actionRequired(_, let command):
                Button("Copy Upgrade Command") { copyToPasteboard(command) }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                    .tint(Cisco.green)
                    .help("Copy the authenticated resolver command to run in Terminal")
                if let url = appState.availableRuntimeUpdate.flatMap({ URL(string: $0.htmlURL) }) {
                    Link("Release notes", destination: url)
                        .font(.caption)
                }
                Button { appState.runtimeBannerDismissed = true } label: {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Dismiss runtime update")
            default:
                Button("Show Upgrade Command") { appState.performRuntimeUpgrade() }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                    .tint(Cisco.green)
                if let url = appState.availableRuntimeUpdate.flatMap({ URL(string: $0.htmlURL) }) {
                    Link("Release notes", destination: url)
                        .font(.caption)
                }
                Button { appState.runtimeBannerDismissed = true } label: {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Dismiss runtime update")
            }
        }
        .padding(10)
        .background(Cisco.surfaceRaised, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Cisco.green.opacity(0.6)))
        .padding(.top, 6)
    }

    private var isRuntimeFailed: Bool {
        if case .failed = appState.runtimeUpgradeState { return true }
        return false
    }

    private var isRuntimeActionRequired: Bool {
        if case .actionRequired = appState.runtimeUpgradeState { return true }
        return false
    }

    private var runtimeStatusText: String {
        switch appState.runtimeUpgradeState {
        case .checking:
            return "Checking for the latest DefenseClaw runtime…"
        case .installing, .downloading:
            return appState.runtimeUpgradeLogTail.isEmpty
                ? "Preparing release-owned resolver guidance…"
                : appState.runtimeUpgradeLogTail
        case .actionRequired(let guidance, _):
            return guidance
        case .failed(let why):
            return why
        default:
            return "Runtime update (CLI + gateway) — installed: \(appState.installedRuntimeVersion ?? "unknown"). Use the release-owned resolver in latest mode without --version."
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
