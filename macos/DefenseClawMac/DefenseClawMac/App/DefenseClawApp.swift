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

// DefenseClaw for macOS — app entry. Menu-bar-first (spec §5):
// MenuBarExtra always present; main window hides to the menu bar on close;
// Dock icon presence is a runtime setting (NSApp activation policy).

import SwiftUI
import ServiceManagement

@main
struct DefenseClawApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup("DefenseClaw", id: "main") {
            MainWindow()
                .environment(appState)
                .frame(minWidth: 980, minHeight: 640)
                .onAppear { appState.start() }
        }
        .defaultSize(width: 1180, height: 760)
        .commands {
            // DefenseClaw has one primary dashboard; WindowGroup gives the menu
            // bar a reliable recreation target without exposing duplicate windows.
            CommandGroup(replacing: .newItem) { }
            CommandGroup(after: .appSettings) {
                Button("Check for Updates…") {
                    Task { await appState.checkForUpdates(force: true) }
                    // Surface the result where the versions live: Settings ▸ General.
                    if NSApp.responds(to: Selector(("showSettingsWindow:"))) {
                        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
                    }
                }
                .disabled(appState.updateOperationInProgress)
            }
            CommandGroup(after: .toolbar) {
                Button("Refresh Panel") {
                    NotificationCenter.default.post(name: .dcRefreshPanel, object: nil)
                }
                .keyboardShortcut("r", modifiers: .command)
            }
            CommandMenu("Monitor") {
                Button("Run Health Check") {
                    appState.selectedPanel = .overview
                    DispatchQueue.main.async {
                        NotificationCenter.default.post(name: .dcRunHealthCheck, object: nil)
                    }
                }
                .keyboardShortcut("h", modifiers: [.command, .shift])
                .disabled(!appState.installationMutationsAllowed)

                Button("Scan AI Components") {
                    appState.selectedPanel = .aiDiscovery
                    DispatchQueue.main.async {
                        NotificationCenter.default.post(name: .dcScanAIDiscovery, object: nil)
                    }
                }
                .keyboardShortcut("a", modifiers: [.command, .shift])
                .disabled(
                    !appState.gatewayReachable
                        || appState.scanInFlight
                        || !appState.installationMutationsAllowed
                )

                // The TUI's `m` key: step the shared connector filter
                // All → conn0 → conn1 → … → All across every panel.
                Button("Cycle Connector Filter") {
                    appState.cycleConnectorFilter()
                }
                .keyboardShortcut("m", modifiers: [.control])
                .disabled(appState.activeConnectorNames.count <= 1)
            }
            CommandMenu("Commands") {
                Button("Command Palette…") {
                    appState.commandPalettePresented = true
                }
                .keyboardShortcut("p", modifiers: [.command, .shift])

                Divider()

                // The TUI's Y yank / Ctrl+S export / Shift+D diagnose chrome.
                Button("Copy Last Command Output") {
                    appState.copyLastCommandOutput()
                }
                .keyboardShortcut("y", modifiers: [.control])

                Button("Export Last Command Output") {
                    appState.exportLastCommandOutput()
                }
                .keyboardShortcut("s", modifiers: [.control])
                .disabled(!appState.installationMutationsAllowed)

                Button("Diagnose in Background") {
                    appState.runBackgroundDiagnose()
                }
                .keyboardShortcut("d", modifiers: [.command, .shift])
                .disabled(appState.diagnoseRunning || !appState.installationMutationsAllowed)
            }
            CommandMenu("Go") {
                ForEach(Array(PanelID.allCases.enumerated()), id: \.element) { index, panel in
                    if index < 9 {
                        Button(panel.title) { appState.selectedPanel = panel }
                            .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
                    } else if index == 9 {
                        Button(panel.title) { appState.selectedPanel = panel }
                            .keyboardShortcut("0", modifiers: .command)
                    } else if panel == .setup {
                        // ⌘⇧3 would collide with macOS's screenshot hotkey.
                        Button(panel.title) { appState.selectedPanel = panel }
                            .keyboardShortcut("s", modifiers: [.command, .shift])
                    } else {
                        Button(panel.title) { appState.selectedPanel = panel }
                            .keyboardShortcut(KeyEquivalent(Character("\(index - 9)")), modifiers: [.command, .shift])
                    }
                }
            }
            CommandGroup(replacing: .help) {
                Link(
                    "DefenseClaw Help",
                    destination: URL(string: "https://cisco-ai-defense.github.io/defenseclaw/docs/")!
                )
            }
        }

        MenuBarExtra {
            MenuBarPopover()
                .environment(appState)
        } label: {
            MenuBarIcon()
                .environment(appState)
        }
        .menuBarExtraStyle(.window)

        Settings {
            AppSettingsView()
                .environment(appState)
        }
    }
}

// Custom template shields (Assets.xcassets) — system tints them for the
// menu bar's light/dark/active states.
private struct MenuBarIcon: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        switch appState.menuBarState {
        case .healthy:
            Image("MenuBarShield")
        case .alerting(let count):
            Image("MenuBarShieldFill")
            Text("\(count)")
        case .degraded:
            Image("MenuBarShieldHalf")
        case .offline:
            Image("MenuBarShieldSlash")
        case .scanning:
            Image("MenuBarShield")
            Image(systemName: "arrow.triangle.2.circlepath")
        case .paused:
            Image("MenuBarShield")
            Image(systemName: "pause.fill")
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    static var recreateMainWindow: (() -> Void)?
    private var miniaturizeObserver: NSObjectProtocol?

    func applicationDidFinishLaunching(_ notification: Notification) {
        applyActivationPolicy()

        // Optional hide-instead-of-minimize behavior. Standard macOS minimize is
        // the default; people can opt into a menu-bar-only transition in Settings.
        miniaturizeObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.didMiniaturizeNotification, object: nil, queue: .main
        ) { notification in
            guard UserDefaults.standard.object(forKey: "hideOnMinimize") as? Bool ?? false,
                  let window = notification.object as? NSWindow,
                  !(window is NSPanel)
            else { return }
            // Order the miniaturized window out (removes its Dock tile) and
            // drop to a menu-bar-only accessory app. The window stays in its
            // miniaturized state; openMainWindow() deminiaturizes on reopen.
            // (Deminiaturizing here instead races orderOut and re-shows it.)
            window.orderOut(nil)
            NSApp.setActivationPolicy(.accessory)
        }
    }

    /// The menu bar is the app's persistent anchor: closing the main window
    /// (red X) NEVER terminates the process — only "Quit" from the menu bar
    /// popover (or ⌘Q, which routes through NSApp.terminate) ends it.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Tidy the Dock when the icon is hidden: drop to a pure menu-bar agent
        // so no empty Dock tile lingers. With the Dock icon shown, keep the
        // tile so the window can be reopened by clicking it.
        let showDock = UserDefaults.standard.object(forKey: "showDockIcon") as? Bool ?? true
        if !showDock {
            NSApp.setActivationPolicy(.accessory)
        }
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { AppDelegate.openMainWindow() }
        return true
    }

    func applyActivationPolicy() {
        let showDock = UserDefaults.standard.object(forKey: "showDockIcon") as? Bool ?? true
        UserDefaults.standard.set(showDock, forKey: "showDockIconResolved")
        NSApp.setActivationPolicy(showDock ? .regular : .accessory)
    }

    static func openMainWindow() {
        NSApp.setActivationPolicy(
            (UserDefaults.standard.object(forKey: "showDockIcon") as? Bool ?? true) ? .regular : .accessory
        )
        NSApp.activate(ignoringOtherApps: true)
        for window in NSApp.windows where window.identifier?.rawValue.contains("main") == true {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.makeKeyAndOrderFront(nil)
            return
        }
        // A non-main utility window must never be promoted as the dashboard.
        // Ask SwiftUI to recreate the released WindowGroup instead.
        recreateMainWindow?()
    }
}

extension Notification.Name {
    static let dcRefreshPanel = Notification.Name("dcRefreshPanel")
    static let dcRunHealthCheck = Notification.Name("dcRunHealthCheck")
    static let dcScanAIDiscovery = Notification.Name("dcScanAIDiscovery")
}
