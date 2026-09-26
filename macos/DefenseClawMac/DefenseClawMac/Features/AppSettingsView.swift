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

// App preferences (spec §10) — distinct from DefenseClaw's own Setup panel.

import SwiftUI
import ServiceManagement

struct AppSettingsView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        @Bindable var state = appState
        TabView(selection: $state.selectedSettingsTab) {
            GeneralSettings()
                .frame(width: 560, height: 620)
                .tabItem { Label("General", systemImage: "gearshape") }
                .tag(AppSettingsTab.general)
            MonitoringSettings()
                .frame(width: 560, height: 350)
                .tabItem { Label("Monitoring", systemImage: "waveform.path.ecg") }
                .tag(AppSettingsTab.monitoring)
            NotificationSettings()
                .frame(width: 560, height: 300)
                .tabItem { Label("Notifications", systemImage: "bell.badge") }
                .tag(AppSettingsTab.notifications)
            ConnectionSettings()
                .frame(width: 560, height: 540)
                .tabItem { Label("Connection", systemImage: "network") }
                .tag(AppSettingsTab.connection)
        }
    }
}

private struct GeneralSettings: View {
    @Environment(AppState.self) private var appState
    @AppStorage("showDockIcon") private var showDockIcon = true
    @AppStorage("hideOnMinimize") private var hideOnMinimize = false
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        Form {
            Section("General") {
                Toggle("Show Dock icon", isOn: $showDockIcon)
                    .onChange(of: showDockIcon) { _, newValue in
                        UserDefaults.standard.set(newValue, forKey: "showDockIconResolved")
                        NSApp.setActivationPolicy(newValue ? .regular : .accessory)
                        if newValue { NSApp.activate(ignoringOtherApps: true) }
                        if !newValue { hideOnMinimize = false }
                    }
                Toggle("Hide instead of minimize", isOn: $hideOnMinimize)
                    .disabled(!showDockIcon)
                Text(showDockIcon
                     ? "When enabled, the yellow window button temporarily removes the Dock icon. Reopen from the menu bar shield."
                     : "The app is already menu-bar-only while the Dock icon is hidden.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Toggle("Launch at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, newValue in
                        do {
                            if newValue { try SMAppService.mainApp.register() }
                            else { try SMAppService.mainApp.unregister() }
                        } catch {
                            launchAtLogin = SMAppService.mainApp.status == .enabled
                        }
                    }
                Label("Closing the window keeps DefenseClaw running in the menu bar. Use Quit in the menu bar popover (or ⌘Q) to fully exit.",
                      systemImage: "menubar.arrow.up.rectangle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Updates") {
                LabeledContent("Mac app", value: UpdateChecker.currentVersion)
                LabeledContent("Runtime (CLI + gateway)", value: runtimeInstalledValue)
                if appState.installedRuntimeVersion == nil, let error = appState.runtimeVersionError {
                    Text(error).font(.caption).foregroundStyle(.secondary)
                }
                LabeledContent("Latest release", value: latestReleaseValue)
                installerStatusRow
                HStack(spacing: 8) {
                    installerButton
                    Button(appState.updateCheckInProgress ? "Checking…" : "Check for Updates") {
                        Task { await appState.checkForUpdates(force: true) }
                    }
                    .disabled(appState.updateOperationInProgress)
                    if appState.installerState != .idle {
                        Button("Open Activity") {
                            appState.selectedPanel = .activity
                            AppDelegate.openMainWindow()
                        }
                    }
                }
                Text("Install and update run the release's install.sh, which brings the runtime and this app to the same version and rolls back automatically if a step fails.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text("The menu bar shield is always available while DefenseClaw is running.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .task {
            await appState.refreshInstalledRuntimeVersion()
        }
    }

    /// The one Install / Update action: update when a newer release exists,
    /// otherwise install this app's own version when no runtime is detected.
    @ViewBuilder
    private var installerButton: some View {
        if appState.relaunchPending {
            Button("Restart DefenseClaw") { appState.relaunch() }
                .buttonStyle(.borderedProminent)
        } else if let version = installerVersion {
            Button(installerButtonTitle(version)) {
                Task { await appState.runReleaseInstaller(version: version) }
            }
            .buttonStyle(.borderedProminent)
            .disabled(appState.updateOperationInProgress || !appState.installationMutationsAllowed)
        }
    }

    private var installerVersion: String? {
        if let update = appState.availableUpdate { return update.version }
        guard appState.installedRuntimeVersion == nil, !appState.runtimeVersionCheckInProgress else { return nil }
        return UpdateChecker.currentVersion
    }

    private func installerButtonTitle(_ version: String) -> String {
        if case .failed(let failed, _) = appState.installerState, failed == version { return "Try Again" }
        guard appState.availableUpdate != nil else { return "Install Runtime v\(version)" }
        return appState.updateRestartsApp ? "Update to \(version) & Restart" : "Update Runtime to \(version)"
    }

    @ViewBuilder
    private var installerStatusRow: some View {
        switch appState.installerState {
        case .idle:
            EmptyView()
        case .downloading(let version):
            progressRow("Downloading and verifying the \(version) installer…")
        case .running(let version):
            progressRow("Installing \(version); progress is in Activity…")
        case .installed(let version):
            Label(
                appState.relaunchPending ? "Installed \(version). Restart DefenseClaw to finish." : "Installed \(version).",
                systemImage: "checkmark.circle.fill"
            )
            .font(.caption).foregroundStyle(Cisco.green)
        case .needsAttention(let version, let detail):
            Label("Installed \(version), but a connector needs attention:\n\(detail)", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(Cisco.orange)
                .textSelection(.enabled)
        case .failed(let version, let detail):
            Label("Installing \(version) failed:\n\(detail)", systemImage: "xmark.circle.fill")
                .font(.caption).foregroundStyle(Cisco.red)
                .textSelection(.enabled)
        }
    }

    private func progressRow(_ text: String) -> some View {
        HStack(spacing: 6) {
            ProgressView().controlSize(.small)
            Text(text).font(.caption).foregroundStyle(.secondary)
        }
    }

    private var latestReleaseValue: String {
        if appState.updateCheckInProgress { return "Checking…" }
        if let update = appState.availableUpdate { return "\(update.version) available" }
        if appState.latestRelease != nil { return "Up to date" }
        return appState.lastCheckFailed ? "Could not check (offline or GitHub rate-limited)" : "Not checked yet"
    }

    private var runtimeInstalledValue: String {
        if let version = appState.installedRuntimeVersion {
            return version
        }
        return appState.runtimeVersionCheckInProgress ? "Detecting…" : "Not detected"
    }
}

private struct MonitoringSettings: View {
    @AppStorage(SettingsKeys.pulseInterval) private var pulseInterval: Double = 5
    @AppStorage(SettingsKeys.backgroundInterval) private var backgroundInterval: Double = 60
    @AppStorage(SettingsKeys.backgroundMonitoring) private var backgroundMonitoring = true

    var body: some View {
        Form {
            Section("Refresh cadence") {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Health pulse")
                        Spacer()
                        Text("\(Int(pulseInterval))s")
                            .font(.body.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    Slider(value: $pulseInterval, in: 2...60, step: 1) {
                        Text("Health pulse")
                    } minimumValueLabel: { Text("2s").font(.caption2) }
                      maximumValueLabel: { Text("60s").font(.caption2) }
                    .labelsHidden()
                    Text("Drives the menu bar icon, health card, and alert detection.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Background refresh")
                        Spacer()
                        Text(backgroundInterval >= 60
                             ? "\(Int(backgroundInterval / 60))m" : "\(Int(backgroundInterval))s")
                            .font(.body.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    Slider(value: $backgroundInterval, in: 15...300, step: 15) {
                        Text("Background refresh")
                    } minimumValueLabel: { Text("15s").font(.caption2) }
                      maximumValueLabel: { Text("5m").font(.caption2) }
                    .labelsHidden()
                    Text("Cadence for heavier panels (audit counts, AI usage) while the app runs.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Section {
                Toggle("Keep monitoring while window is hidden", isOn: $backgroundMonitoring)
            }
        }
        .formStyle(.grouped)
    }
}

private struct NotificationSettings: View {
    @AppStorage(SettingsKeys.notifyCritical) private var notifyCritical = true
    @AppStorage(SettingsKeys.notifyHigh) private var notifyHigh = true
    @AppStorage(SettingsKeys.notifyGatewayOffline) private var notifyGatewayOffline = true
    @AppStorage(SettingsKeys.seenAlertHighWater) private var seenAlertHighWater: Double = 0

    var body: some View {
        Form {
            Section("Desktop notifications") {
                Toggle("Notify on CRITICAL findings", isOn: $notifyCritical)
                Toggle("Notify on HIGH findings", isOn: $notifyHigh)
                Toggle("Notify when gateway goes offline / recovers", isOn: $notifyGatewayOffline)
                Text("Notifications include target and severity only — never prompt or payload contents.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section {
                Button("Reset seen-alert history") { seenAlertHighWater = 0 }
            }
        }
        .formStyle(.grouped)
    }
}

private struct ConnectionSettings: View {
    @Environment(AppState.self) private var appState
    @AppStorage(CLIRunner.pathOverrideKey) private var binaryPath = ""
    @State private var configPathOverride = UserDefaults.standard.string(
        forKey: InstallationContext.configPathOverrideKey
    ) ?? ""

    var body: some View {
        Form {
            Section("Gateway") {
                LabeledContent("Endpoint", value: "http://\(appState.config.gatewayHost):\(appState.config.gatewayPort)")
                LabeledContent("Token", value: appState.config.gatewayToken == nil ? "not set" : "configured (hidden)")
            }
            Section("Installation") {
                LabeledContent("Selected by", value: appState.installationContext.source.label)
                LabeledContent("Access", value: appState.installationContext.accessMode.label)
                if let reason = appState.installationReadOnlyReason {
                    Label(reason, systemImage: "lock.shield")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Config path override")
                    TextField("absolute path to config.yaml", text: $configPathOverride)
                        .textFieldStyle(.roundedBorder)
                    Text("DEFENSECLAW_CONFIG takes precedence. Leave blank to use DEFENSECLAW_HOME, the managed package, or ~/.defenseclaw.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                HStack {
                    Button("Apply Installation") {
                        appState.applyInstallationConfigOverride(configPathOverride)
                    }
                    .disabled(!appState.installationContextSwitchAllowed)
                    Button("Use Automatic Selection") {
                        configPathOverride = ""
                        appState.applyInstallationConfigOverride("")
                    }
                    .disabled(
                        !appState.installationContextSwitchAllowed
                            || (configPathOverride.isEmpty
                                && appState.installationContext.source != .appOverride)
                    )
                }
            }
            // Paths get their own line, monospaced + selectable, so long
            // values aren't clipped by the label/value column truncation.
            Section("Files") {
                pathRow("Config", appState.installationContext.configURL.path)
                pathRow("Data", appState.installationContext.dataDirectory.path)
                pathRow("Environment", appState.installationContext.environmentURL.path)
                pathRow("Audit DB", appState.installationContext.auditDBURL.path)
                pathRow("Virtual environment", appState.installationContext.venvURL.path)
                pathRow("Gateway log", appState.installationContext.gatewayLogURL.path)
            }
            Section("defenseclaw CLI") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Binary path (optional override)")
                    TextField("auto-detected on PATH if blank", text: $binaryPath)
                        .textFieldStyle(.roundedBorder)
                }
                Button("Reload config.yaml now") { appState.reloadConfig() }
            }
        }
        .formStyle(.grouped)
    }

    private func pathRow(_ label: String, _ path: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                .font(.callout.monospaced())
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
