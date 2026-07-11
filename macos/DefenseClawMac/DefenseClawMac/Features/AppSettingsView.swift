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
    var body: some View {
        TabView {
            GeneralSettings()
                .frame(width: 560, height: 620)
                .tabItem { Label("General", systemImage: "gearshape") }
            MonitoringSettings()
                .frame(width: 560, height: 350)
                .tabItem { Label("Monitoring", systemImage: "waveform.path.ecg") }
            NotificationSettings()
                .frame(width: 560, height: 300)
                .tabItem { Label("Notifications", systemImage: "bell.badge") }
            ConnectionSettings()
                .frame(width: 560, height: 420)
                .tabItem { Label("Connection", systemImage: "network") }
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

            Section("Updates — Mac app (this application)") {
                LabeledContent("Installed", value: UpdateChecker.currentVersion)
                if let update = appState.availableUpdate {
                    LabeledContent("Available", value: update.tag)
                    macAppStatus
                } else {
                    LabeledContent("Status",
                                   value: appState.appUpdateCheckFailed
                                       ? "Could not check (offline or GitHub rate-limited)"
                                       : "Up to date")
                }
            }

            Section("Updates — DefenseClaw runtime (CLI + gateway)") {
                LabeledContent("Installed", value: runtimeInstalledValue)
                if let update = appState.availableRuntimeUpdate {
                    LabeledContent("Available", value: update.tag)
                    runtimeStatus
                    if case .failed = appState.runtimeUpgradeState, !appState.runtimeUpgradeLog.isEmpty {
                        Button("Copy Full Upgrade Log") {
                            copyToPasteboard(appState.runtimeUpgradeLog)
                        }
                        .controlSize(.small)
                    }
                    Text("The app does not run a bare CLI upgrade. Choose Show Upgrade Path below for a copy/paste command that authenticates the release-owned defenseclaw-upgrade.sh asset, checksums.txt manifest, signature, and certificate before running latest mode without --version. The same path is documented at https://github.com/cisco-ai-defense/defenseclaw/blob/0.8.4/docs/CLI.md#upgrade.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    LabeledContent("Status", value: runtimeStatusSummary)
                }
                if let payload = RuntimePayload.bundled {
                    LabeledContent("Bundled payload", value: "v\(payload.version)")
                    installStateRow
                    Button("Install Runtime v\(payload.version) (fresh install only)") {
                        Task { await appState.installBundledRuntime() }
                    }
                    .disabled(appState.runtimeInstallState.isRunning || runtimeActionDisabled)
                    Text("Fresh installs only. If an existing or partial runtime is detected, this action makes no changes and directs you to the release-owned latest-mode upgrade resolver. A true fresh install lays the bundled runtime into ~/.defenseclaw and ~/.local/bin; dependency download from PyPI requires network.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Update Actions") {
                HStack(spacing: 8) {
                    Button(macAppButtonTitle) {
                        appState.performMacAppUpgradeCheck()
                    }
                    .disabled(macAppActionDisabled)

                    Button(runtimeButtonTitle) {
                        appState.performRuntimeUpgradeCheck()
                    }
                    .disabled(runtimeActionDisabled)

                    Button(bothButtonTitle) {
                        appState.performBothUpgrades()
                    }
                    .disabled(macAppActionDisabled || runtimeActionDisabled)
                }
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

    @ViewBuilder
    private var installStateRow: some View {
        switch appState.runtimeInstallState {
        case .idle:
            EmptyView()
        case .running(let step):
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text(step).font(.caption).foregroundStyle(.secondary)
            }
        case .failed(let why):
            Label(why, systemImage: "xmark.circle.fill")
                .font(.caption).foregroundStyle(Cisco.red)
                .textSelection(.enabled)
        case .succeeded:
            Label("Runtime installed.", systemImage: "checkmark.circle.fill")
                .font(.caption).foregroundStyle(Cisco.green)
        }
    }

    @ViewBuilder
    private var macAppStatus: some View {
        switch appState.upgradeState {
        case .checking:
            Text("Checking…").font(.caption).foregroundStyle(.secondary)
        case .downloading:
            Text("Downloading…").font(.caption).foregroundStyle(.secondary)
        case .installing:
            Text("Installing…").font(.caption).foregroundStyle(.secondary)
        case .failed(let why):
            Text(why).font(.caption).foregroundStyle(Cisco.red).lineLimit(2)
        default:
            EmptyView()
        }
    }

    @ViewBuilder
    private var runtimeStatus: some View {
        switch appState.runtimeUpgradeState {
        case .checking:
            Text("Checking…").font(.caption).foregroundStyle(.secondary)
        case .installing, .downloading:
            Text(appState.runtimeUpgradeLogTail.isEmpty ? "Preparing release-owned resolver guidance…" : appState.runtimeUpgradeLogTail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        case .failed(let why):
            Text(why).font(.caption).foregroundStyle(Cisco.red).lineLimit(2)
        default:
            EmptyView()
        }
    }

    private var macAppButtonTitle: String {
        switch appState.upgradeState {
        case .checking: "Checking App…"
        case .downloading: "Downloading App…"
        case .installing: "Installing App…"
        default: appState.availableUpdate == nil ? "Check Mac App" : "Install & Restart"
        }
    }

    private var runtimeButtonTitle: String {
        switch appState.runtimeUpgradeState {
        case .checking: "Checking Runtime…"
        case .downloading, .installing: "Preparing Upgrade Path…"
        default: appState.availableRuntimeUpdate == nil ? "Check Runtime" : "Show Upgrade Path"
        }
    }

    private var bothButtonTitle: String {
        if appState.availableUpdate != nil || appState.availableRuntimeUpdate != nil {
            return "Install Available Updates"
        }
        return "Check Both"
    }

    private var runtimeStatusSummary: String {
        if appState.runtimeVersionCheckInProgress {
            return "Detecting installed runtime…"
        }
        if let error = appState.runtimeVersionError {
            return error
        }
        guard appState.installedRuntimeVersion != nil else {
            return "Runtime CLI not detected"
        }
        if appState.runtimeUpdateCheckFailed {
            return "Installed; update check unavailable"
        }
        if !appState.runtimeReleaseChecked {
            return "Installed"
        }
        return "Up to date"
    }

    private var runtimeInstalledValue: String {
        if let version = appState.installedRuntimeVersion {
            return version
        }
        return appState.runtimeVersionCheckInProgress ? "Detecting…" : "Not detected"
    }

    private var macAppActionDisabled: Bool {
        switch appState.upgradeState {
        case .checking, .downloading, .installing: true
        default: false
        }
    }

    private var runtimeActionDisabled: Bool {
        if appState.runtimeVersionCheckInProgress { return true }
        // Do not overlap bundled-payload installation with upgrade guidance.
        if appState.runtimeInstallState.isRunning { return true }
        return switch appState.runtimeUpgradeState {
        case .checking, .downloading, .installing: true
        default: false
        }
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

    var body: some View {
        Form {
            Section("Gateway") {
                LabeledContent("Endpoint", value: "http://\(appState.config.gatewayHost):\(appState.config.gatewayPort)")
                LabeledContent("Token", value: appState.config.gatewayToken == nil ? "not set" : "configured (hidden)")
            }
            // Paths get their own line, monospaced + selectable, so long
            // values aren't clipped by the label/value column truncation.
            Section("Files") {
                pathRow("Config", ConfigStore.configURL.path)
                pathRow("Audit DB", ConfigStore.auditDBURL.path)
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
