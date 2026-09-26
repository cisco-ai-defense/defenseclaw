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

#if !CONNECTOR_DISCOVERY_SELECTION_TESTS
import SwiftUI
#endif

struct ConnectorDiscoverySelection: Equatable {
    static let onboardingConnectors = [
        "codex", "claudecode", "hermes", "cursor", "devin", "copilot",
        "openhands", "antigravity", "opencode", "amp", "omnigent",
    ]

    let registered: Set<String>
    let action: Set<String>

    static func reconciling(
        previouslyDetected: [String],
        detected: [String],
        registered: Set<String>,
        action: Set<String>
    ) -> ConnectorDiscoverySelection {
        let allowed = Set(onboardingConnectors)
        let detectedSet = Set(detected).intersection(allowed)
        let newlyDetected = detectedSet.subtracting(Set(previouslyDetected).intersection(allowed))
        let reconciledRegistered = registered
            .intersection(detectedSet)
            .union(newlyDetected)
        return ConnectorDiscoverySelection(
            registered: reconciledRegistered,
            action: action.intersection(reconciledRegistered)
        )
    }
}

#if !CONNECTOR_DISCOVERY_SELECTION_TESTS
struct FirstRunView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var cliFound = false
    @State private var checked = false
    @State private var connector = "codex"
    @State private var detectedConnectors: [String] = []
    @State private var registeredConnectors: Set<String> = []
    @State private var actionConnectors: Set<String> = []
    @State private var discoveryRequested = false
    @State private var connectorDiscoveryInProgress = false
    @State private var connectorDiscoveryError: String?
    @State private var profile = "observe"
    @State private var scannerMode = "local"
    @State private var llmJudge = false
    @State private var failMode = "open"
    @State private var humanApproval = false
    @State private var hiltSeverity = "HIGH"
    @AppStorage(GatewayAutoStartPreference.key) private var startGateway = true
    @State private var verify = true
    @State private var runID: UUID?
    @State private var exitCode: Int32?
    @State private var setupInProgress = false
    @State private var setupTask: Task<Void, Never>?
    @State private var setupCancellationRequested = false
    @State private var setupError: String?

    private static let connectors = ConnectorDiscoverySelection.onboardingConnectors
    private var runningEntry: CommandActivityEntry? {
        guard let runID else { return nil }
        return appState.activity.entries.first { $0.id == runID }
    }

    private var isRunning: Bool { setupInProgress || runningEntry?.status.isActive == true }
    private var isCancelling: Bool { setupCancellationRequested || runningEntry?.status == .cancelling }
    private var isFinishing: Bool { runningEntry?.status == .finishing }

    private var registeredSelection: [String] {
        detectedConnectors.filter { registeredConnectors.contains($0) }
    }

    private var setupInvalid: Bool {
        connectorDiscoveryInProgress
            || (!detectedConnectors.isEmpty && registeredSelection.isEmpty)
            || (profile == "action" && !detectedConnectors.isEmpty && actionConnectors.isEmpty)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 38))
                    .foregroundStyle(Cisco.blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Set Up DefenseClaw").font(.title2.weight(.semibold))
                    Text(cliFound
                         ? "DefenseClaw registers the hook connectors you select (detected ones are pre-selected). You can optionally choose which connectors enforce policy."
                         : "Install the DefenseClaw runtime first, then return here to configure it.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }

            HStack(spacing: 16) {
                checkRow("Runtime", ok: cliFound)
                checkRow("Configuration", ok: appState.installDetected)
                checkRow("Gateway", ok: appState.gatewayReachable)
            }

            if let reason = appState.installationReadOnlyReason {
                Label(reason, systemImage: "lock.shield")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if cliFound {
                setupForm
                    .disabled(setupInProgress)
            } else {
                installer
            }

            if let entry = runningEntry {
                execution(entry)
            }
            if let setupError {
                Label(setupError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(Cisco.orange)
            }

            HStack {
                Button("Check Again") { checkInstallation() }
                    .disabled(setupInProgress)
                Button("Continue Without Setup") {
                    // Plain dismissal — installDetected stays honest (it
                    // means "config.yaml exists" and feeds Overview notices).
                    dismiss()
                }
                Spacer()
                if isRunning {
                    Button(role: .destructive) {
                        setupCancellationRequested = true
                        setupTask?.cancel()
                        if let runID, runningEntry?.status.isActive == true {
                            appState.activity.cancel(runID)
                        }
                    } label: {
                        Label(
                            isCancelling ? "Cancelling..." : (isFinishing ? "Finishing..." : "Cancel"),
                            systemImage: isFinishing ? "hourglass" : "stop.fill"
                        )
                    }
                    .disabled(isCancelling || isFinishing)
                } else if cliFound {
                    Button {
                        initialize()
                    } label: {
                        Label(exitCode == 0 ? "Run Setup Again" : "Initialize DefenseClaw", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(setupInvalid || !appState.installationMutationsAllowed)
                }
            }
        }
        .padding(24)
        .frame(width: 700, height: cliFound ? 760 : 560)
        .task {
            guard !checked else { return }
            checked = true
            // No auto-discovery: `agent discover` executes detected agent
            // CLIs' --version, and the runtime's trusted-path gate is off
            // until a config exists — never exec other binaries without an
            // explicit user action.
            appState.refreshSourceRuntimeMarker()
            cliFound = await appState.cli.locateBinary() != nil
        }
    }

    private var setupForm: some View {
        Form {
            Section("Agent and Policy") {
                Picker("Profile", selection: $profile) {
                    Text("Observe - detect and log").tag("observe")
                    Text("Action - enforce policy").tag("action")
                }
                if connectorDiscoveryInProgress {
                    LabeledContent("Connectors") {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Detecting installed agents...").foregroundStyle(.secondary)
                        }
                    }
                } else if !detectedConnectors.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Register DefenseClaw for").font(.callout.weight(.medium))
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading) {
                            ForEach(detectedConnectors, id: \.self) { name in
                                Toggle(friendlyConnectorName(name), isOn: registeredConnectorBinding(name))
                                    .toggleStyle(.checkbox)
                            }
                        }
                        if registeredSelection.isEmpty {
                            Label("Select at least one connector to register.", systemImage: "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(Cisco.orange)
                        }
                    }
                    Text("Detected connectors are pre-selected; uncheck any you don't want DefenseClaw hooks installed into. Observe mode never blocks; Action applies only to the checked connectors below.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if profile == "action" {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Enforce on").font(.callout.weight(.medium))
                            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading) {
                                ForEach(registeredSelection, id: \.self) { name in
                                    Toggle(friendlyConnectorName(name), isOn: actionConnectorBinding(name))
                                        .toggleStyle(.checkbox)
                                }
                            }
                            if actionConnectors.isEmpty {
                                Label("Select at least one connector for Action mode.", systemImage: "exclamationmark.triangle.fill")
                                    .font(.caption)
                                    .foregroundStyle(Cisco.orange)
                            }
                        }
                    }
                } else {
                    Picker("Fallback hook connector", selection: $connector) {
                        ForEach(Self.connectors, id: \.self) {
                            Text(friendlyConnectorName($0)).tag($0)
                        }
                    }
                    HStack(spacing: 8) {
                        Button {
                            discoveryRequested = true
                            Task { await discoverConnectors() }
                        } label: {
                            Label(discoveryRequested ? "Detect Again" : "Detect Installed Agents",
                                  systemImage: "magnifyingglass")
                        }
                        .disabled(!appState.installationMutationsAllowed)
                        Text("Runs `defenseclaw agent discover`, which executes each detected agent CLI's --version to identify it.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text(discoveryRequested
                         ? "No installed hook connectors were returned by discovery. Setup will use this explicit hook connector fallback."
                         : "Choose a hook connector directly, or detect the agents installed on this Mac.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let connectorDiscoveryError {
                        Label(connectorDiscoveryError, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(Cisco.orange)
                    }
                }
                Picker("Scanner Mode", selection: $scannerMode) {
                    Text("Local").tag("local")
                    Text("Remote").tag("remote")
                    Text("Both").tag("both")
                }
                Toggle("Enable LLM judge", isOn: $llmJudge)
            }
            Section("Enforcement") {
                Picker("Hook Failure Mode", selection: $failMode) {
                    Text("Open - allow and log").tag("open")
                    Text("Closed - block").tag("closed")
                }
                if profile == "action" {
                    Toggle("Require human approval", isOn: $humanApproval)
                    if humanApproval {
                        Picker("Approval Minimum Severity", selection: $hiltSeverity) {
                            ForEach(["CRITICAL", "HIGH", "MEDIUM", "LOW"], id: \.self) { Text($0).tag($0) }
                        }
                    }
                }
            }
            Section("Finish") {
                Toggle("Start gateway automatically", isOn: $startGateway)
                    .disabled(!appState.installationMutationsAllowed || setupInProgress)
                Text("Starts the gateway after setup and whenever DefenseClawMac opens, including after an app update. You can change this in Settings → Connection.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Toggle("Verify readiness", isOn: $verify)
            }
        }
        .formStyle(.grouped)
    }

    /// First run installs the release matching this app, so app and runtime
    /// agree; the release's install.sh does the work.
    private var installer: some View {
        GroupBox("Install the DefenseClaw Runtime") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Downloads the DefenseClaw \(UpdateChecker.currentVersion) install.sh from its GitHub release, verifies it against the release's checksums.txt, and runs it to install the CLI and gateway into \(appState.installationContext.homeRoot.path) and ~/.local/bin. Progress streams to Activity; the installer rolls back if a step fails.")
                    .font(.callout).foregroundStyle(.secondary)
                if let notice = appState.sourceRuntimeNotice {
                    Label(notice, systemImage: "hammer.circle")
                        .font(.caption).foregroundStyle(Cisco.orange)
                        .textSelection(.enabled)
                }
                installStateRow
                HStack {
                    Button {
                        Task {
                            await appState.runReleaseInstaller(version: UpdateChecker.currentVersion)
                            checkInstallation()
                        }
                    } label: {
                        Label("Install DefenseClaw Runtime v\(UpdateChecker.currentVersion)", systemImage: "arrow.down.circle.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(appState.installerState.isBusy || !appState.installationMutationsAllowed
                              || appState.sourceRuntimeMarker != nil)
                    Button("Open Activity") {
                        appState.selectedPanel = .activity
                        dismiss()
                    }
                    .disabled(appState.installerState == .idle)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private var installStateRow: some View {
        switch appState.installerState {
        case .idle:
            EmptyView()
        case .downloading:
            progressRow("Downloading and verifying the installer")
        case .running:
            progressRow("Installing (progress is in Activity)")
        case .installed:
            Label("Runtime installed. Configure it below.", systemImage: "checkmark.circle.fill")
                .font(.caption).foregroundStyle(Cisco.green)
        case .needsAttention(_, let detail):
            Label("Runtime installed, but a connector needs attention:\n\(detail)", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(Cisco.orange)
                .textSelection(.enabled)
        case .failed(_, let detail):
            Label(detail, systemImage: "xmark.circle.fill")
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

    private func execution(_ entry: CommandActivityEntry) -> some View {
        GroupBox("Setup Output") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    if entry.status.isActive { ProgressView().controlSize(.small) }
                    Image(systemName: statusIcon(entry.status))
                        .foregroundStyle(entry.status == .failed ? Cisco.red : (entry.status == .succeeded ? Cisco.green : .secondary))
                    Text(entry.statusLabel).font(.callout.weight(.semibold))
                    Spacer()
                    Button {
                        appState.selectedPanel = .activity
                        dismiss()
                    } label: { Label("Open Activity", systemImage: "arrow.up.right.square") }
                    .controlSize(.small)
                }
                ScrollView {
                    Text(entry.output.isEmpty ? "Waiting for output..." : entry.output)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: 110)
            }
        }
    }

    private func initialize() {
        guard !setupInProgress else { return }
        setupInProgress = true
        appState.firstRunSetupNeedsCompletion = true
        appState.firstRunSetupInProgress = true
        exitCode = nil
        setupError = nil
        setupCancellationRequested = false
        setupTask = Task {
            defer {
                setupTask = nil
                setupInProgress = false
                setupCancellationRequested = false
                appState.firstRunSetupInProgress = false
            }
            guard !stopIfSetupCancelled() else { return }
            let plan = ConnectorOnboarding.initializationPlan(
                detectedConnectors: detectedConnectors,
                registeredConnectors: registeredConnectors,
                fallbackConnector: connector,
                actionConnectors: actionConnectors,
                profile: profile,
                scannerMode: scannerMode,
                llmJudge: llmJudge,
                failMode: failMode,
                humanApproval: humanApproval,
                hiltSeverity: hiltSeverity,
                // Gateway lifecycle is dispatched separately so administrator
                // mode and Activity recording apply to the final start.
                startGateway: false,
                verify: verify
            )

            for (index, arguments) in plan.enumerated() {
                guard !stopIfSetupCancelled() else { return }
                let id = UUID()
                runID = id // the execution box and Cancel track the current step
                let isLast = index == plan.count - 1
                let title = arguments.first == "init"
                    ? "Initialize DefenseClaw"
                    : "Add \(friendlyConnectorName(ConnectorOnboarding.normalizedConnector(arguments.count > 1 ? arguments[1] : ""))) connector"
                let result = await appState.runCommand(
                    runID: id,
                    title: title,
                    arguments: arguments,
                    category: "setup",
                    origin: "First Run",
                    successEffects: arguments.first == "init"
                        ? ["Configuration initialized"]
                        : [],
                    suggestedNextAction: isLast ? "Review system health on Overview." : "",
                    // Reload once, below, before the final startup check. An
                    // unawaited reload here can race that check's context bind.
                    refreshOnSuccess: false
                )
                guard !stopIfSetupCancelled() else { return }
                exitCode = result.exitCode
                guard result.succeeded else { return }
                if arguments.first == "init",
                   let failure = ConnectorOnboarding.initializationFailure(from: result.output) {
                    exitCode = 1
                    setupError = failure
                    return
                }
            }

            guard !stopIfSetupCancelled() else { return }
            let config = await appState.configStore.reload()
            guard !stopIfSetupCancelled() else { return }
            let installPresent = await appState.configStore.installPresent
            guard !stopIfSetupCancelled() else { return }
            appState.config = config
            appState.installDetected = installPresent
            await appState.gateway.update(config: config)
            guard !stopIfSetupCancelled() else { return }
            guard appState.installDetected, config.loadError.isEmpty else {
                exitCode = 1
                setupError = "Setup finished, but its configuration could not be loaded. Review Setup Output before trying again. The gateway was not started."
                return
            }
            appState.firstRunSetupInProgress = false
            if startGateway {
                let id = UUID()
                runID = id
                let outcome = await appState.ensureGatewayStarted(origin: "First Run", runID: id, afterSetup: true)
                guard !stopIfSetupCancelled() else { return }
                switch outcome {
                case .failed:
                    exitCode = 1
                    setupError = "Setup completed, but the gateway could not start. Review the output in Activity, then try Start Gateway from Overview."
                    return
                case .cancelled:
                    exitCode = 130
                    setupError = "Setup completed. Gateway startup was cancelled; use Start Gateway from Overview when ready."
                    return
                case .skipped:
                    if startGateway {
                        exitCode = 1
                        setupError = "Setup completed, but automatic gateway startup was deferred. Review Activity and the selected installation, then use Start Gateway from Overview."
                        return
                    }
                case .alreadyRunning, .started:
                    break
                }
            }
            await appState.pulse()
            guard !stopIfSetupCancelled() else { return }
            appState.firstRunSetupNeedsCompletion = false
            if appState.installDetected { dismiss() }
        }
    }

    /// A setup run can be between recorded commands or awaiting the gateway
    /// probe when Cancel is pressed. Task cancellation covers those gaps;
    /// Activity cancellation still stops a command that has already launched.
    private func stopIfSetupCancelled() -> Bool {
        guard Task.isCancelled else { return false }
        exitCode = 130
        setupError = "Setup was cancelled. Review Activity for completed steps and Overview for gateway status before continuing."
        return true
    }

    private func checkInstallation() {
        appState.reloadConfig()
        Task {
            appState.refreshSourceRuntimeMarker()
            cliFound = await appState.cli.locateBinary() != nil
            appState.installDetected = await appState.configStore.installPresent
            // Re-discover only after the user opted into discovery — Check
            // Again must not become a back door into exec'ing agent CLIs.
            if cliFound, discoveryRequested { await discoverConnectors() }
        }
    }

    private func discoverConnectors() async {
        guard appState.installationMutationsAllowed else {
            connectorDiscoveryError = appState.installationReadOnlyReason
                ?? "This installation is read only."
            return
        }
        connectorDiscoveryInProgress = true
        connectorDiscoveryError = nil
        // --refresh: every call here follows an explicit user action, and the
        // runtime's discovery cache lives 24h — a stale hit would hide an
        // agent installed since the last scan.
        let result = await appState.cli.run(
            arguments: ["agent", "discover", "--json", "--no-emit-otel", "--refresh"],
            mutation: true
        )
        let detected = result.succeeded
            ? ConnectorOnboarding.installedConnectors(from: result.output, supportedOrder: Self.connectors)
            : []
        let selection = ConnectorDiscoverySelection.reconciling(
            previouslyDetected: detectedConnectors,
            detected: detected,
            registered: registeredConnectors,
            action: actionConnectors
        )
        detectedConnectors = detected
        // Pre-check the first discovery and later additions, while preserving
        // explicit choices for connectors that remain installed.
        registeredConnectors = selection.registered
        actionConnectors = selection.action
        if detected.isEmpty {
            connectorDiscoveryError = result.succeeded
                ? "Agent discovery completed but did not identify a supported connector."
                : "Agent discovery failed (exit \(result.exitCode)); choose a fallback connector."
        }
        connectorDiscoveryInProgress = false
    }

    private func registeredConnectorBinding(_ name: String) -> Binding<Bool> {
        Binding(
            get: { registeredConnectors.contains(name) },
            set: { enabled in
                if enabled {
                    registeredConnectors.insert(name)
                } else {
                    registeredConnectors.remove(name)
                    actionConnectors.remove(name)
                }
            }
        )
    }

    private func actionConnectorBinding(_ name: String) -> Binding<Bool> {
        Binding(
            get: { actionConnectors.contains(name) },
            set: { enabled in
                if enabled { actionConnectors.insert(name) }
                else { actionConnectors.remove(name) }
            }
        )
    }

    private func checkRow(_ label: String, ok: Bool) -> some View {
        Label(label, systemImage: ok ? "checkmark.circle.fill" : "xmark.circle")
            .font(.caption)
            .foregroundStyle(ok ? Cisco.green : .secondary)
    }

    private func statusIcon(_ status: CommandActivityStatus) -> String {
        switch status {
        case .running: "hourglass"
        case .cancelling: "stop.circle"
        case .finishing: "hourglass.circle"
        case .succeeded: "checkmark.circle.fill"
        case .failed: "xmark.circle.fill"
        case .cancelled: "stop.circle.fill"
        }
    }
}
#endif
