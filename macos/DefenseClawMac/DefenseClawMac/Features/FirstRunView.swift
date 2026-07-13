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
    let registered: Set<String>
    let action: Set<String>

    static func reconciling(
        previouslyDetected: [String],
        detected: [String],
        registered: Set<String>,
        action: Set<String>
    ) -> ConnectorDiscoverySelection {
        let detectedSet = Set(detected)
        let newlyDetected = detectedSet.subtracting(previouslyDetected)
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
    @State private var detectedProxyConnectors: [String] = []
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
    @State private var startGateway = false
    @State private var verify = true
    @State private var runID: UUID?
    @State private var exitCode: Int32?

    private static let connectors = [
        "codex", "claudecode", "zeptoclaw", "openclaw", "hermes", "cursor",
        "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent",
    ]
    private static let installerURL = URL(
        string: "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh"
    )!
    private static let downloadCommand = "curl -fL --proto '=https' --tlsv1.2 --output ~/Downloads/defenseclaw-install.sh \(installerURL.absoluteString)"
    private static let runCommand = "bash ~/Downloads/defenseclaw-install.sh"

    private var runningEntry: CommandActivityEntry? {
        guard let runID else { return nil }
        return appState.activity.entries.first { $0.id == runID }
    }

    private var isRunning: Bool { runningEntry?.status.isActive == true }
    private var isCancelling: Bool { runningEntry?.status == .cancelling }
    private var isFinishing: Bool { runningEntry?.status == .finishing }

    private var runtimeInstallIsCancelling: Bool {
        guard let id = appState.runtimeInstallRunID else { return false }
        return appState.activity.entries.first(where: { $0.id == id })?.status == .cancelling
    }

    private var runtimeInstallIsFinishing: Bool {
        guard let id = appState.runtimeInstallRunID else { return false }
        return appState.activity.entries.first(where: { $0.id == id })?.status == .finishing
    }

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

            if cliFound { setupForm } else { installer }

            if let entry = runningEntry {
                execution(entry)
            }

            HStack {
                Button("Check Again") { checkInstallation() }
                Button("Continue Without Setup") {
                    // Plain dismissal — installDetected stays honest (it
                    // means "config.yaml exists" and feeds Overview notices).
                    dismiss()
                }
                Spacer()
                if appState.runtimeInstallState.isRunning {
                    Button(role: .destructive) {
                        if let id = appState.runtimeInstallRunID { appState.activity.cancel(id) }
                    } label: {
                        Label(
                            runtimeInstallIsCancelling
                                ? "Cancelling…"
                                : (runtimeInstallIsFinishing ? "Finishing…" : "Cancel Install"),
                            systemImage: runtimeInstallIsFinishing ? "hourglass" : "stop.fill"
                        )
                    }
                    .disabled(runtimeInstallIsCancelling || runtimeInstallIsFinishing)
                } else if isRunning {
                    Button(role: .destructive) {
                        if let runID { appState.activity.cancel(runID) }
                    } label: {
                        Label(
                            isCancelling ? "Cancelling…" : (isFinishing ? "Finishing…" : "Cancel"),
                            systemImage: isFinishing ? "hourglass" : "stop.fill"
                        )
                    }
                    .disabled(isCancelling || isFinishing)
                } else if cliFound {
                    if detectedConnectors.isEmpty, !detectedProxyConnectors.isEmpty {
                        Button {
                            appState.selectedPanel = .setup
                            dismiss()
                        } label: {
                            Label("Open Proxy Connector Setup", systemImage: "cable.connector")
                        }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                    } else {
                        Button {
                            initialize()
                        } label: {
                            Label(exitCode == 0 ? "Run Setup Again" : "Initialize DefenseClaw", systemImage: "play.fill")
                        }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(setupInvalid)
                    }
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
                    if !detectedProxyConnectors.isEmpty {
                        Text("Proxy connectors \(detectedProxyConnectors.map(friendlyConnectorName).joined(separator: ", ")) require their dedicated Setup flow and are not added to the hook roster.")
                            .font(.caption)
                            .foregroundStyle(Cisco.orange)
                    }
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
                    if detectedProxyConnectors.isEmpty {
                        Picker("Fallback hook connector", selection: $connector) {
                            ForEach(TUIWizards.hookConnectors, id: \.self) {
                                Text(friendlyConnectorName($0)).tag($0)
                            }
                        }
                    } else {
                        LabeledContent("Detected proxy connectors") {
                            Text(detectedProxyConnectors.map(friendlyConnectorName).joined(separator: ", "))
                                .multilineTextAlignment(.trailing)
                        }
                        Text("Proxy connectors require their dedicated Setup flow. Continue with Open Proxy Connector Setup below.")
                            .font(.caption)
                            .foregroundStyle(Cisco.orange)
                    }
                    HStack(spacing: 8) {
                        Button {
                            discoveryRequested = true
                            Task { await discoverConnectors() }
                        } label: {
                            Label(discoveryRequested ? "Detect Again" : "Detect Installed Agents",
                                  systemImage: "magnifyingglass")
                        }
                        Text("Runs `defenseclaw agent discover`, which executes each detected agent CLI's --version to identify it.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if detectedProxyConnectors.isEmpty {
                        Text(discoveryRequested
                             ? "No installed hook connectors were returned by discovery. Setup will use this explicit hook connector fallback."
                             : "Choose a hook connector directly, or detect the agents installed on this Mac.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
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
                Toggle("Start gateway after setup", isOn: $startGateway)
                Toggle("Verify readiness", isOn: $verify)
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder
    private var installer: some View {
        if let payload = RuntimePayload.bundled {
            VStack(alignment: .leading, spacing: 10) {
                GroupBox("Install the Bundled DefenseClaw Runtime") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("This app includes DefenseClaw \(payload.version), verified against the upstream release at build time. Installing lays it into ~/.defenseclaw and ~/.local/bin — no remote script runs. Network is used to fetch the CLI's Python dependencies from PyPI, plus uv and Python 3.12 only if this Mac doesn't have them.")
                            .font(.callout).foregroundStyle(.secondary)
                        installStateRow
                        HStack {
                            Button {
                                Task {
                                    await appState.installBundledRuntime()
                                    checkInstallation()
                                }
                            } label: {
                                Label("Install DefenseClaw Runtime v\(payload.version)", systemImage: "arrow.down.circle.fill")
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(appState.runtimeInstallState.isRunning)
                            Button("Open Activity") {
                                appState.selectedPanel = .activity
                                dismiss()
                            }
                            .disabled(appState.runtimeInstallState == .idle)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                DisclosureGroup("Install with the shell script instead") {
                    scriptInstaller.padding(.top, 6)
                }
                .font(.callout)
            }
        } else {
            GroupBox("Install the DefenseClaw Runtime") {
                scriptInstaller
            }
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
            Label("Runtime installed. Configure it below.", systemImage: "checkmark.circle.fill")
                .font(.caption).foregroundStyle(Cisco.green)
        }
    }

    private var scriptInstaller: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Download the installer, review its contents, then run it from Terminal. The Mac app does not execute a remote script automatically.")
                .font(.callout).foregroundStyle(.secondary)
            Link(destination: Self.installerURL) {
                Label("Review Install Script", systemImage: "safari")
            }
            installCommandRow("1. Download", command: Self.downloadCommand)
            installCommandRow("2. Run After Review", command: Self.runCommand)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
        exitCode = nil
        Task {
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
                startGateway: startGateway,
                verify: verify
            )

            for (index, arguments) in plan.enumerated() {
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
                        ? ["Configuration initialized"] + (startGateway ? ["Gateway started"] : [])
                        : [],
                    suggestedNextAction: isLast ? "Review system health on Overview." : "",
                    refreshOnSuccess: isLast
                )
                exitCode = result.exitCode
                guard result.succeeded else { return }
            }

            let config = await appState.configStore.reload()
            appState.config = config
            appState.installDetected = await appState.configStore.installPresent
            await appState.gateway.update(config: config)
            await appState.pulse()
            if appState.installDetected { dismiss() }
        }
    }

    private func checkInstallation() {
        appState.reloadConfig()
        Task {
            cliFound = await appState.cli.locateBinary() != nil
            appState.installDetected = await appState.configStore.installPresent
            // Re-discover only after the user opted into discovery — Check
            // Again must not become a back door into exec'ing agent CLIs.
            if cliFound, discoveryRequested { await discoverConnectors() }
        }
    }

    private func discoverConnectors() async {
        connectorDiscoveryInProgress = true
        connectorDiscoveryError = nil
        // --refresh: every call here follows an explicit user action, and the
        // runtime's discovery cache lives 24h — a stale hit would hide an
        // agent installed since the last scan.
        let result = await appState.cli.run(arguments: ["agent", "discover", "--json", "--no-emit-otel", "--refresh"])
        let allDetected = result.succeeded
            ? ConnectorOnboarding.installedConnectors(from: result.output, supportedOrder: Self.connectors)
            : []
        let detected = allDetected.filter { TUIWizards.hookConnectors.contains($0) }
        let selection = ConnectorDiscoverySelection.reconciling(
            previouslyDetected: detectedConnectors,
            detected: detected,
            registered: registeredConnectors,
            action: actionConnectors
        )
        detectedProxyConnectors = allDetected.filter { TUIWizards.proxyConnectors.contains($0) }
        detectedConnectors = detected
        // Pre-check the first discovery and later additions, while preserving
        // explicit choices for connectors that remain installed.
        registeredConnectors = selection.registered
        actionConnectors = selection.action
        if allDetected.isEmpty {
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

    private func installCommandRow(_ label: String, command: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            HStack {
                Text(command).font(.caption.monospaced()).lineLimit(2).textSelection(.enabled)
                Spacer(minLength: 8)
                Button { copyToPasteboard(command) } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless).help("Copy Command")
            }
        }
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
