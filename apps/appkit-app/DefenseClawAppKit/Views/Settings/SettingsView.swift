import SwiftUI
import DefenseClawKit
import AppKit

struct SettingsView: View {
    var body: some View {
        TabView {
            GatewaySettingsView()
                .tabItem {
                    Label("Gateway", systemImage: "network")
                }

            GuardrailSettingsView()
                .tabItem {
                    Label("Guardrails", systemImage: "shield")
                }

            EnforcementView()
                .tabItem {
                    Label("Enforcement", systemImage: "lock.shield")
                }

            ScannersView()
                .tabItem {
                    Label("Scanners", systemImage: "magnifyingglass")
                }

            DiagnosticsView()
                .tabItem {
                    Label("Diagnostics", systemImage: "stethoscope")
                }
        }
        .frame(width: 700, height: 550)
    }
}

struct GatewaySettingsView: View {
    @State private var host = "127.0.0.1"
    @State private var apiPort = "18970"
    @State private var gatewayWSPort = "18789"
    @State private var autoStart = true
    @State private var statusMessage = ""
    @State private var isLoading = false
    @State private var sidecarRunning = false
    @State private var isRestarting = false

    private let configManager = ConfigManager()
    private let launchAgent = LaunchAgentManager()

    var body: some View {
        Form {
            Section("Gateway Configuration") {
                TextField("Host", text: $host)
                TextField("API Port", text: $apiPort)
                TextField("Gateway WebSocket Port", text: $gatewayWSPort)
                Toggle("Auto-start Gateway", isOn: $autoStart)
            }

            Section("Service Control") {
                HStack(spacing: 12) {
                    // DefenseClaw Sidecar
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(sidecarRunning ? Color.green : Color.red)
                                .frame(width: 8, height: 8)
                            Text("DefenseClaw Sidecar")
                                .font(.subheadline)
                                .fontWeight(.medium)
                        }
                        Text(sidecarRunning ? "Running" : "Stopped")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Button {
                        restartSidecar()
                    } label: {
                        Label("Restart Sidecar", systemImage: "arrow.clockwise")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .disabled(isRestarting)
                }

                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(Color.gray)
                                .frame(width: 8, height: 8)
                            Text("OpenClaw Gateway")
                                .font(.subheadline)
                                .fontWeight(.medium)
                        }
                        Text("Managed by sidecar")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Button {
                        restartOpenClawGateway()
                    } label: {
                        Label("Restart Gateway", systemImage: "arrow.clockwise")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .disabled(isRestarting)
                }

                if isRestarting {
                    HStack(spacing: 6) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Restarting...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if !statusMessage.isEmpty {
                Section {
                    Text(statusMessage)
                        .foregroundColor(statusMessage.contains("Error") || statusMessage.contains("failed") ? .red : .green)
                        .font(.caption)
                }
            }

            HStack {
                Spacer()
                Button("Save") {
                    saveSettings()
                }
                .buttonStyle(.borderedProminent)
                .disabled(isLoading)
            }
        }
        .padding()
        .onAppear {
            loadSettings()
            refreshStatus()
        }
    }

    private func refreshStatus() {
        sidecarRunning = launchAgent.isRunning
    }

    private func loadSettings() {
        isLoading = true
        do {
            let config = try configManager.load()
            host = config.gateway?.apiBind ?? "127.0.0.1"
            apiPort = String(config.gateway?.apiPort ?? 18970)
            gatewayWSPort = String(config.gateway?.port ?? 18789)
            statusMessage = ""
        } catch {
            host = "127.0.0.1"
            apiPort = "18970"
            gatewayWSPort = "18789"
            statusMessage = "Using defaults (config not found)"
        }
        isLoading = false
    }

    private func saveSettings() {
        isLoading = true
        statusMessage = ""
        do {
            var config = (try? configManager.load()) ?? AppConfig()
            if config.gateway == nil {
                config.gateway = GatewayFullConfig()
            }
            config.gateway?.apiBind = host
            config.gateway?.apiPort = Int(apiPort) ?? 18970
            config.gateway?.port = Int(gatewayWSPort) ?? 18789
            try configManager.save(config)
            statusMessage = "Settings saved successfully"
        } catch {
            statusMessage = "Error saving settings: \(error.localizedDescription)"
        }
        isLoading = false
    }

    private func restartSidecar() {
        isRestarting = true
        statusMessage = ""
        Task.detached {
            // Kill the sidecar process directly
            let pkill = Process()
            pkill.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            pkill.arguments = ["-f", "defenseclaw"]
            pkill.standardOutput = Pipe()
            pkill.standardError = Pipe()
            try? pkill.run()
            pkill.waitUntilExit()
            try? await Task.sleep(for: .seconds(1))

            // Restart via launchctl if installed
            if launchAgent.isInstalled {
                try? launchAgent.unload()
                try? await Task.sleep(for: .seconds(1))
                try? launchAgent.load()
            }
            try? await Task.sleep(for: .seconds(2))

            await MainActor.run {
                refreshStatus()
                statusMessage = "DefenseClaw sidecar restarted"
                isRestarting = false
            }
        }
    }

    private func restartOpenClawGateway() {
        isRestarting = true
        statusMessage = ""
        Task.detached {
            // Kill the openclaw-gateway process; the sidecar should respawn it
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            process.arguments = ["-f", "openclaw.*gateway"]
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            do {
                try process.run()
                process.waitUntilExit()
                try? await Task.sleep(for: .seconds(2))
                await MainActor.run {
                    statusMessage = "OpenClaw gateway restart signal sent"
                    isRestarting = false
                }
            } catch {
                await MainActor.run {
                    statusMessage = "Restart failed: \(error.localizedDescription)"
                    isRestarting = false
                }
            }
        }
    }
}

struct GuardrailSettingsView: View {
    @State private var enabled = false
    @State private var statusMessage = ""
    @State private var isLoading = false
    @State private var isRestarting = false
    @State private var liveMode = "observe"
    @State private var liveScannerMode = "local"

    private let configManager = ConfigManager()
    private let sidecarClient = SidecarClient()
    private let launchAgent = LaunchAgentManager()

    // Sidecar API accepts: "observe" (log only) or "action" (block)
    private let liveModes = ["observe", "action"]
    private let liveScannerModeOptions = ["local", "remote", "both"]

    var body: some View {
        Form {
            // Master enable/disable — equivalent to `defenseclaw setup guardrail --disable --restart`
            Section("Guardrail") {
                Toggle("Enable Guardrail", isOn: $enabled)
                    .onChange(of: enabled) { _, newValue in
                        toggleGuardrail(enable: newValue)
                    }

                Text(enabled
                     ? "Guardrail is active. Requests are scanned based on the mode below."
                     : "Guardrail is disabled. No requests will be scanned or blocked.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if isRestarting {
                    HStack(spacing: 6) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Saving config and restarting sidecar...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if enabled {
                Section("Live Mode (takes effect immediately)") {
                    Picker("Mode", selection: $liveMode) {
                        Text("Observe — log only, no blocking").tag("observe")
                        Text("Action — block malicious requests").tag("action")
                    }
                    .onChange(of: liveMode) { _, newMode in
                        applyLiveMode(mode: newMode)
                    }

                    Picker("Scanner Mode", selection: $liveScannerMode) {
                        ForEach(liveScannerModeOptions, id: \.self) { m in
                            Text(m.capitalized).tag(m)
                        }
                    }
                    .onChange(of: liveScannerMode) { _, newSM in
                        applyLiveScannerMode(scannerMode: newSM)
                    }
                }

                Section {
                    HStack(spacing: 8) {
                        Image(systemName: "info.circle")
                            .foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Observe: Scans and logs threats but allows all requests through")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text("Action: Scans and blocks requests that match threat patterns")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }

            if !statusMessage.isEmpty {
                Section {
                    Text(statusMessage)
                        .foregroundColor(statusMessage.contains("Error") || statusMessage.contains("failed") ? .red : .green)
                        .font(.caption)
                }
            }
        }
        .padding()
        .disabled(isRestarting)
        .onAppear {
            loadAll()
        }
    }

    /// Load both file config (enabled flag) and live sidecar config (mode, scanner_mode)
    private func loadAll() {
        isLoading = true
        // File config → enabled flag
        do {
            let config = try configManager.load()
            enabled = config.guardrail?.enabled ?? false
        } catch {
            enabled = false
        }
        isLoading = false

        // Live sidecar config → mode + scanner_mode
        Task {
            do {
                let config = try await sidecarClient.guardrailConfig()
                await MainActor.run {
                    liveMode = config.mode
                    liveScannerMode = config.scannerMode
                }
            } catch {
                // Sidecar may be offline — that's OK, keep defaults
            }
        }
    }

    /// Toggle guardrail enabled/disabled by running the defenseclaw CLI command,
    /// equivalent to `defenseclaw setup guardrail [--disable] --restart`.
    /// Falls back to manual config write + process restart if CLI is not found.
    private func toggleGuardrail(enable: Bool) {
        isRestarting = true
        statusMessage = ""

        Task.detached {
            // Try the CLI command first — this is the canonical way to toggle guardrail
            let cliSuccess = await runDefenseClawCLI(enable: enable)

            if cliSuccess {
                await MainActor.run {
                    statusMessage = enable
                        ? "Guardrail enabled — sidecar restarted"
                        : "Guardrail disabled — sidecar restarted"
                    isRestarting = false
                }
                return
            }

            // Fallback: write config manually + kill/restart process
            do {
                // 1. Write enabled flag to config file
                var config = (try? configManager.load()) ?? AppConfig()
                if config.guardrail == nil {
                    config.guardrail = GuardrailFullConfig()
                }
                config.guardrail?.enabled = enable
                try configManager.save(config)

                // 2. Kill the sidecar process so it restarts with new config
                await killProcess(name: "defenseclaw")

                // 3. Try launchctl restart if plist is installed
                if launchAgent.isInstalled {
                    try? launchAgent.unload()
                    try? await Task.sleep(for: .seconds(1))
                    try? launchAgent.load()
                    try? await Task.sleep(for: .seconds(2))
                } else {
                    // Give process manager time to restart
                    try? await Task.sleep(for: .seconds(3))
                }

                await MainActor.run {
                    statusMessage = enable
                        ? "Guardrail enabled — sidecar restarted (fallback)"
                        : "Guardrail disabled — sidecar restarted (fallback)"
                    isRestarting = false
                }
            } catch {
                await MainActor.run {
                    statusMessage = "Error: \(error.localizedDescription)"
                    isRestarting = false
                }
            }
        }
    }

    /// Run `defenseclaw setup guardrail [--disable] --restart` via the CLI binary.
    private func runDefenseClawCLI(enable: Bool) async -> Bool {
        let searchPaths = [
            "\(NSHomeDirectory())/.local/bin/defenseclaw",
            "/usr/local/bin/defenseclaw",
            "/opt/homebrew/bin/defenseclaw"
        ]

        guard let binaryPath = searchPaths.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return false
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        if enable {
            process.arguments = ["setup", "guardrail", "--restart"]
        } else {
            process.arguments = ["setup", "guardrail", "--disable", "--restart"]
        }
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        // Ensure PATH includes common locations
        process.environment = ProcessInfo.processInfo.environment

        do {
            try process.run()
            process.waitUntilExit()
            // Give the sidecar time to fully restart
            try? await Task.sleep(for: .seconds(2))
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    /// Kill a process by name using pkill.
    private func killProcess(name: String) async {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        process.arguments = ["-f", name]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            try? await Task.sleep(for: .seconds(1))
        } catch {
            // Process may not be running — that's OK
        }
    }

    /// Apply mode change to live sidecar via PATCH /v1/guardrail/config
    private func applyLiveMode(mode: String) {
        statusMessage = ""
        Task {
            do {
                try await sidecarClient.updateGuardrailConfig(mode: mode)
                await MainActor.run {
                    statusMessage = "Mode changed to \(mode)"
                }
            } catch {
                await MainActor.run {
                    statusMessage = "Error updating mode: \(error.localizedDescription)"
                }
            }
        }
    }

    /// Apply scanner mode change to live sidecar via PATCH /v1/guardrail/config
    private func applyLiveScannerMode(scannerMode: String) {
        statusMessage = ""
        Task {
            do {
                try await sidecarClient.updateGuardrailConfig(scannerMode: scannerMode)
                await MainActor.run {
                    statusMessage = "Scanner mode changed to \(scannerMode)"
                }
            } catch {
                await MainActor.run {
                    statusMessage = "Error updating scanner mode: \(error.localizedDescription)"
                }
            }
        }
    }
}

struct EnforcementView: View {
    @State private var blockedList: [BlockEntry] = []
    @State private var allowedList: [AllowEntry] = []
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingAddBlock = false
    @State private var showingAddAllow = false
    @State private var newEntryType = "skill"
    @State private var newEntryName = ""
    @State private var newEntryReason = ""

    private let sidecarClient = SidecarClient()
    private let entryTypes = ["skill", "mcp", "plugin"]

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Block & Allow Lists")
                    .font(.headline)
                Spacer()
                Button("Refresh") {
                    Task { await loadLists() }
                }
            }
            .padding()

            if !errorMessage.isEmpty {
                Text(errorMessage)
                    .foregroundColor(.red)
                    .font(.caption)
                    .padding(.horizontal)
            }

            HSplitView {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Blocked (\(blockedList.count))")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                        Spacer()
                        Button(action: { showingAddBlock = true }) {
                            Image(systemName: "plus.circle")
                        }
                    }
                    .padding(.horizontal)

                    List {
                        ForEach(blockedList) { entry in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(entry.name)
                                    .font(.system(.body, design: .monospaced))
                                HStack {
                                    Text(entry.type)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    if let reason = entry.reason {
                                        Text("• \(reason)")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }
                            }
                            .contextMenu {
                                Button("Remove", role: .destructive) {
                                    Task { await removeBlocked(entry) }
                                }
                            }
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Allowed (\(allowedList.count))")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                        Spacer()
                        Button(action: { showingAddAllow = true }) {
                            Image(systemName: "plus.circle")
                        }
                    }
                    .padding(.horizontal)

                    List {
                        ForEach(allowedList) { entry in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(entry.name)
                                    .font(.system(.body, design: .monospaced))
                                HStack {
                                    Text(entry.type)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    if let reason = entry.reason {
                                        Text("• \(reason)")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }
                            }
                            .contextMenu {
                                Button("Remove", role: .destructive) {
                                    Task { await removeAllowed(entry) }
                                }
                            }
                        }
                    }
                }
            }
        }
        .onAppear {
            Task { await loadLists() }
        }
        .sheet(isPresented: $showingAddBlock) {
            addEntrySheet(isBlock: true)
        }
        .sheet(isPresented: $showingAddAllow) {
            addEntrySheet(isBlock: false)
        }
    }

    private func addEntrySheet(isBlock: Bool) -> some View {
        VStack(spacing: 16) {
            Text(isBlock ? "Add Blocked Entry" : "Add Allowed Entry")
                .font(.headline)

            Form {
                Picker("Type", selection: $newEntryType) {
                    ForEach(entryTypes, id: \.self) { t in
                        Text(t.capitalized).tag(t)
                    }
                }
                TextField("Name", text: $newEntryName)
                TextField("Reason (optional)", text: $newEntryReason)
            }

            HStack {
                Button("Cancel") {
                    if isBlock {
                        showingAddBlock = false
                    } else {
                        showingAddAllow = false
                    }
                    resetNewEntry()
                }
                Spacer()
                Button(isBlock ? "Block" : "Allow") {
                    Task {
                        if isBlock {
                            await addBlocked()
                        } else {
                            await addAllowed()
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(newEntryName.isEmpty)
            }
        }
        .padding()
        .frame(width: 400, height: 250)
    }

    private func loadLists() async {
        isLoading = true
        errorMessage = ""
        do {
            async let blocked = sidecarClient.blockedList()
            async let allowed = sidecarClient.allowedList()
            (blockedList, allowedList) = try await (blocked, allowed)
        } catch {
            errorMessage = "Error loading lists: \(error.localizedDescription)"
        }
        isLoading = false
    }

    private func addBlocked() async {
        do {
            let req = EnforceRequest(type: newEntryType, name: newEntryName, reason: newEntryReason.isEmpty ? nil : newEntryReason)
            try await sidecarClient.block(req)
            showingAddBlock = false
            resetNewEntry()
            await loadLists()
        } catch {
            errorMessage = "Error adding blocked entry: \(error.localizedDescription)"
        }
    }

    private func addAllowed() async {
        do {
            let req = EnforceRequest(type: newEntryType, name: newEntryName, reason: newEntryReason.isEmpty ? nil : newEntryReason)
            try await sidecarClient.allow(req)
            showingAddAllow = false
            resetNewEntry()
            await loadLists()
        } catch {
            errorMessage = "Error adding allowed entry: \(error.localizedDescription)"
        }
    }

    private func removeBlocked(_ entry: BlockEntry) async {
        errorMessage = ""
        do {
            let req = EnforceRequest(type: entry.targetType, name: entry.targetName)
            try await sidecarClient.unblock(req)
            await loadLists()
        } catch {
            errorMessage = "Error removing blocked entry: \(error.localizedDescription)"
        }
    }

    private func removeAllowed(_ entry: AllowEntry) async {
        errorMessage = ""
        do {
            let req = EnforceRequest(type: entry.targetType, name: entry.targetName)
            try await sidecarClient.unallow(req)
            await loadLists()
        } catch {
            errorMessage = "Error removing allowed entry: \(error.localizedDescription)"
        }
    }

    private func resetNewEntry() {
        newEntryType = "skill"
        newEntryName = ""
        newEntryReason = ""
    }
}

struct ScannersView: View {
    @State private var skillScannerPath = ""
    @State private var mcpScannerPath = ""
    @State private var codeguardPath = ""
    @State private var statusMessage = ""
    @State private var isLoading = false

    private let configManager = ConfigManager()

    var body: some View {
        Form {
            Section("Scanner Binaries") {
                HStack {
                    Text("Skill Scanner:")
                        .frame(width: 120, alignment: .trailing)
                    TextField("Path", text: $skillScannerPath)
                        .font(.system(.body, design: .monospaced))
                }
                HStack {
                    Text("MCP Scanner:")
                        .frame(width: 120, alignment: .trailing)
                    TextField("Path", text: $mcpScannerPath)
                        .font(.system(.body, design: .monospaced))
                }
                HStack {
                    Text("CodeGuard:")
                        .frame(width: 120, alignment: .trailing)
                    TextField("Path", text: $codeguardPath)
                        .font(.system(.body, design: .monospaced))
                }
            }

            Section {
                Text("Scanner binaries must be installed separately")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text("Default locations will be used if paths are empty")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if !statusMessage.isEmpty {
                Section {
                    Text(statusMessage)
                        .foregroundColor(statusMessage.contains("Error") ? .red : .green)
                        .font(.caption)
                }
            }

            HStack {
                Spacer()
                Button("Save") {
                    saveSettings()
                }
                .buttonStyle(.borderedProminent)
                .disabled(isLoading)
            }
        }
        .padding()
        .onAppear {
            loadSettings()
        }
    }

    private func loadSettings() {
        isLoading = true
        do {
            let config = try configManager.load()
            skillScannerPath = config.scanners?.skillScanner?.binary ?? ""
            mcpScannerPath = config.scanners?.mcpScanner?.binary ?? ""
            codeguardPath = config.scanners?.codeguard ?? ""
            statusMessage = ""
        } catch {
            skillScannerPath = ""
            mcpScannerPath = ""
            codeguardPath = ""
            statusMessage = "Using defaults (config not found)"
        }
        isLoading = false
    }

    private func saveSettings() {
        isLoading = true
        statusMessage = ""
        do {
            var config = (try? configManager.load()) ?? AppConfig()
            if config.scanners == nil {
                config.scanners = ScannersConfig()
            }
            if config.scanners?.skillScanner == nil {
                config.scanners?.skillScanner = SkillScannerConfig()
            }
            if config.scanners?.mcpScanner == nil {
                config.scanners?.mcpScanner = MCPScannerConfig()
            }
            config.scanners?.skillScanner?.binary = skillScannerPath.isEmpty ? nil : skillScannerPath
            config.scanners?.mcpScanner?.binary = mcpScannerPath.isEmpty ? nil : mcpScannerPath
            config.scanners?.codeguard = codeguardPath.isEmpty ? nil : codeguardPath
            try configManager.save(config)
            statusMessage = "Settings saved successfully"
        } catch {
            statusMessage = "Error saving settings: \(error.localizedDescription)"
        }
        isLoading = false
    }
}

struct DiagnosticsView: View {
    @State private var health: HealthSnapshot?
    @State private var isLoading = false
    @State private var errorMessage = ""

    private let sidecarClient = SidecarClient()
    private let log = AppLogger.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("System Diagnostics")
                    .font(.headline)
                Spacer()
                Button("Refresh") {
                    Task { await refreshDiagnostics() }
                }
                Button("Export Logs") {
                    exportLogs()
                }
                Button("View Logs") {
                    (NSApp.delegate as? AppDelegate)?.showLogs()
                }
            }

            if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if !errorMessage.isEmpty {
                Text(errorMessage)
                    .foregroundColor(.red)
                    .font(.caption)
            } else if let h = health {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        diagnosticSection(title: "Uptime", value: formatUptime(h.uptimeMs))
                        diagnosticSection(title: "Started At", value: formatDate(h.startedAt))

                        Divider()

                        subsystemRow(name: "Gateway", health: h.gateway)
                        subsystemRow(name: "Watcher", health: h.watcher)
                        subsystemRow(name: "API", health: h.api)
                        subsystemRow(name: "Guardrail", health: h.guardrail)
                        subsystemRow(name: "Telemetry", health: h.telemetry)
                        subsystemRow(name: "Splunk", health: h.splunk)
                        if let sandbox = h.sandbox {
                            subsystemRow(name: "Sandbox", health: sandbox)
                        }
                    }
                    .padding()
                    .background(Color(nsColor: .textBackgroundColor))
                    .cornerRadius(8)
                }
            }
        }
        .padding()
        .onAppear {
            Task { await refreshDiagnostics() }
        }
    }

    private func diagnosticSection(title: String, value: String) -> some View {
        HStack {
            Text("\(title):")
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 100, alignment: .trailing)
            Text(value)
                .font(.system(.caption, design: .monospaced))
        }
    }

    private func subsystemRow(name: String, health: SubsystemHealth) -> some View {
        HStack(spacing: 12) {
            Circle()
                .fill(stateColor(health.state))
                .frame(width: 10, height: 10)
            Text(name)
                .font(.system(.body, design: .monospaced))
                .frame(width: 100, alignment: .leading)
            Text(health.state.rawValue)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
            Spacer()
            Text(formatDate(health.since))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
        }
    }

    private func stateColor(_ state: SubsystemState) -> Color {
        switch state {
        case .running: return .green
        case .starting, .reconnecting: return .yellow
        case .stopped, .disabled: return .gray
        case .error: return .red
        }
    }

    private func formatUptime(_ ms: Int64) -> String {
        let seconds = ms / 1000
        let minutes = seconds / 60
        let hours = minutes / 60
        let days = hours / 24
        if days > 0 {
            return "\(days)d \(hours % 24)h"
        } else if hours > 0 {
            return "\(hours)h \(minutes % 60)m"
        } else if minutes > 0 {
            return "\(minutes)m \(seconds % 60)s"
        } else {
            return "\(seconds)s"
        }
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }

    private func refreshDiagnostics() async {
        isLoading = true
        errorMessage = ""
        do {
            health = try await sidecarClient.health()
        } catch {
            errorMessage = "Error fetching health: \(error.localizedDescription)"
            health = nil
        }
        isLoading = false
    }

    private func exportLogs() {
        let panel = NSSavePanel()
        let timestamp = {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd_HHmmss"
            return f.string(from: Date())
        }()
        panel.nameFieldStringValue = "defenseclaw-logs-\(timestamp).log"
        panel.allowedContentTypes = [.log, .text]
        panel.canCreateDirectories = true

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }

            do {
                // Combine app logs + gateway log into one export
                var combined = "=== DefenseClaw App Logs ===\n"
                combined += log.exportLogContent()

                let home = FileManager.default.homeDirectoryForCurrentUser.path
                let gatewayLogPath = "\(home)/.defenseclaw/gateway.log"
                if FileManager.default.fileExists(atPath: gatewayLogPath),
                   let gatewayLogs = try? String(contentsOfFile: gatewayLogPath, encoding: .utf8) {
                    combined += "\n\n=== Gateway Sidecar Logs ===\n"
                    combined += gatewayLogs
                }

                try combined.write(to: url, atomically: true, encoding: .utf8)
                errorMessage = "Logs exported successfully"
                log.info("app", "Diagnostics logs exported", details: url.path)
            } catch {
                errorMessage = "Error exporting logs: \(error.localizedDescription)"
            }
        }
    }
}
