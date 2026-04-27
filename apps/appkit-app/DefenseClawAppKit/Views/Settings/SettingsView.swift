import SwiftUI
import DefenseClawKit
import AppKit

private enum SettingsTab: String {
    case config
    case gateway
    case guardrails
    case enforcement
    case scanners
    case diagnostics

    static var qaDefault: SettingsTab {
        let arguments = ProcessInfo.processInfo.arguments
        if let index = arguments.firstIndex(of: "--qa-settings-tab"),
           arguments.indices.contains(index + 1),
           let tab = SettingsTab(rawValue: arguments[index + 1]) {
            return tab
        }
        if let argument = arguments.first(where: { $0.hasPrefix("--qa-settings-tab=") }),
           let tab = SettingsTab(rawValue: String(argument.dropFirst("--qa-settings-tab=".count))) {
            return tab
        }
        return .config
    }
}

struct SettingsView: View {
    @State private var selectedTab = SettingsTab.qaDefault

    var body: some View {
        TabView(selection: $selectedTab) {
            ConfigFilesView()
                .tabItem {
                    Label("Config Files", systemImage: "doc.text.magnifyingglass")
                }
                .tag(SettingsTab.config)

            GatewaySettingsView()
                .tabItem {
                    Label("Gateway", systemImage: "network")
                }
                .tag(SettingsTab.gateway)

            GuardrailSettingsView()
                .tabItem {
                    Label("Guardrails", systemImage: "shield")
                }
                .tag(SettingsTab.guardrails)

            EnforcementView()
                .tabItem {
                    Label("Enforcement", systemImage: "lock.shield")
                }
                .tag(SettingsTab.enforcement)

            ScannersView()
                .tabItem {
                    Label("Scanners", systemImage: "magnifyingglass")
                }
                .tag(SettingsTab.scanners)

            DiagnosticsView()
                .tabItem {
                    Label("Diagnostics", systemImage: "stethoscope")
                }
                .tag(SettingsTab.diagnostics)
        }
        .frame(minWidth: 980, idealWidth: 1080, minHeight: 650, idealHeight: 740)
    }
}

struct ConfigFilesView: View {
    @State private var model = TextFileEditorModel(mode: .configuration)

    var body: some View {
        ManagedTextFileWorkspaceView(
            model: model,
            title: "Config Files",
            subtitle: "Edit DefenseClaw, OpenClaw, coding-agent, scanner, and observability configuration files from one workspace.",
            emptyMessage: "No config files found"
        )
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
    @State private var openClawGatewayRunning = false
    @State private var isRestarting = false

    private let configManager = ConfigManager()
    private let launchAgent = LaunchAgentManager()
    private let sidecarClient = SidecarClient()

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
                                .fill(openClawGatewayRunning ? Color.green : Color.gray)
                                .frame(width: 8, height: 8)
                            Text("OpenClaw Gateway")
                                .font(.subheadline)
                                .fontWeight(.medium)
                        }
                        Text(openClawGatewayRunning ? "Running" : "Managed by sidecar")
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
        Task {
            let launchAgentRunning = launchAgent.isRunning
            do {
                let health = try await sidecarClient.health()
                await MainActor.run {
                    sidecarRunning = true
                    openClawGatewayRunning = health.gateway.state == .running
                }
            } catch {
                await MainActor.run {
                    sidecarRunning = launchAgentRunning
                    openClawGatewayRunning = false
                }
            }
        }
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
    @State private var skills: [Skill] = []
    @State private var mcpServers: [MCPServer] = []
    @State private var tools: [ToolEntry] = []
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var searchText = ""
    @State private var statusFilter = "All"
    @State private var selectedItemID: String?
    @State private var newEntryAction = "block"
    @State private var newEntryType = "skill"
    @State private var newEntryName = ""
    @State private var newEntryReason = ""

    private let sidecarClient = SidecarClient()
    private let entryTypes = ["skill", "mcp", "plugin", "tool"]
    private let statusOptions = ["All", "Blocked", "Allowed", "Quarantined", "Monitored"]

    private var items: [EnforcementItem] {
        EnforcementItem.merge(
            blocked: blockedList,
            allowed: allowedList,
            skills: skills,
            mcpServers: mcpServers,
            tools: tools
        )
    }

    private var filteredItems: [EnforcementItem] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return items.filter { item in
            let matchesStatus = statusFilter == "All" || item.status == statusFilter
            guard matchesStatus else {
                return false
            }
            guard !query.isEmpty else {
                return true
            }
            return [
                item.name,
                item.type,
                item.source,
                item.detail,
                item.reason ?? ""
            ].contains { $0.lowercased().contains(query) }
        }
        .sorted {
            if $0.statusRank != $1.statusRank {
                return $0.statusRank < $1.statusRank
            }
            if $0.type != $1.type {
                return $0.type < $1.type
            }
            return $0.name < $1.name
        }
    }

    private var selectedItem: EnforcementItem? {
        guard let selectedItemID else {
            return filteredItems.first
        }
        return items.first { $0.id == selectedItemID } ?? filteredItems.first
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            HSplitView {
                itemList
                    .frame(minWidth: 520)

                detailPanel
                    .frame(minWidth: 360, idealWidth: 420)
            }
        }
        .task {
            await loadData()
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Enforcement")
                        .font(.title2.weight(.semibold))
                    Text("Block, allow, unblock, and review skills, MCP servers, plugins, and tools from one operator surface.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .layoutPriority(1)

                Spacer()

                Button {
                    Task { await loadData() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh enforcement data")
                .disabled(isLoading)
            }

            HStack(spacing: 10) {
                countChip("Items", items.count, .blue)
                countChip("Blocked", blockedList.count, .red)
                countChip("Allowed", allowedList.count, .green)

                Spacer()

                Picker("Status", selection: $statusFilter) {
                    ForEach(statusOptions, id: \.self) { option in
                        Text(option).tag(option)
                    }
                }
                .frame(width: 140)

                if isLoading {
                    ProgressView()
                        .controlSize(.small)
                }

                if !errorMessage.isEmpty {
                    Label("Partial data", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.caption.weight(.semibold))
                }
            }

            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search name, source, reason", text: $searchText)
                    .textFieldStyle(.plain)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        }
        .padding(18)
        .padding(.leading, 128)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var itemList: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                Text("TYPE")
                    .frame(width: 86, alignment: .leading)
                Text("STATUS")
                    .frame(width: 104, alignment: .leading)
                Text("NAME")
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text("SOURCE")
                    .frame(width: 150, alignment: .leading)
            }
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(Color(nsColor: .controlBackgroundColor))

            Divider()

            if filteredItems.isEmpty {
                ContentUnavailableView(
                    items.isEmpty ? "No enforcement inventory loaded" : "No entries match these filters",
                    systemImage: "lock.shield",
                    description: Text(items.isEmpty
                                      ? "Refresh to load explicit allow/block lists plus discovered skills, MCP servers, and tools."
                                      : "Clear search or status filters to show every enforcement item.")
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(filteredItems) { item in
                            EnforcementRow(item: item, isSelected: item.id == selectedItem?.id)
                                .contentShape(Rectangle())
                                .onTapGesture {
                                    selectedItemID = item.id
                                }
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }

    private var detailPanel: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if !errorMessage.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("Some runtime data could not be loaded", systemImage: "exclamationmark.triangle.fill")
                            .font(.headline)
                            .foregroundStyle(.orange)
                        Text(errorMessage)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    .padding(12)
                    .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                }

                if let item = selectedItem {
                    selectedItemCard(item)
                } else {
                    ContentUnavailableView(
                        "Select an item",
                        systemImage: "target",
                        description: Text("Status, source details, and enforcement actions appear here.")
                    )
                }

                inlineAddCard
            }
            .padding(18)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func selectedItemCard(_ item: EnforcementItem) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                Text(item.name)
                    .font(.headline)
                    .lineLimit(2)
                Text("\(item.type.capitalized) • \(item.source)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                statusBadge(item.status)
            }

            detailRow("Detail", item.detail)
            if let reason = item.reason, !reason.isEmpty {
                detailRow("Reason", reason)
            }
            detailRow("Identifier", item.id)

            HStack {
                Button {
                    Task { await block(item) }
                } label: {
                    Label("Block", systemImage: "hand.raised.fill")
                }
                .disabled(item.isBlocked)

                Button {
                    Task { await allow(item) }
                } label: {
                    Label("Allow", systemImage: "checkmark.shield")
                }
                .disabled(item.isAllowed)

                Button(role: .destructive) {
                    Task { await unblock(item) }
                } label: {
                    Label("Unblock", systemImage: "xmark.shield")
                }
                .disabled(!item.isBlocked)

                Button {
                    Task { await unallow(item) }
                } label: {
                    Label("Remove Allow", systemImage: "minus.circle")
                }
                .disabled(!item.isAllowed)
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var inlineAddCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Enforcement Entry")
                .font(.headline)

            Picker("Action", selection: $newEntryAction) {
                Text("Block").tag("block")
                Text("Allow").tag("allow")
            }
            .pickerStyle(.segmented)

            Picker("Type", selection: $newEntryType) {
                ForEach(entryTypes, id: \.self) { type in
                    Text(type.capitalized).tag(type)
                }
            }

            TextField("Target name", text: $newEntryName)
                .textFieldStyle(.roundedBorder)
            TextField("Reason", text: $newEntryReason)
                .textFieldStyle(.roundedBorder)

            HStack {
                Button {
                    Task { await addEntry() }
                } label: {
                    Label(newEntryAction == "block" ? "Block Target" : "Allow Target", systemImage: newEntryAction == "block" ? "hand.raised.fill" : "checkmark.shield")
                }
                .buttonStyle(.borderedProminent)
                .disabled(newEntryName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                Spacer()
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private func countChip(_ label: String, _ value: Int, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(value)")
                .font(.headline.monospacedDigit())
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(minWidth: 70, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
    }

    private func statusBadge(_ status: String) -> some View {
        Text(status)
            .font(.caption.weight(.semibold))
            .foregroundStyle(statusColor(status))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(statusColor(status).opacity(0.12), in: Capsule())
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value.isEmpty ? "Not reported" : value)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func loadData() async {
        isLoading = true
        errorMessage = ""
        var errors: [String] = []

        do {
            blockedList = try await sidecarClient.blockedList()
        } catch {
            errors.append("Blocked list: \(error.localizedDescription)")
        }

        do {
            allowedList = try await sidecarClient.allowedList()
        } catch {
            errors.append("Allowed list: \(error.localizedDescription)")
        }

        do {
            skills = try await sidecarClient.skills()
        } catch {
            errors.append("Skills: \(error.localizedDescription)")
        }

        do {
            mcpServers = try await sidecarClient.mcpServers()
        } catch {
            errors.append("MCP servers: \(error.localizedDescription)")
        }

        do {
            tools = try await sidecarClient.toolsCatalog()
        } catch {
            errors.append("Tools: \(error.localizedDescription)")
        }

        errorMessage = errors.joined(separator: "\n")
        if let selectedItemID, !items.contains(where: { $0.id == selectedItemID }) {
            self.selectedItemID = filteredItems.first?.id
        } else if selectedItemID == nil {
            selectedItemID = filteredItems.first?.id
        }
        isLoading = false
    }

    private func addEntry() async {
        let name = newEntryName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            return
        }

        let request = EnforceRequest(
            type: newEntryType,
            name: name,
            reason: newEntryReason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : newEntryReason
        )

        do {
            if newEntryAction == "block" {
                try await sidecarClient.block(request)
            } else {
                try await sidecarClient.allow(request)
            }
            newEntryName = ""
            newEntryReason = ""
            await loadData()
        } catch {
            errorMessage = "Enforcement update failed: \(error.localizedDescription)"
        }
    }

    private func block(_ item: EnforcementItem) async {
        do {
            try await sidecarClient.block(EnforceRequest(type: item.type, name: item.name))
            await loadData()
        } catch {
            errorMessage = "Block failed: \(error.localizedDescription)"
        }
    }

    private func allow(_ item: EnforcementItem) async {
        do {
            try await sidecarClient.allow(EnforceRequest(type: item.type, name: item.name))
            await loadData()
        } catch {
            errorMessage = "Allow failed: \(error.localizedDescription)"
        }
    }

    private func unblock(_ item: EnforcementItem) async {
        do {
            try await sidecarClient.unblock(EnforceRequest(type: item.type, name: item.name))
            await loadData()
        } catch {
            errorMessage = "Unblock failed: \(error.localizedDescription)"
        }
    }

    private func unallow(_ item: EnforcementItem) async {
        do {
            try await sidecarClient.unallow(EnforceRequest(type: item.type, name: item.name))
            await loadData()
        } catch {
            errorMessage = "Remove allow failed: \(error.localizedDescription)"
        }
    }

    private func statusColor(_ status: String) -> Color {
        switch status {
        case "Blocked":
            return .red
        case "Allowed":
            return .green
        case "Quarantined":
            return .orange
        default:
            return .secondary
        }
    }
}

private struct EnforcementRow: View {
    let item: EnforcementItem
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 0) {
            Text(item.type.capitalized)
                .frame(width: 86, alignment: .leading)
            Label(item.status, systemImage: item.statusIcon)
                .foregroundStyle(item.statusColor)
                .frame(width: 104, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .lineLimit(1)
                Text(item.detail)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Text(item.source)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .frame(width: 150, alignment: .leading)
        }
        .font(.caption)
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(isSelected ? Color.accentColor.opacity(0.14) : Color.clear)
    }
}

private struct EnforcementItem: Identifiable {
    let type: String
    let name: String
    let source: String
    let detail: String
    let reason: String?
    let isBlocked: Bool
    let isAllowed: Bool
    let isQuarantined: Bool

    var id: String { "\(type):\(name)" }

    var status: String {
        if isQuarantined {
            return "Quarantined"
        }
        if isBlocked {
            return "Blocked"
        }
        if isAllowed {
            return "Allowed"
        }
        return "Monitored"
    }

    var statusRank: Int {
        switch status {
        case "Blocked":
            return 0
        case "Quarantined":
            return 1
        case "Allowed":
            return 2
        default:
            return 3
        }
    }

    var statusIcon: String {
        switch status {
        case "Blocked":
            return "hand.raised.fill"
        case "Allowed":
            return "checkmark.shield"
        case "Quarantined":
            return "archivebox.fill"
        default:
            return "eye"
        }
    }

    var statusColor: Color {
        switch status {
        case "Blocked":
            return .red
        case "Allowed":
            return .green
        case "Quarantined":
            return .orange
        default:
            return .secondary
        }
    }

    static func merge(
        blocked: [BlockEntry],
        allowed: [AllowEntry],
        skills: [Skill],
        mcpServers: [MCPServer],
        tools: [ToolEntry]
    ) -> [EnforcementItem] {
        var merged: [String: EnforcementItem] = [:]
        let blockedMap = Dictionary(uniqueKeysWithValues: blocked.map { ($0.id, $0) })
        let allowedMap = Dictionary(uniqueKeysWithValues: allowed.map { ($0.id, $0) })

        func add(
            type: String,
            name: String,
            source: String,
            detail: String,
            reason: String? = nil,
            blocked: Bool = false,
            allowed: Bool = false,
            quarantined: Bool = false
        ) {
            let key = "\(type):\(name)"
            let blockEntry = blockedMap[key]
            let allowEntry = allowedMap[key]
            merged[key] = EnforcementItem(
                type: type,
                name: name,
                source: source,
                detail: detail,
                reason: blockEntry?.reason ?? allowEntry?.reason ?? reason,
                isBlocked: blocked || blockEntry != nil,
                isAllowed: allowed || allowEntry != nil,
                isQuarantined: quarantined
            )
        }

        for skill in skills {
            add(
                type: "skill",
                name: skill.name,
                source: "Skills",
                detail: skill.path ?? "No path reported",
                blocked: skill.blocked,
                allowed: skill.allowed,
                quarantined: skill.quarantined
            )
        }

        for server in mcpServers {
            add(
                type: "mcp",
                name: server.name,
                source: "MCP Servers",
                detail: server.command ?? server.url,
                blocked: server.blocked,
                allowed: server.allowed
            )
        }

        for tool in tools {
            add(
                type: "tool",
                name: tool.name,
                source: tool.group ?? tool.source ?? "Tools",
                detail: tool.description ?? tool.id,
                blocked: tool.blocked ?? false
            )
        }

        for entry in blocked where merged[entry.id] == nil {
            add(type: entry.targetType, name: entry.targetName, source: "Manual Block", detail: "Explicit block entry", reason: entry.reason, blocked: true)
        }

        for entry in allowed where merged[entry.id] == nil {
            add(type: entry.targetType, name: entry.targetName, source: "Manual Allow", detail: "Explicit allow entry", reason: entry.reason, allowed: true)
        }

        return Array(merged.values)
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
    @State private var statusPayload: [String: AnyCodable] = [:]
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var doctorOutput = ""
    @State private var isRunningDoctor = false
    @State private var lastRefresh: Date?

    private let sidecarClient = SidecarClient()
    private let commandRunner = LocalCommandRunner()
    private let log = AppLogger.shared

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header

                if !errorMessage.isEmpty {
                    diagnosticErrorCard
                }

                if let health {
                    summaryGrid(health)
                    subsystemGrid(health)
                } else if isLoading {
                    ProgressView("Checking DefenseClaw backend...")
                        .frame(maxWidth: .infinity, minHeight: 180)
                } else {
                    backendOfflineCard
                }

                statusPayloadCard
                doctorCard
                logLocationsCard
            }
            .padding(18)
        }
        .onAppear {
            Task { await refreshDiagnostics() }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("System Diagnostics")
                        .font(.title2.weight(.semibold))
                    Text("Install, backend health, subsystem status, logs, and repair commands for a self-contained macOS app.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if let lastRefresh {
                    Text("Updated \(lastRefresh.formatted(date: .omitted, time: .standard))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Button {
                    Task { await refreshDiagnostics() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(isLoading)

                Button {
                    exportLogs()
                } label: {
                    Label("Export Logs", systemImage: "square.and.arrow.up")
                }

                Button {
                    (NSApp.delegate as? AppDelegate)?.showLogs()
                } label: {
                    Label("View Logs", systemImage: "doc.text.magnifyingglass")
                }
            }

            if isLoading {
                ProgressView()
                    .controlSize(.small)
            }
        }
    }

    private var diagnosticErrorCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Backend health check failed", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)
            Text(errorMessage)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            HStack {
                Button {
                    (NSApp.delegate as? AppDelegate)?.showSetup()
                } label: {
                    Label("Open Setup", systemImage: "list.clipboard")
                }
                Button {
                    Task { await runDoctor() }
                } label: {
                    Label("Run Doctor", systemImage: "stethoscope")
                }
                .disabled(isRunningDoctor)
                Button {
                    (NSApp.delegate as? AppDelegate)?.showLogs()
                } label: {
                    Label("Open Logs", systemImage: "doc.text")
                }
            }
        }
        .padding(14)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    private var backendOfflineCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("DefenseClaw backend is not reporting health", systemImage: "wifi.exclamationmark")
                .font(.headline)
            Text("A downloaded app user should not have to fix this in a terminal. Use Setup to install or repair the backend, then re-run diagnostics here.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button {
                    (NSApp.delegate as? AppDelegate)?.showSetup()
                } label: {
                    Label("Install or Repair Backend", systemImage: "wrench.and.screwdriver")
                }
                .buttonStyle(.borderedProminent)

                Button {
                    Task { await refreshDiagnostics() }
                } label: {
                    Label("Retry", systemImage: "arrow.clockwise")
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private func summaryGrid(_ health: HealthSnapshot) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 12)], spacing: 12) {
            summaryCard("Backend", health.isHealthy ? "healthy" : "degraded", health.isHealthy ? .green : .orange, "Overall helper state")
            summaryCard("Uptime", formatUptime(health.uptimeMs), .blue, "Started \(formatDate(health.startedAt))")
            summaryCard("Gateway", health.gateway.state.rawValue, stateColor(health.gateway.state), health.gateway.lastError ?? "OpenClaw connection")
            summaryCard("Guardrail", health.guardrail.state.rawValue, stateColor(health.guardrail.state), health.guardrail.lastError ?? "Request scanner")
        }
    }

    private func summaryCard(_ title: String, _ value: String, _ color: Color, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.headline)
                .foregroundStyle(color)
            Text(detail)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private func subsystemGrid(_ health: HealthSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Subsystems")
                .font(.headline)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 12)], spacing: 12) {
                subsystemCard("Gateway", health.gateway)
                subsystemCard("Watcher", health.watcher)
                subsystemCard("API", health.api)
                subsystemCard("Guardrail", health.guardrail)
                subsystemCard("Telemetry", health.telemetry)
                subsystemCard("Sinks", health.splunk)
                if let sandbox = health.sandbox {
                    subsystemCard("Sandbox", sandbox)
                }
            }
        }
    }

    private func subsystemCard(_ name: String, _ health: SubsystemHealth) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Circle()
                    .fill(stateColor(health.state))
                    .frame(width: 9, height: 9)
                Text(name)
                    .font(.headline)
                Spacer()
                Text(health.state.rawValue)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(stateColor(health.state))
            }

            Text(health.lastError ?? "No subsystem detail reported")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(3)

            Text("Since \(formatDate(health.since))")
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var statusPayloadCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Raw Status Snapshot")
                    .font(.headline)
                Spacer()
                Text("\(statusPayload.count) keys")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if statusPayload.isEmpty {
                Text("No /status payload available yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                LazyVGrid(columns: [GridItem(.fixed(180), alignment: .leading), GridItem(.flexible(), alignment: .leading)], alignment: .leading, spacing: 8) {
                    ForEach(statusPayload.keys.sorted(), id: \.self) { key in
                        Text(key)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Text(statusPayload[key]?.description ?? "")
                            .font(.caption.monospaced())
                            .lineLimit(2)
                            .textSelection(.enabled)
                    }
                }
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var doctorCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Doctor")
                    .font(.headline)
                Spacer()
                Button {
                    Task { await runDoctor() }
                } label: {
                    Label("Run Doctor", systemImage: "stethoscope")
                }
                .disabled(isRunningDoctor)
            }

            if isRunningDoctor {
                ProgressView("Running diagnostics...")
            } else if doctorOutput.isEmpty {
                Text("Run doctor from the app to verify install state, gateway, scanner setup, policies, and observability prerequisites.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ScrollView {
                    Text(doctorOutput)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                }
                .frame(minHeight: 120, maxHeight: 240)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var logLocationsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Local Files")
                .font(.headline)
            diagnosticPath("Config", "~/.defenseclaw/config.yaml")
            diagnosticPath("Environment", "~/.defenseclaw/.env")
            diagnosticPath("Gateway log", "~/.defenseclaw/gateway.log")
            diagnosticPath("Policies", "~/.defenseclaw/policies")
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private func diagnosticPath(_ label: String, _ path: String) -> some View {
        HStack {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 110, alignment: .leading)
            Text(path)
                .font(.caption.monospaced())
                .textSelection(.enabled)
            Spacer()
        }
    }

    private func stateColor(_ state: SubsystemState) -> Color {
        switch state {
        case .running:
            return .green
        case .starting, .reconnecting:
            return .yellow
        case .stopped, .disabled:
            return .gray
        case .error:
            return .red
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
            async let healthSnapshot = sidecarClient.health()
            async let status = sidecarClient.status()
            let (resolvedHealth, resolvedStatus) = try await (healthSnapshot, status)
            health = resolvedHealth
            statusPayload = resolvedStatus
        } catch {
            errorMessage = "Error fetching backend diagnostics: \(error.localizedDescription)"
            health = nil
            do {
                statusPayload = try await sidecarClient.status()
            } catch {
                statusPayload = [:]
            }
        }

        lastRefresh = Date()
        isLoading = false
    }

    private func runDoctor() async {
        isRunningDoctor = true
        doctorOutput = ""
        do {
            let result = try await commandRunner.run("defenseclaw", arguments: ["doctor"])
            let output = result.combinedOutput.isEmpty ? "Doctor exited with code \(result.exitCode)." : result.combinedOutput
            doctorOutput = "$ \(result.commandLine)\nexit \(result.exitCode)\n\n\(output)"
        } catch {
            doctorOutput = "Could not run defenseclaw doctor from the app: \(error.localizedDescription)\n\nUse Setup to install or repair the bundled backend."
        }
        isRunningDoctor = false
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
