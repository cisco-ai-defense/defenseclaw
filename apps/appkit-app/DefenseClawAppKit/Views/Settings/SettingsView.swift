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

    private let configManager = ConfigManager()

    var body: some View {
        Form {
            Section("Gateway Configuration") {
                TextField("Host", text: $host)
                TextField("API Port", text: $apiPort)
                TextField("Gateway WebSocket Port", text: $gatewayWSPort)
                Toggle("Auto-start Gateway", isOn: $autoStart)
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
}

struct GuardrailSettingsView: View {
    @State private var enabled = false
    @State private var mode = "enforce"
    @State private var scannerMode = "full"
    @State private var statusMessage = ""
    @State private var isLoading = false

    private let configManager = ConfigManager()
    private let modes = ["enforce", "observe", "disabled"]
    private let scannerModes = ["full", "fast", "minimal"]

    var body: some View {
        Form {
            Section("Guardrail Configuration") {
                Toggle("Enabled", isOn: $enabled)
                Picker("Mode", selection: $mode) {
                    ForEach(modes, id: \.self) { m in
                        Text(m.capitalized).tag(m)
                    }
                }
                Picker("Scanner Mode", selection: $scannerMode) {
                    ForEach(scannerModes, id: \.self) { m in
                        Text(m.capitalized).tag(m)
                    }
                }
            }

            Section {
                Text("Enforce: Block malicious requests")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text("Observe: Log only, no blocking")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text("Disabled: No guardrail checks")
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
            enabled = config.guardrail?.enabled ?? false
            mode = config.guardrail?.mode ?? "enforce"
            scannerMode = config.guardrail?.scannerMode ?? "full"
            statusMessage = ""
        } catch {
            enabled = false
            mode = "enforce"
            scannerMode = "full"
            statusMessage = "Using defaults (config not found)"
        }
        isLoading = false
    }

    private func saveSettings() {
        isLoading = true
        statusMessage = ""
        do {
            var config = (try? configManager.load()) ?? AppConfig()
            if config.guardrail == nil {
                config.guardrail = GuardrailFullConfig()
            }
            config.guardrail?.enabled = enabled
            config.guardrail?.mode = mode
            config.guardrail?.scannerMode = scannerMode
            try configManager.save(config)
            statusMessage = "Settings saved successfully"
        } catch {
            statusMessage = "Error saving settings: \(error.localizedDescription)"
        }
        isLoading = false
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
        blockedList.removeAll { $0.id == entry.id }
        await loadLists()
    }

    private func removeAllowed(_ entry: AllowEntry) async {
        errorMessage = ""
        allowedList.removeAll { $0.id == entry.id }
        await loadLists()
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
        panel.nameFieldStringValue = "gateway.log"
        panel.allowedContentTypes = [.log, .text]
        panel.canCreateDirectories = true

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }

            let home = FileManager.default.homeDirectoryForCurrentUser.path
            let logPath = "\(home)/.defenseclaw/gateway.log"
            let logURL = URL(fileURLWithPath: logPath)

            do {
                if FileManager.default.fileExists(atPath: logPath) {
                    try FileManager.default.copyItem(at: logURL, to: url)
                    errorMessage = "Logs exported successfully"
                } else {
                    errorMessage = "Log file not found at \(logPath)"
                }
            } catch {
                errorMessage = "Error exporting logs: \(error.localizedDescription)"
            }
        }
    }
}
