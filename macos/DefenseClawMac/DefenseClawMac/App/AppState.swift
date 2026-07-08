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

// Root observable state + tiered RefreshEngine (spec §3.2/§3.3).
// Pulse tier feeds the menu bar icon, Overview health, and new-alert detection.

import Foundation
import Observation
import SwiftUI
import UserNotifications

enum MenuBarState {
    case healthy, alerting(count: Int), degraded, offline, scanning, paused
}

enum PanelID: String, CaseIterable, Identifiable {
    case overview, alerts, logs, audit, activity
    case skills, mcps, plugins, tools
    case inventory, aiDiscovery, registries
    case setup

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: "Overview"
        case .alerts: "Alerts"
        case .logs: "Logs"
        case .audit: "Audit"
        case .activity: "Activity"
        case .skills: "Skills"
        case .mcps: "MCPs"
        case .plugins: "Plugins"
        case .tools: "Tools"
        case .inventory: "Inventory"
        case .aiDiscovery: "AI Discovery"
        case .registries: "Registries"
        case .setup: "Setup"
        }
    }

    var systemImage: String {
        switch self {
        case .overview: "gauge.with.dots.needle.50percent"
        case .alerts: "exclamationmark.shield"
        case .logs: "text.alignleft"
        case .audit: "checklist"
        case .activity: "clock.arrow.circlepath"
        case .skills: "wand.and.stars"
        case .mcps: "server.rack"
        case .plugins: "puzzlepiece.extension"
        case .tools: "wrench.and.screwdriver"
        case .inventory: "shippingbox"
        case .aiDiscovery: "sparkle.magnifyingglass"
        case .registries: "books.vertical"
        case .setup: "gearshape.2"
        }
    }
}

enum AlertPanelRequest: Equatable {
    case all
    case blocks
}

enum SettingsKeys {
    static let pulseInterval = "pulseInterval"
    static let backgroundInterval = "backgroundInterval"
    static let backgroundMonitoring = "backgroundMonitoring"
    static let notifyCritical = "notifyCritical"
    static let notifyHigh = "notifyHigh"
    static let notifyGatewayOffline = "notifyGatewayOffline"
    static let seenAlertHighWater = "seenAlertHighWater"
}

struct LogPanelRequest: Equatable {
    var stream: LogStream = .gateway
    var preset: LogPreset
    var actionFilter: String = "all"
    var eventTypeFilter: String = "all"
}

@Observable
@MainActor
final class AppState {
    // Data layer singletons
    let configStore = ConfigStore()
    let gateway = GatewayClient()
    let audit = AuditStore()
    let stream = EventStreamReader()
    let cli: CLIRunner
    let activity: CommandActivityStore
    let updater = UpdateChecker()

    // Self-update state (this Mac app)
    var availableUpdate: ReleaseInfo?
    var upgradeState: UpgradeState = .idle
    var updateBannerDismissed = false
    /// Persisted across launches: GitHub's unauthenticated API allows 60
    /// requests/hour per IP, so app relaunches must not re-check each time.
    @ObservationIgnored @AppStorage("lastUpdateCheckTime") private var lastUpdateCheckTime: Double = 0
    @ObservationIgnored @AppStorage("lastMacAppUpdateCheckTime") private var lastMacAppUpdateCheckTime: Double = 0

    // DefenseClaw runtime (CLI + gateway) update state
    var installedRuntimeVersion: String?
    var runtimeVersionCheckInProgress = false
    var runtimeVersionError: String?
    var runtimeReleaseChecked = false
    var availableRuntimeUpdate: ReleaseInfo?
    var runtimeUpgradeState: UpgradeState = .idle
    /// Bundled-payload install/repair progress (RuntimeInstaller.swift).
    var runtimeInstallState: RuntimeInstallState = .idle
    /// Current installer step's activity runID — the Cancel target.
    var runtimeInstallRunID: UUID?
    /// First-run sheet dismissal for this launch (Open Activity / Esc); the
    /// sheet re-presents next launch while no configuration exists.
    var firstRunDismissed = false
    var runtimeBannerDismissed = false
    var runtimeUpgradeLogTail = ""
    @ObservationIgnored @AppStorage("lastRuntimeUpdateCheckTime") private var lastRuntimeUpdateCheckTime: Double = 0
    /// Full `defenseclaw upgrade` output from the last failed run (for Copy).
    var runtimeUpgradeLog = ""
    /// True when the last release lookup failed (offline / GitHub rate limit) —
    /// "Up to date" must not be claimed on a failed check.
    var lastCheckFailed = false
    var appUpdateCheckFailed = false
    var runtimeUpdateCheckFailed = false
    @ObservationIgnored private var alertRefreshInProgress = false

    var updateOperationInProgress: Bool {
        func busy(_ state: UpgradeState) -> Bool {
            switch state {
            case .checking, .downloading, .installing: true
            default: false
            }
        }
        return busy(upgradeState) || busy(runtimeUpgradeState) || runtimeInstallState.isRunning
    }

    // Pulse state
    var health: HealthSnapshot = HealthSnapshot()
    var scanners: [ScannerStatus] = []
    /// Last scanner Fix failure, shown inline in the Scanners card.
    var scannerFixError: String?
    /// Located `defenseclaw` binary, cached here so the 5s pulse never
    /// spawns the login-shell fallback search; refreshed on start/reload.
    private var probeCLIPath: String?
    /// Scanner names the login-shell PATH resolves (custom bin dirs the
    /// standard probe misses) — checked once, alongside probeCLIPath.
    private var shellResolvedScanners: Set<String> = []
    private var probeResolved = false

    /// One-time (per launch / per config reload) subprocess-backed lookups
    /// backing the scanner probe. Runs at the top of the first pulse, so
    /// panel-triggered pulses can't race ahead of start() and briefly show
    /// fixable scanners as "missing".
    private func resolveProbePaths(force: Bool = false) async {
        if probeResolved && !force { return }
        probeCLIPath = await cli.locateBinary()
        var found: Set<String> = []
        for name in ScannerProbe.externalScanners where !ScannerProbe.binaryInstalled(name) {
            if await cli.locateTool(name) != nil { found.insert(name) }
        }
        shellResolvedScanners = found
        probeResolved = true
    }
    var gatewayReachable = false
    var lastGatewayError: GatewayError?
    var config = DefenseClawConfig()
    var installDetected = true
    var aiSnapshot = AIUsageSnapshot()
    var aiFetchEverSucceeded = false
    var connectorSetupInFlight: Set<String> = []
    var connectorSetupError: String?

    // Alerts state
    var unackedAlerts: [AlertRow] = []
    var dismissedIDs: Set<String> = []
    var overviewEnforcementMetrics = OverviewEnforcementMetrics()
    /// Last `alerts acknowledge` failure, surfaced in the popover/panel.
    var ackError: String?
    var scanInFlight = false

    // UI state
    var selectedPanel: PanelID = .overview
    var monitoringPaused = false
    /// Connector filter shared by Alerts/Audit/Logs/Activity ("" = All),
    /// the multi-connector equivalent of the TUI's connector-filter chip.
    var connectorFilter: String = ""
    /// Latest audit-derived per-connector stats (pulse-fed) — the fallback
    /// source for scoped metrics when /health has no row for a connector.
    var connectorStatsCache: [String: AuditStore.ConnectorStats] = [:]
    /// ALL-TIME per-connector totals (db.py connector_hook_event_stats) —
    /// the Connectors table's no-live-window fallback so CALLS doesn't
    /// freeze at the recent-window size. Empty on pre-v7 schemas.
    var connectorStatsAllTimeCache: [String: AuditStore.ConnectorStats] = [:]
    /// Last-good doctor cache from <data_dir>/doctor_cache.json (pulse-fed).
    var doctorCache: DoctorCache?
    /// Silent LLM bypass egress events in the last 5 minutes (pulse-fed).
    var silentBypassCount = 0
    /// Session-scoped "Total scans" for the Activity card (pulse-fed).
    var sessionTotalScans = 0
    /// True while a background diagnose probe is running (⇧⌘D).
    var diagnoseRunning = false
    var alertPanelRequest: AlertPanelRequest?
    var auditPresetRequest: String?
    var logPanelRequest: LogPanelRequest?
    var commandPalettePresented = false

    // Settings (mirrored via @AppStorage in views; defaults here)
    @ObservationIgnored @AppStorage(SettingsKeys.pulseInterval) var pulseInterval: Double = 5
    @ObservationIgnored @AppStorage(SettingsKeys.backgroundInterval) var backgroundInterval: Double = 60
    @ObservationIgnored @AppStorage(SettingsKeys.notifyCritical) var notifyCritical = true
    @ObservationIgnored @AppStorage(SettingsKeys.notifyHigh) var notifyHigh = true
    @ObservationIgnored @AppStorage(SettingsKeys.notifyGatewayOffline) var notifyGatewayOffline = true
    @ObservationIgnored @AppStorage(SettingsKeys.seenAlertHighWater) var seenAlertHighWater: Double = 0

    private var pulseTask: Task<Void, Never>?
    private var wasReachable: Bool?
    @ObservationIgnored private var lastConfigSignature = ""

    init() {
        let runner = CLIRunner()
        cli = runner
        activity = CommandActivityStore(runner: runner)
    }

    var menuBarState: MenuBarState {
        if monitoringPaused { return .paused }
        if scanInFlight { return .scanning }
        if !gatewayReachable { return .offline }
        // Same definition as the Findings tile and Alerts badge (C/H/M/L).
        let count = unackedAlerts.filter { $0.severity > .info }.count
        if count > 0 { return .alerting(count: count) }
        let degraded = health.subsystems.contains { EntityState.classify($0.state) == .warn || EntityState.classify($0.state) == .blocked }
        if degraded || EntityState.classify(health.state) == .warn { return .degraded }
        return .healthy
    }

    // MARK: - Lifecycle

    func start() {
        Task {
            let cfg = await configStore.reload()
            config = cfg
            installDetected = await configStore.installPresent
            await gateway.update(config: cfg)
            startPulse()
            // Local runtime detection is independent of the throttled GitHub
            // release lookup so every launch can report the installed CLI.
            await refreshInstalledRuntimeVersion()
            // Respect the persisted 6h check window — relaunches must not
            // burn the unauthenticated GitHub API quota (60/hr per IP).
            await checkForUpdates()
        }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { _, _ in }
    }

    func startPulse() {
        pulseTask?.cancel()
        pulseTask = Task { [weak self] in
            while !Task.isCancelled {
                if let self, !self.monitoringPaused {
                    await self.pulse()
                }
                let interval = self?.pulseInterval ?? 5
                try? await Task.sleep(for: .seconds(max(2, interval)))
            }
        }
    }

    func pulse() async {
        // Re-resolve config + gateway token when config.yaml/.env changed on
        // disk (token rotation, setup commands, the TUI editing config) —
        // /health is unauthenticated, so a stale token otherwise only
        // surfaces as 401s on the authed endpoints until app relaunch.
        let signature = ConfigStore.diskSignature
        if signature != lastConfigSignature {
            lastConfigSignature = signature
            let cfg = await configStore.reload()
            config = cfg
            await gateway.update(config: cfg)
        }
        await resolveProbePaths() // no-op after the first pulse
        do {
            var snap = try await gateway.health()
            // Enrich connector rows: mode/rule pack from config, and
            // audit-derived activity (hook connectors deliver calls
            // out-of-band, so /health counters can sit at zero).
            let stats = await audit.connectorStats()
            connectorStatsCache = stats
            connectorStatsAllTimeCache = await audit.connectorStatsAllTime()
            for i in snap.connectors.indices {
                let name = snap.connectors[i].name
                snap.connectors[i].mode = connectorValue(config.connectorModes, for: name)
                    ?? config.guardrailMode ?? "observe"
                snap.connectors[i].rulePack = connectorValue(config.connectorRulePacks, for: name) ?? "default"
                if let s = stats.first(where: { $0.key.caseInsensitiveCompare(name) == .orderedSame })?.value {
                    if snap.connectors[i].calls == 0 { snap.connectors[i].calls = s.hookCalls }
                    if snap.connectors[i].blocks == 0 { snap.connectors[i].blocks = s.blocks }
                    snap.connectors[i].alerts = s.alerts
                    snap.connectors[i].lastActivity = s.lastActivity
                }
            }
            health = snap
            if let usage = try? await gateway.aiUsage() {
                aiSnapshot = usage
                aiFetchEverSucceeded = true
            }
            // normalize_filter parity: a torn-down connector or a
            // single-connector roster silently falls back to All so the app
            // can never stay trapped in a filter with no chrome to clear it.
            let names = activeConnectorNames
            if !connectorFilter.isEmpty,
               names.count <= 1 || !names.contains(where: { $0.lowercased() == connectorFilter.lowercased() }) {
                connectorFilter = ""
            }
            if !gatewayReachable, wasReachable == false, notifyGatewayOffline {
                notify(title: "DefenseClaw gateway recovered",
                       body: "Gateway is reachable again on port \(config.gatewayPort).", id: "gw-recovered-\(Date().timeIntervalSince1970)")
            }
            gatewayReachable = true
            lastGatewayError = nil
        } catch let err as GatewayError {
            if gatewayReachable, notifyGatewayOffline, case .offline = err {
                notify(title: "DefenseClaw gateway offline",
                       body: "Lost contact with the gateway on port \(config.gatewayPort).", id: "gw-offline-\(Date().timeIntervalSince1970)")
            }
            gatewayReachable = false
            lastGatewayError = err
        } catch {
            gatewayReachable = false
        }
        wasReachable = gatewayReachable

        // Scanner statuses don't depend on the gateway (binaries on PATH,
        // config, .env) — refresh them even when offline so the card stays
        // useful. guardrailState falls back to the last-known subsystem.
        let guardrailState = health.subsystems.first { $0.name == "guardrail" }?.state
        // Doctor cache: keep last-good on parse failure (TUI semantics).
        doctorCache = DoctorCache.load() ?? doctorCache
        scanners = ScannerProbe.statuses(
            config: config,
            guardrailState: guardrailState,
            missingCredentials: (doctorCache?.isEmpty == false) ? doctorCache!.missingRequiredCredentials : nil,
            cliPath: probeCLIPath,
            shellFound: shellResolvedScanners
        )
        // A Fix error is only meaningful while a fixable row remains; once
        // the rows resolve (externally or via a later Fix), drop the banner.
        if scannerFixError != nil, !scanners.contains(where: { $0.fixSource != nil }) {
            scannerFixError = nil
        }
        // Session-scoped Total scans since the earliest connector session
        // start; all-time when no session window has ever been observed.
        sessionTotalScans = await audit.countScanResultsSince(sessionStart)

        // Tail the JSONL stream and refresh the alert set.
        _ = await stream.poll()
        await refreshAlerts()
        await checkForUpdates() // no-op unless 6h have passed
    }

    func refreshAlerts() async {
        guard !alertRefreshInProgress else { return }
        alertRefreshInProgress = true
        defer { alertRefreshInProgress = false }
        // Parity with the TUI's flat_rows: audit alert queue (severity-bearing
        // rows from list_alerts) + one row per scan block grouped by scan_id
        // from gateway.jsonl + egress rows. Nested findings stay inside their
        // block (the chips never count them).
        let queue = await audit.alertQueueEvents(limit: 500)
        let blocks = await stream.scanBlocks
        let egress = await stream.egress

        // count_recent_silent_bypass: allow-decision LLM-shaped bypasses in
        // the last 300s (passthrough+looks_like_llm, or the shape branch).
        let bypassCutoff = Date().addingTimeInterval(-300)
        silentBypassCount = egress.filter {
            let decision = $0.decision.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let branch = $0.branch.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return $0.timestampParsed && $0.timestamp >= bypassCutoff
                && (decision == "allow" || decision == "allowed")
                && ((branch == "passthrough" && $0.looksLikeLLM) || branch == "shape")
        }.count

        var rows: [AlertRow] = queue.map { .audit($0) }
        rows += blocks.map { .scan($0) }
        rows += egress.suffix(100).filter {
            let decision = $0.decision.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return (decision != "allow" && decision != "allowed") || $0.looksLikeLLM
        }.map { .egress($0) }
        rows.sort { $0.timestamp > $1.timestamp }

        let fresh = rows.filter { !dismissedIDs.contains($0.id) }

        // Notify on rows newer than the persisted high-water mark.
        let highWater = Date(timeIntervalSince1970: seenAlertHighWater)
        var newest = highWater
        for row in fresh where row.timestamp > highWater {
            newest = max(newest, row.timestamp)
            let wantNotify = (row.severity == .critical && notifyCritical) || (row.severity == .high && notifyHigh)
            if wantNotify {
                notify(
                    title: "\(row.severity.rawValue): \(row.action)",
                    body: "Target: \(row.target)", // target + severity only — never payload contents
                    id: row.id
                )
            }
        }
        if newest > highWater { seenAlertHighWater = newest.timeIntervalSince1970 }
        // Gather every count before publishing so Overview, the sidebar, Alerts,
        // and the menu bar advance as one coherent security snapshot.
        let nextMetrics = OverviewEnforcementMetrics(
            hookCalls: await audit.overviewHookCallCount(),
            blocks: await audit.overviewBlockCount(),
            findings: fresh.filter { $0.severity > .info }.count,
            updatedAt: Date()
        )

        // Publish only on real row changes so Table does not re-diff mid-gesture.
        // These adjacent assignments contain no suspension point, preventing a
        // frame where the badge and the detailed alert list disagree.
        if fresh.map(\.id) != unackedAlerts.map(\.id) {
            unackedAlerts = fresh
        }
        overviewEnforcementMetrics = nextMetrics
    }

    // MARK: - Actions

    @discardableResult
    func runCommand(
        runID: UUID = UUID(),
        title: String,
        binary: String = "defenseclaw",
        arguments: [String],
        standardInput: String? = nil,
        environment: [String: String] = [:],
        category: String = "other",
        origin: String,
        successEffects: [String] = [],
        suggestedNextAction: String = "",
        refreshOnSuccess: Bool = false
    ) async -> CLIResult {
        let result = await activity.run(
            id: runID,
            title: title,
            binary: binary,
            arguments: arguments,
            standardInput: standardInput,
            environment: environment,
            category: category,
            origin: origin,
            successEffects: successEffects,
            suggestedNextAction: suggestedNextAction
        )
        if result.succeeded, refreshOnSuccess {
            NotificationCenter.default.post(name: .dcRefreshPanel, object: nil)
            reloadConfig()
        }
        return result
    }

    /// Register a discovered hook connector without replacing existing peers.
    /// Proxy connectors need their full scanner/proxy wizard, so those route to
    /// Setup instead of attempting a lossy one-click configuration.
    func configureDetectedConnector(_ name: String) {
        let normalized = ConnectorOnboarding.normalizedConnector(name)
        guard TUIWizards.hookConnectors.contains(normalized) else {
            selectedPanel = .setup
            return
        }
        guard connectorSetupInFlight.insert(normalized).inserted else { return }
        connectorSetupError = nil
        Task {
            let commandName = normalized == "claudecode" ? "claude-code" : normalized
            let result = await runCommand(
                title: "Add \(friendlyConnectorName(normalized)) connector",
                arguments: ["setup", commandName, "--yes", "--mode", "observe"],
                category: "setup",
                origin: "Overview",
                successEffects: ["\(friendlyConnectorName(normalized)) added to connector roster"],
                suggestedNextAction: "Resume the agent so it emits a fresh hook event."
            )
            if result.succeeded {
                let updated = await configStore.reload()
                config = updated
                await gateway.update(config: updated)
                await pulse()
            } else {
                let detail = result.output
                    .split(separator: "\n")
                    .last(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty })
                    .map(String.init) ?? "exit \(result.exitCode)"
                connectorSetupError = "Could not add \(friendlyConnectorName(normalized)): \(detail)"
            }
            connectorSetupInFlight.remove(normalized)
        }
    }

    func isConnectorSetupInFlight(_ name: String) -> Bool {
        connectorSetupInFlight.contains(ConnectorOnboarding.normalizedConnector(name))
    }

    /// Mirrors the TUI exactly: `defenseclaw alerts acknowledge --severity <S>`
    /// downgrades that whole severity class to ACK in the audit DB. Audit rows
    /// then drop out of the queue on refresh by themselves. Scan blocks and
    /// egress rows are NOT suppressed — they come from the immutable
    /// gateway.jsonl and the TUI re-shows them on every reload; hiding them
    /// locally made Findings drift to zero against the TUI. Use Dismiss for a
    /// view-local hide (also TUI parity: cleared on next app launch).
    func acknowledge(_ rows: [AlertRow]) async {
        ackError = nil
        var severities = Set<Severity>()
        for row in rows {
            if case .audit = row {
                severities.insert(row.severity)
            } else {
                // Scan blocks / egress rows have no DB-side ack (they live in
                // gateway.jsonl). An explicit Ack is still a user request to
                // clear them, so hide them view-locally — the TUI's
                // "Dismiss all" does the same local clear. Passive refreshes
                // never suppress them (Findings parity).
                dismissedIDs.insert(row.id)
            }
        }
        for severity in severities {
            let result = await runCommand(
                title: "Acknowledge \(severity.rawValue) alerts",
                arguments: ["alerts", "acknowledge", "--severity", severity.rawValue],
                category: "alerts",
                origin: "Alerts",
                successEffects: ["\(severity.rawValue) alerts acknowledged"]
            )
            if !result.succeeded {
                ackError = "alerts acknowledge \(severity.rawValue) failed (exit \(result.exitCode))"
            }
        }
        await refreshAlerts()
    }

    /// `defenseclaw alerts dismiss --severity <S|all>` — same DB semantics as the TUI.
    func dismissViaCLI(severity: Severity?) async {
        ackError = nil
        let result = await runCommand(
            title: "Dismiss alerts",
            arguments: ["alerts", "dismiss", "--severity", severity?.rawValue ?? "all"],
            category: "alerts",
            origin: "Alerts",
            successEffects: ["Alert queue updated"]
        )
        if !result.succeeded {
            ackError = "alerts dismiss \(severity?.rawValue ?? "all") failed (exit \(result.exitCode))"
        }
        await refreshAlerts()
    }

    func dismiss(_ rows: [AlertRow]) {
        for row in rows { dismissedIDs.insert(row.id) }
        unackedAlerts.removeAll { row in rows.contains { $0.id == row.id } }
    }

    // MARK: - Panel deep links

    func openAlerts(filter: AlertPanelRequest) {
        alertPanelRequest = filter
        selectedPanel = .alerts
    }

    func consumeAlertPanelRequest() -> AlertPanelRequest? {
        defer { alertPanelRequest = nil }
        return alertPanelRequest
    }

    func openAudit(preset: String) {
        auditPresetRequest = preset
        selectedPanel = .audit
    }

    func consumeAuditPresetRequest() -> String? {
        defer { auditPresetRequest = nil }
        return auditPresetRequest
    }

    func openLogs(_ request: LogPanelRequest) {
        logPanelRequest = request
        selectedPanel = .logs
    }

    func consumeLogPanelRequest() -> LogPanelRequest? {
        defer { logPanelRequest = nil }
        return logPanelRequest
    }

    // MARK: - Self-update

    /// Check GitHub for newer releases of BOTH the Mac app and the
    /// DefenseClaw runtime; re-checked every 6h by the pulse.
    func checkForUpdates(force: Bool = false) async {
        guard !updateOperationInProgress else { return }
        guard force || Date().timeIntervalSince1970 - lastUpdateCheckTime > 6 * 3600 else { return }
        let now = Date().timeIntervalSince1970
        lastUpdateCheckTime = now
        lastMacAppUpdateCheckTime = now
        lastRuntimeUpdateCheckTime = now

        let appRelease = await refreshMacAppUpdate()
        let runtimeRelease = await refreshRuntimeUpdate()
        lastCheckFailed = (appRelease == nil || runtimeRelease == nil)
    }

    /// Check only this macOS app. Used by Settings when the user wants to keep
    /// the DefenseClaw runtime untouched.
    func checkForMacAppUpdate(force: Bool = false) async {
        guard !updateOperationInProgress else { return }
        guard force || Date().timeIntervalSince1970 - lastMacAppUpdateCheckTime > 6 * 3600 else { return }
        lastMacAppUpdateCheckTime = Date().timeIntervalSince1970

        _ = await refreshMacAppUpdate()
        lastCheckFailed = appUpdateCheckFailed || runtimeUpdateCheckFailed
    }

    /// Check only the underlying DefenseClaw runtime.
    func checkForRuntimeUpdate(force: Bool = false) async {
        guard !updateOperationInProgress else { return }
        // Always refresh the local version. Only the network release lookup is
        // subject to the six-hour throttle.
        await refreshInstalledRuntimeVersion()
        guard force || Date().timeIntervalSince1970 - lastRuntimeUpdateCheckTime > 6 * 3600 else { return }
        lastRuntimeUpdateCheckTime = Date().timeIntervalSince1970

        _ = await refreshRuntimeUpdate(refreshInstalledVersion: false)
        lastCheckFailed = appUpdateCheckFailed || runtimeUpdateCheckFailed
    }

    private func refreshMacAppUpdate() async -> ReleaseInfo? {
        upgradeState = .checking
        defer {
            if upgradeState == .checking { upgradeState = .idle }
        }

        // Mac app. A nil release means the check FAILED (offline, API rate
        // limit) — keep any previously known update rather than clearing it.
        let appRelease = await updater.latestRelease()
        if let release = appRelease {
            appUpdateCheckFailed = false
            if UpdateChecker.isNewer(release.version, than: UpdateChecker.currentVersion) {
                if release != availableUpdate { updateBannerDismissed = false }
                availableUpdate = release
            } else {
                availableUpdate = nil
            }
        } else {
            appUpdateCheckFailed = true
        }
        return appRelease
    }

    /// Detect the locally installed CLI without contacting GitHub. Settings
    /// calls this when opened, and startup calls it even when release checks
    /// are still inside their persisted throttle window.
    func refreshInstalledRuntimeVersion() async {
        guard !runtimeVersionCheckInProgress else { return }
        runtimeVersionCheckInProgress = true
        defer { runtimeVersionCheckInProgress = false }

        guard await cli.locateBinary() != nil else {
            installedRuntimeVersion = nil
            runtimeVersionError = "DefenseClaw CLI not found. Set its path in Connection."
            return
        }

        let result = await cli.run(arguments: ["--version"])
        if let version = UpdateChecker.parseVersion(result.output) {
            installedRuntimeVersion = version
            runtimeVersionError = nil
            // A detected, working CLI supersedes an earlier bundled-install
            // failure (e.g. the user installed via the shell script instead);
            // don't leave a stale red "failed" label for the life of this
            // menu-bar process. Activity retains the full failure record.
            if case .failed = runtimeInstallState { runtimeInstallState = .idle }
        } else {
            installedRuntimeVersion = nil
            runtimeVersionError = result.succeeded
                ? "Could not read the installed runtime version."
                : "Runtime version check failed (exit \(result.exitCode))."
        }
    }

    private func refreshRuntimeUpdate(refreshInstalledVersion: Bool = true) async -> ReleaseInfo? {
        runtimeUpgradeState = .checking
        defer {
            if runtimeUpgradeState == .checking { runtimeUpgradeState = .idle }
        }

        // DefenseClaw runtime: installed via `defenseclaw --version`,
        // latest from the upstream repo's releases.
        if refreshInstalledVersion {
            await refreshInstalledRuntimeVersion()
        }
        let runtimeRelease = await updater.latestRuntimeRelease()
        runtimeReleaseChecked = true
        runtimeUpdateCheckFailed = runtimeRelease == nil
        if let installed = installedRuntimeVersion, let latest = runtimeRelease {
            if UpdateChecker.isNewer(latest.version, than: installed) {
                if latest != availableRuntimeUpdate { runtimeBannerDismissed = false }
                availableRuntimeUpdate = latest
            } else {
                availableRuntimeUpdate = nil
            }
        } else if installedRuntimeVersion == nil {
            availableRuntimeUpdate = nil
        }
        return runtimeRelease
    }

    /// Runs `defenseclaw upgrade --yes` — downloads release artifacts,
    /// migrates, and restarts the gateway. Non-destructive per upstream docs.
    /// Turn raw `defenseclaw upgrade` output into a human message. The common
    /// case today is an UPSTREAM packaging conflict (the 0.7.2 wheel pins
    /// click==8.3.1 while its own cisco-ai-mcp-scanner→litellm dep pins
    /// click==8.1.8) — unsatisfiable in any environment, so it is not an app
    /// problem and no app-side flag fixes it. Name that explicitly.
    nonisolated static func summarizeUpgradeFailure(_ output: String, exitCode: Int32) -> String {
        if output.contains("No solution found when resolving dependencies") {
            // Pull the conflicting package names if present, for specificity.
            let pkg = output.contains("cisco-ai-mcp-scanner") ? "cisco-ai-mcp-scanner" : "a dependency"
            return "Upstream packaging conflict in this DefenseClaw release: its Python wheel and \(pkg) pin incompatible versions of the same library, so it cannot be installed in any environment. This is a bug in the release itself — not the app — and there is no upgrade flag that fixes it. Wait for a corrected upstream release. (Copy Full Upgrade Log in Settings for details.)"
        }
        if output.localizedCaseInsensitiveContains("could not determine latest release") {
            return "Couldn't reach the release server (offline or GitHub rate-limited). Try again shortly."
        }
        // Fall back to the most meaningful single line.
        let errorLine = output.split(separator: "\n")
            .first { $0.contains("×") || $0.localizedCaseInsensitiveContains("error:") }
            .map { $0.trimmingCharacters(in: .whitespaces) }
        return errorLine ?? "defenseclaw upgrade exited \(exitCode). See Copy Full Upgrade Log in Settings."
    }

    func performMacAppUpgradeCheck() {
        Task {
            await checkForMacAppUpdate(force: true)
            performUpgrade()
        }
    }

    func performRuntimeUpgradeCheck() {
        Task {
            await checkForRuntimeUpdate(force: true)
            _ = await runRuntimeUpgradeIfAvailable()
        }
    }

    func performBothUpgrades() {
        Task {
            await checkForUpdates(force: true)
            let shouldRefreshRuntimeAfterUpgrade = availableUpdate == nil
            let runtimeUpgradeSucceeded = await runRuntimeUpgradeIfAvailable(refreshAfterSuccess: shouldRefreshRuntimeAfterUpgrade)
            guard runtimeUpgradeSucceeded else { return }
            performUpgrade()
        }
    }

    func performRuntimeUpgrade() {
        Task {
            _ = await runRuntimeUpgradeIfAvailable()
        }
    }

    private func runRuntimeUpgradeIfAvailable(refreshAfterSuccess: Bool = true) async -> Bool {
        switch runtimeUpgradeState {
        case .checking, .downloading, .installing:
            return false
        default:
            break
        }
        // The bundled-payload installer mutates the same venv and gateway
        // binary — never run both at once.
        guard !runtimeInstallState.isRunning else { return false }
        guard availableRuntimeUpdate != nil else { return true }
        runtimeUpgradeState = .installing
        runtimeUpgradeLogTail = ""
        let result = await cli.run(arguments: ["upgrade", "--yes"]) { line in
            await MainActor.run {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty { self.runtimeUpgradeLogTail = trimmed }
            }
        }
        if result.succeeded {
            runtimeUpgradeState = .idle
            runtimeUpgradeLogTail = ""
            runtimeUpgradeLog = ""
            availableRuntimeUpdate = nil
            if refreshAfterSuccess {
                await checkForRuntimeUpdate(force: true) // re-read installed version
            }
            reloadConfig()                    // gateway restarted; reconnect
            return true
        } else {
            runtimeUpgradeLog = result.output // full log, for Copy in Settings
            runtimeUpgradeState = .failed(Self.summarizeUpgradeFailure(result.output, exitCode: result.exitCode))
            return false
        }
    }

    /// Download, install over the current bundle, and restart the app.
    func performUpgrade() {
        guard let release = availableUpdate, upgradeState == .idle || upgradeState == .checking else { return }
        upgradeState = .downloading
        Task {
            let failure = await updater.downloadAndInstall(release) { state in
                Task { @MainActor in self.upgradeState = state }
            }
            if let failure {
                upgradeState = .failed(failure)
            }
            // On success the app terminates and relaunches — nothing to do here.
        }
    }

    // MARK: - Services card (Overview hero, parity with the TUI SERVICES panel)

    /// The nine SERVICES rows mirrored from the TUI's `service_cards()`, in the
    /// same order: each carries a runtime state (from /health) and a one-line
    /// detail sourced from the matching subsystem's details and/or config.
    var services: [ServiceStatus] {
        let running = Set(["running", "active", "enabled"])

        // Agent: roll the per-connector states into one aggregate, the way an
        // operator reads the CONNECTORS table — running only when all are up,
        // degraded when some are, disabled when every one is down/absent.
        let connStates = health.connectors.map { $0.state.lowercased() }
        let up = connStates.filter { running.contains($0) }.count
        let roster = config.connectors
        let disabledN = roster.filter { connectorIsDisabled($0) }.count
        let rosterTotal = roster.count
        let enabledTotal = max(rosterTotal - disabledN, 0)
        let multiConnector = rosterTotal > 1

        let agentState: String = {
            // TUI: health None → "unknown" unconditionally.
            guard gatewayReachable else { return "unknown" }
            guard multiConnector else {
                // Single-connector: the primary connector's live state.
                return health.primaryConnector?.state.nonEmpty ?? "unknown"
            }
            guard !connStates.isEmpty else {
                // No live rows: every rostered connector killed → disabled;
                // else a pre-connectors[] gateway falls back to the singular
                // primary connector's state.
                if rosterTotal > 0, disabledN == rosterTotal { return "disabled" }
                return health.primaryConnector?.state.nonEmpty ?? "unknown"
            }
            if up == connStates.count { return "running" }
            if up > 0 { return "degraded" }
            return connStates.first ?? "unknown"
        }()
        let agentDetail: String = {
            guard multiConnector else {
                // Single-connector: friendly name + live counters, or the
                // configured-but-not-connected hint (TUI agent_detail).
                let configured = (config.connectorMode ?? config.connectorName ?? "")
                guard let primary = health.primaryConnector else {
                    return configured.isEmpty ? "" : "\(friendlyConnectorName(configured)) (configured, not connected)"
                }
                var parts = [friendlyConnectorName(primary.name)]
                if !primary.toolInspectionMode.isEmpty { parts.append(primary.toolInspectionMode) }
                if primary.requests > 0 { parts.append("\(primary.requests) req") }
                if primary.toolBlocks > 0 { parts.append("\(primary.toolBlocks) tool blocks") }
                if primary.subprocessBlocks > 0 { parts.append("\(primary.subprocessBlocks) subprocess blocks") }
                return parts.joined(separator: " - ")
            }
            if disabledN == 0 {
                if connStates.isEmpty { return "\(rosterTotal) connectors configured" }
                if up == rosterTotal { return "\(rosterTotal) connectors active" }
                return "\(up)/\(rosterTotal) connectors running"
            }
            // One or more kill switches: report the disabled count separately.
            let suffix = " · \(disabledN) disabled"
            if enabledTotal == 0 { return "0 active\(suffix)" }
            if !connStates.isEmpty, up < enabledTotal { return "\(up)/\(enabledTotal) running\(suffix)" }
            return "\(enabledTotal) active\(suffix)"
        }()

        func sub(_ key: String) -> HealthSnapshot.Subsystem? { health.subsystem(key) }
        func state(_ key: String, default def: String = "disabled") -> String {
            sub(key)?.state ?? def
        }

        // Gateway: standalone-mode summary when disabled, else uptime.
        let gatewayDetail: String = {
            let g = sub("gateway")
            if (g?.state.lowercased() ?? "") == "disabled", let summary = g?.details["summary"], !summary.isEmpty {
                return summary
            }
            let secs = health.uptimeMs / 1000
            guard secs > 0 else { return "" }
            let h = secs / 3600, m = (secs % 3600) / 60
            return h > 0 ? "up \(h)h \(m)m" : "up \(m)m"
        }()

        // Watchdog: "N skill dirs, M plugin dirs".
        let watchdogDetail: String = {
            guard let d = sub("watcher")?.details else { return "" }
            var parts: [String] = []
            if let s = d["skill_dirs"] { parts.append("\(s) skill dirs") }
            if let p = d["plugin_dirs"] { parts.append("\(p) plugin dirs") }
            return parts.joined(separator: ", ")
        }()

        // Guardrail: from config (mode, port, rule pack) — only when enabled.
        let guardrailDetail: String = {
            guard config.guardrailEnabled else { return "" }
            var parts: [String] = []
            if let m = config.guardrailMode, !m.isEmpty { parts.append(m) }
            if let p = config.guardrailPort { parts.append("port \(p)") }
            if !config.guardrailRulePack.isEmpty { parts.append(config.guardrailRulePack) }
            return parts.joined(separator: ", ")
        }()

        // AI Discovery: "N active, M new, mode".
        let aiDetail: String = {
            guard let d = sub("ai_discovery")?.details else { return "" }
            var parts: [String] = []
            if let a = d["active_signals"] { parts.append("\(a) active") }
            if let n = d["new_signals"] { parts.append("\(n) new") }
            if let mode = d["mode"], !mode.isEmpty { parts.append(mode) }
            return parts.joined(separator: ", ")
        }()

        return [
            ServiceStatus(key: "gateway", name: "Gateway", state: state("gateway"), detail: gatewayDetail),
            ServiceStatus(key: "agent", name: "Agent", state: agentState, detail: agentDetail),
            ServiceStatus(key: "watchdog", name: "Watchdog", state: state("watcher"), detail: watchdogDetail),
            ServiceStatus(key: "guardrail", name: "Guardrail", state: state("guardrail"), detail: guardrailDetail),
            ServiceStatus(key: "api", name: "API", state: state("api"), detail: sub("api")?.details["addr"] ?? ""),
            // Deliberate Mac extra: the TUI leaves the Sinks detail empty,
            // but the /health summary ("1 of 1 enabled") is worth showing.
            ServiceStatus(key: "sinks", name: "Sinks", state: state("sinks"),
                          detail: sub("sinks")?.details["summary"] ?? ""),
            ServiceStatus(key: "telemetry", name: "Telemetry", state: state("telemetry"),
                          detail: health.telemetryDetail),
            ServiceStatus(key: "ai_discovery", name: "AI Discovery", state: state("ai_discovery"), detail: aiDetail),
            ServiceStatus(key: "sandbox", name: "Sandbox", state: state("sandbox"), detail: ""),
        ]
    }

    // MARK: - Command-output chrome (TUI Y / Ctrl+S / Shift+D)

    /// The TUI's Y yank: copy the LAST command's output body (no header) to
    /// the clipboard, with the two warn cases surfaced as notifications.
    func copyLastCommandOutput() {
        guard let entry = activity.entries.first else {
            notify(title: "DefenseClaw", body: "No command output to copy yet.", id: "yank-\(Date().timeIntervalSince1970)")
            return
        }
        let body = entry.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !body.isEmpty else {
            notify(title: "DefenseClaw", body: "Last command produced no output.", id: "yank-\(Date().timeIntervalSince1970)")
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(entry.output, forType: .string)
        notify(title: "DefenseClaw", body: "Copied last output to clipboard.", id: "yank-\(Date().timeIntervalSince1970)")
    }

    /// The TUI's Ctrl+S: write the last command's output (with the run-header
    /// preamble) to <data_dir>/last-run.log, chmod 0600.
    func exportLastCommandOutput() {
        guard let entry = activity.entries.first else {
            notify(title: "DefenseClaw", body: "No command output to save yet.", id: "export-\(Date().timeIntervalSince1970)")
            return
        }
        let iso = ISO8601DateFormatter()
        let header = """
        # \(entry.command)
        # \(entry.statusLabel.lowercased())
        # started \(iso.string(from: entry.startedAt))
        # saved   \(iso.string(from: Date()))

        """
        let target = ConfigStore.dataDirectory.appendingPathComponent("last-run.log")
        do {
            try (header + entry.output + "\n").write(to: target, atomically: true, encoding: .utf8)
            do {
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            } catch {
                try? FileManager.default.removeItem(at: target)
                throw error
            }
            notify(title: "DefenseClaw", body: "Wrote last-run.log → \(target.path)", id: "export-\(Date().timeIntervalSince1970)")
        } catch {
            notify(title: "DefenseClaw", body: "Save failed: \(error.localizedDescription)", id: "export-\(Date().timeIntervalSince1970)")
        }
    }

    /// The TUI's Shift+D background diagnose: run `defenseclaw doctor`
    /// silently (no panel switch, no Activity entry), report a one-line
    /// summary, and reload the doctor cache it rewrites.
    func runBackgroundDiagnose() {
        guard !diagnoseRunning else {
            notify(title: "DefenseClaw", body: "Diagnose already running — waiting for the current probe to finish.",
                   id: "diag-\(Date().timeIntervalSince1970)")
            return
        }
        diagnoseRunning = true
        notify(title: "DefenseClaw", body: "Running defenseclaw doctor…", id: "diag-start-\(Date().timeIntervalSince1970)")
        Task {
            // TUI: 60s budget, then kill the probe.
            let runID = UUID()
            let watchdog = Task {
                try? await Task.sleep(for: .seconds(60))
                if !Task.isCancelled { await cli.cancel(runID: runID) }
            }
            let result = await cli.run(arguments: ["doctor"], runID: runID)
            watchdog.cancel()
            diagnoseRunning = false
            doctorCache = DoctorCache.load() ?? doctorCache
            let lines = result.output.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
            let summary = Self.diagnoseSummaryLine(lines)
            if result.succeeded {
                notify(title: "Doctor OK", body: summary.isEmpty ? "All checks completed." : summary,
                       id: "diag-ok-\(Date().timeIntervalSince1970)")
            } else {
                notify(title: "Doctor exit \(result.exitCode)", body: lines.last ?? "",
                       id: "diag-fail-\(Date().timeIntervalSince1970)")
            }
        }
    }

    /// TUI _diagnose_summary_line: prefer a "summary" line, then known result
    /// needles scanned in reverse, then the first line.
    private static func diagnoseSummaryLine(_ lines: [String]) -> String {
        func trimmed(_ line: String) -> String {
            line.trimmingCharacters(in: CharacterSet(charactersIn: ": -=")).trimmingCharacters(in: .whitespaces)
        }
        if let summary = lines.last(where: { $0.lowercased().contains("summary") }) {
            return trimmed(summary)
        }
        for needle in ["checks passed", "issues detected", "issue(s)", "failures", "errors", "ok"] {
            if let hit = lines.reversed().first(where: { $0.lowercased().contains(needle) }) {
                return trimmed(hit)
            }
        }
        return lines.first.map(trimmed) ?? ""
    }

    // MARK: - Attention notices (TUI build_notices, emission order = display order)

    /// Earliest connector session start from /health connectors[].since —
    /// nil means no live session window (fall back to all-time counts).
    var sessionStart: Date? {
        health.connectors.compactMap(\.since).min()
            ?? health.primaryConnector?.since
            ?? health.subsystem("guardrail")?.since
    }

    /// High-confidence local agents that DefenseClaw knows how to configure but
    /// which are absent from both config and live /health. These are surfaced as
    /// unmanaged candidates; discovery alone never changes enforcement state.
    var detectedUnconfiguredConnectors: [ConnectorRegistrationCandidate] {
        var managed = Set(config.connectors.map(ConnectorOnboarding.normalizedConnector))
        if let legacy = config.connectorName?.nonEmpty {
            managed.insert(ConnectorOnboarding.normalizedConnector(legacy))
        }
        for name in health.connectors.map(\.name) {
            managed.insert(ConnectorOnboarding.normalizedConnector(name))
        }
        if let primary = health.primaryConnector?.name.nonEmpty {
            managed.insert(ConnectorOnboarding.normalizedConnector(primary))
        }

        var best: [String: ConnectorRegistrationCandidate] = [:]
        for signal in aiSnapshot.signals {
            let name = ConnectorOnboarding.normalizedConnector(signal.supportedConnector)
            let score = max(signal.confidence, signal.identityScore, signal.presenceScore)
            guard !name.isEmpty,
                  signal.state.lowercased() != "gone",
                  score >= 0.8,
                  Self.knownConnectors.contains(name),
                  !managed.contains(name)
            else { continue }

            let candidate = ConnectorRegistrationCandidate(
                name: name,
                confidence: score,
                lastSeen: signal.lastSeen ?? signal.lastActive,
                canConfigureInline: TUIWizards.hookConnectors.contains(name)
            )
            if let current = best[name] {
                let currentDate = current.lastSeen ?? .distantPast
                let candidateDate = candidate.lastSeen ?? .distantPast
                if candidate.confidence < current.confidence
                    || (candidate.confidence == current.confidence && candidateDate <= currentDate) {
                    continue
                }
            }
            best[name] = candidate
        }
        return Self.knownConnectors.compactMap { best[$0] }
    }

    var overviewNotices: [OverviewNotice] {
        var notices: [OverviewNotice] = []
        let gatewayState = (health.subsystem("gateway")?.state ?? "")
            .trimmingCharacters(in: .whitespaces).lowercased()
        let gatewayBroken = !gatewayReachable || !["running", "disabled"].contains(gatewayState)
        let gatewayStandalone = gatewayReachable && gatewayState == "disabled"
        let guardrailOff = !config.guardrailEnabled
        let skillScannerAvailable = ScannerProbe.binaryInstalled("skill-scanner")

        if gatewayBroken && guardrailOff && !skillScannerAvailable {
            notices.append(.init(level: .info, message: "First time? Head to the Setup panel to configure DefenseClaw."))
        }
        if gatewayBroken {
            notices.append(.init(level: .error, message: "Gateway is offline - use Start Gateway in Quick Actions"))
        } else if gatewayStandalone {
            let details = health.subsystem("gateway")?.details ?? [:]
            if let hint = (details["hint"]?.nonEmpty ?? details["summary"]?.nonEmpty) {
                notices.append(.init(level: .info, message: hint))
            }
        }
        if !config.rosterError.isEmpty {
            notices.append(.init(level: .error, message: "Connector roster degraded: \(config.rosterError) - showing a reduced view; check your connector config"))
        }
        if !config.loadError.isEmpty {
            notices.append(.init(level: .error, message: config.loadError))
        }
        let unmanaged = detectedUnconfiguredConnectors
        if !unmanaged.isEmpty {
            let names = unmanaged.map { friendlyConnectorName($0.name) }.joined(separator: ", ")
            notices.append(.init(
                level: .warn,
                message: "Detected but not configured: \(names) - add from the Connectors card or Setup"
            ))
        }
        if installDetected, guardrailOff {
            notices.append(.init(level: .warn, message: "LLM guardrail not configured - set it up in Setup → Guardrail"))
        }
        if !skillScannerAvailable {
            notices.append(.init(level: .warn, message: "skill-scanner not on PATH - run: pip install skill-scanner"))
        }
        if silentBypassCount > 0 {
            notices.append(.init(level: .warn, message: "\(silentBypassCount) silent LLM bypass event(s) in the last 5m - see Alerts -> egress"))
        }
        if let doctor = doctorCache, !doctor.isEmpty {
            let contradicted = doctor.checks.filter { liveHealthContradicts($0) }
            let staleFailures = contradicted.filter { $0.status == "fail" }.count
            let effectiveFailed = max(doctor.failed - staleFailures, 0)
            if effectiveFailed > 0 {
                notices.append(.init(level: .error, message: "Doctor found \(effectiveFailed) failure(s) - see the Doctor card or run: defenseclaw doctor"))
            } else if !contradicted.isEmpty {
                notices.append(.init(level: .info, message: "Doctor cache shows \(contradicted.count) stale failure(s) that /health disagrees with - run Health Check to refresh"))
            } else if doctor.isStale() {
                notices.append(.init(level: .info, message: "Doctor cache is stale - run Health Check to re-probe"))
            }
            let missing = doctor.missingRequiredCredentials
            if !missing.isEmpty {
                let preview = missing.prefix(2).joined(separator: ", ")
                let overflow = missing.count > 2 ? " (+\(missing.count - 2) more)" : ""
                notices.append(.init(level: .error, message: "Missing required API key(s): \(preview)\(overflow) - run: defenseclaw keys fill-missing"))
            }
        }
        // TUI parity: health=None (gateway unreachable) skips this block —
        // otherwise stale drift/zero-requests notices freeze alongside the
        // "Gateway is offline" error.
        if gatewayReachable, let primary = health.primaryConnector, installDetected {
            let live = primary.name.trimmingCharacters(in: .whitespaces)
            // The drift check compares against claw.mode with the runtime
            // loader's "openclaw" default (NOT connectorMode's fallback chain).
            let configured = config.clawMode.trimmingCharacters(in: .whitespaces)
            if !live.isEmpty, !configured.isEmpty, live != configured {
                notices.append(.init(level: .warn, message: "Connector drift: configured \(friendlyConnectorName(configured)) but gateway is routing for \(friendlyConnectorName(live)) - restart the sidecar after editing claw.mode"))
            }
            if primary.requests == 0, health.uptimeMs > 60_000 {
                notices.append(.init(level: .info, message: Self.zeroRequestsNotice(live: live, uptimeMs: health.uptimeMs)))
            }
        }
        return notices
    }

    /// TUI zero_connector_requests_notice.
    private static func zeroRequestsNotice(live: String, uptimeMs: Int) -> String {
        let name = friendlyConnectorName(live)
        let secs = uptimeMs / 1000
        let h = secs / 3600, m = (secs % 3600) / 60
        let formatted = h > 0 ? "\(h)h \(m)m" : (m > 0 ? "\(m)m" : "\(secs)s")
        switch live.trimmingCharacters(in: .whitespaces).lowercased() {
        case "codex":
            return "\(name) connector has seen 0 hook events after \(formatted) - normal until Codex emits a hook/notify event; verify ~/.codex hooks if this persists"
        case "claudecode":
            return "\(name) connector has seen 0 hook events after \(formatted) - normal until Claude Code emits a hook event; verify Claude Code hooks if this persists"
        case "omnigent":
            return "\(name) connector has seen 0 policy events after \(formatted) - normal until OmniGent emits a supported policy callback; verify OmniGent policy setup if this persists"
        case "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode":
            return "\(name) connector has seen 0 hook events after \(formatted) - verify connector hook setup if this persists"
        default:
            return "\(name) connector has seen 0 requests after \(formatted) - verify your agent is dialing the gateway port (gateway.port)"
        }
    }

    /// TUI live_health_contradicts: a cached fail/warn check is STALE when
    /// /health says the subsystem is actually running.
    func liveHealthContradicts(_ check: DoctorCache.Check) -> Bool {
        guard gatewayReachable, ["fail", "warn"].contains(check.status) else { return false }
        func running(_ key: String) -> Bool {
            (health.subsystem(key)?.state ?? "").lowercased() == "running"
        }
        switch check.label.trimmingCharacters(in: .whitespaces).lowercased() {
        case "sidecar api": return running("api")
        case "guardrail proxy": return running("guardrail")
        case "openclaw gateway", "gateway": return running("gateway")
        case let label where label.hasPrefix("otel"): return running("telemetry")
        default: return false
        }
    }

    // MARK: - Doctor box (TUI doctor_box)

    struct DoctorBoxState {
        struct CheckRow: Identifiable {
            var badge: String   // FAIL | WARN | STALE
            var label: String
            var detail: String
            var stale: Bool
            var id: String { "\(badge)-\(label)" }
        }
        var empty = true
        var summaryParts: [String] = []
        var ageLabel = ""
        var stale = false
        var checks: [CheckRow] = []
        var allGreen = false
    }

    var doctorBox: DoctorBoxState {
        let unmanaged = detectedUnconfiguredConnectors
        let registrationCheck: DoctorBoxState.CheckRow? = unmanaged.isEmpty ? nil : .init(
            badge: "WARN",
            label: "Connector registration",
            detail: "Detected but not configured: \(unmanaged.map { friendlyConnectorName($0.name) }.joined(separator: ", ")). Add from the Connectors card.",
            stale: false
        )
        guard let doctor = doctorCache, !doctor.isEmpty else {
            guard let registrationCheck else { return DoctorBoxState() }
            return DoctorBoxState(
                empty: false,
                summaryParts: ["1 warn"],
                checks: [registrationCheck],
                allGreen: false
            )
        }
        let top = doctor.topFailures(3)
        let staleFailures = doctor.checks.filter { $0.status == "fail" && liveHealthContradicts($0) }.count
        let staleWarnings = doctor.checks.filter { $0.status == "warn" && liveHealthContradicts($0) }.count
        let effectiveFailed = max(doctor.failed - staleFailures, 0)
        let effectiveWarned = max(doctor.warned - staleWarnings, 0) + (registrationCheck == nil ? 0 : 1)
        let staleCount = staleFailures + staleWarnings

        var parts: [String] = []
        if doctor.passed > 0 { parts.append("\(doctor.passed) pass") }
        if effectiveFailed > 0 { parts.append("\(effectiveFailed) fail") }
        if effectiveWarned > 0 { parts.append("\(effectiveWarned) warn") }
        if staleCount > 0 { parts.append("\(staleCount) stale") }
        if doctor.skipped > 0 { parts.append("\(doctor.skipped) skip") }

        var rows = top.map { check in
            let contradicted = liveHealthContradicts(check)
            return DoctorBoxState.CheckRow(
                badge: contradicted ? "STALE" : check.status.uppercased(),
                label: check.label,
                detail: contradicted && !check.detail.isEmpty ? "\(check.detail) (live state OK)" : check.detail,
                stale: contradicted
            )
        }
        if let registrationCheck { rows.append(registrationCheck) }
        return DoctorBoxState(
            empty: false,
            summaryParts: parts,
            ageLabel: doctor.ageLabel(),
            stale: doctor.isStale(),
            checks: rows,
            allGreen: rows.isEmpty
        )
    }

    // MARK: - Connectors table rows (TUI _overview_connector_rows)

    /// The dashboard's agent table: configured connectors, active /health
    /// rows, and high-confidence discovered-but-unconfigured candidates.
    /// Discovery never activates a connector; candidates render with an
    /// explicit repair action in Overview.
    var connectorTableRows: [ConnectorHealth] {
        // Configured = the guardrail.connectors roster plus the legacy
        // singular connector.name/guardrail.connector shape, so
        // single-connector installs keep their agent visible.
        var configured = config.connectors
        if let legacy = config.connectorName?.nonEmpty,
           !configured.contains(where: { $0.lowercased() == legacy.lowercased() }) {
            configured.append(legacy)
        }
        var seen = Set(configured.map { $0.lowercased() })
        var extras: [String] = []
        var liveNames = health.connectors.map(\.name)
        if let primary = health.primaryConnector?.name { liveNames.append(primary) }
        for name in liveNames {
            let lower = name.lowercased()
            guard !lower.isEmpty, seen.insert(lower).inserted else { continue }
            extras.append(name)
        }
        let candidates = detectedUnconfiguredConnectors
        let candidatesByName = Dictionary(uniqueKeysWithValues: candidates.map { ($0.name, $0) })
        var unmanaged: [String] = []
        for candidate in candidates where seen.insert(candidate.name).inserted {
            unmanaged.append(candidate.name)
        }
        let roster = configured
            + extras.sorted { $0.lowercased() < $1.lowercased() }
            + unmanaged.sorted()

        let gatewayState = (health.subsystem("gateway")?.state ?? "").trimmingCharacters(in: .whitespaces)
        let fallbackStatus = !gatewayReachable
            ? "unknown"
            : (gatewayState.lowercased() == "running" ? "active" : (gatewayState.nonEmpty ?? "unknown"))
        return roster.map { name in
            let lower = name.lowercased()
            if let candidate = candidatesByName[ConnectorOnboarding.normalizedConnector(name)] {
                return ConnectorHealth(
                    name: candidate.name,
                    mode: "—",
                    rulePack: "—",
                    lastActivity: candidate.lastSeen,
                    calls: 0,
                    blocks: 0,
                    alerts: 0,
                    state: "not configured",
                    since: nil
                )
            }
            // connectorDisabled stores the raw roster key — match it
            // case-insensitively like every other name comparison here.
            let disabled = connectorIsDisabled(name)
            if var row = health.connectors.first(where: { $0.name.lowercased() == lower }) {
                if disabled { row.state = "disabled" }
                return row
            }
            // TUI Tier 2: all-time totals; windowed cache only as a last
            // resort on pre-v7 schemas without the connector column.
            let stats = connectorStatsAllTimeCache.first { $0.key.lowercased() == lower }?.value
                ?? connectorStatsCache.first { $0.key.lowercased() == lower }?.value
            // Legacy gateways report the hooked agent only via the singular
            // /health connector object — overlay its live state/counters.
            if let primary = health.primaryConnector, primary.name.lowercased() == lower {
                var calls = primary.requests
                if calls == 0 { calls = stats?.hookCalls ?? 0 }
                var blocks = primary.toolBlocks + primary.subprocessBlocks
                if blocks == 0 { blocks = stats?.blocks ?? 0 }
                return ConnectorHealth(
                    name: name,
                    mode: connectorValue(config.connectorModes, for: name)?.nonEmpty ?? config.guardrailMode ?? "observe",
                    rulePack: connectorValue(config.connectorRulePacks, for: name)?.nonEmpty ?? "default",
                    lastActivity: stats?.lastActivity,
                    calls: calls,
                    blocks: blocks,
                    alerts: stats?.alerts ?? 0,
                    state: disabled ? "disabled" : primary.state,
                    since: primary.since
                )
            }
            return ConnectorHealth(
                name: name,
                mode: connectorValue(config.connectorModes, for: name)?.nonEmpty ?? config.guardrailMode ?? "observe",
                rulePack: connectorValue(config.connectorRulePacks, for: name)?.nonEmpty ?? "default",
                lastActivity: stats?.lastActivity,
                calls: stats?.hookCalls ?? 0,
                blocks: stats?.blocks ?? 0,
                alerts: stats?.alerts ?? 0,
                state: disabled ? "disabled" : fallbackStatus,
                since: nil
            )
        }
    }

    // MARK: - Configuration box (Overview, parity with the TUI CONFIGURATION panel)

    /// The global CONFIGURATION rows shown above the Connectors table, mirroring
    /// the TUI's "All connectors" configuration view (Agents / Redaction /
    /// Policy posture / Enforcement / Human approval / Environment / dirs / LLM
    /// / AI Defense).
    var configurationRows: [ConfigurationRow] {
        // Connector selected via the shared filter: the box narrows to that
        // connector's rows (TUI _connector_configuration_lines), with the
        // machine-wide settings suffixed "(global)".
        if !connectorFilter.isEmpty {
            return connectorConfigurationRows(connectorFilter)
        }
        // Roster size: live connector rows first, then the config roster.
        let agentCount = health.connectors.isEmpty ? config.connectors.count : health.connectors.count
        let multiConnector = config.connectorModes.count > 1 || config.connectors.count > 1

        // First row: "Agents: N active" when multi-connector, else the single
        // connector's name (TUI's active_connector_name()).
        let agentRow: ConfigurationRow = {
            if multiConnector || agentCount > 1 {
                return .init(label: "Agents", value: "\(agentCount) active")
            }
            let name = (config.connectorName ?? config.connectorMode ?? "").lowercased()
            return .init(label: "Agent", value: name)
        }()

        let redaction = config.redactionEnabled ? "ON (redacted)" : "OFF (RAW)"
        let approval = config.hiltEnabled ? "ON (min \(config.hiltMinSeverity))" : "OFF"

        var rows: [ConfigurationRow] = [
            agentRow,
            .init(label: "Redaction", value: redaction),
            .init(label: "Policy posture", value: policyPosture),
            .init(label: "Enforcement", value: enforcementLabel),
            .init(label: "Human approval", value: approval),
            .init(label: "Environment", value: (config.environment?.isEmpty == false ? config.environment! : "unknown")),
            .init(label: "Policy dir", value: config.policyDir?.nonEmpty ?? "—"),
            .init(label: "Data dir", value: config.dataDir?.nonEmpty ?? "—"),
        ]
        if let provider = config.llmProvider?.nonEmpty {
            rows.append(.init(label: "LLM provider", value: provider))
        }
        if let model = config.llmModel?.nonEmpty {
            rows.append(.init(label: "LLM model", value: model))
        }
        if let endpoint = config.aiDefenseEndpoint?.nonEmpty {
            rows.append(.init(label: "AI Defense", value: endpoint))
        }
        return rows
    }

    /// Connector-scoped CONFIGURATION rows (TUI _connector_configuration_lines):
    /// Connector/Mode/Rule pack/Guardrail/Status/Last activity from the live
    /// roster row, then the global posture rows tagged "(global)".
    private func connectorConfigurationRows(_ name: String) -> [ConfigurationRow] {
        let row = health.connectors.first { $0.name.lowercased() == name.lowercased() }
        let mode = row?.mode.nonEmpty ?? connectorValue(config.connectorModes, for: name)?.nonEmpty ?? "?"
        let rulePack = row?.rulePack.nonEmpty ?? connectorValue(config.connectorRulePacks, for: name)?.nonEmpty ?? "default"
        let status = row?.state.nonEmpty ?? "unknown"
        let lastActivity = row?.lastActivity.map { DCDates.relative($0) } ?? "none"
        // Per-connector kill switch (guardrail.connectors.<name>.enabled:
        // false) outranks the global flag, exactly like connector_is_disabled.
        let guardrail = (connectorIsDisabled(name) || !config.guardrailEnabled)
            ? "disabled" : "enabled"
        let redaction = config.redactionEnabled ? "ON (global redacted)" : "OFF (global RAW)"
        let approval = config.hiltEnabled ? "ON (global min \(config.hiltMinSeverity))" : "OFF (global)"

        // Exactly the TUI's rows: 8 fixed + optional Environment. LLM/AI
        // Defense rows stay global-view-only.
        var rows: [ConfigurationRow] = [
            .init(label: "Connector", value: "\(friendlyConnectorName(name)) (\(name.lowercased()))"),
            .init(label: "Mode", value: mode),
            .init(label: "Rule pack", value: rulePack),
            .init(label: "Guardrail", value: guardrail),
            .init(label: "Status", value: status),
            .init(label: "Last activity", value: lastActivity),
            .init(label: "Redaction", value: redaction),
            .init(label: "Human approval", value: approval),
        ]
        if let env = config.environment?.nonEmpty {
            rows.append(.init(label: "Environment", value: "\(env) (global)"))
        }
        return rows
    }

    /// Mirrors the TUI's `_policy_posture`.
    private var policyPosture: String {
        let mode = config.guardrailMode?.nonEmpty ?? "observe"
        let scanner = config.guardrailRulePack.nonEmpty ?? "default"
        let packs = Set(config.connectorRulePacks.values.filter { !$0.isEmpty })
        if config.connectorModes.count > 1 {
            let modes = Set(config.connectorModes.values.filter { !$0.isEmpty })
            if packs.count > 1 || modes.count > 1 { return "per-connector (see roster)" }
            let onlyPack = packs.first ?? scanner
            let onlyMode = modes.first ?? mode
            return "all connectors: \(onlyMode) (\(onlyPack))"
        }
        if mode == "action" { return "action: block CRIT, alert MED+ (\(scanner))" }
        return "balanced: block CRIT, alert MED+ (\(scanner))"
    }

    /// Mirrors the TUI's `_enforcement_label`.
    private var enforcementLabel: String {
        if config.connectorModes.count > 1 {
            return "\(config.connectorModes.count) connectors (hook observability)"
        }
        let connector = (config.connectorName ?? config.connectorMode ?? "").lowercased()
        let mode = config.guardrailMode?.nonEmpty ?? "observe"
        if connector.isEmpty { return "not configured (\(mode))" }
        if connector == "openclaw" || connector == "zeptoclaw" {
            return "\(connector) proxy guardrail (\(mode))"
        }
        return "\(connector) hook observability (\(mode))"
    }

    // MARK: - Connector filter (multi-connector parity, connector_filter.py)

    /// Active connector names in roster order — live health first, then config.
    /// ≤1 means single-connector: no filter chrome (the TUI hides the chip).
    var activeConnectorNames: [String] {
        let fromHealth = health.connectors.map(\.name).filter { !$0.isEmpty }
        if !fromHealth.isEmpty { return fromHealth }
        return config.connectors
    }

    /// Step the filter All → conn0 → conn1 → … → All (collapses to All when ≤1).
    func cycleConnectorFilter() {
        let names = activeConnectorNames
        guard names.count > 1 else { connectorFilter = ""; return }
        let order = [""] + names
        let idx = order.firstIndex(of: connectorFilter) ?? 0
        connectorFilter = order[(idx + 1) % order.count]
    }

    /// True when a row attributed to `connector` is visible under the filter.
    /// All shows everything; an explicit filter requires an exact match and
    /// hides unattributed rows (connector_filter.filter_allows).
    func connectorFilterAllows(_ connector: String) -> Bool {
        let current = connectorFilter.trimmingCharacters(in: .whitespaces).lowercased()
        if current.isEmpty { return true }
        return current == connector.trimmingCharacters(in: .whitespaces).lowercased()
    }

    /// Enforcement metrics scoped to the active connector filter. All → the
    /// shared global snapshot; a selected connector reads its enriched
    /// ConnectorHealth row (live gateway counters with the audit fallback
    /// already applied in pulse(), same as the TUI's CONNECTORS table source)
    /// and Findings narrow to alert rows attributed to that connector.
    var scopedEnforcementMetrics: OverviewEnforcementMetrics {
        guard !connectorFilter.isEmpty else { return overviewEnforcementMetrics }
        let row = health.connectors.first { $0.name.lowercased() == connectorFilter.lowercased() }
        // No live health row (gateway offline / older gateway): fall back to
        // the pulse-cached audit stats, like the TUI's audit-derived scope
        // breakdown.
        let fallback = connectorStatsCache.first { $0.key.lowercased() == connectorFilter.lowercased() }?.value
        return OverviewEnforcementMetrics(
            hookCalls: row?.calls ?? fallback?.hookCalls ?? 0,
            blocks: row?.blocks ?? fallback?.blocks ?? 0,
            findings: unackedAlerts.filter {
                $0.severity > .info && connectorFilterAllows($0.connectorName)
            }.count,
            updatedAt: overviewEnforcementMetrics.updatedAt
        )
    }

    /// The filtered SCANNERS box's "policy" context row: "{mode} · {rule pack}"
    /// from config only (TUI _connector_policy_label — live-row fallbacks
    /// would fabricate "observe · default" where the TUI hides the row).
    var connectorPolicyLabel: String {
        guard !connectorFilter.isEmpty else { return "" }
        let mode = connectorValue(config.connectorModes, for: connectorFilter)?.nonEmpty ?? ""
        let pack = connectorValue(config.connectorRulePacks, for: connectorFilter)?.nonEmpty ?? ""
        return [mode, pack].filter { !$0.isEmpty }.joined(separator: " · ")
    }

    // MARK: - Per-connector aibom coverage (TUI _request_enforcement_inventory)

    /// One snapshot per connector from `aibom scan --json --connector <name>`,
    /// shared by the filtered Overview boxes. nil entry = not yet loaded
    /// ("scan pending" in the UI).
    var enforcementInventory: [String: ConnectorScanMetrics] = [:]
    @ObservationIgnored private var enforcementInventoryRequested = false

    /// One-shot per app session, multi-connector only — dispatches the same
    /// per-connector aibom scans the Inventory panel runs and caches the
    /// coverage counts. Renders keep calling this idempotently.
    func requestEnforcementInventory() {
        guard !enforcementInventoryRequested, activeConnectorNames.count > 1 else { return }
        enforcementInventoryRequested = true
        Task {
            for name in activeConnectorNames {
                let result = await cli.run(arguments: ["aibom", "scan", "--json", "--connector", name])
                guard result.succeeded,
                      let parsed = InventoryOutputParser.parse(result.output),
                      let document = parsed.documents.first
                else { continue }
                enforcementInventory[name] = Self.scanMetrics(from: document)
            }
        }
    }

    /// TUI _connector_scan_metrics: verdict sets BLOCK/ALLOW over skills;
    /// scanned = skills+plugins carrying any scan_* evidence; scannable =
    /// |skills| + |plugins|; MCPs have no verdicts (count only).
    private static func scanMetrics(from document: [String: Any]) -> ConnectorScanMetrics {
        let blockSet: Set<String> = ["block", "blocked", "deny", "denied", "quarantine", "quarantined"]
        let allowSet: Set<String> = ["allow", "allowed", "clean", "ok", "pass"]
        let skills = (document["skills"] as? [[String: Any]]) ?? []
        let plugins = (document["plugins"] as? [[String: Any]]) ?? []
        let mcps = (document["mcp"] as? [[String: Any]]) ?? []

        func verdict(_ item: [String: Any]) -> String {
            ((item["policy_verdict"] as? String)?.nonEmpty
                ?? (item["verdict"] as? String) ?? "").lowercased()
        }
        func hasScanEvidence(_ item: [String: Any]) -> Bool {
            if let target = item["scan_target"] as? String, !target.isEmpty { return true }
            if let findings = item["scan_findings"] as? Int, findings > 0 { return true }
            if let severity = item["scan_severity"] as? String, !severity.isEmpty { return true }
            return false
        }

        return ConnectorScanMetrics(
            skills: skills.count,
            skillsBlocked: skills.filter { blockSet.contains(verdict($0)) }.count,
            skillsAllowed: skills.filter { allowSet.contains(verdict($0)) }.count,
            mcps: mcps.count,
            scanned: (skills + plugins).filter(hasScanEvidence).count,
            scannable: skills.count + plugins.count
        )
    }

    /// Connector roster for filesystem catalog scans: live health first,
    /// then config's guardrail.connectors, then every known connector so
    /// the panels work regardless of agent type.
    /// Every agent DefenseClaw knows how to hook — the catalog-scan and
    /// Connectors-table fallback roster.
    static let knownConnectors = ["openclaw", "zeptoclaw", "codex", "claudecode", "hermes",
                                  "cursor", "windsurf", "geminicli", "copilot", "openhands",
                                  "antigravity", "opencode", "omnigent"]

    func configuredConnectors() -> [String] {
        let fromHealth = health.connectors.map(\.name)
        if !fromHealth.isEmpty { return fromHealth }
        if !config.connectors.isEmpty { return config.connectors }
        return Self.knownConnectors
    }

    func reloadConfig() {
        Task {
            let cfg = await configStore.reload()
            config = cfg
            await gateway.update(config: cfg)
            await resolveProbePaths(force: true) // path override may have changed
            await pulse()
        }
    }

    /// One-click repair for a scanner that exists in the DefenseClaw install
    /// but isn't linked into a PATH dir: recreate the installer's
    /// ~/.local/bin symlinks (binary + its -api/-pre-commit siblings), then
    /// re-probe so the row flips to "installed" immediately.
    func fixScanner(_ status: ScannerStatus) {
        guard let source = status.fixSource else { return }
        scannerFixError = nil
        do {
            try ScannerProbe.linkIntoLocalBin(name: status.name, source: source)
            let guardrailState = health.subsystems.first { $0.name == "guardrail" }?.state
            scanners = ScannerProbe.statuses(
                config: config,
                guardrailState: guardrailState,
                missingCredentials: (doctorCache?.isEmpty == false) ? doctorCache!.missingRequiredCredentials : nil,
                cliPath: probeCLIPath,
                shellFound: shellResolvedScanners
            )
        } catch {
            scannerFixError = "\(status.name): \(error.localizedDescription)"
        }
    }

    private func connectorValue(_ values: [String: String], for name: String) -> String? {
        values.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    private func connectorIsDisabled(_ name: String) -> Bool {
        config.connectorDisabled.contains { $0.caseInsensitiveCompare(name) == .orderedSame }
    }

    private func notify(title: String, body: String, id: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
