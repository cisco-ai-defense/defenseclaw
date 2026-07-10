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

// Overview dashboard (spec §9.1): health, connectors, 24h enforcement,
// hourly histogram, doctor, AI discovery, credentials.

import SwiftUI
import Charts

struct OverviewView: View {
    @Environment(AppState.self) private var appState
    @State private var summary: (blockedSkills: Int, allowedSkills: Int, blockedMCPs: Int, allowedMCPs: Int, totalScans: Int, activeAlerts: Int) = (0, 0, 0, 0, 0, 0)
    @State private var hourly: [HourlyPoint] = []
    @State private var doctorRunning = false
    @State private var doctorOutput = ""
    @State private var showDoctorSheet = false
    @State private var configurationExpanded = false

    struct HourlyPoint: Identifiable {
        let hour: Date
        let klass: String
        let count: Int
        var id: String { "\(hour.timeIntervalSince1970)-\(klass)" }
    }

    /// The shared connector filter ("" = All) — scopes Configuration,
    /// Enforcement, Scanners, and highlights the Connectors row (TUI parity).
    private var scopeConnector: String { appState.connectorFilter }

    /// " · name" suffix for card titles when a connector is selected.
    private var scopeSuffix: String { scopeConnector.isEmpty ? "" : " · \(scopeConnector.lowercased())" }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                noticesCard
                // Hero row: System Health · Scanners · Enforcement —
                // the three at-a-glance status blocks, all equal height.
                // fixedSize pins the row to its tallest card; fillHeight on
                // each card stretches the shorter ones to match.
                HStack(alignment: .top, spacing: 14) {
                    servicesCard
                        .frame(maxWidth: .infinity)
                    scannersCard
                        .frame(maxWidth: .infinity)
                    enforcementTilesCard
                        .frame(maxWidth: .infinity)
                }
                .fixedSize(horizontal: false, vertical: true)
                quickActionsCard
                configurationCard
                if !overviewConnectorRows.isEmpty { connectorCard }
                observabilityCard
                activityCard
                HStack(alignment: .top, spacing: 14) {
                    doctorCard
                    aiCard
                }
            }
            .padding(16)
        }
        .toolbar {
            ToolbarItemGroup {
                connectorScopeChip
                StaleBadge(date: appState.health.fetchedAt)
                Button {
                    runDoctor()
                } label: {
                    Label("Run Health Check", systemImage: "stethoscope")
                }
                .disabled(doctorRunning)
                Button {
                    refresh()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
        }
        .task { refresh() }
        .task(id: appState.health.fetchedAt) { await loadData() } // pulse-fed
        .onChange(of: appState.connectorFilter, initial: true) { _, newValue in
            // The TUI dispatches the lazy per-connector aibom load whenever
            // the ENFORCEMENT box renders with a connector selected —
            // `initial: true` covers a filter set before Overview mounted.
            if !newValue.isEmpty { appState.requestEnforcementInventory() }
        }
        .onReceive(NotificationCenter.default.publisher(for: .dcRefreshPanel)) { _ in refresh() }
        .onReceive(NotificationCenter.default.publisher(for: .dcRunHealthCheck)) { _ in runDoctor() }
        .sheet(isPresented: $showDoctorSheet) {
            VStack(alignment: .leading, spacing: 10) {
                Text("defenseclaw doctor").font(.headline)
                ScrollView {
                    Text(doctorOutput.isEmpty ? "Running…" : doctorOutput)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(minHeight: 300)
                Button("Close") { showDoctorSheet = false }
            }
            .padding(16)
            .frame(width: 620, height: 420)
        }
    }

    // MARK: Cards

    /// Toolbar connector-scope picker (multi-connector only) — the Overview
    /// equivalent of the TUI's "Connector scope: … (press m to switch)" line.
    @ViewBuilder
    private var connectorScopeChip: some View {
        @Bindable var state = appState
        ConnectorFilterChip(names: appState.activeConnectorNames, selection: $state.connectorFilter)
    }

    /// "What needs attention" (TUI build_notices): top-3 notices in emission
    /// order with [!]/[*]/[>] severity glyphs, or the quiet fallback line.
    private var noticesCard: some View {
        let notices = Array(appState.overviewNotices.prefix(3))
        return DCCard("What Needs Attention", systemImage: "exclamationmark.bubble") {
            if notices.isEmpty {
                HStack(spacing: 6) {
                    Text("[OK]")
                        .font(.caption.weight(.bold).monospaced())
                        .foregroundStyle(Cisco.green)
                    Text("Runtime signals are quiet.")
                        .font(.callout)
                }
            } else {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(notices) { notice in
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(noticeGlyph(notice.level))
                                .font(.caption.weight(.bold).monospaced())
                                .foregroundStyle(noticeColor(notice.level))
                            Text(notice.message)
                                .font(.callout)
                                .textSelection(.enabled)
                        }
                    }
                }
            }
        }
    }

    private func noticeGlyph(_ level: OverviewNotice.Level) -> String {
        switch level {
        case .error: "[!]"
        case .warn: "[*]"
        case .info: "[>]"
        }
    }

    private func noticeColor(_ level: OverviewNotice.Level) -> Color {
        switch level {
        case .error: Cisco.red
        case .warn: Cisco.orange
        case .info: Cisco.blue
        }
    }

    private var quickActionsCard: some View {
        DCCard("Quick Actions", systemImage: "bolt") {
            HStack(spacing: 8) {
                Button {
                    runOverviewCommand(
                        title: "Scan all skills",
                        arguments: ["skill", "scan", "--all"],
                        category: "scan",
                        effects: ["Skill scan results refreshed"]
                    )
                } label: {
                    Label("Scan Skills", systemImage: "wand.and.rays")
                }
                Button {
                    appState.selectedPanel = .inventory
                } label: {
                    Label("Open Inventory", systemImage: "shippingbox")
                }
                Button {
                    let action = appState.gatewayReachable ? "restart" : "start"
                    runOverviewCommand(
                        title: "\(action.capitalized) gateway",
                        binary: "defenseclaw-gateway",
                        arguments: [action],
                        category: "daemon",
                        effects: [appState.gatewayReachable ? "Gateway restarted" : "Gateway started"]
                    )
                } label: {
                    Label(appState.gatewayReachable ? "Restart Gateway" : "Start Gateway",
                          systemImage: appState.gatewayReachable ? "arrow.clockwise.circle" : "play.circle")
                }
                Button {
                    runDoctor()
                } label: {
                    Label("Run Doctor", systemImage: "stethoscope")
                }
                .disabled(doctorRunning)
                Menu {
                    Button("Validate Configuration") {
                        runOverviewCommand(title: "Validate configuration", arguments: ["config", "validate"], category: "info")
                    }
                    Button("Check Credentials") {
                        runOverviewCommand(title: "Check credentials", arguments: ["keys", "check"], category: "info")
                    }
                    Button("Gateway Status") {
                        runOverviewCommand(title: "Gateway status", binary: "defenseclaw-gateway", arguments: ["status"], category: "info")
                    }
                    Button("Show Provenance") {
                        runOverviewCommand(title: "Show gateway provenance", binary: "defenseclaw-gateway", arguments: ["provenance", "show"], category: "info")
                    }
                    Divider()
                    Button("Open Command Palette") { appState.commandPalettePresented = true }
                } label: {
                    Label("Diagnostics", systemImage: "ellipsis.circle")
                }
                Spacer()
            }
            .controlSize(.small)
        }
    }

    /// Hero left: the TUI's SERVICES box — the nine subsystems (Gateway, Agent,
    /// Watchdog, Guardrail, API, Sinks, Telemetry, AI Discovery, Sandbox), each
    /// with a state-colored bullet, name, running/disabled state word, and
    /// detail. Falls back to a gateway-unreachable hint when the API is down.
    private var servicesCard: some View {
        DCCard("Services", systemImage: "square.stack.3d.up", fillHeight: true) {
            if appState.gatewayReachable {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(appState.services) { svc in
                        HStack(spacing: 8) {
                            serviceBullet(svc.state)
                            Text(svc.name)
                                .font(.callout.weight(.medium))
                                .frame(width: 92, alignment: .leading)
                            Text(svc.state)
                                .font(.caption.monospaced())
                                .foregroundStyle(Cisco.stateColor(raw: svc.state))
                                .frame(width: 66, alignment: .leading)
                            Text(svc.detail)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.tail)
                            Spacer(minLength: 0)
                        }
                    }
                }
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Gateway unreachable on port \(appState.config.gatewayPort)", systemImage: "bolt.slash")
                        .foregroundStyle(Cisco.red)
                    Text("File-based panels (Audit, Logs, Activity, alert history) keep working. Start the gateway with:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack {
                        Text("defenseclaw gateway start")
                            .font(.system(.caption, design: .monospaced))
                        Button {
                            copyToPasteboard("defenseclaw gateway start")
                        } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Copy gateway start command")
                    }
                }
            }
        }
    }

    /// Filled dot for a running-ish service, hollow ring otherwise — the TUI's
    /// ●/○ convention, colored by state.
    @ViewBuilder
    private func serviceBullet(_ state: String) -> some View {
        let running = ["running", "active", "enabled", "clean", "allowed"].contains(state.lowercased())
        let color = Cisco.stateColor(raw: state)
        if running {
            Circle().fill(color).frame(width: 7, height: 7)
        } else {
            Circle().strokeBorder(color, lineWidth: 1).frame(width: 7, height: 7)
        }
    }


    /// Full-width CONFIGURATION box (parity with the TUI's global configuration
    /// panel). Uses the same DCCard chrome as the Connectors box — navy panel
    /// background and blue header — with the same zebra-striped table rows. The
    /// stripes use the system's *neutral* alternating content background colors
    /// (the exact colors SwiftUI's Table paints in the Connectors box), so the
    /// rows read black/grey over the blue card rather than blue-on-blue.
    private var configurationCard: some View {
        DCCard("Configuration\(scopeSuffix)", systemImage: "slider.horizontal.3") {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(appState.configurationRows
                    .prefix(configurationExpanded ? appState.configurationRows.count : 4)
                    .enumerated()), id: \.element.id) { index, row in
                    HStack(alignment: .top, spacing: 12) {
                        Text(row.label)
                            .font(.body)
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                            .frame(width: 150, alignment: .leading)
                        Text(row.value)
                            .font(.body)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .lineLimit(2)
                            .truncationMode(.middle)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Self.zebra(index))
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 6))
            if appState.configurationRows.count > 4 {
                Button {
                    withAnimation(.snappy) { configurationExpanded.toggle() }
                } label: {
                    Label(
                        configurationExpanded
                            ? "Show Less"
                            : "Show \(appState.configurationRows.count - 4) More Settings",
                        systemImage: configurationExpanded ? "chevron.up" : "chevron.down"
                    )
                }
                .buttonStyle(.link)
            }
        }
    }

    /// The two neutral, opaque alternating-row colors for the config table —
    /// true black/grey (no blue tint) covering the navy card, matching the
    /// black/grey zebra striping of the Connectors table.
    private static func zebra(_ index: Int) -> Color {
        index.isMultiple(of: 2)
            ? Color.adaptive(light: 0xFFFFFF, dark: 0x1C1C1E)   // base row (near-black)
            : Color.adaptive(light: 0xEFEFEF, dark: 0x2A2A2C)   // alternate row (grey)
    }

    /// Roster-driven rows (TUI: config roster overlaid with live health; the
    /// table only exists on multi-connector installs). Falls back to the live
    /// health rows when the roster is unavailable but the gateway reports >1.
    private var overviewConnectorRows: [ConnectorHealth] {
        let rows = appState.connectorTableRows
        if !rows.isEmpty { return rows }
        return appState.health.connectors.count > 1 ? appState.health.connectors : []
    }

    private var connectorCard: some View {
        let rows = overviewConnectorRows
        return DCCard("Connectors", systemImage: "cable.connector") {
            Table(rows, selection: connectorRowSelection) {
                TableColumn("Connector") { c in
                    Text("\(friendlyConnectorName(c.name)) (\(c.name))")
                        .fontWeight(isScoped(c.name) ? .semibold : .regular)
                        .foregroundStyle(isScoped(c.name) ? Cisco.blue : .primary)
                }
                TableColumn("Mode", value: \.mode)
                TableColumn("Rule Pack", value: \.rulePack)
                TableColumn("Last Activity") { c in Text(DCDates.relative(c.lastActivity)) }
                TableColumn("Calls") { c in Text("\(c.calls)") }
                TableColumn("Blocks") { c in
                    Text("\(c.blocks)")
                        .foregroundStyle(c.blocks > 0 ? Cisco.red : .secondary)
                }
                TableColumn("Alerts") { c in
                    Text("\(c.alerts)")
                        .foregroundStyle(c.alerts > 0 ? Cisco.orange : .secondary)
                }
                TableColumn("Status") { c in
                    // TUI: ●/○ + state word, both in the state color; filled
                    // only for running/active/enabled.
                    let normalized = c.state.trimmingCharacters(in: .whitespaces).lowercased()
                    let filled = ["running", "active", "enabled"].contains(normalized)
                    HStack(spacing: 5) {
                        if filled {
                            Circle().fill(Cisco.stateColor(raw: c.state)).frame(width: 7, height: 7)
                        } else {
                            Circle().strokeBorder(Cisco.stateColor(raw: c.state), lineWidth: 1)
                                .frame(width: 7, height: 7)
                        }
                        Text(c.state.nonEmpty ?? "unknown")
                            .foregroundStyle(Cisco.stateColor(raw: c.state))
                    }
                }
                TableColumn("Action") { c in
                    if c.state.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "not configured" {
                        let candidate = appState.detectedUnconfiguredConnectors.first { $0.name == c.name }
                        if appState.isConnectorSetupInFlight(c.name) {
                            ProgressView().controlSize(.small)
                        } else {
                            Button(candidate?.canConfigureInline == true ? "Add" : "Setup") {
                                appState.configureDetectedConnector(c.name)
                            }
                            .controlSize(.small)
                            .help(candidate?.canConfigureInline == true
                                  ? "Add \(friendlyConnectorName(c.name)) in observe mode without replacing existing connectors. Briefly restarts the DefenseClaw gateway to wire the agent's hooks."
                                  : "Open Setup for \(friendlyConnectorName(c.name))")
                        }
                    }
                }
                .width(66)
            }
            .frame(height: CGFloat(rows.count) * 28 + 32)
            .scrollDisabled(true)
            if let connectorSetupError = appState.connectorSetupError {
                Label(connectorSetupError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(Cisco.red)
                    .textSelection(.enabled)
            }
            if appState.activeConnectorNames.count > 1 {
                HStack {
                    Text(scopeConnector.isEmpty
                         ? "Select a row to scope the Overview to that connector."
                         : "Overview scoped to \(friendlyConnectorName(scopeConnector)).")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                    Spacer()
                    if !scopeConnector.isEmpty {
                        Button("Open \(friendlyConnectorName(scopeConnector)) Alerts →") {
                            appState.openAlerts(filter: .all)
                        }
                        .controlSize(.small)
                        .buttonStyle(.link)
                    }
                }
            }
        }
    }

    private func isScoped(_ name: String) -> Bool {
        scopeConnector.lowercased() == name.lowercased()
    }

    /// Row selection ↔ shared connector filter (TUI: selecting a CONNECTORS
    /// row scopes every view; re-selecting All via the chip clears it). The
    /// setter is a no-op on single-connector installs — the TUI's
    /// normalize_filter keeps those permanently at All, and every clear
    /// affordance (chip, ⌃M, caption) is hidden there.
    private var connectorRowSelection: Binding<String?> {
        Binding(
            get: { appState.connectorFilter.isEmpty ? nil : appState.connectorFilter },
            set: { newValue in
                // Normalize instead of silently rejecting: the AppKit Table
                // highlights the clicked row before the setter runs, so a
                // bare `return` would strand a ghost selection with no
                // @Observable invalidation to snap it back. Always assign —
                // the write triggers a re-render that reconciles the Table
                // to whatever value survived.
                var accepted = newValue ?? ""
                if appState.activeConnectorNames.count <= 1 {
                    accepted = appState.connectorFilter // single-connector: inert
                } else if !accepted.isEmpty,
                          !appState.activeConnectorNames.contains(where: { $0.lowercased() == accepted.lowercased() }) {
                    // Non-scopeable roster row (e.g. configured but not
                    // live) — the pulse's normalize_filter would clear it
                    // right back, so keep the prior scope.
                    accepted = appState.connectorFilter
                }
                appState.connectorFilter = accepted
            }
        )
    }

    /// Hero right half: the TUI's four tiles as a 2×2 grid. When a connector
    /// is selected the tiles narrow to that connector (title "(name)", fleet
    /// caption) and per-connector aibom coverage rows appear (TUI §ENFORCEMENT).
    private var enforcementTilesCard: some View {
        let scoped = appState.scopedEnforcementMetrics
        let fleet = appState.overviewEnforcementMetrics
        let filtered = !scopeConnector.isEmpty
        return DCCard("Enforcement\(scopeSuffix)", systemImage: "checkmark.shield", fillHeight: true) {
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible())], spacing: 10) {
                Button {
                    appState.openLogs(.init(stream: .otel, preset: .hooks))
                } label: {
                    StatCard(
                        title: filtered
                            ? "Hook Calls (\(scopeConnector))"
                            : "Hook Calls (\(max(appState.health.connectors.count, 1)) connectors)",
                        value: "\(scoped.hookCalls)", tint: Cisco.blue
                    ) {
                        metricDetail(filtered ? "fleet \(fleet.hookCalls)" : "Latest 500 audit events")
                    }
                }
                .buttonStyle(InteractiveCardButtonStyle())
                .help("Open hook logs")
                .accessibilityHint("Opens Logs filtered to hook calls")

                Button {
                    appState.openAudit(preset: "blocks")
                } label: {
                    StatCard(title: filtered ? "Blocks (\(scopeConnector))" : "Blocks",
                             value: "\(scoped.blocks)",
                             tint: scoped.blocks > 0 ? Cisco.red : .secondary) {
                        metricDetail(filtered ? "fleet \(fleet.blocks)" : "Latest 500 decisions")
                    }
                }
                .buttonStyle(InteractiveCardButtonStyle())
                .help("Open blocked audit events")
                .accessibilityHint("Opens Audit filtered to blocked decisions")

                Button {
                    appState.openAlerts(filter: .all)
                } label: {
                    StatCard(title: filtered ? "Findings (\(scopeConnector))" : "Findings",
                             value: "\(scoped.findings)", tint: Cisco.orange) {
                        metricDetail(filtered ? "fleet \(fleet.findings)" : "Unacknowledged")
                    }
                }
                .buttonStyle(InteractiveCardButtonStyle())
                .help("Open all alerts")
                .accessibilityHint("Opens all unacknowledged alerts")

                Button {
                    appState.openLogs(.init(preset: .guardrail))
                } label: {
                    StatCard(
                        title: guardrailTileTitle,
                        value: appState.config.guardrailEnabled ? "ON" : "OFF",
                        tint: appState.config.guardrailEnabled ? Cisco.green : .secondary
                    ) {
                        metricDetail("Current configuration")
                    }
                }
                .buttonStyle(InteractiveCardButtonStyle())
                .help("Open guardrail logs")
                .accessibilityHint("Opens Logs filtered to guardrail events")
            }
            if filtered { connectorCoverageRows }
            // Global silent-bypass row (TUI: appended outside the filter
            // branch, hidden entirely at 0).
            if appState.silentBypassCount > 0 {
                HStack(spacing: 8) {
                    Text("Silent bypass")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(Cisco.orange)
                    Text("\(appState.silentBypassCount)")
                        .font(.caption.weight(.bold).monospacedDigit())
                        .foregroundStyle(Cisco.red)
                    Text("(see Alerts → egress)")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    Spacer(minLength: 0)
                }
            }
            if appState.overviewEnforcementMetrics.updatedAt != .distantPast {
                Text("Updated \(DCDates.relative(appState.overviewEnforcementMetrics.updatedAt))")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    /// Per-connector aibom coverage (filtered ENFORCEMENT rows): Skills with
    /// blocked/allowed split, MCPs configured, Scanned x/y assets — or the
    /// TUI's "scan pending" line until the one-shot inventory load lands.
    @ViewBuilder
    private var connectorCoverageRows: some View {
        Divider()
        if let metrics = appState.enforcementInventory[scopeConnector] {
            VStack(alignment: .leading, spacing: 3) {
                coverageRow("Skills", "\(metrics.skills)   \(metrics.skillsBlocked) blocked   \(metrics.skillsAllowed) allowed")
                coverageRow("MCPs", "\(metrics.mcps) configured")
                coverageRow("Scanned", "\(metrics.scanned)/\(metrics.scannable) assets",
                            tint: metrics.scanned >= metrics.scannable && metrics.scannable > 0 ? Cisco.green : Cisco.orange)
            }
        } else {
            Text("Skills  scan pending — loading inventory…")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func coverageRow(_ label: String, _ value: String, tint: Color = .primary) -> some View {
        HStack(spacing: 8) {
            Text(label)
                .font(.caption.weight(.medium))
                .frame(width: 64, alignment: .leading)
            Text(value)
                .font(.caption.monospacedDigit())
                .foregroundStyle(tint)
            Spacer(minLength: 0)
        }
    }

    private func metricDetail(_ scope: String) -> some View {
        HStack(spacing: 4) {
            Text(scope)
                .lineLimit(1)
            Spacer(minLength: 4)
            Image(systemName: "chevron.right")
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
    }

    private var guardrailTileTitle: String {
        if let mode = appState.config.guardrailMode, !mode.isEmpty {
            return "Guardrail - \(mode)"
        }
        return "Guardrail"
    }

    /// Hero card: scanner/guardrail/keys status, mirroring the TUI's SCANNERS box.
    /// When a connector is selected, two context rows are prepended: the
    /// connector's policy ("mode · rule pack") and its scan coverage.
    private var scannersCard: some View {
        DCCard("Scanners\(scopeSuffix)", systemImage: "magnifyingglass.circle", fillHeight: true) {
            VStack(alignment: .leading, spacing: 6) {
                if !scopeConnector.isEmpty {
                    if !appState.connectorPolicyLabel.isEmpty {
                        scannerContextRow("policy", appState.connectorPolicyLabel, tint: Cisco.blue, filled: true)
                    }
                    if let metrics = appState.enforcementInventory[scopeConnector] {
                        scannerContextRow(
                            "coverage", "\(metrics.scanned)/\(metrics.scannable) assets",
                            tint: metrics.scanned >= metrics.scannable && metrics.scannable > 0 ? Cisco.green : Cisco.orange,
                            filled: metrics.scanned >= metrics.scannable && metrics.scannable > 0
                        )
                    } else {
                        scannerContextRow("coverage", "scan pending", tint: .secondary, filled: false)
                    }
                }
                ForEach(appState.scanners) { s in
                    HStack(spacing: 6) {
                        Circle().fill(scannerColor(s.level)).frame(width: 7, height: 7)
                        Text(s.name)
                            .font(.callout.weight(.medium))
                        Spacer(minLength: 8)
                        Text(s.detail)
                            .font(.callout)
                            .foregroundStyle(scannerColor(s.level))
                            .lineLimit(1)
                            .truncationMode(.tail)
                        if s.fixSource != nil {
                            Button("Fix") { appState.fixScanner(s) }
                                .buttonStyle(.borderless)
                                .font(.caption.weight(.semibold))
                                .help("Link \(s.name) into ~/.local/bin so the CLI and gateway can find it")
                        }
                    }
                }
                if let err = appState.scannerFixError {
                    Text(err)
                        .font(.caption2)
                        .foregroundStyle(Cisco.red)
                        .lineLimit(2)
                }
                if appState.scanners.isEmpty {
                    Text("Probing scanners…").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    /// TUI ●/○ context row prepended to the filtered SCANNERS box.
    private func scannerContextRow(_ name: String, _ detail: String, tint: Color, filled: Bool) -> some View {
        HStack(spacing: 6) {
            if filled {
                Circle().fill(tint).frame(width: 7, height: 7)
            } else {
                Circle().strokeBorder(tint, lineWidth: 1).frame(width: 7, height: 7)
            }
            Text(name)
                .font(.callout.weight(.medium))
            Spacer(minLength: 8)
            Text(detail)
                .font(.callout)
                .foregroundStyle(tint)
                .lineLimit(1)
                .truncationMode(.tail)
        }
    }

    private func scannerColor(_ level: ScannerStatus.Level) -> Color {
        switch level {
        case .active: Cisco.green
        case .builtin: .secondary
        case .warn: Cisco.orange
        case .missing: Cisco.red
        }
    }

    /// Full-width OBSERVABILITY DESTINATIONS · RUNTIME box: every
    /// runtime-loaded OTel destination and audit sink from /health, with
    /// delivery/eligibility routing labels and redacted endpoints (TUI
    /// _overview_observability_panel).
    private var observabilityCard: some View {
        DCCard("Observability Destinations · Runtime", systemImage: "antenna.radiowaves.left.and.right") {
            if appState.health.observabilityRows.isEmpty {
                Text("No runtime-loaded destinations. Configure one in Setup → Observability / Galileo, then restart the gateway.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Table(appState.health.observabilityRows) {
                    TableColumn("Name") { row in
                        Text(row.name).fontWeight(.medium)
                    }
                    TableColumn("Target", value: \.target).width(78)
                    TableColumn("Scope") { row in
                        Text(row.scope).foregroundStyle(.secondary)
                    }
                    .width(70)
                    TableColumn("Kind/Preset") { row in
                        Text(row.kind).foregroundStyle(.secondary)
                    }
                    .width(90)
                    TableColumn("State") { row in
                        Text(row.state)
                            .foregroundStyle(row.state == "enabled" ? Cisco.green : Color.secondary)
                    }
                    .width(64)
                    TableColumn("Signals") { row in
                        Text(row.signals).foregroundStyle(.secondary)
                    }
                    .width(130)
                    TableColumn("Routing") { row in
                        Text(row.routing.nonEmpty ?? "—")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(Cisco.sky)
                            .lineLimit(1)
                            .truncationMode(.tail)
                            .help(row.routing.nonEmpty ?? "No routing data yet")
                    }
                    TableColumn("Endpoint") { row in
                        Text(row.endpoint)
                            .font(.caption.monospaced())
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .frame(height: CGFloat(appState.health.observabilityRows.count) * 28 + 32)
                .scrollDisabled(true)
                Text("Names are identities: a new name adds a route; the same name updates it. Manage in Setup → Observability / Galileo.")
                    .font(.caption2)
                    .italic()
                    .foregroundStyle(.tertiary)
            }
        }
    }

    /// Full-width: enforcement summary counters + 24h histogram.
    private var activityCard: some View {
        DCCard("Activity — last 24h", systemImage: "chart.bar.xaxis") {
            HStack(spacing: 18) {
                summaryItem("Skills", "\(summary.blockedSkills) blocked · \(summary.allowedSkills) allowed")
                summaryItem("MCPs", "\(summary.blockedMCPs) blocked · \(summary.allowedMCPs) allowed")
                // Session-scoped like the TUI: scans/alerts since the earliest
                // live connector session start; all-time when offline.
                summaryItem("Total scans", "\(appState.sessionTotalScans)")
                summaryItem("Active alerts", "\(sessionActiveAlerts)")
                Spacer()
            }
            if !hourly.isEmpty {
                Chart(hourly) { point in
                    BarMark(
                        x: .value("Hour", point.hour, unit: .hour),
                        y: .value("Events", point.count)
                    )
                    .foregroundStyle(by: .value("Class", point.klass))
                }
                .chartForegroundStyleScale(["allowed": Cisco.green, "blocked": Cisco.red])
                .frame(height: 110)
            }
        }
    }

    /// DOCTOR box (TUI doctor_box): cache-hydrated at launch, summary counts
    /// with live-health STALE reconciliation, age + 15-min staleness flag,
    /// top-3 fail/warn rows, all-green message.
    private var doctorCard: some View {
        let box = appState.doctorBox
        return DCCard("Doctor", systemImage: "stethoscope") {
            if doctorRunning {
                Text("Running health probe…").font(.caption).foregroundStyle(.secondary)
            } else if box.empty {
                Text("Not yet run — use “Run Health Check” in the toolbar.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                // Summary: "20 pass  2 fail  5 warn  1 stale  8 skip · 3m ago (stale — rerun)"
                HStack(spacing: 8) {
                    if box.summaryParts.isEmpty {
                        Text("no data").font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(box.summaryParts, id: \.self) { part in
                        Text(part)
                            .font(.caption.weight(.semibold).monospacedDigit())
                            .foregroundStyle(summaryPartColor(part))
                    }
                    if !box.ageLabel.isEmpty {
                        Text("· \(box.ageLabel)")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                    if box.stale {
                        Text("(stale — rerun)")
                            .font(.caption)
                            .foregroundStyle(Cisco.orange)
                    }
                    Spacer(minLength: 0)
                }
                if box.allGreen {
                    Text("All checks passing — nothing to address.")
                        .font(.caption)
                        .foregroundStyle(Cisco.green)
                } else {
                    Divider()
                    ForEach(Array(box.checks.enumerated()), id: \.offset) { _, check in
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text("[\(check.badge)]")
                                .font(.caption2.weight(.bold).monospaced())
                                .foregroundStyle(badgeColor(check.badge))
                            Text(check.label).font(.caption)
                            Text(check.detail)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                                .lineLimit(1)
                                .truncationMode(.tail)
                            Spacer(minLength: 0)
                        }
                    }
                }
                if !doctorOutput.isEmpty {
                    Button("Deep-dive output…") { showDoctorSheet = true }
                        .controlSize(.small)
                }
            }
        }
    }

    /// Summary-part tint keyed by the word: pass=green fail=red warn=amber
    /// stale=blue skip=muted (TUI header coloring).
    private func summaryPartColor(_ part: String) -> Color {
        if part.hasSuffix(" pass") { return Cisco.green }
        if part.hasSuffix(" fail") { return Cisco.red }
        if part.hasSuffix(" warn") { return Cisco.orange }
        if part.hasSuffix(" stale") { return Cisco.blue }
        return .secondary
    }

    private func badgeColor(_ badge: String) -> Color {
        switch badge {
        case "FAIL": Cisco.red
        case "WARN": Cisco.orange
        case "STALE": Cisco.blue
        default: .secondary
        }
    }

    /// One deduped Overview row per discovered agent (TUI ai_discovery_box).
    private struct AIOverviewRow: Identifiable {
        var badge: String       // [NEW] / [CHG] / [GONE] / [OK ]
        var name: String
        var vendor: String
        var confidence: String  // " 98%"
        var seenLabel: String   // "seen 3m ago"
        var id: String { "\(badge)-\(name)-\(vendor)" }
    }

    /// Sort (state rank, -confidence, -last_seen, name), dedup by
    /// connector/component/display key, cap 8 with overflow.
    private var aiOverviewRows: (rows: [AIOverviewRow], overflow: Int) {
        func stateRank(_ state: String) -> Int {
            switch state.lowercased() {
            case "new": 0
            case "changed": 1
            case "active", "": 2
            case "gone": 3
            default: 4
            }
        }
        func displayName(_ s: AISignal) -> String {
            s.name.nonEmpty ?? s.product.nonEmpty ?? s.signatureID.nonEmpty ?? s.signalID.nonEmpty ?? "(unknown)"
        }
        let sorted = appState.aiSnapshot.signals.sorted { a, b in
            let ra = stateRank(a.state), rb = stateRank(b.state)
            if ra != rb { return ra < rb }
            if a.confidence != b.confidence { return a.confidence > b.confidence }
            let ta = a.lastSeen?.timeIntervalSince1970 ?? 0
            let tb = b.lastSeen?.timeIntervalSince1970 ?? 0
            if ta != tb { return ta > tb }
            return displayName(a).lowercased() < displayName(b).lowercased()
        }
        var seen = Set<String>()
        var unique: [AISignal] = []
        for signal in sorted {
            let key: String
            if !signal.supportedConnector.isEmpty {
                key = "connector:\(signal.supportedConnector.lowercased())"
            } else if !signal.ecosystem.isEmpty || !signal.componentName.isEmpty {
                key = "component:\(signal.ecosystem.lowercased()):\(signal.componentName.lowercased())"
            } else {
                // TUI display key uses the vendor label WITH the version
                // suffix, so same-vendor different-version signals stay apart.
                var vendorLabel = signal.vendor.nonEmpty ?? signal.category.nonEmpty ?? "-"
                if !signal.version.isEmpty { vendorLabel += " \(signal.version)" }
                key = "display:\(vendorLabel.lowercased()):\(displayName(signal).lowercased())"
            }
            if seen.insert(key).inserted { unique.append(signal) }
        }
        let overflow = max(unique.count - 8, 0)
        let rows = unique.prefix(8).map { signal -> AIOverviewRow in
            let badge: String = switch signal.state.lowercased() {
            case "new": "[NEW]"
            case "changed": "[CHG]"
            case "gone": "[GONE]"
            default: "[OK ]"
            }
            var vendor = signal.vendor.nonEmpty ?? signal.category.nonEmpty ?? "-"
            if !signal.version.isEmpty { vendor += " \(signal.version)" }
            if !signal.supportedConnector.isEmpty { vendor += " (\(signal.supportedConnector))" }
            let pct = min(max(Int(signal.confidence * 100 + 0.5), 0), 100)
            let seenLabel = signal.lastSeen.map { "seen \(DCDates.relative($0))" } ?? "seen -"
            return AIOverviewRow(
                badge: badge,
                name: displayName(signal),
                vendor: vendor,
                confidence: String(format: "%3d%%", pct),
                seenLabel: seenLabel
            )
        }
        return (Array(rows), overflow)
    }

    private var aiCard: some View {
        let box = aiOverviewRows
        return DCCard("Discovered AI Agents", systemImage: "sparkle.magnifyingglass") {
            if !appState.aiFetchEverSucceeded {
                Text("ai discovery offline - run: defenseclaw agent discovery status")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if !appState.aiSnapshot.enabled {
                Text("disabled - run: defenseclaw agent discovery enable")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if appState.aiSnapshot.signals.isEmpty {
                Text("no AI agents detected yet - try: defenseclaw agent discover")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                // Rich-panel parity: first 8 rows + "+N more".
                ForEach(box.rows) { row in
                    HStack(spacing: 8) {
                        Text(row.badge)
                            .font(.caption2.weight(.bold).monospaced())
                            .foregroundStyle(aiBadgeColor(row.badge))
                        Text(row.name)
                            .font(.caption)
                            .lineLimit(1)
                            .frame(maxWidth: 170, alignment: .leading)
                        Text(row.vendor)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        Spacer(minLength: 4)
                        Text(row.confidence)
                            .font(.caption2.monospacedDigit())
                        Text(row.seenLabel)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
                // TUI math: overflow counts rows beyond the rendered 8-cap.
                if box.overflow > 0 {
                    Text("+\(box.overflow) more")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Button("See all →") { appState.selectedPanel = .aiDiscovery }
                    .controlSize(.small)
            }
        }
    }

    private func aiBadgeColor(_ badge: String) -> Color {
        switch badge {
        case "[NEW]": Cisco.green
        case "[CHG]": Cisco.orange
        case "[GONE]": .secondary
        default: Cisco.blue
        }
    }

    // MARK: Actions

    /// Severity-bearing alert rows within the live session window (TUI's
    /// session-scoped "Active alerts"); all rows when no session start.
    private var sessionActiveAlerts: Int {
        let severityBearing = appState.unackedAlerts.filter { $0.severity > .info }
        guard let start = appState.sessionStart else { return severityBearing.count }
        return severityBearing.filter { $0.timestamp >= start }.count
    }

    private func summaryItem(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.caption.weight(.medium))
        }
    }

    private func refresh() {
        Task {
            let before = appState.health.fetchedAt
            await appState.pulse()
            // Online: pulse advances fetchedAt → task(id:) re-runs loadData on its own.
            // Offline: fetchedAt is unchanged, so reload tiles explicitly from the audit DB.
            if appState.health.fetchedAt == before {
                await loadData()
            }
        }
    }

    /// Summary/chart reload WITHOUT triggering a pulse — also driven by the
    /// pulse tick (task(id: fetchedAt)) so the panels track live data without a
    /// pulse→fetchedAt→pulse loop. Hero enforcement counts come from
    /// AppState.overviewEnforcementMetrics so they reconcile with the menu bar.
    private func loadData() async {
        summary = await appState.audit.enforcementSummary()
        hourly = await appState.audit.hourlyEnforcement24h()
            .map { HourlyPoint(hour: $0.hour, klass: $0.action, count: $0.count) }
    }

    private func runDoctor() {
        guard !doctorRunning else { return }
        doctorRunning = true
        doctorOutput = ""
        Task {
            let result = await appState.runCommand(
                title: "DefenseClaw Doctor",
                arguments: ["doctor"],
                category: "info",
                origin: "Overview",
                successEffects: ["Diagnostic results refreshed"]
            )
            doctorOutput = result.output
            // The CLI rewrites <data_dir>/doctor_cache.json at the end of
            // every run (even failing ones) — reload it for the Doctor card
            // instead of scraping stdout.
            appState.doctorCache = DoctorCache.load() ?? appState.doctorCache
            doctorRunning = false
        }
    }

    private func runOverviewCommand(
        title: String,
        binary: String = "defenseclaw",
        arguments: [String],
        category: String,
        effects: [String] = []
    ) {
        appState.selectedPanel = .activity
        Task {
            _ = await appState.runCommand(
                title: title,
                binary: binary,
                arguments: arguments,
                category: category,
                origin: "Overview",
                successEffects: effects,
                refreshOnSuccess: true
            )
        }
    }


}
