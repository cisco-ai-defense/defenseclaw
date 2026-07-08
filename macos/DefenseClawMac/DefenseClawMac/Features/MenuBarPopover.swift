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

// Menu bar popover (spec §5.1): health header, per-connector lines,
// recent enforcement metrics, recent unacked alerts, footer actions.

import SwiftUI

struct MenuBarPopover: View {
    @Environment(AppState.self) private var appState
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            Divider()
            connectorLines
            enforcementBars
            Divider()
            recentAlerts
            Divider()
            footer
        }
        .padding(12)
        .frame(width: 360)
        .task {
            await appState.refreshAlerts()
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "shield.lefthalf.filled")
                .foregroundStyle(Cisco.blue)
                .font(.title3)
            VStack(alignment: .leading, spacing: 1) {
                Text("DefenseClaw").font(.headline)
                Text(appState.gatewayReachable
                     ? "Gateway up · \(uptimeText) · \(appState.health.connectors.count) connector(s)"
                     : "Gateway offline")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            StatePill(raw: appState.gatewayReachable ? appState.health.state : "offline")
        }
    }

    private var uptimeText: String {
        let secs = appState.health.uptimeMs / 1000
        if secs > 86400 { return "\(secs / 86400)d up" }
        if secs > 3600 { return "\(secs / 3600)h up" }
        return "\(max(secs, 0) / 60)m up"
    }

    @ViewBuilder
    private var connectorLines: some View {
        ForEach(appState.health.connectors) { c in
            HStack(spacing: 6) {
                Circle().fill(Cisco.stateColor(raw: c.state)).frame(width: 6, height: 6)
                Text(c.name).font(.caption.weight(.medium))
                Text(c.mode).font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Text("\(c.calls) calls · \(c.blocks) blocks")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var enforcementBars: some View {
        let metrics = appState.overviewEnforcementMetrics
        return VStack(alignment: .leading, spacing: 7) {
            enforcementRow(
                "Hook Calls",
                value: metrics.hookCalls,
                detail: "latest 500 audit events",
                tint: Cisco.blue,
                progress: activityProgress(metrics.hookCalls)
            ) {
                appState.openLogs(.init(stream: .otel, preset: .hooks))
                openMainWindow()
            }
            enforcementRow(
                "Blocks",
                value: metrics.blocks,
                detail: "latest 500 decisions · \(blockRateText(blocks: metrics.blocks, hookCalls: metrics.hookCalls))",
                tint: Cisco.red,
                progress: blockProgress(blocks: metrics.blocks, hookCalls: metrics.hookCalls)
            ) {
                appState.openAudit(preset: "blocks")
                openMainWindow()
            }
            enforcementRow(
                "Findings",
                value: metrics.findings,
                detail: "unacknowledged",
                tint: metrics.findings == 0 ? Cisco.green : Cisco.orange,
                progress: findingsProgress(metrics.findings)
            ) {
                appState.openAlerts(filter: .all)
                openMainWindow()
            }
            if metrics.updatedAt != .distantPast {
                Text("Updated \(DCDates.relative(metrics.updatedAt))")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 2)
    }

    private func enforcementRow(
        _ title: String,
        value: Int,
        detail: String,
        tint: Color,
        progress: Double,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline) {
                    Text(title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(detail)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer()
                    Text("\(value)")
                        .font(.caption.monospacedDigit().weight(.semibold))
                        .foregroundStyle(value == 0 ? Color.secondary : tint)
                }
                GeometryReader { proxy in
                    let clamped = min(max(progress, 0), 1)
                    let width = value == 0
                        ? CGFloat.zero
                        : max(CGFloat(3), proxy.size.width * CGFloat(clamped))
                    ZStack(alignment: .leading) {
                        Capsule().fill(.secondary.opacity(0.14))
                        Capsule().fill(tint).frame(width: width)
                    }
                }
                .frame(height: 4)
            }
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title) \(value), \(detail)")
    }

    private func activityProgress(_ value: Int) -> Double {
        guard value > 0 else { return 0 }
        return Double(value) / Double(value + 250)
    }

    private func blockProgress(blocks: Int, hookCalls: Int) -> Double {
        guard blocks > 0 else { return 0 }
        if hookCalls <= 0 { return min(Double(blocks) / 10, 1) }
        return min(max((Double(blocks) / Double(hookCalls)) * 8, 0.06), 1)
    }

    private func findingsProgress(_ findings: Int) -> Double {
        guard findings > 0 else { return 0 }
        return Double(findings) / Double(findings + 10)
    }

    private func blockRateText(blocks: Int, hookCalls: Int) -> String {
        guard hookCalls > 0 else { return "recent block decisions" }
        guard blocks > 0 else { return "0% block rate" }
        let rate = Double(blocks) * 100 / Double(hookCalls)
        if rate < 1 { return String(format: "%.1f%% block rate", rate) }
        return "\(Int(rate.rounded()))% block rate"
    }

    private func openMainWindow() {
        AppDelegate.openMainWindow()
        openWindow(id: "main")
    }

    @ViewBuilder
    private var recentAlerts: some View {
        let top = Array(appState.unackedAlerts.prefix(5))
        if top.isEmpty {
            Text("No unacknowledged alerts")
                .font(.caption)
                .foregroundStyle(.secondary)
        } else {
            ForEach(top) { row in
                Button {
                    appState.selectedPanel = .alerts
                    openMainWindow()
                } label: {
                    HStack(spacing: 6) {
                        Circle().fill(Cisco.severityColor(row.severity)).frame(width: 7, height: 7)
                        Text(row.target.isEmpty ? row.action : row.target)
                            .font(.caption)
                            .lineLimit(1)
                        Spacer()
                        Text(DCDates.relative(row.timestamp))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let error = appState.ackError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption2)
                    .foregroundStyle(Cisco.red)
            }
            footerButtons
        }
    }

    private var footerButtons: some View {
        HStack {
            Button("Open DefenseClaw") {
                openMainWindow()
            }
            .controlSize(.small)
            Button {
                openSettings()
            } label: {
                Image(systemName: "gearshape")
            }
            .controlSize(.small)
            .help("Settings")
            Button("Ack All") {
                Task { await appState.acknowledge(appState.unackedAlerts) }
            }
            .controlSize(.small)
            .disabled(appState.unackedAlerts.isEmpty)
            Button(appState.monitoringPaused ? "Resume" : "Pause") {
                appState.monitoringPaused.toggle()
            }
            .controlSize(.small)
            Spacer()
            Button("Quit") { NSApp.terminate(nil) }
                .controlSize(.small)
        }
    }

}
