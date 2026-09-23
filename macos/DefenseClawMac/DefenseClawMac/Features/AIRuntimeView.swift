// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// The AI Discovery Runtime panel.
///
/// A separate panel from AI Discovery rather than more columns on it, because
/// the two answer different questions and fail independently: an operator
/// reading a healthy inventory as evidence of runtime coverage would draw
/// exactly the wrong conclusion.
struct AIRuntimeView: View {
    @Environment(AppState.self) private var appState
    @State private var snapshot = AIRuntimeSnapshot()
    @State private var selection: AIRuntimeFinding.ID?
    @State private var search = ""
    @State private var scanning = false
    @State private var error: String?
    @State private var loaded = false

    private var filtered: [AIRuntimeFinding] {
        guard !search.isEmpty else { return snapshot.findings }
        return snapshot.findings.filter { finding in
            let haystack = [
                finding.process, finding.cmdline, finding.user, finding.agentName,
                finding.severity, finding.providerSummary, finding.correlation.verdict,
            ].joined(separator: " ")
            return haystack.localizedCaseInsensitiveContains(search)
        }
    }

    private var selected: AIRuntimeFinding? {
        guard let selection else { return nil }
        return snapshot.findings.first { $0.id == selection }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            // Rendered before the findings, unconditionally. A detector
            // reporting clean because it was never able to look is
            // indistinguishable, on a dashboard, from a host that is genuinely
            // clean, so coverage is not something the operator has to go find.
            planeStrip
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
            content
        }
        .padding(16)
        .task {
            if !loaded { await load() }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("AI Discovery Runtime")
                    .font(.title3.weight(.semibold))
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            TextField("Filter", text: $search)
                .textFieldStyle(.roundedBorder)
                .frame(width: 200)
            Button {
                Task { await load() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(!appState.gatewayReachable)
            Button {
                scan()
            } label: {
                Label("Poll now", systemImage: "bolt")
            }
            .disabled(scanning || !appState.gatewayReachable || !appState.installationMutationsAllowed)
        }
    }

    /// Coverage sits beside the finding count on purpose: a reader who sees
    /// only the count cannot tell a quiet host from a blind sensor.
    private var subtitle: String {
        guard snapshot.enabled else {
            return "Disabled — enable with: defenseclaw agent discovery runtime enable"
        }
        var parts = ["\(filtered.count) of \(snapshot.findings.count) findings"]
        parts.append(snapshot.coverageSummary)
        if let scannedAt = snapshot.scannedAt {
            parts.append("polled \(scannedAt.formatted(date: .omitted, time: .standard))")
        }
        if snapshot.degraded { parts.append("DEGRADED") }
        return parts.joined(separator: " · ")
    }

    private var planeStrip: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                ForEach(snapshot.planes) { plane in
                    HStack(spacing: 4) {
                        Circle()
                            .fill(planeColor(plane))
                            .frame(width: 7, height: 7)
                        Text("\(plane.name): \(plane.badge)")
                            .font(.caption.monospaced())
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(.quaternary, in: Capsule())
                    .help(plane.summary)
                }
                if snapshot.planes.isEmpty {
                    Text("plane health unavailable: the gateway reported no planes")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            // Every non-running plane states why, in full, rather than only in
            // a tooltip. A blind plane rendering as a grey dot is the failure
            // mode this whole subsystem exists to prevent.
            ForEach(snapshot.planesNotRunning) { plane in
                Text(plane.summary)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            if snapshot.connectionsObserved > 0, snapshot.unattributedShare >= 0.5 {
                Text("\(Int(snapshot.unattributedShare * 100))% of connections could not be attributed to a process. "
                     + "Run the gateway with elevated privilege for machine-wide egress attribution.")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
        }
    }

    private func planeColor(_ plane: AIRuntimePlane) -> Color {
        if plane.running { return .green }
        return plane.available ? .yellow : .red
    }

    @ViewBuilder
    private var content: some View {
        if !snapshot.enabled {
            ContentUnavailableView(
                "Runtime planes are disabled",
                systemImage: "waveform.path.ecg",
                description: Text("Enable with: defenseclaw agent discovery runtime enable")
            )
        } else if snapshot.scannedAt == nil {
            ContentUnavailableView(
                "No poll yet",
                systemImage: "clock",
                description: Text("The runtime planes have not completed a poll.")
            )
        } else if filtered.isEmpty {
            ContentUnavailableView(
                "No findings",
                systemImage: "checkmark.shield",
                description: Text("Nothing at or above the reporting floor. Coverage is shown above — "
                                  + "\"nothing found\" and \"nothing could be looked at\" are different results.")
            )
        } else {
            HSplitView {
                findingsTable
                detailPane
                    .frame(minWidth: 320)
            }
        }
    }

    private var findingsTable: some View {
        Table(filtered, selection: $selection) {
            TableColumn("Severity") { finding in
                Text(finding.severity.capitalized)
                    .foregroundStyle(severityColor(finding.severity))
            }
            .width(min: 70, ideal: 80)
            TableColumn("Score") { Text("\($0.score)") }
                .width(min: 48, ideal: 54)
            TableColumn("Process") { Text($0.process) }
            TableColumn("PID") { Text("\($0.pid)") }
                .width(min: 54, ideal: 62)
            TableColumn("Agent") { Text($0.agentName.isEmpty ? "—" : $0.agentName) }
            TableColumn("Providers") { Text($0.providerSummary) }
            TableColumn("Inventory") { finding in
                Text(finding.correlation.verdict.isEmpty ? "—" : finding.correlation.verdict)
                    .foregroundStyle(finding.correlation.isUnaccounted ? .orange : .secondary)
            }
        }
    }

    @ViewBuilder
    private var detailPane: some View {
        if let finding = selected {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text("\(finding.severity.uppercased())  score \(finding.score)")
                        .font(.headline)
                        .foregroundStyle(severityColor(finding.severity))
                    detailRow("process", "\(finding.process) (pid \(finding.pid), user \(finding.user.isEmpty ? "unknown" : finding.user))")
                    if !finding.agentName.isEmpty { detailRow("agent", finding.agentName) }
                    if !finding.cmdline.isEmpty { detailRow("cmdline", finding.cmdline) }
                    if !finding.chain.isEmpty {
                        // Rendered as a sequence rather than a set, because the
                        // order is the finding.
                        detailRow("chain", finding.chain)
                    }
                    if !finding.providers.isEmpty {
                        Divider()
                        Text("providers").font(.caption.weight(.semibold))
                        ForEach(finding.providers) { provider in
                            Text("\(provider.hostname)  (\(provider.category.isEmpty ? "uncategorised" : provider.category), "
                                 + "\(provider.attributionSource))")
                                .font(.caption.monospaced())
                        }
                    }
                    Divider()
                    Text("signals").font(.caption.weight(.semibold))
                    ForEach(finding.signals) { signal in
                        Text("+\(signal.weight)  \(signal.signalID)\(signal.detail.isEmpty ? "" : "  " + signal.detail)")
                            .font(.caption.monospaced())
                    }
                    Divider()
                    // Always shown, including "unobserved". Omitting it would
                    // let a reader mistake blindness for agreement.
                    Text("inventory").font(.caption.weight(.semibold))
                    Text(finding.correlation.verdict.isEmpty ? "unknown" : finding.correlation.verdict)
                        .font(.caption.monospaced())
                        .foregroundStyle(finding.correlation.isUnaccounted ? .orange : .primary)
                    if !finding.correlation.reason.isEmpty {
                        Text(finding.correlation.reason)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
            }
        } else {
            ContentUnavailableView(
                "Select a finding",
                systemImage: "sidebar.right",
                description: Text("Its evidence trail, attributed peers, and inventory verdict appear here.")
            )
        }
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.caption.monospaced()).textSelection(.enabled)
        }
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity.lowercased() {
        case "critical": return .red
        case "high": return .orange
        case "medium": return .yellow
        case "low": return .blue
        default: return .secondary
        }
    }

    private func load() async {
        guard appState.gatewayReachable else { return }
        let installationGeneration = appState.installationGeneration
        do {
            let fresh = try await appState.gateway.aiRuntime()
            guard installationGeneration == appState.installationGeneration else { return }
            snapshot = fresh
            loaded = true
            // A selection whose finding is gone must clear, or the detail pane
            // keeps showing a process that has exited.
            if let selection, !snapshot.findings.contains(where: { $0.id == selection }) {
                self.selection = nil
            }
            error = nil
        } catch {
            // Keep the previous snapshot on a transient failure: replacing a
            // stale-but-true coverage report with an empty one would read as a
            // clean host rather than as a lost connection.
            guard installationGeneration == appState.installationGeneration else { return }
            self.error = error.localizedDescription
        }
    }

    private func scan() {
        guard appState.installationMutationsAllowed else {
            error = appState.installationReadOnlyReason ?? "This installation is read only."
            return
        }
        scanning = true
        Task {
            defer { scanning = false }
            do {
                try await appState.gateway.scanAIRuntime()
                await load()
            } catch {
                self.error = "Poll failed: \(error.localizedDescription)"
            }
        }
    }
}
