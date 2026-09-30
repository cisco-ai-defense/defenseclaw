// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// OpenShell sandboxes: the Sandboxes panel, the menu-bar section and the
// Overview card. All three render AppState.sandbox (pulse-refreshed from the
// daemon's /api/v1/sandbox API). Unblock and ask decisions go to the daemon;
// stop, review, undo and a pull to a branch run the CLI so their output lands
// in Activity (stop and undo also keep a detached run's log there for
// `sandbox logs`). Harness sessions (run, connect) need a terminal, and so
// does a pull that applies to the working tree after showing the changes,
// so the app offers the command to copy rather than a window pretending to
// be one.

import AppKit
import SwiftUI

struct SandboxesView: View {
    @Environment(AppState.self) private var appState
    @State private var selection: SandboxRow.ID?
    @State private var confirmStop: SandboxRow?
    @State private var confirmUndo: SandboxRow?
    @State private var confirmAlways: SandboxAsk?
    @State private var confirmAlwaysUnblock: SandboxActivity?

    private var snapshot: SandboxSnapshot { appState.sandbox }
    private var selected: SandboxRow? {
        guard let selection else { return nil }
        return snapshot.sandboxes.first { $0.id == selection }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if let message = appState.sandboxActionMessage {
                Label(message, systemImage: appState.sandboxActionFailed ? "exclamationmark.triangle" : "checkmark.circle")
                    .font(.callout)
                    .foregroundStyle(appState.sandboxActionFailed ? Cisco.orange : Cisco.green)
                    .textSelection(.enabled)
            }
            if snapshot.state == "ready" {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        sandboxTable
                        if let selected { detail(selected) }
                        asksCard
                        activityCard
                    }
                }
            } else {
                notReady
            }
        }
        .padding(16)
        .task { await appState.refreshSandboxes() }
        .confirmationDialog(
            "Stop \(confirmStop?.name ?? "")?",
            isPresented: Binding(get: { confirmStop != nil }, set: { if !$0 { confirmStop = nil } }),
            presenting: confirmStop
        ) { row in
            // The CLI looks for a detached run first: it says so in Activity,
            // marks the run interrupted and keeps its log for `sandbox logs`.
            Button("Stop", role: .destructive) { runCLI("Stop \(row.name)", ["sandbox", "stop", row.name, "--yes"]) }
        } message: { row in
            Text("Ends the harness session running in \(row.name), and a detached run (sandbox run --detach) if one "
                + "is still going; DefenseClaw keeps that run's log for: defenseclaw sandbox logs \(row.name). "
                + "The sandbox is kept: resume it with defenseclaw sandbox connect \(row.name).")
        }
        .confirmationDialog(
            "Undo \(confirmUndo?.name ?? "")?",
            isPresented: Binding(get: { confirmUndo != nil }, set: { if !$0 { confirmUndo = nil } }),
            presenting: confirmUndo
        ) { row in
            // The CLI undoes a mounted project's session, or reverts a copy's
            // last `pull --apply` in the project folder.
            Button(row.copyMode ? "Revert the apply" : "Undo everything", role: .destructive) {
                runCLI("Undo \(row.name)", ["sandbox", "undo", row.name, "--yes"])
            }
        } message: { row in
            if row.copyMode {
                Text("Reverts the last `pull --apply` of \(row.name) in "
                    + "\(row.project.isEmpty ? "the project folder" : row.project). Edits you made since stay; "
                    + "if one changed the same files, nothing is reverted and Activity says why.")
            } else {
                Text("Puts \(row.project.isEmpty ? "the project folder" : row.project) back to its pre-session snapshot. "
                    + "The sandbox is stopped first (a detached run still going ends; its log is kept). "
                    + "Activity lists what undo cannot restore.")
            }
        }
        .confirmationDialog(
            "Always allow \(confirmAlways?.destination ?? "")?",
            isPresented: Binding(get: { confirmAlways != nil }, set: { if !$0 { confirmAlways = nil } }),
            presenting: confirmAlways
        ) { ask in
            Button("Always allow") { Task { await appState.decideSandboxAsk(ask, approve: true, always: true) } }
        } message: { _ in
            Text("Every future sandbox may reach it too (openshell.egress.unblocked).")
        }
        .confirmationDialog(
            "Unblock \(confirmAlwaysUnblock?.host ?? "") everywhere?",
            isPresented: Binding(get: { confirmAlwaysUnblock != nil }, set: { if !$0 { confirmAlwaysUnblock = nil } }),
            presenting: confirmAlwaysUnblock
        ) { event in
            Button("Unblock in every sandbox") {
                Task { await appState.unblockSandboxDestination(host: event.host, sandbox: event.sandbox, always: true) }
            }
        } message: { _ in
            Text("Adds the host to openshell.egress.unblocked. Private networks stay closed.")
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Sandboxes").font(.title3.weight(.semibold))
                Text(snapshot.headline)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                if snapshot.status.adminConfigured {
                    Text("Organization policy: \(snapshot.status.adminDetail.isEmpty ? snapshot.status.adminAuthority : snapshot.status.adminDetail)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if !snapshot.staleNote.isEmpty {
                    Text(snapshot.staleNote)
                        .font(.caption2)
                        .foregroundStyle(Cisco.orange)
                }
            }
            Spacer()
            Button {
                copy("cd <project> && defenseclaw sandbox run claude")
            } label: {
                Label("Copy run command", systemImage: "doc.on.doc")
            }
            .help("A harness session needs a terminal: paste this in one, in your project folder.")
            Button {
                Task { await appState.refreshSandboxes() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(!appState.gatewayReachable)
        }
    }

    @ViewBuilder
    private var notReady: some View {
        switch snapshot.state {
        case "off":
            DCEmptyState(
                title: "Sandboxes are off",
                message: "Run coding agents in an NVIDIA OpenShell sandbox that sees only your project folder. "
                    + "Open Setup → Sandbox, or run: defenseclaw sandbox setup",
                systemImage: "cube.transparent"
            )
            Button("Open Setup") { appState.selectedPanel = .setup }
        case "unavailable":
            DCEmptyState(title: "Sandboxes are unavailable", message: snapshot.headline, systemImage: "exclamationmark.triangle")
            Button("Run sandbox doctor") { runCLI("Sandbox doctor", ["sandbox", "doctor"], mutation: false) }
        default:
            DCEmptyState(title: "Sandboxes", message: snapshot.headline, systemImage: "cube.transparent")
        }
    }

    private var sandboxTable: some View {
        DCCard("Sandboxes", systemImage: "cube.transparent") {
            if snapshot.sandboxes.isEmpty {
                Text("No sandboxes yet. In a project folder run: defenseclaw sandbox run claude")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                Table(snapshot.sandboxes, selection: $selection) {
                    TableColumn("Name", value: \.name)
                    TableColumn("Phase") { row in StatePill(raw: row.phase.isEmpty ? "unknown" : row.phase) }
                    TableColumn("Harness", value: \.harnessLabel)
                    TableColumn("Pack/Profile", value: \.policyLabel)
                    TableColumn("Mode") { row in Text(row.workdirMode.isEmpty ? "—" : row.workdirMode) }
                    TableColumn("Up", value: \.uptimeText)
                    TableColumn("Sites") { row in Text("\(row.destinations) (\(row.blocked) blocked)") }
                    TableColumn("Alerts") { row in
                        if row.alerts.isEmpty {
                            Text("—").foregroundStyle(.secondary)
                        } else {
                            Label("\(row.alerts.count)", systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(Cisco.orange)
                                .help(row.alerts.joined(separator: "\n"))
                        }
                    }
                }
                .frame(minHeight: 140, idealHeight: 200)
            }
        }
    }

    private func detail(_ row: SandboxRow) -> some View {
        DCCard(row.name, systemImage: "info.circle") {
            KeyValueGrid(pairs: [
                ("Harness", row.harnessLabel),
                ("Project", row.project.isEmpty ? "—" : "\(row.project) → \(row.workdir) (\(row.workdirMode))"),
                ("Skip-permissions", row.yolo ? "on" : "off"),
                ("Tool calls", "\(row.toolCalls) (\(row.toolBlocked) blocked)"),
                ("Hook events", row.hookEventsLabel),
                ("Last tool block", row.lastBlocked.isEmpty ? "—" : row.lastBlocked),
                ("Undo", row.undoLabel),
            ] + (row.runImage.isEmpty ? [] : [("Run image", row.runImage)]))
            ForEach(row.alerts, id: \.self) { alert in
                Label(alert, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(Cisco.orange)
            }
            HStack {
                Button("Stop…") { confirmStop = row }
                    .disabled(!row.running)
                if row.copyMode {
                    // A copy's work comes back through pull, which shows it
                    // first; applying it merges into the working tree, so it
                    // runs in a terminal. A branch leaves the tree alone.
                    Button("Copy pull command") { copy(row.pullCommand) }
                        .help("Paste it in a terminal: it shows the changes, then --apply, --branch or --patch-out FILE brings them back.")
                    Button("Pull to branch") {
                        runCLI("Pull \(row.name) to branch dc/\(row.name)", row.pullToBranchArguments)
                    }
                    .help("Puts \(row.name)'s work on branch dc/\(row.name); your working tree stays as it is.")
                } else {
                    Button("Review changes") {
                        runCLI("Review \(row.name)", ["sandbox", "review", row.name], mutation: false)
                    }
                }
                Button("Undo…") { confirmUndo = row }
                    .disabled(!row.undoOffered)
                    .help(row.copyMode ? "Reverts the last pull --apply of \(row.name)" : "")
                Button("Copy connect command") { copy("defenseclaw sandbox connect \(row.name)") }
            }
            .controlSize(.small)
            .disabled(!appState.sandboxActionsAvailable)
        }
    }

    private var asksCard: some View {
        DCCard("Asks", systemImage: "questionmark.circle") {
            if snapshot.asks.isEmpty {
                Text(SandboxSnapshot.noAsksText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(snapshot.asks) { ask in
                    SandboxAskRow(ask: ask) { confirmAlways = ask }
                }
            }
        }
    }

    private var activityCard: some View {
        DCCard("Activity", systemImage: "waveform") {
            let events = Array(snapshot.activity.reversed().prefix(60))
            if events.isEmpty {
                Text("No activity yet. Destinations, blocks, tool blocks and findings appear here as they happen.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(events) { event in
                    HStack(spacing: 8) {
                        Text(event.time.map { $0.formatted(date: .omitted, time: .standard) } ?? "--:--:--")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                        Text(event.glyph)
                            .foregroundStyle(event.glyph == "✓" ? Cisco.green : (event.glyph == "✗" ? Cisco.red : Cisco.orange))
                        Text(event.sandbox).font(.caption).foregroundStyle(.secondary)
                        Text(event.summary).font(.caption).lineLimit(2).textSelection(.enabled)
                        Spacer()
                        if event.isBlockedDestination, event.unblockable {
                            SandboxUnblockMenu(event: event) { confirmAlwaysUnblock = event }
                        } else if event.unblocked {
                            Text("unblocked").font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func runCLI(_ title: String, _ arguments: [String], mutation: Bool = true) {
        Task {
            _ = await appState.runCommand(
                title: title, arguments: arguments, mutation: mutation, category: "sandbox", origin: "Sandboxes"
            )
            await appState.refreshSandboxes()
        }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        appState.sandboxActionMessage = "Copied: \(text)"
        appState.sandboxActionFailed = false
    }
}

/// Unblock for this sandbox, or (after a confirmation) for every sandbox.
struct SandboxUnblockMenu: View {
    @Environment(AppState.self) private var appState
    let event: SandboxActivity
    var always: () -> Void

    var body: some View {
        let key = "unblock|\(event.sandbox)|\(event.host)"
        Menu("Unblock") {
            if !event.sandbox.isEmpty {
                Button("Only in \(event.sandbox)") {
                    Task { await appState.unblockSandboxDestination(host: event.host, sandbox: event.sandbox, always: false) }
                }
            }
            Button("In every sandbox (always)…", action: always)
        }
        .controlSize(.small)
        .fixedSize()
        .disabled(appState.sandboxActionInFlight(key) || !appState.sandboxActionsAvailable)
    }
}

/// One rare ask with its decision buttons.
struct SandboxAskRow: View {
    @Environment(AppState.self) private var appState
    let ask: SandboxAsk
    var always: () -> Void
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: ask.risky ? "exclamationmark.shield.fill" : "questionmark.circle")
                    .foregroundStyle(ask.risky ? Cisco.orange : Cisco.blue)
                // Every endpoint Approve opens, not only the first: one ask
                // can cover several ports of one host.
                Text("\(ask.sandbox) wants \(ask.kindLabel): \(ask.opens)")
                    .font(.caption.weight(.medium))
                    .lineLimit(compact ? 2 : 3)
                    .help(ask.opens)
            }
            if !compact, !(ask.reason.isEmpty && ask.binary.isEmpty) {
                Text([ask.binary, ask.reason].filter { !$0.isEmpty }.joined(separator: " · "))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Button(ask.endpoints.count > 1 ? "Approve all \(ask.endpoints.count)" : "Approve") {
                    Task { await appState.decideSandboxAsk(ask, approve: true) }
                }
                .help("Opens \(ask.opens) for \(ask.sandbox)")
                if !compact { Button("Always…", action: always) }
                Button("Reject") { Task { await appState.decideSandboxAsk(ask, approve: false) } }
            }
            .controlSize(.small)
            .disabled(appState.sandboxActionInFlight("ask|\(ask.id)") || !appState.sandboxActionsAvailable)
        }
    }
}

/// The menu-bar popover's Sandboxes section: active sandboxes, blocked
/// destinations with Unblock, and the rare asks. Hidden until sandboxes are on.
struct SandboxMenuSection: View {
    @Environment(AppState.self) private var appState
    var openPanel: () -> Void

    var body: some View {
        let snapshot = appState.sandbox
        if snapshot.status.loaded, snapshot.status.enabled {
            VStack(alignment: .leading, spacing: 6) {
                Button(action: openPanel) {
                    HStack(spacing: 6) {
                        Image(systemName: "cube.transparent").foregroundStyle(Cisco.blue)
                        Text("Sandboxes").font(.caption.weight(.semibold))
                        Text(snapshot.state == "ready"
                             ? "\(snapshot.active.count) active"
                             : "unavailable")
                            .font(.caption2)
                            .foregroundStyle(snapshot.state == "ready" ? Color.secondary : Cisco.orange)
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                .buttonStyle(.plain)
                if !snapshot.staleNote.isEmpty {
                    Text(snapshot.staleNote)
                        .font(.caption2)
                        .foregroundStyle(Cisco.orange)
                        .lineLimit(2)
                }
                ForEach(snapshot.active.prefix(3)) { row in
                    HStack(spacing: 6) {
                        Circle().fill(row.alerts.isEmpty ? Cisco.green : Cisco.orange).frame(width: 6, height: 6)
                        Text(row.name).font(.caption).lineLimit(1)
                        Spacer()
                        Text("\(row.harnessLabel) · \(row.uptimeText)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                ForEach(Array(snapshot.recentBlocks.filter(\.unblockable).prefix(2))) { event in
                    HStack(spacing: 6) {
                        Text("✗").foregroundStyle(Cisco.red)
                        Text(event.summary).font(.caption2).lineLimit(1)
                        Spacer()
                        Button("Unblock") {
                            Task {
                                await appState.unblockSandboxDestination(host: event.host, sandbox: event.sandbox, always: false)
                            }
                        }
                        .controlSize(.mini)
                        .help("Unblock \(event.host) for \(event.sandbox) (use the Sandboxes panel to unblock everywhere)")
                        .disabled(!appState.sandboxActionsAvailable)
                    }
                }
                ForEach(snapshot.asks.prefix(2)) { ask in
                    SandboxAskRow(ask: ask, always: openPanel, compact: true)
                }
                if let message = appState.sandboxActionMessage {
                    Text(message)
                        .font(.caption2)
                        .foregroundStyle(appState.sandboxActionFailed ? Cisco.orange : .secondary)
                        .lineLimit(2)
                }
            }
        }
    }
}

/// Overview's Sandboxes card. Empty until sandboxes were set up.
struct SandboxOverviewCard: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        let snapshot = appState.sandbox
        if snapshot.status.loaded, snapshot.status.enabled {
            DCCard("Sandboxes", systemImage: "cube.transparent") {
                Text(snapshot.headline)
                    .font(.caption)
                    .foregroundStyle(snapshot.state == "ready" ? Color.secondary : Cisco.orange)
                if !snapshot.staleNote.isEmpty {
                    Text(snapshot.staleNote)
                        .font(.caption2)
                        .foregroundStyle(Cisco.orange)
                }
                HStack(spacing: 18) {
                    metric("Active", "\(snapshot.active.count)")
                    metric("Blocked sites", "\(snapshot.sandboxes.reduce(0) { $0 + $1.blocked })")
                    metric("Asks", "\(snapshot.asks.count)", tint: snapshot.asks.isEmpty ? .primary : Cisco.orange)
                    metric("Alerts", "\(snapshot.sandboxes.reduce(0) { $0 + $1.alerts.count })",
                           tint: snapshot.sandboxes.contains { !$0.alerts.isEmpty } ? Cisco.orange : .primary)
                }
                Button("Open Sandboxes") { appState.openSandboxes() }
                    .controlSize(.small)
            }
        }
    }

    private func metric(_ title: String, _ value: String, tint: Color = .primary) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).font(.title3.weight(.semibold).monospacedDigit()).foregroundStyle(tint)
            Text(title).font(.caption2).foregroundStyle(.secondary)
        }
    }
}
