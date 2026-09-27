// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// OpenShell sandboxes as the daemon's /api/v1/sandbox API describes them
// (internal/openshell/sandboxapi). Pure models and decoding only, so the
// menu bar, Overview and the Sandboxes panel render from one snapshot and the
// logic is testable without SwiftUI. Mirrors the TUI's sandbox_state.py.

import Foundation

/// The sentence every openshell.admin refusal starts with (sandboxapi.AdminMessage).
let sandboxAdminMessage = "blocked by your organization's DefenseClaw policy"

struct SandboxStatus: Sendable, Hashable {
    var loaded = false
    var enabled = false
    var available = false
    var reason = ""
    var gateway = ""
    var pack = ""
    var profile = ""
    var adminConfigured = false
    var adminAuthority = ""
    var adminDetail = ""
    var sandboxes = 0
    var running = 0
    var pendingApprovals = 0
}

struct SandboxRow: Identifiable, Sendable, Hashable {
    var name = ""
    var harness = ""
    var harnessName = ""
    var phase = ""
    var pack = ""
    var profile = ""
    var workdirMode = ""
    var project = ""
    var workdir = ""
    var yolo = false
    var uptimeSeconds = 0
    var destinations = 0
    var blocked = 0
    var pendingApprovals = 0
    var toolCalls = 0
    var toolBlocked = 0
    var lastBlocked = ""
    var tampered = 0
    var hooksSilent = false
    var orphaned = false
    var undoAvailable = false
    var nestedRepos: [String] = []

    var id: String { name }
    var running: Bool { ["ready", "running"].contains(phase.lowercased()) }
    var harnessLabel: String { harnessName.isEmpty ? (harness.isEmpty ? "—" : harness) : harnessName }

    var policyLabel: String {
        let packText = pack.isEmpty ? "—" : pack
        return (!profile.isEmpty && profile != pack) ? "\(packText)/\(profile)" : packText
    }

    var uptimeText: String { running ? SandboxFormat.duration(uptimeSeconds) : "—" }

    /// Plain alert lines: hook tamper, planted repositories, silent hooks.
    var alerts: [String] {
        var out: [String] = []
        if tampered > 0 {
            out.append("hook tamper: \(tampered) tool call(s) ran without a DefenseClaw verdict")
        }
        out.append(contentsOf: nestedRepos)
        if hooksSilent {
            out.append("hooks are silent: the harness is active but no DefenseClaw hook has been heard")
        }
        if orphaned {
            out.append("no DefenseClaw binding: its hooks cannot authenticate; delete it and run again")
        }
        return out
    }
}

struct SandboxAsk: Identifiable, Sendable, Hashable {
    var id = ""
    var sandbox = ""
    var kind = ""
    var host = ""
    var port = 0
    var binary = ""
    var risky = false
    var reason = ""
    var rationale = ""
    var status = ""
    var createdAt: Date?

    var destination: String { host.isEmpty ? "—" : SandboxFormat.hostPort(host, port) }
    var kindLabel: String {
        switch kind {
        case "host_port": "a port on this machine"
        case "network_rule": "network"
        default: kind.isEmpty ? "—" : kind
        }
    }
}

struct SandboxActivity: Identifiable, Sendable, Hashable {
    var seq = 0
    var time: Date?
    var kind = ""
    var sandbox = ""
    var host = ""
    var port = 0
    var category = ""
    var reason = ""
    var message = ""
    var unblockable = false
    var approvalID = ""
    var tool = ""

    var id: String { "\(seq)|\(kind)|\(host)" }
    var isBlockedDestination: Bool { kind == "egress.blocked" && !host.isEmpty }

    var glyph: String {
        switch kind {
        case "egress.allowed": "✓"
        case "egress.blocked", "tool.blocked": "✗"
        case "egress.unblocked": "↺"
        case "egress.large_upload", "finding": "⚠"
        case "approval.requested": "?"
        case "dropped": "…"
        default: "·"
        }
    }

    /// The display line without the glyph the daemon's message may carry.
    var summary: String {
        var text = message.trimmingCharacters(in: .whitespaces)
        if let first = text.first, "✓✗⚠?↺".contains(first) {
            text = String(text.dropFirst()).trimmingCharacters(in: .whitespaces)
        }
        switch kind {
        case "egress.allowed":
            return host.isEmpty ? text : SandboxFormat.hostPort(host, port)
        case "egress.blocked":
            guard !host.isEmpty else { return text.isEmpty ? "a destination was blocked" : text }
            let why = category.isEmpty ? reason : category
            return SandboxFormat.hostPort(host, port) + (why.isEmpty ? "" : " (\(why))")
        case "approval.requested":
            return "asks to reach " + (text.isEmpty ? SandboxFormat.hostPort(host, port) : text)
        case "tool.blocked":
            return (tool.isEmpty ? "tool call" : tool) + " blocked" + (reason.isEmpty ? "" : ": \(reason)")
        default:
            return text.isEmpty ? (reason.isEmpty ? kind : reason) : text
        }
    }
}

/// One notification the app should post for new activity.
struct SandboxNotification: Sendable, Hashable {
    enum Kind: String, Sendable { case blocked, ask, finding }
    var kind: Kind
    var id: String
    var title: String
    var body: String
    var sandbox: String
    var host = ""
    var approvalID = ""
}

/// The Sandboxes snapshot the menu bar, Overview and panel share.
struct SandboxSnapshot: Sendable {
    static let feedLimit = 200
    static let notifyWindow: TimeInterval = 60

    var status = SandboxStatus()
    var sandboxes: [SandboxRow] = []
    var asks: [SandboxAsk] = []
    var activity: [SandboxActivity] = []
    var lastSeq = 0
    var fetchedAt: Date?
    var error = ""
    /// (sandbox|host) → when it was last notified, so a flapping destination
    /// raises one notification a minute, not one per connection.
    var notifiedBlocks: [String: Date] = [:]
    var notifiedAsks: Set<String> = []

    var state: String {
        if !status.loaded { return error.isEmpty ? "waiting" : "unreachable" }
        if !status.enabled { return "off" }
        if !status.available { return "unavailable" }
        return "ready"
    }

    var active: [SandboxRow] { sandboxes.filter(\.running) }

    /// Unblockable blocked destinations, newest first.
    var recentBlocks: [SandboxActivity] {
        activity.reversed().filter { $0.isBlockedDestination }
    }

    var headline: String {
        switch state {
        case "waiting": return "Loading sandboxes…"
        case "unreachable": return "The DefenseClaw daemon is not answering: \(error)"
        case "off": return "Sandboxes are off. Run Setup → Sandbox, or: defenseclaw sandbox setup"
        case "unavailable":
            let why = status.reason.isEmpty ? "the daemon is not connected to OpenShell" : status.reason
            return "Sandboxes are unavailable: \(why). Check: defenseclaw sandbox doctor"
        default:
            var parts = ["\(status.running) running", "\(status.sandboxes) total"]
            if !asks.isEmpty { parts.append("\(asks.count) ask(s) waiting") }
            if !status.gateway.isEmpty { parts.append(status.gateway) }
            return parts.joined(separator: " · ")
        }
    }

    /// Replace the REST part of the snapshot after a successful refresh.
    mutating func apply(status newStatus: SandboxStatus, sandboxes rows: [SandboxRow]?, asks newAsks: [SandboxAsk]?, at now: Date = Date()) {
        status = newStatus
        if let rows {
            sandboxes = rows.sorted { lhs, rhs in
                if lhs.running != rhs.running { return lhs.running }
                return lhs.name < rhs.name
            }
        }
        if let newAsks {
            asks = newAsks.filter { $0.status.isEmpty || $0.status == "pending" }
        }
        error = ""
        fetchedAt = now
    }

    /// Append new events (by sequence number) and return what to notify.
    mutating func merge(events: [SandboxActivity], notify: Bool, now: Date = Date()) -> [SandboxNotification] {
        var out: [SandboxNotification] = []
        for event in events {
            if event.kind != "dropped" {
                // A "dropped" marker shares its sequence with the next event.
                if event.seq > 0 && event.seq <= lastSeq { continue }
                lastSeq = max(lastSeq, event.seq)
            }
            activity.append(event)
            if event.kind == "approval.resolved", !event.approvalID.isEmpty {
                asks.removeAll { $0.id == event.approvalID }
            }
            guard notify, let note = notification(for: event, now: now) else { continue }
            out.append(note)
        }
        if activity.count > Self.feedLimit {
            activity.removeFirst(activity.count - Self.feedLimit)
        }
        return out
    }

    private mutating func notification(for event: SandboxActivity, now: Date) -> SandboxNotification? {
        switch event.kind {
        case "egress.blocked" where event.unblockable && !event.host.isEmpty:
            let key = "\(event.sandbox)|\(event.host)"
            if let last = notifiedBlocks[key], now.timeIntervalSince(last) < Self.notifyWindow { return nil }
            notifiedBlocks[key] = now
            let why = event.category.isEmpty ? event.reason : event.category
            return SandboxNotification(
                kind: .blocked,
                id: "sandbox-block-\(event.seq)",
                title: "Blocked \(SandboxFormat.hostPort(event.host, event.port))",
                body: (event.sandbox.isEmpty ? "A sandbox" : event.sandbox)
                    + " tried to reach it" + (why.isEmpty ? "." : " (\(why)).") + " Unblock it if the agent needs it.",
                sandbox: event.sandbox,
                host: event.host
            )
        case "approval.requested":
            let key = event.approvalID.isEmpty ? "seq-\(event.seq)" : event.approvalID
            guard !notifiedAsks.contains(key) else { return nil }
            notifiedAsks.insert(key)
            let target = event.message.isEmpty ? SandboxFormat.hostPort(event.host, event.port) : event.message
            return SandboxNotification(
                kind: .ask,
                id: "sandbox-ask-\(key)",
                title: "\(event.sandbox.isEmpty ? "A sandbox" : event.sandbox) asks for access",
                body: "It wants to reach \(target). Review it in DefenseClaw.",
                sandbox: event.sandbox,
                approvalID: event.approvalID
            )
        case "finding" where event.reason == "nested_repo":
            return SandboxNotification(
                kind: .finding,
                id: "sandbox-finding-\(event.seq)",
                title: "\(event.sandbox.isEmpty ? "A sandbox" : event.sandbox): planted git repository",
                body: event.summary,
                sandbox: event.sandbox
            )
        default:
            return nil
        }
    }
}

enum SandboxFormat {
    static func hostPort(_ host: String, _ port: Int) -> String {
        (port == 0 || port == 80 || port == 443) ? host : "\(host):\(port)"
    }

    /// 59s, 12m, 3h05m, 2d04h.
    static func duration(_ seconds: Int) -> String {
        let s = max(0, seconds)
        if s < 60 { return "\(s)s" }
        let minutes = s / 60
        if minutes < 60 { return "\(minutes)m" }
        let hours = minutes / 60
        if hours < 24 { return String(format: "%dh%02dm", hours, minutes % 60) }
        return String(format: "%dd%02dh", hours / 24, hours % 24)
    }
}

/// Tolerant decoding: an older daemon that omits a field yields the zero value.
enum SandboxDecoding {
    private static func int(_ raw: Any?) -> Int {
        if let n = raw as? Int { return n }
        if let n = raw as? Double, n.isFinite { return Int(n) }
        return 0
    }

    private static func str(_ raw: Any?) -> String { (raw as? String) ?? "" }
    private static func dict(_ raw: Any?) -> [String: Any] { (raw as? [String: Any]) ?? [:] }
    private static func list(_ raw: Any?) -> [Any] { (raw as? [Any]) ?? [] }

    static func status(from json: Any?) -> SandboxStatus {
        let d = dict(json)
        var out = SandboxStatus()
        out.loaded = true
        out.enabled = (d["enabled"] as? Bool) ?? false
        out.available = (d["available"] as? Bool) ?? false
        out.reason = str(d["reason"])
        let gateway = dict(d["gateway"])
        if !gateway.isEmpty {
            let version = str(gateway["version"])
            out.gateway = "OpenShell" + (version.isEmpty ? "" : " \(version)") + " gateway \(str(gateway["name"]))"
            if (gateway["healthy"] as? Bool) == false { out.gateway += " (unhealthy)" }
        }
        out.pack = str(d["pack"])
        out.profile = str(d["profile"])
        let admin = dict(d["admin"])
        out.adminConfigured = (admin["configured"] as? Bool) ?? false
        out.adminAuthority = str(admin["authority"])
        out.adminDetail = str(admin["detail"])
        out.sandboxes = int(d["sandboxes"])
        out.running = int(d["running"])
        out.pendingApprovals = int(d["pending_approvals"])
        return out
    }

    static func sandboxes(from json: Any?) -> [SandboxRow] {
        list(dict(json)["sandboxes"]).compactMap(sandbox)
    }

    static func sandbox(_ raw: Any) -> SandboxRow? {
        let d = dict(raw)
        let name = str(d["name"])
        guard !name.isEmpty else { return nil }
        let hooks = dict(d["hooks"])
        let egress = dict(d["egress"])
        let snapshot = dict(d["snapshot"])
        var row = SandboxRow()
        row.name = name
        row.harness = str(d["harness"])
        row.harnessName = str(d["harness_name"])
        row.phase = str(d["phase"]).lowercased()
        row.pack = str(d["pack"])
        row.profile = str(d["profile"])
        row.workdirMode = str(d["workdir_mode"])
        row.project = str(d["project"])
        row.workdir = str(d["workdir"])
        row.yolo = (d["yolo"] as? Bool) ?? false
        row.uptimeSeconds = int(d["uptime_seconds"])
        row.destinations = int(egress["destinations"])
        row.blocked = int(egress["blocked"])
        row.pendingApprovals = int(d["pending_approvals"])
        row.toolCalls = int(hooks["tool_calls"])
        row.toolBlocked = int(hooks["tool_blocked"])
        row.lastBlocked = str(hooks["last_blocked"])
        row.tampered = int(hooks["tampered"])
        row.hooksSilent = (hooks["silent"] as? Bool) ?? false
        row.orphaned = (d["orphaned"] as? Bool) ?? false
        // undone_at is omitted until undo ran (Go omitzero).
        row.undoAvailable = !snapshot.isEmpty && DCDates.parse(snapshot["undone_at"]) == nil
        row.nestedRepos = list(d["nested_repos"]).compactMap { item in
            let repo = dict(item)
            let path = str(repo["path"])
            guard !path.isEmpty else { return nil }
            if str(repo["kind"]) == "gitlink" { return "gitlink added to the index: \(path)" }
            let error = str(repo["error"])
            if !error.isEmpty { return "new git repository at \(path) (not quarantined: \(error))" }
            return "new git repository at \(path) quarantined as \(str(repo["quarantined"]))"
        }
        return row
    }

    static func approvals(from json: Any?) -> [SandboxAsk] {
        list(dict(json)["approvals"]).compactMap { raw in
            let d = dict(raw)
            let id = str(d["id"])
            guard !id.isEmpty else { return nil }
            return SandboxAsk(
                id: id,
                sandbox: str(d["sandbox"]),
                kind: str(d["kind"]),
                host: str(d["host"]),
                port: int(d["port"]),
                binary: str(d["binary"]),
                risky: (d["risky"] as? Bool) ?? false,
                reason: str(d["reason"]),
                rationale: str(d["rationale"]),
                status: str(d["status"]),
                createdAt: DCDates.parse(d["created_at"])
            )
        }
    }

    static func activity(from json: Any?) -> [SandboxActivity] {
        list(dict(json)["events"]).compactMap(event)
    }

    static func event(_ raw: Any) -> SandboxActivity? {
        let d = dict(raw)
        let kind = str(d["kind"])
        guard !kind.isEmpty else { return nil }
        var message = str(d["message"])
        if kind == "sandbox.lifecycle", message.isEmpty, !str(d["phase"]).isEmpty {
            message = "now \(str(d["phase"]).lowercased())"
        }
        return SandboxActivity(
            seq: int(d["seq"]),
            time: DCDates.parse(d["time"]),
            kind: kind,
            sandbox: str(d["sandbox"]),
            host: str(d["host"]),
            port: int(d["port"]),
            category: str(d["category"]),
            reason: str(d["reason"]),
            message: message,
            unblockable: (d["unblockable"] as? Bool) ?? false,
            approvalID: str(d["approval_id"]),
            tool: str(d["tool"])
        )
    }

    /// A plain line for a failed sandbox call: the daemon's own sentence for
    /// API refusals (GatewayErrorBody.sandboxMessage), never a raw body.
    static func message(for error: Error) -> String {
        if let gateway = error as? GatewayError {
            return gateway.errorDescription ?? "The DefenseClaw daemon refused the request."
        }
        return error.localizedDescription
    }
}

/// openshell.* config keys an administrator constrains, with the reason
/// (mirrors openshell_admin_locks in tui/panels/setup.py).
enum SandboxAdminLocks {
    static let lockedConfigKeys: [String: [String]] = [
        "pack": ["openshell.pack", "openshell.pack_dir"],
        "profile": ["openshell.profile"],
        "yolo": ["openshell.yolo"],
        "workdir.mode": ["openshell.workdir.mode"],
        "workdir.unmask": ["openshell.workdir.unmask"],
        "mcp.import": ["openshell.mcp.import"],
        "mcp.host_ports": ["openshell.mcp.host_ports"],
        "resources": ["openshell.resources.cpu", "openshell.resources.memory"],
    ]

    /// `admin` is the openshell.admin mapping as scalars ("true"/"false") and
    /// lists; `managed` marks an administrator-owned config.yaml.
    static func locks(admin: [String: Any], managed: Bool, keys: [String]) -> [String: String] {
        if managed {
            return Dictionary(uniqueKeysWithValues: keys.map { ($0, "config.yaml is administrator-owned (managed_enterprise)") })
        }
        var out: [String: String] = [:]
        func lock(_ targets: [String], _ reason: String) {
            for key in targets where out[key] == nil { out[key] = reason }
        }
        func isFalse(_ key: String) -> Bool {
            if let b = admin[key] as? Bool { return !b }
            return (admin[key] as? String)?.lowercased() == "false"
        }
        if let required = admin["required_pack"] as? String, !required.isEmpty {
            lock(["openshell.pack", "openshell.pack_dir"], "your organization requires the \(required) pack")
        }
        if isFalse("allow_yolo") { lock(["openshell.yolo"], "skip-permissions mode is not allowed") }
        if isFalse("allow_mount") { lock(["openshell.workdir.mode"], "your organization requires copy mode") }
        if isFalse("allow_host_ports") { lock(["openshell.mcp.host_ports"], "opening host ports is not allowed") }
        if isFalse("allow_unblock") {
            lock(["openshell.egress.allow", "openshell.egress.unblocked", "openshell.egress.feed"],
                 "unblocking and allow entries are not allowed")
        }
        for entry in (admin["locked"] as? [String]) ?? [] {
            if let targets = lockedConfigKeys[entry] {
                lock(targets, "locked by your organization (openshell.admin.locked: \(entry))")
            }
        }
        return out
    }
}
