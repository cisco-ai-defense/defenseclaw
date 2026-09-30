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
/// sandboxapi.HooksUnreachableWarning.
let sandboxHooksUnreachableWarning = "DefenseClaw hooks are not reaching the daemon; every tool call is being blocked"

/// The OpenShell compute driver a gateway runs, as far as the app needs it:
/// a port of the table in internal/openshell/driver.go (the TUI's
/// COMPUTE_DRIVERS). A driver without host mounts runs every sandbox on a
/// copy, and pull brings the work back.
struct SandboxDriver: Sendable, Hashable {
    var name: String
    var label: String
    var hostMounts: Bool

    static let docker = SandboxDriver(name: "docker", label: "docker", hostMounts: true)
    static let vm = SandboxDriver(name: "vm", label: "MicroVM", hostMounts: false)

    /// openshell.LookupDriver: "" is docker (a daemon older than
    /// gateway.driver drove docker only); a driver the table does not know
    /// mounts nothing, as in Go.
    static func lookup(_ name: String) -> SandboxDriver {
        switch name.trimmingCharacters(in: .whitespaces) {
        case "", "docker": return .docker
        case "vm": return .vm
        case let other: return SandboxDriver(name: other, label: other, hostMounts: false)
        }
    }
}

struct SandboxStatus: Sendable, Hashable {
    var loaded = false
    var enabled = false
    var available = false
    var reason = ""
    var gateway = ""
    /// gateway.driver: "docker" or "vm"; empty from a daemon older than the
    /// field, or before a gateway answered.
    var driver = ""
    var pack = ""
    var profile = ""
    var adminConfigured = false
    var adminAuthority = ""
    var adminDetail = ""
    var sandboxes = 0
    var running = 0
    var pendingApprovals = 0

    /// Why every new run works on a copy (the gateway's driver mounts no
    /// host folders), or "".
    var copyOnlyNote: String {
        let current = SandboxDriver.lookup(driver)
        guard !driver.isEmpty, !current.hostMounts else { return "" }
        return "\(current.label) sandboxes work on a copy; pull brings the changes back."
    }
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
    /// The hook verdicts per hook event, as the harness names it, the most
    /// frequent first ("PreToolUse 12"); otherHookEvents counts those past
    /// the daemon's cap.
    var hookEvents: [String] = []
    var otherHookEvents = 0
    var lastBlocked = ""
    var tampered = 0
    var hooksSilent = false
    /// The session's hooks do not reach DefenseClaw (they fail closed, so
    /// the harness can do nothing); ingressRefused counts refused requests.
    var hooksUnreachable = false
    var unreachableReason = ""
    var ingressRefused = 0
    /// Hook posts DefenseClaw answered with an error (a refused route, the
    /// rate limit): each failed closed, so the harness did not do it.
    var hookFailed = 0
    var lastHookFailure = ""
    var orphaned = false
    var undoAvailable = false
    /// The user kept the last session's changes (the daemon's accept): the
    /// next start takes a new undo point, whoever starts the sandbox.
    var undoAccepted = false
    var nestedRepos: [String] = []
    /// The image the sandbox runs when it is not the harness image: on the
    /// MicroVM (vm) driver, the image its per-run harness files are baked into.
    var runImage = ""

    var id: String { name }
    var running: Bool { ["ready", "running"].contains(phase.lowercased()) }
    /// The sandbox works on a copy: pull brings its work back, and undo
    /// reverts its last `pull --apply` (it needs no snapshot).
    var copyMode: Bool { workdirMode == "copy" }
    var undoOffered: Bool { copyMode || undoAvailable }
    var undoLabel: String {
        if copyMode { return "reverts the last pull --apply" }
        if !undoAvailable { return "no snapshot" }
        return undoAccepted ? "available; the last session's changes were kept, so the next start takes a new undo point" : "available"
    }
    /// Pull shows the work first; --apply, --branch or --patch-out FILE brings it back.
    var pullCommand: String { "defenseclaw sandbox pull \(name)" }
    /// The work on branch dc/<name>; the working tree stays as it is.
    var pullToBranchArguments: [String] { ["sandbox", "pull", name, "--branch"] }
    var harnessLabel: String { harnessName.isEmpty ? (harness.isEmpty ? "—" : harness) : harnessName }

    var policyLabel: String {
        let packText = pack.isEmpty ? "—" : pack
        return (!profile.isEmpty && profile != pack) ? "\(packText)/\(profile)" : packText
    }

    var uptimeText: String { running ? SandboxFormat.duration(uptimeSeconds) : "—" }

    /// "PreToolUse 12 · PostToolUse 11 · Stop 2", as `sandbox status` shows
    /// it (the TUI's SandboxRow.hook_events_text).
    var hookEventsText: String {
        (hookEvents + (otherHookEvents > 0 ? ["other events \(otherHookEvents)"] : [])).joined(separator: " · ")
    }
    var hookEventsLabel: String { hookEventsText.isEmpty ? "—" : hookEventsText }

    /// The failed hook calls, as the daemon's hook.failed event words them
    /// (the TUI's SandboxRow.hook_failure_alert).
    var hookFailureAlert: String {
        guard hookFailed > 0 else { return "" }
        let line = hookFailed == 1
            ? "1 hook call failed, so the harness's action was blocked (hooks fail closed)"
            : "\(hookFailed) hook calls failed, so the harness's actions were blocked (hooks fail closed)"
        guard !lastHookFailure.isEmpty else { return line }
        return line + "; DefenseClaw \(hookFailed == 1 ? "answered" : "last answered") \(lastHookFailure)"
    }

    /// Plain alert lines: hook tamper, planted repositories, failing or silent hooks.
    var alerts: [String] {
        var out: [String] = []
        if tampered > 0 {
            out.append("hook tamper: \(tampered) tool call(s) ran without a DefenseClaw verdict")
        }
        out.append(contentsOf: nestedRepos)
        if hooksUnreachable {
            let why = unreachableReason.isEmpty ? "" : " (\(unreachableReason))"
            out.append("\(sandboxHooksUnreachableWarning)\(why). Run: defenseclaw sandbox doctor")
        } else if ingressRefused > 0 {
            out.append("OpenShell refused \(ingressRefused) hook request(s) to DefenseClaw")
        }
        if hookFailed > 0 {
            out.append(hookFailureAlert)
        }
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
    /// Every host:port approving opens: one ask can cover several ports of
    /// one host (triage.withPorts), while host and port name only the first.
    var endpoints: [String] = []
    var risky = false
    var reason = ""
    var rationale = ""
    var status = ""
    var createdAt: Date?

    var destination: String { host.isEmpty ? "—" : SandboxFormat.hostPort(host, port) }
    /// What Approve opens: every endpoint when there are several.
    var opens: String { endpoints.count > 1 ? endpoints.joined(separator: ", ") : destination }
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
    /// An egress.unblocked event lifted this block since it happened.
    var unblocked = false

    var id: String { "\(seq)|\(kind)|\(host)" }
    var isBlockedDestination: Bool { kind == "egress.blocked" && !host.isEmpty }

    /// The same feed event (unblock marks aside): a daemon that restarted
    /// numbers its events from one again, so a sequence number alone is not.
    func isSameEvent(as other: SandboxActivity) -> Bool {
        seq == other.seq && time == other.time && kind == other.kind && sandbox == other.sandbox
            && host == other.host && port == other.port
    }

    var glyph: String {
        switch kind {
        case "egress.allowed": "✓"
        case "egress.blocked", "tool.blocked", "hook.failed": "✗"
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
            let why = category == "large_upload" ? Self.largeUploadBlockedText(reason) : (category.isEmpty ? reason : category)
            return SandboxFormat.hostPort(host, port) + (why.isEmpty ? "" : " (\(why))")
        case "approval.requested":
            // The daemon's message is a whole sentence ("the sandbox asks to
            // reach port 5432 on your machine"), as the Go CLI prints it.
            return text.isEmpty ? "asks to reach " + SandboxFormat.hostPort(host, port) : text
        case "tool.blocked":
            return (tool.isEmpty ? "tool call" : tool) + " blocked" + (reason.isEmpty ? "" : ": \(reason)")
        default:
            return text.isEmpty ? (reason.isEmpty ? kind : reason) : text
        }
    }

    /// sandboxapi.LargeUploadBlockedText: the words for a block of the
    /// large-upload block (egress.block_large_uploads), from the proxy's
    /// sentence, which names the threshold.
    static func largeUploadBlockedText(_ reason: String) -> String {
        var clause = reason.trimmingCharacters(in: .whitespaces)
        if clause.hasSuffix(".") { clause.removeLast() }
        guard let first = clause.first else { return "large upload blocked" }
        return "large upload blocked: " + first.lowercased() + clause.dropFirst()
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
    /// The Asks card with nothing waiting, as the TUI says it (NO_ASKS_TEXT):
    /// what asks depends on each sandbox's pack.
    static let noAsksText = "No asks are waiting. An ask appears when a program connects around DefenseClaw's proxy: "
        + "to a private-network address with any pack, to a host off the allowlist with balanced, "
        + "and to every new destination with strict. Ports on this machine never ask; run with --host-port PORT."

    var status = SandboxStatus()
    var sandboxes: [SandboxRow] = []
    var asks: [SandboxAsk] = []
    var activity: [SandboxActivity] = []
    var lastSeq = 0
    /// The event lastSeq names, which tells a daemon that started its feed
    /// over from one that stayed quiet (resumePointLost).
    var resumeEvent: SandboxActivity?
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

    /// Set when the rows on screen are the last good snapshot, not the
    /// daemon's current answer (the TUI's stale_note).
    var staleNote: String {
        guard status.loaded, !error.isEmpty else { return "" }
        let age = fetchedAt.map { " (last update \(SandboxFormat.duration(Int(Date().timeIntervalSince($0)))) ago)" } ?? ""
        return "Showing the last good snapshot\(age): \(error)"
    }

    /// The daemon cannot be asked (the gateway health check fails): keep
    /// the rows, but say they are not current.
    mutating func markUnreachable(_ message: String) {
        error = message.isEmpty ? "its health check fails" : message
    }

    /// Blocked destinations still in force, newest first: blocks an unblock
    /// lifted, and blocks of sandboxes that no longer exist, are history.
    var recentBlocks: [SandboxActivity] {
        activity.reversed().filter { $0.isBlockedDestination && !$0.unblocked && sandboxExists($0.sandbox) }
    }

    private func sandboxExists(_ name: String) -> Bool {
        // Before the first list read nothing is known to be gone.
        name.isEmpty || !status.loaded || sandboxes.contains { $0.name == name }
    }

    /// Mark earlier blocks of `host` as lifted: in `sandbox`, or with
    /// `always` in every sandbox. A later block arrives as a new event.
    mutating func markUnblocked(sandbox: String, host: String, always: Bool) {
        guard !host.isEmpty else { return }
        for index in activity.indices {
            let event = activity[index]
            guard event.isBlockedDestination, !event.unblocked, always || event.sandbox == sandbox,
                  SandboxFormat.hostMatches(host, event.host) else { continue }
            activity[index].unblocked = true
            activity[index].unblockable = false
        }
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

    /// Whether the daemon's feed started over, from a read of the events
    /// after lastSeq - 1. The feed keeps the event lastSeq names until newer
    /// events push it out, so a feed that still counts on answers with it
    /// (or newer ones). An empty answer, or another event under that number,
    /// is a new feed: the daemon restarted and numbers from one again. The
    /// daemon's uptime cannot tell: it stops while the Mac sleeps.
    func resumePointLost(_ events: [SandboxActivity]) -> Bool {
        guard lastSeq > 0 else { return false }
        let feed = events.filter { $0.kind != "dropped" }
        if feed.isEmpty { return true }
        // Only newer events: they pushed the resume point out of the feed.
        guard let same = feed.first(where: { $0.seq == lastSeq }) else { return false }
        guard let resumeEvent else { return false }
        return !same.isSameEvent(as: resumeEvent)
    }

    /// Read the daemon's feed from its start again (after resumePointLost):
    /// the old events' numbers mean nothing to the new feed.
    mutating func restartFeed() {
        lastSeq = 0
        resumeEvent = nil
        activity = []
    }

    /// Append new events (by sequence number) and return what to notify.
    mutating func merge(events: [SandboxActivity], notify: Bool, now: Date = Date()) -> [SandboxNotification] {
        var out: [SandboxNotification] = []
        for event in events {
            if event.kind != "dropped" {
                // A "dropped" marker shares its sequence with the next event.
                if event.seq > 0 && event.seq <= lastSeq { continue }
                lastSeq = max(lastSeq, event.seq)
                if event.seq > 0, event.seq == lastSeq { resumeEvent = event }
            }
            if event.kind == "egress.unblocked", !event.host.isEmpty {
                // Reason is the scope: "always" lifts the host everywhere.
                markUnblocked(sandbox: event.sandbox, host: event.host, always: event.reason == "always")
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
                // An unblockable block holds the host on every port: the
                // port of the first request would say it stops there.
                title: "Blocked \(event.host)",
                body: (event.sandbox.isEmpty ? "A sandbox" : event.sandbox)
                    + " tried to reach it" + (why.isEmpty ? "." : " (\(why)).") + " Unblock it if the agent needs it.",
                sandbox: event.sandbox,
                host: event.host
            )
        case "approval.requested":
            let key = event.approvalID.isEmpty ? "seq-\(event.seq)" : event.approvalID
            guard !notifiedAsks.contains(key) else { return nil }
            notifiedAsks.insert(key)
            let message = event.message.trimmingCharacters(in: .whitespaces)
            let what = message.isEmpty
                ? "It wants to reach \(SandboxFormat.hostPort(event.host, event.port))."
                : message.prefix(1).uppercased() + message.dropFirst() + (message.hasSuffix(".") ? "" : ".")
            return SandboxNotification(
                kind: .ask,
                id: "sandbox-ask-\(key)",
                title: "\(event.sandbox.isEmpty ? "A sandbox" : event.sandbox) asks for access",
                body: "\(what) Review it in DefenseClaw.",
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
        case "finding" where event.reason == "hooks_unreachable":
            return SandboxNotification(
                kind: .finding,
                id: "sandbox-finding-\(event.seq)",
                title: "\(event.sandbox.isEmpty ? "A sandbox" : event.sandbox): hooks are not reaching DefenseClaw",
                body: event.summary,
                sandbox: event.sandbox
            )
        default:
            return nil
        }
    }
}

enum SandboxFormat {
    /// sandboxapi.HostPort: the host, with its port unless that is 443
    /// (HTTPS) or unknown. Plain HTTP reads host:80, so an HTTPS and an HTTP
    /// refusal of one host are told apart. An IPv6 literal with its port is
    /// bracketed ("[fd00:ec2::254]:80"; "fd00:ec2::254:80" is another
    /// address).
    static func hostPort(_ host: String, _ port: Int) -> String {
        if port == 0 || port == 443 {
            return host
        }
        let shown = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        return "\(shown):\(port)"
    }

    /// triage.NormalizeHost: lower case, no brackets, no trailing dot.
    static func normalizeHost(_ host: String) -> String {
        var text = host.trimmingCharacters(in: .whitespaces).lowercased()
        if text.hasPrefix("["), text.hasSuffix("]") { text = String(text.dropFirst().dropLast()) }
        if text.hasSuffix(".") { text.removeLast() }
        return text
    }

    /// Whether an unblock pattern covers `host` (exact, or "*." for subdomains).
    static func hostMatches(_ pattern: String, _ host: String) -> Bool {
        let pattern = normalizeHost(pattern), host = normalizeHost(host)
        guard !pattern.isEmpty, !host.isEmpty else { return false }
        if pattern.hasPrefix("*.") { return host.hasSuffix(String(pattern.dropFirst())) }
        return pattern == host
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
        out.driver = str(gateway["driver"]).trimmingCharacters(in: .whitespaces)
        if !gateway.isEmpty {
            let version = str(gateway["version"])
            out.gateway = "OpenShell" + (version.isEmpty ? "" : " \(version)") + " gateway \(str(gateway["name"]))"
            var notes: [String] = out.driver.isEmpty ? [] : [SandboxDriver.lookup(out.driver).label]
            if (gateway["healthy"] as? Bool) == false { notes.append("unhealthy") }
            if !notes.isEmpty { out.gateway += " (\(notes.joined(separator: ", ")))" }
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
        row.hookEvents = dict(hooks["events"])
            .map { (name: $0.key, count: int($0.value)) }
            .filter { !$0.name.isEmpty && $0.count > 0 }
            .sorted { $0.count != $1.count ? $0.count > $1.count : $0.name < $1.name }
            .map { "\($0.name) \($0.count)" }
        row.otherHookEvents = int(hooks["other_events"])
        row.lastBlocked = str(hooks["last_blocked"])
        row.tampered = int(hooks["tampered"])
        row.hooksSilent = (hooks["silent"] as? Bool) ?? false
        row.hooksUnreachable = (hooks["unreachable"] as? Bool) ?? false
        row.unreachableReason = str(hooks["unreachable_reason"])
        row.ingressRefused = int(hooks["ingress_refused"])
        row.hookFailed = int(hooks["hook_failed"])
        row.lastHookFailure = str(hooks["last_hook_failure"])
        row.orphaned = (d["orphaned"] as? Bool) ?? false
        row.runImage = str(d["run_image"])
        // undone_at is omitted until undo ran (Go omitzero).
        row.undoAvailable = !snapshot.isEmpty && DCDates.parse(snapshot["undone_at"]) == nil
        // accepted_at is omitted until the user keeps a session's changes.
        row.undoAccepted = !snapshot.isEmpty && DCDates.parse(snapshot["accepted_at"]) != nil
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
                endpoints: list(d["endpoints"]).compactMap { item in
                    let endpoint = dict(item)
                    let host = str(endpoint["host"])
                    return host.isEmpty ? nil : SandboxFormat.hostPort(host, int(endpoint["port"]))
                },
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
        func isTrue(_ key: String) -> Bool {
            if let b = admin[key] as? Bool { return b }
            return (admin[key] as? String)?.lowercased() == "true"
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
        if isTrue("block_large_uploads") {
            lock(["openshell.egress.block_large_uploads"], "your organization blocks large uploads to first-seen hosts")
        }
        for entry in (admin["locked"] as? [String]) ?? [] {
            if let targets = lockedConfigKeys[entry] {
                lock(targets, "locked by your organization (openshell.admin.locked: \(entry))")
            }
        }
        return out
    }
}
