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
    var gatewayName = ""
    var gatewayWorkspace = ""
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
    /// What holds this machine's OpenShell gateway when sandboxes are off
    /// for this account because another account's process runs it
    /// (GAP-0307): setup would stop there.
    var gatewayElsewhere = ""

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
    var toolAsked = 0
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
    /// The harness image, tagged as `sandbox image list` shows it. Not the
    /// run image a MicroVM boots (defenseclaw.invalid/sandbox-run:...), a
    /// name no other view shows (GAP-0188).
    var image = ""
    var createdAt: Date?
    /// egress.model_providers / harness_vendor / shadow_ai: the AI
    /// destinations by kind (GAP-0319).
    var modelProviders = 0
    var harnessVendor = 0
    var shadowAI = 0
    /// The sandbox's processes are sampled while it runs (observe.process_tree).
    var processTree = false
    /// The repository policy (.defenseclaw/sandbox.yaml) its posture
    /// includes, and the settings it made stricter (GAP-0244).
    var repoPolicy = false
    var repoTightened: [String] = []
    /// OpenShell refuses this conversation's requests: it holds a sandbox
    /// credential placeholder (hooks.placeholder_refused_at).
    var placeholderRefused = false
    /// The last hook failure was a hook post of such a conversation, not
    /// DefenseClaw's answer; hooksAnsweredAt is the first verdict after it
    /// (GAP-0377).
    var hookFailurePlaceholder = false
    var hooksAnsweredAt: Date?

    static let repoPolicyPath = ".defenseclaw/sandbox.yaml"

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
    /// The work on a branch the user names (`--branch-name BRANCH`), as the
    /// TUI's "Put it on a branch you name" pull action runs it.
    func pullToBranchArguments(named branch: String) -> [String] {
        ["sandbox", "pull", name, "--branch-name", branch.trimmingCharacters(in: .whitespacesAndNewlines)]
    }
    /// sandbox_state.branch_name_problem: why Pull cannot use a branch name,
    /// or nil; git judges the rest (GAP-0266).
    static func branchNameProblem(_ value: String) -> String? {
        let name = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty { return "Type a branch name." }
        if name.hasPrefix("-") || name.contains(where: \.isWhitespace) {
            return "A branch name has no spaces and does not start with -."
        }
        return nil
    }
    var harnessLabel: String { harnessName.isEmpty ? (harness.isEmpty ? "—" : harness) : harnessName }

    /// The repository policy as the launch banner words it, or "".
    var repoPolicyText: String {
        guard repoPolicy else { return "" }
        if repoTightened.isEmpty { return "\(Self.repoPolicyPath): the policy is as strict already" }
        let settings = repoTightened.count == 1 ? "1 setting" : "\(repoTightened.count) settings"
        return "\(Self.repoPolicyPath): tightened \(settings) (\(repoTightened.joined(separator: ", ")))"
    }

    /// The AI part of the Sites line, by destination kind (GAP-0319): ""
    /// without AI destinations.
    var aiSitesText: String {
        var parts: [String] = []
        if modelProviders > 0 { parts.append(modelProviders == 1 ? "1 model provider" : "\(modelProviders) model providers") }
        if harnessVendor > 0 { parts.append(harnessVendor == 1 ? "1 harness vendor host" : "\(harnessVendor) harness vendor hosts") }
        if shadowAI > 0 { parts.append("\(shadowAI) shadow AI") }
        return parts.isEmpty ? "" : " · AI: \(parts.joined(separator: ", "))"
    }

    /// The detail's Sites line: contacted, blocked, and the AI destinations.
    var sitesText: String { "\(destinations) contacted, \(blocked) blocked\(aiSitesText)" }

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
        var line = hookFailed == 1
            ? "1 hook call failed, so the harness's action was blocked (hooks fail closed)"
            : "\(hookFailed) hook calls failed, so the harness's actions were blocked (hooks fail closed)"
        var answered = hookFailed == 1 ? "DefenseClaw answered" : "DefenseClaw last answered"
        if hookFailurePlaceholder {
            answered = "the last was a hook post of a conversation OpenShell refuses for its credential placeholder:"
        }
        if !lastHookFailure.isEmpty { line += "; \(answered) \(lastHookFailure)" }
        if let hooksAnsweredAt {
            line += "; hooks answered again since \(SandboxFormat.clock(hooksAnsweredAt))"
        }
        return line
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
        if placeholderRefused {
            out.append("OpenShell refuses this conversation's requests: it holds a sandbox credential placeholder; "
                + "start a new conversation (defenseclaw sandbox connect \(name), without --continue)")
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
    /// The feed that numbered seq: a daemon that restarted numbers its
    /// events from one again under another epoch.
    var epoch = ""
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
    var severity = ""
    var rule = ""
    /// The refusals like this one folded into it ("(and N more like it)").
    var repeats = 0
    /// An egress.unblocked event lifted this block since it happened.
    var unblocked = false

    var id: String { "\(epoch)|\(seq)|\(kind)|\(host)" }
    var isBlockedDestination: Bool { kind == "egress.blocked" && !host.isEmpty }

    var glyph: String {
        switch kind {
        case "egress.allowed": "✓"
        case "egress.blocked", "tool.blocked", "hook.failed": "✗"
        case "egress.unblocked": "↺"
        case "egress.large_upload", "finding": "⚠"
        case "approval.requested", "tool.asked": "?"
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
            if host == SandboxReasonLabels.openShellHostAlias, port > 0 {
                // As sandboxcli.activityLine words it (GAP-0154, GAP-0182).
                return "\(SandboxFormat.hostPort(host, port)) (port \(port) on this machine)"
            }
            return host.isEmpty ? text : SandboxFormat.hostPort(host, port)
        case "egress.blocked":
            guard !host.isEmpty else {
                return text.isEmpty ? (SandboxReasonLabels.label(reason).nonEmpty ?? "a destination was blocked") : text
            }
            let more = repeats > 0 ? " (and \(repeats) more like it)" : ""
            return SandboxFormat.hostPort(host, port) + (why.isEmpty ? "" : " (\(why))") + more
        case "approval.requested":
            // The daemon's message is a whole sentence ("the sandbox asks to
            // reach port 5432 on your machine"), as the Go CLI prints it.
            return text.isEmpty ? "asks to reach " + SandboxFormat.hostPort(host, port) : text
        case "tool.blocked":
            return (tool.isEmpty ? "tool call" : tool) + " blocked" + (reason.isEmpty ? "" : ": \(reason)")
        case "tool.asked":
            return (tool.isEmpty ? "tool call" : tool) + " asked for your confirmation" + (reason.isEmpty ? "" : ": \(reason)")
        default:
            return text.isEmpty ? (reason.isEmpty ? kind : reason) : text
        }
    }

    /// Why the destination was refused, in words (the TUI's ActivityRow.why):
    /// SSH first, then a large upload, then a metadata or link-local host by
    /// name whatever refused it, then the reason token as a label.
    var why: String {
        if kind == "egress.blocked", port == SandboxReasonLabels.sshPort, !host.isEmpty {
            return SandboxReasonLabels.sshBlockedText(host)
        }
        if category == "large_upload" { return Self.largeUploadBlockedText(reason) }
        let token = category.isEmpty ? reason : category
        if !token.trimmingCharacters(in: .whitespaces).isEmpty, SandboxReasonLabels.metadataOrLinkLocal(host) {
            return SandboxReasonLabels.metadataText
        }
        return SandboxReasonLabels.label(token)
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
        + "and to every new destination with strict. A port on this machine asks only if the run named it "
        + "with --host-port PORT."

    var status = SandboxStatus()
    var sandboxes: [SandboxRow] = []
    var asks: [SandboxAsk] = []
    var activity: [SandboxActivity] = []
    var lastSeq = 0
    /// The epoch of the feed lastSeq is from, which tells a daemon that
    /// started its feed over from one that stayed quiet (resumePointLost).
    var epoch = ""
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
        case "off":
            if !status.gatewayElsewhere.isEmpty {
                // Setup would stop at the other account's gateway (GAP-0307).
                return "Sandboxes are off for this account: another account runs this machine's OpenShell gateway. "
                    + "Run sandboxes from that account, or have it hand the gateway over; see: defenseclaw sandbox doctor"
            }
            return "Sandboxes are off. Run Setup → Sandbox, or: defenseclaw sandbox setup"
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
    /// after lastSeq - 1. Every event names its feed (its epoch), and a
    /// daemon that restarted numbers from one again in a new feed: an answer
    /// from another epoch is a new feed, and so is an empty answer, since the
    /// feed keeps the event lastSeq names until newer events push it out.
    /// The daemon's uptime cannot tell: it stops while the Mac sleeps.
    func resumePointLost(_ events: [SandboxActivity]) -> Bool {
        guard lastSeq > 0 else { return false }
        guard let first = events.first(where: { $0.kind != "dropped" }) else { return true }
        return first.epoch != epoch
    }

    /// Read the daemon's feed from its start again (after resumePointLost):
    /// the old events' numbers mean nothing to the new feed.
    mutating func restartFeed() {
        lastSeq = 0
        epoch = ""
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
                if event.seq > 0, event.seq == lastSeq { epoch = event.epoch }
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
            let why = event.why
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

/// sandboxapi.reasonTexts (internal/openshell/sandboxapi/reasons.go), word
/// for word, so the panel reads like `sandbox activity` and the alerts
/// (the TUI's REASON_LABELS).
enum SandboxReasonLabels {
    /// A refused port 22 is git over SSH or ssh, which OpenShell never opens.
    static let sshPort = 22
    /// packs.OpenShellHostAlias: the name a sandbox reaches this machine by.
    static let openShellHostAlias = "host.openshell.internal"
    /// sandboxapi.metadataText: a cloud metadata or link-local destination,
    /// whatever refused it.
    static let metadataText = "cloud metadata or link-local address, never reachable from a sandbox"

    static let labels: [String: String] = [
        "transparent_tcp_policy_denied": "no OpenShell rule allows it",
        "transparent_tcp_mapping_denied": "no OpenShell rule allows this port",
        "policy_dns_ineligible": "no OpenShell rule allows the name",
        "paste_site": "paste site",
        "file_drop": "file-sharing site",
        "webhook_catcher": "webhook catcher",
        "tunnel": "tunnel service",
        "anonymizer": "anonymizer",
        "host_internal": "this machine",
        "private_network": "private network",
        "port_not_allowed": "port not allowed",
        "invalid_destination": "invalid destination",
        "admin_block": "blocked by your organization",
        "admin_allow_only": "not on your organization's allowed list",
        "operator_block": "on your block list",
        "pack_block": "on the pack's block list",
        "repo_policy_block": "on the repository policy's block list, .defenseclaw/sandbox.yaml",
        "firewall_block": "a deny rule of the host egress firewall",
        "not_allowlisted": "not on the allowlist",
        "rate_limited": "rate limited",
        "ip_literal": "IP address instead of a name",
        "unsupported_rule": "no OpenShell rule allows it, and DefenseClaw does not approve the rule drafted for it",
        "no_endpoints": "the rule drafted for it names no destination",
        "wildcard_destination": "wildcard destination",
        "policy_refused": "the sandbox policy refuses it",
        "admin_violation": "blocked by your organization",
        "blocklisted": "on the block list",
        "agent_proposals_disabled": "no OpenShell rule allows it, and this sandbox takes no new rules",
        "resolves_to_host": "the name leads to this machine",
        "unresolved": "the name does not resolve",
        "multiple_hosts": "the rule drafted for it names several hosts",
        "harness_background_fetch": "a background fetch of the harness, which it does without",
        "rule_limit": "the sandbox added its limit of rules this session",
        "too_many_pending": "too many approvals are waiting",
        "model_host_side": "a connection outside the model channel, which stays open; no OpenShell rule allows it",
        "host_local": "this machine",
    ]

    /// sandboxapi.SSHBlockedText: OpenShell opens no SSH out of a sandbox,
    /// which no unblock changes.
    static func sshBlockedText(_ host: String) -> String {
        "SSH does not leave a sandbox: use an HTTPS remote (https://\(host)/…)"
    }

    /// A lower-case snake_case token (`webhook_catcher`) rather than a sentence.
    static func isToken(_ text: String) -> Bool {
        guard let first = text.unicodeScalars.first, first == "_" || CharacterSet.letters.contains(first) else { return false }
        return text.unicodeScalars.allSatisfy { $0 == "_" || CharacterSet.alphanumerics.contains($0) }
            && text == text.lowercased()
    }

    /// A reason or category token in plain words (sandboxapi.ReasonText);
    /// other text as is.
    static func label(_ text: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard isToken(trimmed) else { return trimmed }
        return labels[trimmed] ?? trimmed.replacingOccurrences(of: "_", with: " ")
    }

    /// sandboxapi.metadataOrLinkLocal: a link-local or cloud metadata
    /// address, or metadata.google.internal.
    static func metadataOrLinkLocal(_ host: String) -> Bool {
        var text = host.trimmingCharacters(in: .whitespaces).lowercased()
        if text.hasPrefix("["), text.hasSuffix("]") { text = String(text.dropFirst().dropLast()) }
        if text.hasSuffix(".") { text.removeLast() }
        if text == "metadata.google.internal" { return true }
        if text.hasPrefix("::ffff:") { text = String(text.dropFirst(7)) }
        let v4 = text.split(separator: ".", omittingEmptySubsequences: false).map { Int($0) }
        if v4.count == 4, v4.allSatisfy({ ($0 ?? -1) >= 0 && ($0 ?? 256) <= 255 }) {
            let octets = v4.map { $0! }
            if octets[0] == 169, octets[1] == 254 { return true }          // link-local
            return octets == [168, 63, 129, 16]                             // Azure wire server
        }
        // IPv6: link-local fe80::/10, site-local fec0::/10, and the metadata hosts.
        let hextets = text.split(separator: ":", omittingEmptySubsequences: false)
        guard hextets.count >= 3, text.contains(":"), let head = UInt16(hextets[0].isEmpty ? "0" : String(hextets[0]), radix: 16) else {
            return false
        }
        if head & 0xffc0 == 0xfe80 || head & 0xffc0 == 0xfec0 { return true }
        return ["fd20:ce::254", "fd00:c1::a9fe:a9fe"].contains(text)
    }
}

/// GET /sandboxes/{name}/logs: how a stopped sandbox's last detached run
/// ended, from the log its stop kept (GAP-0273).
struct SandboxRunLog: Sendable, Hashable {
    var state = ""
    var exit = ""
    var startedAt: Date?

    static func decode(_ json: Any?) -> SandboxRunLog? {
        guard let d = json as? [String: Any] else { return nil }
        return SandboxRunLog(
            state: (d["state"] as? String) ?? "",
            exit: (d["exit"] as? String) ?? "",
            startedAt: DCDates.parse(d["started_at"])
        )
    }

    /// The detail's line (the TUI's detached_run_text), or "" for a state it
    /// does not know.
    func text(name: String) -> String {
        let outcome: String
        switch state {
        case "exited": outcome = "finished: exited with status \(exit.isEmpty ? "?" : exit)"
        case "interrupted": outcome = "did not finish: the sandbox stopped while it ran"
        case "running": outcome = "was still going when the sandbox stopped"
        default: return ""
        }
        let when = startedAt.map { ", started \(SandboxFormat.clock($0, seconds: false))" } ?? ""
        return "\(outcome)\(when) · log: defenseclaw sandbox logs \(name)"
    }
}

/// GET /sandboxes/{name}/processes rendered as the sandbox detail shows it
/// (the TUI's process_tree_lines): each process under its parent, a
/// process whose parent is not listed starting a tree of its own, at most
/// `limit` lines of `width` characters (the agent chooses its processes'
/// names and arguments).
enum SandboxProcessTree {
    static let lineLimit = 12

    static func lines(from json: Any?, limit: Int = lineLimit, width: Int = 72) -> [String] {
        let payload = (json as? [String: Any]) ?? [:]
        func text(_ raw: Any?) -> String { (raw as? String) ?? "" }
        func int(_ raw: Any?) -> Int {
            if let n = raw as? Int { return n }
            if let n = raw as? Double { return Int(n) }
            if let n = raw as? NSNumber { return n.intValue }
            return 0
        }
        let procs = ((payload["processes"] as? [Any]) ?? [])
            .compactMap { $0 as? [String: Any] }
            .filter { int($0["pid"]) > 0 }
        let byPid = Dictionary(procs.map { (int($0["pid"]), $0) }, uniquingKeysWith: { first, _ in first })
        var children: [Int: [[String: Any]]] = [:]
        var roots: [[String: Any]] = []
        for proc in procs {
            let pid = int(proc["pid"]), ppid = int(proc["ppid"])
            if byPid[ppid] != nil, ppid != pid {
                children[ppid, default: []].append(proc)
            } else {
                roots.append(proc)
            }
        }
        var out: [String] = []
        var seen: Set<Int> = []
        func walk(_ proc: [String: Any], depth: Int) {
            let pid = int(proc["pid"])
            guard !seen.contains(pid), depth <= 32 else { return }
            seen.insert(pid)
            let command = text(proc["cmdline"]).nonEmpty ?? text(proc["comm"]).nonEmpty ?? "?"
            let line = String(repeating: "  ", count: depth) + "\(pid) \(command)"
            out.append(line.count <= width ? line : String(line.prefix(width - 1)) + "…")
            for child in (children[pid] ?? []).sorted(by: { int($0["pid"]) < int($1["pid"]) }) {
                walk(child, depth: depth + 1)
            }
        }
        for root in roots.sorted(by: { int($0["pid"]) < int($1["pid"]) }) { walk(root, depth: 0) }
        if out.count > limit {
            let more = out.count - limit
            out = Array(out.prefix(limit)) + ["...and \(more) more (defenseclaw sandbox ps --tree)"]
        }
        return out
    }

    /// The detail's line while no tree is shown: the sampling interval the
    /// daemon reports (every 5 s on docker, 15 s on the MicroVM driver).
    static func placeholder(from json: Any?, running: Bool) -> String {
        guard running else { return "none while it is stopped" }
        let interval = ((json as? [String: Any])?["interval_seconds"] as? Int) ?? 5
        return "none sampled yet (every \(max(interval, 1)) s while it runs)"
    }
}

/// The alerts (the Alerts panel's rows) raised in each listed sandbox (the
/// TUI's set_alert_events / alerts_cell / alerts_text). An alert older than
/// the sandbox belongs to an earlier one of the same name.
enum SandboxRaisedAlerts {
    static func counts(for row: SandboxRow, alerts: [AlertRow]) -> [Severity: Int] {
        var out: [Severity: Int] = [:]
        for alert in alerts {
            guard case .audit(let event) = alert else { continue }
            // cmd_alerts.py: the row's "sandbox" fact names the sandbox; a
            // sandbox-finding row whose target is the sandbox blanks the
            // fact, so there the target names it (no other row does).
            let named = event.runtimeFacts.first { $0.label == "Sandbox" }?.value ?? ""
            guard named == row.name
                || (named.isEmpty && event.action == "sandbox-finding" && event.target == row.name) else { continue }
            if let since = row.createdAt, event.timestamp < since { continue }
            out[event.severity, default: 0] += 1
        }
        return out
    }

    static func total(_ counts: [Severity: Int]) -> Int { counts.values.reduce(0, +) }

    /// "1 alert" / "N alerts", or "".
    static func cellText(_ counts: [Severity: Int]) -> String {
        let count = total(counts)
        guard count > 0 else { return "" }
        return count == 1 ? "1 alert" : "\(count) alerts"
    }

    /// The detail's Alerts line, or "" when the sandbox raised none.
    static func detailText(_ counts: [Severity: Int]) -> String {
        guard !counts.isEmpty else { return "" }
        let ranked = counts.sorted { $0.key > $1.key || ($0.key == $1.key && $0.key.rawValue < $1.key.rawValue) }
        let parts = ranked.map { "\($0.value) \($0.key.rawValue)" }.joined(separator: ", ")
        return "\(total(counts)) (\(parts)): the Alerts panel lists them; or run defenseclaw alerts"
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

    /// A local wall-clock time, HH:MM:SS (or HH:MM), as the TUI's
    /// `.astimezone().strftime` renders the daemon's timestamps.
    static func clock(_ date: Date, seconds: Bool = true) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        formatter.dateFormat = seconds ? "HH:mm:ss" : "HH:mm"
        return formatter.string(from: date)
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
        out.gatewayName = str(gateway["name"])
        out.gatewayWorkspace = str(gateway["workspace"])
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
        out.gatewayElsewhere = str(d["gateway_elsewhere"])
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
        row.toolAsked = int(hooks["tool_asked"])
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
        row.placeholderRefused = DCDates.parse(hooks["placeholder_refused_at"]) != nil
        row.hookFailurePlaceholder = str(hooks["last_hook_failure_cause"]) == "credential_placeholder_refused"
        row.hooksAnsweredAt = DCDates.parse(hooks["hooks_answered_at"])
        row.orphaned = (d["orphaned"] as? Bool) ?? false
        row.image = str(d["image"])
        row.createdAt = DCDates.parse(d["created_at"])
        row.modelProviders = int(egress["model_providers"])
        row.harnessVendor = int(egress["harness_vendor"])
        row.shadowAI = int(egress["shadow_ai"])
        row.processTree = (d["process_tree"] as? Bool) ?? false
        let repoPolicy = dict(d["repo_policy"])
        row.repoPolicy = !repoPolicy.isEmpty
        row.repoTightened = list(repoPolicy["tightened"]).map { str($0) }.filter { !$0.isEmpty }
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
            epoch: str(d["epoch"]),
            time: DCDates.parse(d["time"]),
            kind: kind,
            sandbox: str(d["sandbox"]),
            host: str(d["host"]),
            port: int(d["port"]),
            category: str(d["category"]),
            reason: str(d["reason"]),
            message: message,
            // A refused port 22 is SSH, which no unblock opens (the daemon
            // sends false; the TUI guards the same way).
            unblockable: ((d["unblockable"] as? Bool) ?? false)
                && !(kind == "egress.blocked" && int(d["port"]) == SandboxReasonLabels.sshPort),
            approvalID: str(d["approval_id"]),
            tool: str(d["tool"]),
            severity: str(d["severity"]),
            rule: str(d["rule"]),
            repeats: int(d["repeats"])
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
