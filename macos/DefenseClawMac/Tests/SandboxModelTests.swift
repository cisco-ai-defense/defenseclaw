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

import Foundation
import UserNotifications

@main
struct SandboxModelTests {
    private static var failureCount = 0

    static func main() {
        decodesTheStatusAndSandboxes()
        sortsRunningSandboxesFirstAndKeepsPendingAsks()
        mergesEventsBySequenceAndNotifiesOnce()
        droppedMarkersDoNotSwallowTheNextEvent()
        aFeedThatStartedOverIsReadFromItsStart()
        resolvedAsksLeaveTheSnapshot()
        headlineExplainsEachState()
        anUnreachableDaemonIsNotShownAsCurrent()
        activitySummariesArePlain()
        decodesSandboxAPIErrorBodies()
        adminLocksMirrorThePythonEditor()
        decodingToleratesOmittedFields()
        theStatusNamesTheGatewaysComputeDriver()
        copyRowsPullAndUndoTheLastApply()
        unreachableHooksAreAnAlertAndANotification()
        failedHookCallsAreAnAlert()
        hookEventsAreCountedPerEvent()
        unblockedDestinationsAreNoLongerOffered()
        askTextIsTheDaemonsSentence()
        anAskShowsEveryPortItOpens()
        notificationUnblockNeedsAnUnlockedMac()
        noAsksTextHoldsForEveryPackAndMatchesTheTUI()
        if failureCount > 0 {
            FileHandle.standardError.write("\(failureCount) failure(s)\n".data(using: .utf8)!)
            exit(1)
        }
        print("SandboxModelTests: all checks passed")
    }

    private static func expect(_ condition: Bool, _ message: String) {
        if !condition {
            failureCount += 1
            FileHandle.standardError.write("FAIL: \(message)\n".data(using: .utf8)!)
        }
    }

    private static let running: [String: Any] = [
        "name": "myapp-claude-7f3a", "harness": "claudecode", "harness_name": "Claude Code",
        "phase": "ready", "pack": "open", "profile": "open", "workdir_mode": "mount",
        "uptime_seconds": 3725, "egress": ["destinations": 23, "blocked": 1],
        "hooks": ["tool_calls": 57, "tool_blocked": 1, "tampered": 2],
        "snapshot": ["kind": "git"],
        "nested_repos": [["kind": "repository", "path": "vendor/x/.git", "quarantined": "vendor/x/.git.dc"]],
    ]
    private static let stopped: [String: Any] = [
        "name": "docs", "harness": "claudecode", "phase": "stopped", "pack": "open", "profile": "strict",
        "workdir_mode": "copy", "snapshot": ["kind": "git", "undone_at": "2026-09-27T10:00:00Z"],
    ]
    private static let blocked: [String: Any] = [
        "seq": 5, "kind": "egress.blocked", "sandbox": "myapp-claude-7f3a", "host": "webhook.site",
        "category": "exfil destination", "unblockable": true, "message": "✗ webhook.site (exfil destination)",
    ]

    private static func decodesTheStatusAndSandboxes() {
        let status = SandboxDecoding.status(from: [
            "enabled": true, "available": true, "sandboxes": 2, "running": 1, "pending_approvals": 1,
            "gateway": ["name": "openshell", "version": "0.1.1", "healthy": true],
            "admin": ["configured": true, "authority": "authoritative", "detail": "administrator-owned"],
        ])
        expect(status.loaded && status.enabled && status.available, "status flags")
        expect(status.gateway == "OpenShell 0.1.1 gateway openshell", "gateway text: \(status.gateway)")
        expect(status.adminConfigured && status.adminAuthority == "authoritative", "admin status")

        let rows = SandboxDecoding.sandboxes(from: ["sandboxes": [running, stopped, ["phase": "ready"]]])
        expect(rows.count == 2, "a row without a name is dropped")
        let row = rows[0]
        expect(row.running && row.uptimeText == "1h02m", "uptime \(row.uptimeText)")
        expect(row.undoAvailable, "snapshot not undone yet")
        expect(row.alerts.contains { $0.contains("2 tool call(s) ran without a DefenseClaw verdict") }, "tamper alert")
        expect(row.alerts.contains { $0.contains("quarantined as vendor/x/.git.dc") }, "nested repo alert")
        expect(rows[1].policyLabel == "open/strict" && !rows[1].undoAvailable && rows[1].uptimeText == "—",
               "stopped row")
    }

    private static func sortsRunningSandboxesFirstAndKeepsPendingAsks() {
        var snapshot = SandboxSnapshot()
        snapshot.apply(
            status: SandboxDecoding.status(from: ["enabled": true, "available": true]),
            sandboxes: SandboxDecoding.sandboxes(from: ["sandboxes": [stopped, running]]),
            asks: SandboxDecoding.approvals(from: ["approvals": [
                ["id": "a1", "sandbox": "x", "status": "pending", "host": "host.openshell.internal", "port": 5432],
                ["id": "a2", "sandbox": "x", "status": "approved"],
            ]])
        )
        expect(snapshot.sandboxes.map(\.name) == ["myapp-claude-7f3a", "docs"], "running first")
        expect(snapshot.asks.map(\.id) == ["a1"], "only pending asks")
        expect(snapshot.asks[0].destination == "host.openshell.internal:5432", "ask destination")
        expect(snapshot.state == "ready", "ready state")
    }

    private static func mergesEventsBySequenceAndNotifiesOnce() {
        var snapshot = SandboxSnapshot()
        let start = Date(timeIntervalSince1970: 1_000_000)
        let events = SandboxDecoding.activity(from: ["events": [
            ["seq": 4, "kind": "egress.allowed", "host": "registry.npmjs.org"],
            blocked,
            ["seq": 6, "kind": "egress.blocked", "host": "10.0.0.5", "unblockable": false],
            ["seq": 7, "kind": "approval.requested", "sandbox": "myapp-claude-7f3a", "approval_id": "a1",
             "message": "host.openshell.internal:5432"],
        ]])
        let notes = snapshot.merge(events: events, notify: true, now: start)
        expect(notes.map(\.kind) == [.blocked, .ask], "one block and one ask notification")
        expect(notes[0].host == "webhook.site" && notes[0].sandbox == "myapp-claude-7f3a", "block target")
        expect(notes[0].title == "Blocked webhook.site", "block title \(notes[0].title)")
        expect(notes[1].approvalID == "a1", "ask id")
        expect(snapshot.lastSeq == 7, "last seq")
        expect(snapshot.merge(events: events, notify: true, now: start).isEmpty, "a replay adds nothing")
        var again = blocked
        again["seq"] = 8
        let soon = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [again]]),
                                  notify: true, now: start.addingTimeInterval(30))
        expect(soon.isEmpty, "the same destination within a minute does not notify again")
        again["seq"] = 9
        let later = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [again]]),
                                   notify: true, now: start.addingTimeInterval(61))
        expect(later.count == 1, "after a minute it notifies again")
        expect(snapshot.recentBlocks.first?.seq == 9, "recent blocks are newest first")
        var backlog = SandboxSnapshot()
        expect(backlog.merge(events: events, notify: false).isEmpty, "backlog never notifies")
    }

    private static func droppedMarkersDoNotSwallowTheNextEvent() {
        var snapshot = SandboxSnapshot()
        _ = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [
            ["seq": 10, "kind": "dropped", "message": "12 events were skipped"],
            ["seq": 10, "kind": "egress.allowed", "host": "a"],
        ]]), notify: true)
        expect(snapshot.activity.map(\.kind) == ["dropped", "egress.allowed"], "marker plus event")
    }

    private static func aFeedThatStartedOverIsReadFromItsStart() {
        var snapshot = SandboxSnapshot()
        let last: [String: Any] = ["seq": 40, "kind": "egress.allowed", "host": "a.example", "time": "2026-09-27T12:00:00Z"]
        _ = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [last]]), notify: false)
        func lost(_ events: [[String: Any]]) -> Bool {
            snapshot.resumePointLost(SandboxDecoding.activity(from: ["events": events]))
        }
        var newer = blocked
        newer["seq"] = 45
        expect(!lost([last, newer]), "the daemon still holds the resume point")
        expect(!lost([newer]), "only newer events pushed it out")
        expect(lost([]), "a restarted daemon with fewer events")
        var other = last
        other["time"] = "2026-09-27T13:00:00Z"
        expect(lost([other]), "another event under that number")
        snapshot.restartFeed()
        expect(snapshot.lastSeq == 0 && snapshot.activity.isEmpty && !lost([]), "read from the start again")
    }

    private static func resolvedAsksLeaveTheSnapshot() {
        var snapshot = SandboxSnapshot()
        snapshot.asks = [SandboxAsk(id: "a1", sandbox: "x", status: "pending")]
        _ = snapshot.merge(events: [SandboxActivity(seq: 3, kind: "approval.resolved", approvalID: "a1")], notify: true)
        expect(snapshot.asks.isEmpty, "resolved ask removed")
    }

    private static func headlineExplainsEachState() {
        var snapshot = SandboxSnapshot()
        expect(snapshot.state == "waiting", "waiting")
        snapshot.error = "the DefenseClaw daemon is not reachable"
        expect(snapshot.state == "unreachable" && snapshot.headline.contains("not answering"), "unreachable")
        snapshot.apply(status: SandboxDecoding.status(from: ["enabled": false]), sandboxes: [], asks: [])
        expect(snapshot.state == "off" && snapshot.headline.contains("defenseclaw sandbox setup"), "off")
        snapshot.apply(status: SandboxDecoding.status(from: ["enabled": true, "reason": "gateway down"]),
                       sandboxes: [], asks: [])
        expect(snapshot.state == "unavailable" && snapshot.headline.contains("gateway down"), "unavailable")
    }

    private static func anUnreachableDaemonIsNotShownAsCurrent() {
        var never = SandboxSnapshot()
        never.markUnreachable("")
        expect(never.state == "unreachable", "never reached: not Loading forever (\(never.state))")
        expect(never.headline == "The DefenseClaw daemon is not answering: its health check fails",
               "headline says why: \(never.headline)")

        var stale = SandboxSnapshot()
        stale.apply(status: SandboxDecoding.status(from: ["enabled": true, "available": true]),
                    sandboxes: SandboxDecoding.sandboxes(from: ["sandboxes": [running]]), asks: [])
        expect(stale.staleNote.isEmpty, "a fresh snapshot has no note")
        stale.markUnreachable("the DefenseClaw gateway is offline")
        expect(stale.staleNote.hasPrefix("Showing the last good snapshot"), "stale note: \(stale.staleNote)")
        expect(stale.staleNote.hasSuffix(": the DefenseClaw gateway is offline"), "stale note says why")
        expect(stale.sandboxes.count == 1, "the rows stay")
    }

    private static func activitySummariesArePlain() {
        let block = SandboxDecoding.event(blocked)!
        expect(block.summary == "webhook.site (exfil destination)", "block summary \(block.summary)")
        let tool = SandboxActivity(kind: "tool.blocked", tool: "Bash")
        expect(tool.summary == "Bash blocked", "tool summary")
        let private22 = SandboxActivity(kind: "egress.blocked", host: "10.0.0.5", port: 22, reason: "private network")
        expect(private22.summary == "10.0.0.5:22 (private network)", "private summary")
        let lifecycle = SandboxDecoding.event(["seq": 1, "kind": "sandbox.lifecycle", "phase": "Stopped"])!
        expect(lifecycle.summary == "now stopped", "lifecycle summary")
        // The large-upload block names the threshold the upload crossed.
        let upload = SandboxActivity(kind: "egress.blocked", host: "files.example.net", category: "large_upload",
                                     reason: "This sandbox tried to send more than 10 MiB to a destination it had not contacted before.")
        expect(upload.summary == "files.example.net (large upload blocked: this sandbox tried to send more than 10 MiB "
               + "to a destination it had not contacted before)", "large upload summary \(upload.summary)")
        // An HTTPS and a plain-HTTP refusal of one host read apart (PR 1022
        // live retest N3): the port shows unless it is 443.
        let https = SandboxActivity(kind: "egress.blocked", host: "httpbin.org", port: 443, category: "large_upload", reason: "Blocked.")
        let http = SandboxActivity(kind: "egress.blocked", host: "httpbin.org", port: 80, category: "large_upload", reason: "Blocked.")
        expect(https.summary == "httpbin.org (large upload blocked: blocked)", "https summary \(https.summary)")
        expect(http.summary == "httpbin.org:80 (large upload blocked: blocked)", "http summary \(http.summary)")
        // An IPv6 literal with its port is bracketed: "fd00:ec2::254:80" is
        // another address (PR 1022 review of N3).
        expect(SandboxFormat.hostPort("fd00:ec2::254", 80) == "[fd00:ec2::254]:80", "ipv6 host port")
        expect(SandboxFormat.hostPort("fd00:ec2::254", 443) == "fd00:ec2::254", "ipv6 on 443")
        expect(SandboxFormat.hostPort("[::1]", 8080) == "[::1]:8080", "bracketed ipv6 host port")
    }

    private static func decodesSandboxAPIErrorBodies() {
        let admin = GatewayErrorBody.sandboxMessage(
            body: #"{"code":"admin_violation","error":"unblocking is not allowed"}"#)
        expect(admin == "\(sandboxAdminMessage): unblocking is not allowed", "admin prefix: \(admin ?? "nil")")
        let already = GatewayErrorBody.sandboxMessage(
            body: #"{"code":"admin_violation","error":"blocked by your organization's DefenseClaw policy: x"}"#)
        expect(already == "blocked by your organization's DefenseClaw policy: x", "no double prefix")
        let flagged = GatewayErrorBody.sandboxMessage(
            body: #"{"code":"policy_violation","error":"approve-always is off","violation":{"admin":true}}"#)
        expect(flagged == "\(sandboxAdminMessage): approve-always is off", "violation.admin prefix")
        let conflict = GatewayErrorBody.sandboxMessage(body: #"{"code":"conflict","error":"stop sandbox x first"}"#)
        expect(conflict == "stop sandbox x first", "conflict message")
        expect(GatewayErrorBody.sandboxMessage(body: "plain text") == nil, "not a sandbox error")
        expect(GatewayErrorBody.sandboxMessage(body: #"{"error":"no code"}"#) == nil, "needs a code")
        let degraded = GatewayError.degraded(status: 403, body: #"{"code":"admin_violation","error":"no"}"#)
        expect(SandboxDecoding.message(for: degraded) == "\(sandboxAdminMessage): no", "degraded 403 reads plainly")
    }

    private static func adminLocksMirrorThePythonEditor() {
        let keys = ["openshell.pack", "openshell.yolo", "openshell.profile", "openshell.egress.unblocked",
                    "openshell.resources.cpu", "openshell.egress.block_large_uploads"]
        let locks = SandboxAdminLocks.locks(
            admin: ["required_pack": "balanced", "allow_yolo": "false", "allow_unblock": false,
                    "block_large_uploads": "true", "locked": ["resources"]],
            managed: false,
            keys: keys
        )
        expect(locks["openshell.pack"] == "your organization requires the balanced pack", "required pack")
        expect(locks["openshell.yolo"] == "skip-permissions mode is not allowed", "yolo")
        expect(locks["openshell.egress.unblocked"] == "unblocking and allow entries are not allowed", "unblock")
        expect(locks["openshell.resources.cpu"]?.contains("openshell.admin.locked: resources") == true, "locked")
        expect(locks["openshell.profile"] == nil, "profile stays editable")
        expect(locks["openshell.egress.block_large_uploads"] == "your organization blocks large uploads to first-seen hosts",
               "upload block")
        let managed = SandboxAdminLocks.locks(admin: [:], managed: true, keys: keys)
        expect(managed.count == keys.count, "managed_enterprise locks every key")
    }

    private static func unreachableHooksAreAnAlertAndANotification() {
        var raw = running
        raw["hooks"] = ["unreachable": true, "unreachable_reason": "no hook arrived in 90s"]
        let row = SandboxDecoding.sandbox(raw)!
        expect(row.alerts.contains {
            $0.hasPrefix("\(sandboxHooksUnreachableWarning) (no hook arrived in 90s)")
                && $0.contains("defenseclaw sandbox doctor")
        }, "unreachable alert: \(row.alerts)")
        raw["hooks"] = ["ingress_refused": 2]
        expect(SandboxDecoding.sandbox(raw)!.alerts.contains { $0.contains("refused 2 hook request(s)") },
               "refused ingress alert")
        var snapshot = SandboxSnapshot()
        let notes = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [
            ["seq": 50, "kind": "finding", "sandbox": "x", "reason": "hooks_unreachable",
             "message": "⚠ \(sandboxHooksUnreachableWarning) (why). Run: defenseclaw sandbox doctor"],
        ]]), notify: true)
        expect(notes.count == 1 && notes[0].title == "x: hooks are not reaching DefenseClaw", "unreachable note")
        expect(notes.first?.body.hasPrefix(sandboxHooksUnreachableWarning) == true, "note body without the glyph")
    }

    private static func failedHookCallsAreAnAlert() {
        var hooks = running
        hooks["hooks"] = ["hook_failed": 3, "last_hook_failure": "HTTP 429 Too Many Requests"]
        let row = SandboxDecoding.sandbox(hooks)
        let expected = "3 hook calls failed, so the harness's actions were blocked (hooks fail closed); "
            + "DefenseClaw last answered HTTP 429 Too Many Requests"
        expect(row?.alerts.contains(expected) == true, "hook failure alert (the TUI's wording): \(row?.alerts ?? [])")
        hooks["hooks"] = ["hook_failed": 1]
        expect(SandboxDecoding.sandbox(hooks)?.alerts
            .contains("1 hook call failed, so the harness's action was blocked (hooks fail closed)") == true,
            "one failed hook call")
        expect(SandboxDecoding.sandbox(running)?.hookFailed == 0, "no failures by default")
        let event = SandboxDecoding.event(["seq": 1, "kind": "hook.failed", "message": "✗ a hook call failed (HTTP 429)"])
        expect(event?.glyph == "✗" && event?.summary == "a hook call failed (HTTP 429)", "hook.failed event line")
    }

    private static func hookEventsAreCountedPerEvent() {
        var raw = running
        raw["hooks"] = ["tool_calls": 12, "other_events": 1, "events": [
            "Stop": 2, "PostToolUse": 11, "SessionStart": 2, "PreToolUse": 12, "bad": "x", "": 4,
        ]]
        let row = SandboxDecoding.sandbox(raw)
        expect(row?.hookEvents == ["PreToolUse 12", "PostToolUse 11", "SessionStart 2", "Stop 2"],
               "most frequent first, then by name: \(row?.hookEvents ?? [])")
        expect(row?.hookEventsText == "PreToolUse 12 · PostToolUse 11 · SessionStart 2 · Stop 2 · other events 1",
               "the status line (the TUI's wording): \(row?.hookEventsText ?? "")")
        expect(SandboxDecoding.sandbox(stopped)?.hookEventsLabel == "—", "no events before the first verdict")
    }

    private static func unblockedDestinationsAreNoLongerOffered() {
        var snapshot = SandboxSnapshot()
        snapshot.apply(
            status: SandboxDecoding.status(from: ["enabled": true, "available": true]),
            sandboxes: SandboxDecoding.sandboxes(from: ["sandboxes": [running, ["name": "other", "phase": "ready"]]]),
            asks: []
        )
        var elsewhere = blocked
        elsewhere["seq"] = 6
        elsewhere["sandbox"] = "other"
        _ = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [blocked, elsewhere]]), notify: false)
        expect(snapshot.recentBlocks.count == 2, "two blocks")
        _ = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [
            ["seq": 7, "kind": "egress.unblocked", "sandbox": "myapp-claude-7f3a", "host": "WEBHOOK.site.",
             "reason": "sandbox", "message": "unblocked webhook.site for sandbox myapp-claude-7f3a"],
        ]]), notify: false)
        expect(snapshot.recentBlocks.map(\.sandbox) == ["other"], "only that sandbox's block is lifted")
        expect(snapshot.activity.first { $0.seq == 5 }?.unblocked == true, "the lifted block is marked")
        expect(snapshot.activity.first { $0.seq == 5 }?.unblockable == false, "and no longer offers Unblock")
        _ = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [
            ["seq": 8, "kind": "egress.unblocked", "sandbox": "", "host": "webhook.site", "reason": "always"],
        ]]), notify: false)
        expect(snapshot.recentBlocks.isEmpty, "always lifts it everywhere")
        var again = blocked
        again["seq"] = 9
        _ = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [again]]), notify: false)
        expect(snapshot.recentBlocks.map(\.seq) == [9], "a later block is offered again")

        var local = SandboxSnapshot()
        local.apply(status: SandboxDecoding.status(from: ["enabled": true, "available": true]),
                    sandboxes: SandboxDecoding.sandboxes(from: ["sandboxes": [running]]), asks: [])
        _ = local.merge(events: SandboxDecoding.activity(from: ["events": [blocked]]), notify: false)
        local.markUnblocked(sandbox: "myapp-claude-7f3a", host: "webhook.site", always: false)
        expect(local.recentBlocks.isEmpty, "the app's own unblock lifts it without waiting for the event")

        var gone = SandboxSnapshot()
        _ = gone.merge(events: SandboxDecoding.activity(from: ["events": [blocked]]), notify: false)
        expect(gone.recentBlocks.count == 1, "before the first list read the block shows")
        gone.apply(status: SandboxDecoding.status(from: ["enabled": true, "available": true]),
                   sandboxes: [], asks: [])
        expect(gone.recentBlocks.isEmpty, "a deleted sandbox's block is not offered")
        expect(SandboxFormat.hostMatches("*.example.com", "api.example.com"), "wildcard subdomain")
        expect(!SandboxFormat.hostMatches("*.example.com", "example.com"), "wildcard is subdomains only")
    }

    /// A private-network address asks in every pack; balanced also asks for
    /// hosts off its allowlist and strict for every destination, and a port on
    /// this machine never asks (--host-port opens it). The TUI's Asks view says
    /// the same (sandbox_state.NO_ASKS_TEXT).
    private static func noAsksTextHoldsForEveryPackAndMatchesTheTUI() {
        let text = SandboxSnapshot.noAsksText
        expect(!text.contains("Only") && text.contains("private-network") && text.contains("balanced")
               && text.contains("strict") && text.contains("--host-port"), "no-asks text covers every pack: \(text)")
        let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let python = (try? String(
            contentsOf: testsDirectory.appendingPathComponent("../../../cli/defenseclaw/tui/services/sandbox_state.py"),
            encoding: .utf8
        )) ?? ""
        guard let start = python.range(of: "NO_ASKS_TEXT = ("),
              let end = python.range(of: "\n)", range: start.upperBound..<python.endIndex)
        else {
            expect(false, "NO_ASKS_TEXT was not found in sandbox_state.py")
            return
        }
        let body = String(python[start.upperBound..<end.lowerBound])
        let literal = try! NSRegularExpression(pattern: #""([^"]*)""#)
        let tui = literal.matches(in: body, range: NSRange(body.startIndex..., in: body)).compactMap { match in
            Range(match.range(at: 1), in: body).map { String(body[$0]) }
        }.joined()
        expect(tui == text, "the app's no-asks text differs from the TUI's: \(tui)")
    }

    private static func askTextIsTheDaemonsSentence() {
        let sentence = SandboxActivity(kind: "approval.requested", sandbox: "myapp",
                                       message: "the sandbox asks to reach port 5432 on your machine")
        expect(sentence.summary == "the sandbox asks to reach port 5432 on your machine",
               "summary: \(sentence.summary)")
        let bare = SandboxActivity(kind: "approval.requested", host: "10.0.0.5", port: 22)
        expect(bare.summary == "asks to reach 10.0.0.5:22", "bare summary: \(bare.summary)")
        var snapshot = SandboxSnapshot()
        let notes = snapshot.merge(events: SandboxDecoding.activity(from: ["events": [
            ["seq": 3, "kind": "approval.requested", "sandbox": "myapp", "approval_id": "a1",
             "host": "host.openshell.internal", "port": 5432,
             "message": "the sandbox asks to reach port 5432 on your machine"],
            ["seq": 4, "kind": "approval.requested", "sandbox": "myapp", "approval_id": "a2",
             "host": "10.0.0.5", "port": 22],
        ]]), notify: true)
        expect(notes.first?.body == "The sandbox asks to reach port 5432 on your machine. Review it in DefenseClaw.",
               "ask body: \(notes.first?.body ?? "nil")")
        expect(notes.last?.body == "It wants to reach 10.0.0.5:22. Review it in DefenseClaw.",
               "bare ask body: \(notes.last?.body ?? "nil")")
    }

    private static func anAskShowsEveryPortItOpens() {
        let asks = SandboxDecoding.approvals(from: ["approvals": [
            ["id": "a1", "sandbox": "myapp", "kind": "host_port", "status": "pending", "risky": true,
             "host": "host.openshell.internal", "port": 5432,
             "endpoints": [["host": "host.openshell.internal", "port": 5432],
                           ["host": "host.openshell.internal", "port": 6379]]],
            ["id": "a2", "sandbox": "myapp", "status": "pending", "host": "api.example.com", "port": 443,
             "endpoints": [["host": "api.example.com", "port": 443]]],
        ]])
        expect(asks[0].endpoints == ["host.openshell.internal:5432", "host.openshell.internal:6379"], "endpoints decode")
        expect(asks[0].opens == "host.openshell.internal:5432, host.openshell.internal:6379",
               "Approve names every port it opens: \(asks[0].opens)")
        expect(asks[1].opens == "api.example.com", "one endpoint reads as the destination")
    }

    private static func notificationUnblockNeedsAnUnlockedMac() {
        expect(SandboxNotificationCategories.unblockOptions.contains(.authenticationRequired),
               "Unblock from a notification needs the Mac unlocked")
        let blocked = SandboxNotificationCategories.all.first { $0.identifier == SandboxNotificationCategories.blocked }
        let unblock = blocked?.actions.first { $0.identifier == SandboxNotificationCategories.unblockAction }
        expect(unblock?.options.contains(.authenticationRequired) == true, "the registered Unblock action")
        expect(unblock?.options.contains(.foreground) == false, "Unblock still runs without opening the app")
        expect(SandboxNotificationCategories.isSandboxCategory("dc.sandbox.review"), "review category")
    }

    private static func decodingToleratesOmittedFields() {
        expect(SandboxDecoding.status(from: nil).enabled == false, "nil status")
        expect(SandboxDecoding.sandboxes(from: "junk").isEmpty, "junk sandboxes")
        expect(SandboxDecoding.activity(from: ["events": [["seq": 1]]]).isEmpty, "event without a kind")
        let row = SandboxDecoding.sandbox(["name": "bare"])!
        expect(row.harnessLabel == "—" && row.policyLabel == "—" && !row.undoAvailable, "bare row")
        expect(row.runImage.isEmpty && !row.copyMode && !row.undoOffered, "a bare row has no run image and no undo")
        // A daemon older than gateway.driver drove docker only.
        let older = SandboxDecoding.status(from: ["gateway": ["name": "openshell", "version": "0.1.1"]])
        expect(older.driver.isEmpty && older.copyOnlyNote.isEmpty, "no driver: docker, mount mode possible")
        expect(older.gateway == "OpenShell 0.1.1 gateway openshell", "no driver suffix: \(older.gateway)")
    }

    private static func theStatusNamesTheGatewaysComputeDriver() {
        func status(_ gateway: [String: Any]) -> SandboxStatus {
            SandboxDecoding.status(from: ["enabled": true, "available": true,
                                          "gateway": ["name": "openshell", "version": "0.1.1"].merging(gateway) { $1 }])
        }
        let vm = status(["driver": "vm", "healthy": true])
        expect(vm.driver == "vm" && vm.gateway == "OpenShell 0.1.1 gateway openshell (MicroVM)", "vm gateway: \(vm.gateway)")
        expect(vm.copyOnlyNote == "MicroVM sandboxes work on a copy; pull brings the changes back.",
               "vm copy note: \(vm.copyOnlyNote)")
        let sick = status(["driver": "vm", "healthy": false])
        expect(sick.gateway.hasSuffix("(MicroVM, unhealthy)"), "unhealthy vm gateway: \(sick.gateway)")
        let docker = status(["driver": "docker", "healthy": true])
        expect(docker.gateway.hasSuffix("(docker)") && docker.copyOnlyNote.isEmpty, "docker gateway: \(docker.gateway)")
        var snapshot = SandboxSnapshot()
        snapshot.apply(status: vm, sandboxes: [], asks: [])
        expect(snapshot.headline.contains("gateway openshell (MicroVM)"), "headline: \(snapshot.headline)")
        // As in Go, a driver the table does not know mounts nothing.
        expect(SandboxDriver.lookup("").hostMounts && !SandboxDriver.lookup("vm").hostMounts
               && !SandboxDriver.lookup("podman").hostMounts, "the driver table")
    }

    private static func copyRowsPullAndUndoTheLastApply() {
        let image = "defenseclaw.invalid/sandbox-run:claudecode-0123456789ab-ba9876543210-u501"
        var raw = stopped
        raw["run_image"] = image
        let copy = SandboxDecoding.sandbox(raw)!
        expect(copy.copyMode && copy.runImage == image, "a copy row with its run image")
        // A copy's undo reverts the last pull --apply: no snapshot needed.
        expect(copy.undoOffered && !copy.undoAvailable, "undo is offered for a copy")
        expect(copy.undoLabel == "reverts the last pull --apply", "copy undo label: \(copy.undoLabel)")
        expect(copy.pullCommand == "defenseclaw sandbox pull docs", "pull command: \(copy.pullCommand)")
        expect(copy.pullToBranchArguments == ["sandbox", "pull", "docs", "--branch"], "pull to branch argv")
        let mounted = SandboxDecoding.sandbox(running)!
        expect(!mounted.copyMode && mounted.undoOffered && mounted.undoLabel == "available" && !mounted.undoAccepted, "a mounted row")
        // The user kept the last session's changes (the daemon's accept).
        var keptRaw = running
        var snapshot = keptRaw["snapshot"] as? [String: Any] ?? [:]
        snapshot["accepted_at"] = "2026-09-30T10:00:00Z"
        keptRaw["snapshot"] = snapshot
        let kept = SandboxDecoding.sandbox(keptRaw)!
        expect(kept.undoAccepted && kept.undoLabel.hasPrefix("available; the last session's changes were kept"),
               "a row whose changes were kept: \(kept.undoLabel)")
    }
}
