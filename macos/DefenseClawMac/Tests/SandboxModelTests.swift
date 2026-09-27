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

@main
struct SandboxModelTests {
    private static var failureCount = 0

    static func main() {
        decodesTheStatusAndSandboxes()
        sortsRunningSandboxesFirstAndKeepsPendingAsks()
        mergesEventsBySequenceAndNotifiesOnce()
        droppedMarkersDoNotSwallowTheNextEvent()
        resolvedAsksLeaveTheSnapshot()
        headlineExplainsEachState()
        activitySummariesArePlain()
        decodesSandboxAPIErrorBodies()
        adminLocksMirrorThePythonEditor()
        decodingToleratesOmittedFields()
        unreachableHooksAreAnAlertAndANotification()
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

    private static func activitySummariesArePlain() {
        let block = SandboxDecoding.event(blocked)!
        expect(block.summary == "webhook.site (exfil destination)", "block summary \(block.summary)")
        let tool = SandboxActivity(kind: "tool.blocked", tool: "Bash")
        expect(tool.summary == "Bash blocked", "tool summary")
        let private22 = SandboxActivity(kind: "egress.blocked", host: "10.0.0.5", port: 22, reason: "private network")
        expect(private22.summary == "10.0.0.5:22 (private network)", "private summary")
        let lifecycle = SandboxDecoding.event(["seq": 1, "kind": "sandbox.lifecycle", "phase": "Stopped"])!
        expect(lifecycle.summary == "now stopped", "lifecycle summary")
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
                    "openshell.resources.cpu"]
        let locks = SandboxAdminLocks.locks(
            admin: ["required_pack": "balanced", "allow_yolo": "false", "allow_unblock": false,
                    "locked": ["resources"]],
            managed: false,
            keys: keys
        )
        expect(locks["openshell.pack"] == "your organization requires the balanced pack", "required pack")
        expect(locks["openshell.yolo"] == "skip-permissions mode is not allowed", "yolo")
        expect(locks["openshell.egress.unblocked"] == "unblocking and allow entries are not allowed", "unblock")
        expect(locks["openshell.resources.cpu"]?.contains("openshell.admin.locked: resources") == true, "locked")
        expect(locks["openshell.profile"] == nil, "profile stays editable")
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

    private static func decodingToleratesOmittedFields() {
        expect(SandboxDecoding.status(from: nil).enabled == false, "nil status")
        expect(SandboxDecoding.sandboxes(from: "junk").isEmpty, "junk sandboxes")
        expect(SandboxDecoding.activity(from: ["events": [["seq": 1]]]).isEmpty, "event without a kind")
        let row = SandboxDecoding.sandbox(["name": "bare"])!
        expect(row.harnessLabel == "—" && row.policyLabel == "—" && !row.undoAvailable, "bare row")
    }
}
