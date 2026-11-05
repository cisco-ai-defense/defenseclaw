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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation
import Security

@main
private enum GatewayAdminHelperTests {
    private static var checks = 0

    private static func check(_ value: Bool, _ message: String) {
        guard value else { fatalError(message) }
        checks += 1
    }

    private static func rejects(_ message: String, _ operation: () throws -> Void) {
        do { try operation(); fatalError(message) } catch { checks += 1 }
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2, getuid() != 0 else {
            fatalError("Run these tests as a normal user with a private fixture directory.")
        }
        let account = try InvokingAccount(uid: getuid())
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let home = root.appendingPathComponent("home", isDirectory: true)
        let config = home.appendingPathComponent("config.yaml")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        try Data("config_version: 8\n".utf8).write(to: config)
        _ = chmod(config.path, 0o600)
        try GatewayAdminTrust.validateInstallation(home: home.path, config: config.path, account: account)
        checks += 1

        rejects("Another account's installation was accepted") {
            try GatewayAdminTrust.validateInstallation(home: "/Users/other-account/.defenseclaw",
                config: "/Users/other-account/.defenseclaw/config.yaml", account: account)
        }
        rejects("A configuration outside the selected home was accepted") {
            try GatewayAdminTrust.validateInstallation(home: home.path,
                config: root.appendingPathComponent("config.yaml").path, account: account)
        }
        rejects("A managed installation was accepted") {
            try GatewayAdminTrust.validateInstallation(home: "/opt/cisco/secureclient/defenseclaw",
                config: "/opt/cisco/secureclient/defenseclaw/etc/config.yaml", account: account)
        }
        rejects("The entire account home was accepted as runtime root") {
            try GatewayAdminTrust.validateInstallation(home: account.home, config: config.path, account: account)
        }
        let link = home.appendingPathComponent("linked.yaml")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: config)
        rejects("A symlink configuration was accepted") {
            try GatewayAdminTrust.validateInstallation(home: home.path, config: link.path, account: account)
        }
        let homeLink = root.appendingPathComponent("linked-home")
        try FileManager.default.createSymbolicLink(at: homeLink, withDestinationURL: home)
        rejects("A symlink installation root was accepted") {
            try GatewayAdminTrust.validateInstallation(home: homeLink.path,
                config: homeLink.appendingPathComponent("config.yaml").path, account: account)
        }
        _ = chmod(config.path, 0o666)
        rejects("A world-writable configuration was accepted") {
            try GatewayAdminTrust.validateInstallation(home: home.path, config: config.path, account: account)
        }
        _ = chmod(config.path, 0o600)
        _ = chmod(home.path, 0o770)
        rejects("A group-writable runtime root was accepted") {
            try GatewayAdminTrust.validateInstallation(home: home.path, config: config.path, account: account)
        }
        _ = chmod(home.path, 0o700)

        let grantACL = Process()
        grantACL.executableURL = URL(fileURLWithPath: "/bin/chmod")
        grantACL.arguments = ["+a", "everyone allow write", config.path]
        try grantACL.run()
        grantACL.waitUntilExit()
        check(grantACL.terminationStatus == 0, "Could not prepare the isolated ACL fixture")
        rejects("An ACL-writable configuration was accepted") {
            try GatewayAdminTrust.validateInstallation(home: home.path, config: config.path, account: account)
        }

        rejects("Malformed authorization was accepted") { try GatewayAdminTrust.validateAuthorization(Data()) }
        rejects("An unsigned file was accepted as the helper") {
            try GatewayAdminTrust.verifySignature(at: config.path, requirement: GatewayAdminPolicy.helperRequirement)
        }
        check(GatewayAdminAction.allCases.map(\.rawValue) == ["repair"],
              "The helper must offer only the repair action; it never starts a gateway")
        for action in ["start", "restart", "stop", "start --help", "watchdog start", "/bin/sh", "", "REPAIR"] {
            check(GatewayAdminAction(rawValue: action) == nil, "An unsupported operation was accepted: \(action)")
        }
        for path in ["/Users/person/../root", "relative/path", "/Users/person\nroot", "/Users/person\0root", "/Users/person/./config"] {
            check(!GatewayAdminPolicy.isCanonicalAbsolutePath(path), "A noncanonical path was accepted")
        }
        check(!GatewayAdminPolicy.isStrictDescendant("/Users/person2/config", of: "/Users/person"), "A sibling prefix was accepted")
        check(!GatewayAdminPolicy.isStrictDescendant("/etc/config", of: "/"), "The filesystem root was accepted")

        let safe = GatewayAdminPolicy.authorizationDefinition
        check(GatewayAdminPolicy.authorizationDefinitionIsSafe(safe as CFDictionary), "The intended administrator rule was rejected")
        check(!GatewayAdminPolicy.authorizationDefinitionIsSafe(nil), "An absent authorization rule was accepted")
        check(!GatewayAdminPolicy.authorizationDefinitionIsSafe(["class": "allow"] as CFDictionary), "An allow-all authorization rule was accepted")
        for (key, value) in ["class": "allow", "group": "everyone", "authenticate-user": false,
                             "session-owner": true, "shared": true, "allow-root": true, "timeout": 300] as [String: Any] {
            var alteredDefinition = safe
            alteredDefinition[key] = value
            check(!GatewayAdminPolicy.authorizationDefinitionIsSafe(alteredDefinition as CFDictionary), "An unsafe administrator rule was accepted: \(key)")
        }
        var receivedFlags: AuthorizationFlags = []
        var privilegedWorkCount = 0
        let successfulResult = try GatewayAdminAuthorization.perform(request: { flags in
            receivedFlags = flags
            return errAuthorizationSuccess
        }, operation: {
            privilegedWorkCount += 1
            return "authorized operation completed"
        })
        check(receivedFlags.contains(.extendRights), "The helper must obtain the actual right, not merely inspect preauthorization")
        check(receivedFlags.contains(.interactionAllowed), "The helper must allow the native per-operation authorization prompt")
        check(!receivedFlags.contains(.preAuthorize), "The privileged action must not accept preauthorization as a grant")
        check(successfulResult == "authorized operation completed" && privilegedWorkCount == 1,
              "Exactly one operation must run after successful authorization")
        for status in [errAuthorizationCanceled, errAuthorizationDenied, errAuthorizationInteractionNotAllowed] {
            do {
                _ = try GatewayAdminAuthorization.perform(request: { _ in status }, operation: {
                    privilegedWorkCount += 1
                })
                fatalError("A failed authorization reached privileged work")
            } catch let error as GatewayAdminFailure {
                guard case .authorization(let recordedStatus) = error else {
                    fatalError("Authorization failure lost its status")
                }
                check(recordedStatus == status, "The diagnostic must preserve the safe macOS status code")
                check(error.exitCode == (status == errAuthorizationCanceled ? 130 : 77),
                      "Native cancellation must remain distinct from authorization failure")
                check(privilegedWorkCount == 1, "A failed authorization must not stop a gateway or change files")
                check(error.localizedDescription.contains(String(status)), "The safe status code must remain available for diagnosis")
            }
        }
        try testStagedGatewayCopy(root: root)
        try testOwnershipRepair(root: root)
        try testRepairOrder()
        testRootProcessRecord()
        try testVendorPolicyGuard(root: root)

        var idle = GatewayAdminIdleState()
        check(idle.isIdle, "The helper should begin idle")
        idle.connected()
        check(!idle.isIdle, "An authenticated client must keep the helper alive")
        idle.operationStarted()
        idle.disconnected()
        check(!idle.isIdle, "An authorized operation must finish after its client disconnects")
        idle.operationFinished()
        let pendingExit = idle.generation
        check(idle.canExit(observedGeneration: pendingExit), "The helper should exit after all work and connections finish")
        idle.connected()
        check(!idle.canExit(observedGeneration: pendingExit), "A new client must cancel a scheduled idle exit")
        idle.disconnected()
        check(!idle.canExit(observedGeneration: pendingExit), "An old idle timer must not terminate a new lifecycle")
        check(idle.canExit(observedGeneration: idle.generation), "The new idle generation should permit exit")
        print("Gateway administrator helper: \(checks) security checks passed")
    }

    /// The only program the helper runs is the private copy an earlier app
    /// version staged for the same account, and only to stop it.
    private static func testStagedGatewayCopy(root: URL) throws {
        let firstAccountDirectory = GatewayAdminTrust.stagingDirectory(uid: 501)
        let secondAccountDirectory = GatewayAdminTrust.stagingDirectory(uid: 502)
        check(firstAccountDirectory != secondAccountDirectory, "Private gateway copies must be isolated by authenticated UID")
        check(firstAccountDirectory == GatewayAdminTrust.stagingRoot + "/uid-501" &&
              secondAccountDirectory == GatewayAdminTrust.stagingRoot + "/uid-502",
              "Each account must use only its own fixed root-private directory")
        let fixture = root.appendingPathComponent("staged", isDirectory: true)
        try FileManager.default.createDirectory(at: fixture, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        let native = fixture.appendingPathComponent("defenseclaw-gateway")
        try FileManager.default.copyItem(atPath: CommandLine.arguments[0], toPath: native.path)
        _ = chmod(native.path, 0o700)
        let signer = Process()
        signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        signer.arguments = ["--force", "--sign", "-", native.path]
        signer.standardOutput = FileHandle.nullDevice
        signer.standardError = FileHandle.nullDevice
        try signer.run()
        signer.waitUntilExit()
        check(signer.terminationStatus == 0, "Could not prepare the ad-hoc signed native fixture")
        try GatewayAdminTrust.verifyGatewayIntegrity(at: native.path)
        checks += 1
        let script = fixture.appendingPathComponent("gateway-script")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: script)
        _ = chmod(script.path, 0o700)
        rejects("A script was accepted as the private gateway copy") {
            try GatewayAdminTrust.verifyGatewayIntegrity(at: script.path)
        }
        let invalid = fixture.appendingPathComponent("unsigned-native")
        try Data([0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).write(to: invalid)
        _ = chmod(invalid.path, 0o700)
        rejects("Invalid unsigned Mach-O bytes were accepted") {
            try GatewayAdminTrust.verifyGatewayIntegrity(at: invalid.path)
        }
        let linked = fixture.appendingPathComponent("linked-gateway")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: native)
        rejects("A symlinked private copy was accepted") {
            try GatewayAdminTrust.verifyGatewayIntegrity(at: linked.path)
        }
    }

    /// The ownership repair changes only folders and single-link regular files
    /// owned by the repaired owner inside the home, through their own
    /// descriptors; it never follows a symlink and skips hard links and
    /// special files. This account stands in for root and a recorder stands
    /// in for fchown, so the walk is observable without privilege.
    private static func testOwnershipRepair(root: URL) throws {
        let fm = FileManager.default
        let home = root.appendingPathComponent("repair-home", isDirectory: true)
        let outside = root.appendingPathComponent("outside", isDirectory: true)
        for directory in [home, outside, home.appendingPathComponent("hooks", isDirectory: true),
                          home.appendingPathComponent("hooks/nested", isDirectory: true)] {
            try fm.createDirectory(at: directory, withIntermediateDirectories: false,
                                   attributes: [.posixPermissions: NSNumber(value: 0o700)])
        }
        for name in ["gateway.pid", "hook_contract_lock.json", "hooks/.hook-codex.token", "hooks/nested/state.json"] {
            try Data("x".utf8).write(to: home.appendingPathComponent(name))
            _ = chmod(home.appendingPathComponent(name).path, 0o600)
        }
        let secret = outside.appendingPathComponent("system-file")
        try Data("not DefenseClaw's".utf8).write(to: secret)
        try fm.createSymbolicLink(at: home.appendingPathComponent("linked-file"), withDestinationURL: secret)
        try fm.createSymbolicLink(at: home.appendingPathComponent("linked-folder"), withDestinationURL: outside)
        check(link(secret.path, home.appendingPathComponent("hard-linked").path) == 0, "Could not prepare the hard-link fixture")
        check(mkfifo(home.appendingPathComponent("pipe").path, 0o600) == 0, "Could not prepare the named-pipe fixture")

        var changed: [String] = []
        var descriptorsWereOpen = true
        let outcome = try GatewayAdminOwnershipRepair.restore(
            home: home.path, from: getuid(), to: (getuid(), getgid()),
            change: { descriptor, relative in
                var metadata = stat()
                descriptorsWereOpen = descriptorsWereOpen && fstat(descriptor, &metadata) == 0
                changed.append(relative)
                return 0
            })
        check(descriptorsWereOpen, "Every change must go through an open descriptor")
        check(Set(changed) == [".", "gateway.pid", "hook_contract_lock.json", "hooks", "hooks/.hook-codex.token",
                               "hooks/nested", "hooks/nested/state.json"],
              "Only the home's own folders and files are returned: \(changed)")
        check(!changed.contains(where: { $0.hasPrefix("linked") || $0 == "hard-linked" || $0 == "pipe" }),
              "Symlinks, hard links and special files must never be changed")
        check(Set(outcome.skipped) == ["hard-linked", "pipe"], "Skipped root-owned items are reported: \(outcome.skipped)")
        check(outcome.restored.count == changed.count && !outcome.incomplete, "The outcome must match the changes")
        check(outcome.summary.contains("Returned 7 root-owned files and folders"), "The summary must count the repair: \(outcome.summary)")

        let bounded = try GatewayAdminOwnershipRepair.restore(
            home: home.path, from: getuid(), to: (getuid(), getgid()), maximumEntries: 2,
            change: { _, _ in 0 })
        check(bounded.incomplete, "A walk over its entry budget must report itself incomplete")
        let untouched = try GatewayAdminOwnershipRepair.restore(
            home: home.path, from: getuid() &+ 1, to: (getuid(), getgid()),
            change: { _, relative in fatalError("A file of another owner was changed: \(relative)") })
        check(untouched.restored.isEmpty && untouched.summary.contains("No root-owned"), "Nothing else is changed")
        rejects("A symlinked home was walked") {
            _ = try GatewayAdminOwnershipRepair.restore(
                home: home.appendingPathComponent("linked-folder").path, from: getuid(), to: (getuid(), getgid()),
                change: { _, relative in fatalError("A symlinked home was followed: \(relative)") })
        }
    }

    /// Stop first, and only through the helper's own copy; never change files
    /// while a root gateway still serves the home; then return the files and
    /// delete the copy.
    private static func testRepairOrder() throws {
        var calls: [String] = []
        var liveAfterStop = false
        var live = true
        func perform(staged: String?) throws -> (Int32, String) {
            try GatewayAdminRepair.perform(
                stagedGateway: staged,
                liveRootGateway: { calls.append("live?"); return live ? 42 : nil },
                stop: { gateway in
                    calls.append("stop " + gateway)
                    live = liveAfterStop
                    return (0, "stopped\n")
                },
                restoreOwnership: {
                    calls.append("restore")
                    return GatewayAdminOwnershipRepair.Outcome(restored: ["gateway.pid"])
                },
                removeStagedGateway: { calls.append("remove") })
        }
        var result = try perform(staged: "private-copy")
        check(result.0 == 0 && calls == ["stop private-copy", "live?", "restore", "remove"],
              "A staged root gateway is stopped before its files are returned and its copy deleted: \(calls)")
        check(result.1.contains("Stopped the gateway") && result.1.contains("Returned 1"), "The repair reports what it did")

        calls = []; live = true; liveAfterStop = true
        result = try perform(staged: "private-copy")
        check(result.0 != 0 && calls == ["stop private-copy", "live?"], "A gateway that did not stop keeps its files untouched")

        calls = []; live = true
        result = try perform(staged: nil)
        check(result.0 != 0 && calls == ["live?"] && result.1.contains("sudo defenseclaw-gateway stop"),
              "A root gateway the helper did not start is never stopped or touched by the helper")

        calls = []; live = false
        result = try perform(staged: nil)
        check(result.0 == 0 && calls == ["live?", "restore", "remove"], "Leftover root files are returned when nothing runs")
    }

    private static func testRootProcessRecord() {
        check(GatewayAdminRootProcess.record(from: Data("1234\n".utf8))! == (1234, ""), "The plain PID format is read")
        let json = Data(#"{"pid": 4321, "executable": "/Library/PrivilegedHelperTools/x/defenseclaw-gateway"}"#.utf8)
        check(GatewayAdminRootProcess.record(from: json)! == (4321, "/Library/PrivilegedHelperTools/x/defenseclaw-gateway"),
              "The JSON PID envelope is read")
        for bad in ["", "abc", "-1", "0", #"{"pid": "12"}"#, #"{"pid": 1.5}"#, #"[1]"#] {
            check(GatewayAdminRootProcess.record(from: Data(bad.utf8)) == nil, "A malformed PID record was accepted: \(bad)")
        }
        check(GatewayAdminRootProcess.owner(of: getpid()) == getuid(), "The process owner comes from the kernel")
        let gateway = (pid: pid_t(7), executable: "/opt/staged/defenseclaw-gateway")
        check(GatewayAdminRootProcess.isRootGateway(gateway, owner: { _ in 0 }, executable: { _ in gateway.executable }),
              "A live root process running the recorded executable is the root gateway")
        check(!GatewayAdminRootProcess.isRootGateway(gateway, owner: { _ in 501 }, executable: { _ in gateway.executable }),
              "A gateway run as the account is not a root gateway")
        check(!GatewayAdminRootProcess.isRootGateway(gateway, owner: { _ in 0 }, executable: { _ in "/usr/sbin/cron" }),
              "A reused PID of another root program is not the gateway")
        check(GatewayAdminRootProcess.isRootGateway((7, ""), owner: { _ in 0 }, executable: { _ in "/x/defenseclaw-gateway" }),
              "A legacy integer record matches a defenseclaw-gateway program")
        check(GatewayAdminRootProcess.liveRootGateway(home: "/nonexistent-defenseclaw-home") == nil,
              "A home without a PID record has no root gateway")
    }

    /// The vendor policy repair only ever touches the fixed list, only real
    /// directory chains, only folders owned by the expected account that others
    /// cannot traverse; it removes empty trees with rmdir and leaves populated
    /// folders private. Fixtures stand in for /etc/codex and friends, with
    /// this account standing in for root.
    private static func testVendorPolicyGuard(root: URL) throws {
        let fm = FileManager.default
        let owner = getuid()
        let etc = root.appendingPathComponent("etc", isDirectory: true)
        try fm.createDirectory(at: etc, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: NSNumber(value: 0o755)])
        func make(_ path: URL, mode: Int) throws {
            try fm.createDirectory(at: path, withIntermediateDirectories: true)
            _ = chmod(path.path, mode_t(mode))
        }
        func mode(_ path: URL) -> Int { Int((try? fm.attributesOfItem(atPath: path.path)[.posixPermissions] as? NSNumber)?.intValue ?? -1) }

        // An unreadable tree of only empty folders (the watcher's /etc/codex/skills) is removed.
        let codex = etc.appendingPathComponent("codex", isDirectory: true)
        try make(codex.appendingPathComponent("skills", isDirectory: true), mode: 0o700)
        _ = chmod(codex.path, 0o700)
        // A private folder with real content stays private, including nested folders.
        let cursor = etc.appendingPathComponent("cursor", isDirectory: true)
        let nested = cursor.appendingPathComponent("policy.d", isDirectory: true)
        try make(nested, mode: 0o700)
        let policy = nested.appendingPathComponent("hooks.json")
        try Data("{}".utf8).write(to: policy)
        _ = chmod(policy.path, 0o644)
        _ = chmod(nested.path, 0o700)
        _ = chmod(cursor.path, 0o700)
        // A readable folder is left alone.
        let copilot = etc.appendingPathComponent("github-copilot", isDirectory: true)
        try make(copilot.appendingPathComponent("policy.d", isDirectory: true), mode: 0o700)
        _ = chmod(copilot.path, 0o755)
        // A symlinked vendor folder and a folder behind a symlinked parent are never followed.
        let elsewhere = root.appendingPathComponent("elsewhere", isDirectory: true)
        try make(elsewhere, mode: 0o700)
        let opencode = etc.appendingPathComponent("opencode")
        try fm.createSymbolicLink(at: opencode, withDestinationURL: elsewhere)
        let linkedEtc = root.appendingPathComponent("linked-etc")
        try fm.createSymbolicLink(at: linkedEtc, withDestinationURL: etc)
        let viaLink = linkedEtc.appendingPathComponent("cursor", isDirectory: true)
        // A folder owned by a different account is left alone.
        let claude = etc.appendingPathComponent("ClaudeCode", isDirectory: true)
        try make(claude, mode: 0o700)

        let outcome = GatewayAdminVendorPolicyGuard.sweep(
            directories: [codex.path, cursor.path, copilot.path, opencode.path, viaLink.path, root.appendingPathComponent("etc/missing").path],
            owner: owner)
        check(outcome.removed == [codex.path], "Only the empty unreadable tree is removed: \(outcome.removed)")
        check(!fm.fileExists(atPath: codex.path), "The empty unreadable vendor folder must be gone")
        check(outcome.preserved == [cursor.path], "Only the populated private folder is preserved: \(outcome.preserved)")
        check(mode(cursor) == 0o700 && mode(nested) == 0o700 && mode(policy) == 0o644,
              "Private policy directory permissions must not be broadened")
        check(fm.fileExists(atPath: policy.path), "Policy content must survive the repair")
        check(mode(copilot) == 0o755 && mode(copilot.appendingPathComponent("policy.d")) == 0o700,
              "A readable folder and what is below it stay untouched")
        check(mode(elsewhere) == 0o700, "A symlinked vendor folder must never be followed")
        check(outcome.notes.count == 2, "One note per outcome, got \(outcome.notes)")

        let foreign = GatewayAdminVendorPolicyGuard.sweep(directories: [claude.path], owner: owner &+ 1)
        check(foreign.removed.isEmpty && foreign.preserved.isEmpty && mode(claude) == 0o700,
              "A folder owned by another account must be left alone")

        // settle reports nothing when nothing needs repair.
        check(GatewayAdminVendorPolicyGuard.settle(owner: owner, directories: [copilot.path]).isEmpty,
              "A clean sweep must add nothing to the activity record")
        let preservedNote = GatewayAdminVendorPolicyGuard.settle(owner: owner, directories: [cursor.path])
        check(preservedNote.components(separatedBy: "Left \(cursor.path) private:").count == 2,
              "A preserved private policy is reported once")
        _ = chmod(claude.path, 0o700)
        let settled = GatewayAdminVendorPolicyGuard.settle(owner: owner, directories: [claude.path])
        check(settled.contains("Removed " + claude.path), "A settle pass must report the repair: \(settled)")
        check(!fm.fileExists(atPath: claude.path), "The settle pass must perform the repair")
    }
}
