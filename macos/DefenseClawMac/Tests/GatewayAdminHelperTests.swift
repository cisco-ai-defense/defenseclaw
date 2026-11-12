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
        func install(_ home: URL, config: URL? = nil) throws -> GatewayAdminInstallation {
            try GatewayAdminInstallation(home: home.path, config: (config ?? home.appendingPathComponent("config.yaml")).path,
                                         account: account)
        }
        _ = try install(home)
        checks += 1

        rejects("Another account's installation was accepted") {
            _ = try GatewayAdminInstallation(home: "/Users/other-account/.defenseclaw",
                config: "/Users/other-account/.defenseclaw/config.yaml", account: account)
        }
        rejects("A configuration outside the selected home was accepted") {
            _ = try install(home, config: root.appendingPathComponent("config.yaml"))
        }
        rejects("A configuration elsewhere inside the home was accepted as the DefenseClaw marker") {
            _ = try install(home, config: home.appendingPathComponent("sub/config.yaml"))
        }
        rejects("A managed installation was accepted") {
            _ = try GatewayAdminInstallation(home: "/opt/cisco/secureclient/defenseclaw",
                config: "/opt/cisco/secureclient/defenseclaw/config.yaml", account: account)
        }
        rejects("The entire account home was accepted as runtime root") {
            _ = try GatewayAdminInstallation(home: account.home, config: account.home + "/config.yaml", account: account)
        }
        let unmarked = root.appendingPathComponent("not-defenseclaw", isDirectory: true)
        try FileManager.default.createDirectory(at: unmarked, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        rejects("A folder without a DefenseClaw config.yaml was accepted") { _ = try install(unmarked) }
        let homeLink = root.appendingPathComponent("linked-home")
        try FileManager.default.createSymbolicLink(at: homeLink, withDestinationURL: home)
        rejects("A symlink installation root was accepted") { _ = try install(homeLink) }
        // MF-1: a symlinked PARENT folder must be refused, not resolved.
        let target = root.appendingPathComponent("target", isDirectory: true)
        let targetHome = target.appendingPathComponent("etc", isDirectory: true)
        try FileManager.default.createDirectory(at: targetHome, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        try Data("config_version: 8\n".utf8).write(to: targetHome.appendingPathComponent("config.yaml"))
        _ = chmod(targetHome.appendingPathComponent("config.yaml").path, 0o600)
        let linkedParent = root.appendingPathComponent("linked-parent")
        try FileManager.default.createSymbolicLink(at: linkedParent, withDestinationURL: target)
        rejects("A home below a symlinked parent folder was accepted") {
            _ = try install(linkedParent.appendingPathComponent("etc", isDirectory: true))
        }
        try testMidWalkSwap(root: root, account: account)

        let configLink = home.appendingPathComponent("linked.yaml")
        try FileManager.default.createSymbolicLink(at: configLink, withDestinationURL: config)
        let linkedConfigHome = root.appendingPathComponent("linked-config-home", isDirectory: true)
        try FileManager.default.createDirectory(at: linkedConfigHome, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        try FileManager.default.createSymbolicLink(at: linkedConfigHome.appendingPathComponent("config.yaml"),
                                                   withDestinationURL: config)
        rejects("A symlink configuration was accepted") { _ = try install(linkedConfigHome) }
        _ = chmod(config.path, 0o666)
        rejects("A world-writable configuration was accepted") { _ = try install(home) }
        _ = chmod(config.path, 0o600)
        _ = chmod(home.path, 0o770)
        rejects("A group-writable runtime root was accepted") { _ = try install(home) }
        _ = chmod(home.path, 0o700)

        let grantACL = Process()
        grantACL.executableURL = URL(fileURLWithPath: "/bin/chmod")
        grantACL.arguments = ["+a", "everyone allow write", config.path]
        try grantACL.run()
        grantACL.waitUntilExit()
        check(grantACL.terminationStatus == 0, "Could not prepare the isolated ACL fixture")
        rejects("An ACL-writable configuration was accepted") { _ = try install(home) }

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
        testStagedExecutables()
        try testOwnershipRepair(root: root, account: account)
        try testRepairOrder()
        try testRootProcessRecord(root: root)
        try testStop()
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

    /// MF-1: a parent folder swapped for a symlink while the home is being
    /// opened is refused; one renamed away leaves the descriptor on the folder
    /// that was verified, never on the symlink target.
    private static func testMidWalkSwap(root: URL, account: InvokingAccount) throws {
        let fm = FileManager.default
        let base = root.appendingPathComponent("swap", isDirectory: true)
        let parent = base.appendingPathComponent("parent", isDirectory: true)
        let home = parent.appendingPathComponent("home", isDirectory: true)
        let outside = root.appendingPathComponent("swap-outside", isDirectory: true)
        let outsideHome = outside.appendingPathComponent("home", isDirectory: true)
        for directory in [home, outsideHome] {
            try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: NSNumber(value: 0o700)])
            try Data("config_version: 8\n".utf8).write(to: directory.appendingPathComponent("config.yaml"))
            _ = chmod(directory.appendingPathComponent("config.yaml").path, 0o600)
        }
        let components = home.path.dropFirst(account.home.count + 1).split(separator: "/").count
        let baseIndex = components - 3
        func swapParent() {
            guard rename(parent.path, base.appendingPathComponent("parent-moved").path) == 0,
                  symlink(outside.path, parent.path) == 0 else { fatalError("Could not swap the parent fixture") }
        }
        func restoreParent() {
            _ = unlink(parent.path)
            _ = rename(base.appendingPathComponent("parent-moved").path, parent.path)
        }
        // Swap after `base` is open, before `parent` is: the next openat meets a symlink.
        GatewayAdminInstallation.componentOpenedForTesting = { index in if index == baseIndex { swapParent() } }
        rejects("A parent folder swapped for a symlink during the walk was followed") {
            _ = try GatewayAdminInstallation(home: home.path, config: home.path + "/config.yaml", account: account)
        }
        GatewayAdminInstallation.componentOpenedForTesting = nil
        restoreParent()
        // Swap after `parent` is open: the descriptor stays on the verified folder.
        GatewayAdminInstallation.componentOpenedForTesting = { index in if index == baseIndex + 1 { swapParent() } }
        let installation = try GatewayAdminInstallation(home: home.path, config: home.path + "/config.yaml", account: account)
        GatewayAdminInstallation.componentOpenedForTesting = nil
        var opened = stat()
        var original = stat()
        var redirected = stat()
        check(fstat(installation.descriptor, &opened) == 0
              && stat(base.appendingPathComponent("parent-moved/home").path, &original) == 0
              && stat(outsideHome.path, &redirected) == 0, "Could not inspect the swap fixtures")
        check(opened.st_ino == original.st_ino && opened.st_ino != redirected.st_ino,
              "The home descriptor must stay on the verified folder, not the symlink target")
        restoreParent()
    }

    /// The helper stops only processes running its own fixed private copies.
    private static func testStagedExecutables() {
        let firstAccountDirectory = GatewayAdminTrust.stagingDirectory(uid: 501)
        let secondAccountDirectory = GatewayAdminTrust.stagingDirectory(uid: 502)
        check(firstAccountDirectory != secondAccountDirectory, "Private gateway copies must be isolated by authenticated UID")
        check(firstAccountDirectory == GatewayAdminTrust.stagingRoot + "/uid-501" &&
              secondAccountDirectory == GatewayAdminTrust.stagingRoot + "/uid-502",
              "Each account must use only its own fixed root-private directory")
        let staged = GatewayAdminTrust.stagedExecutables(uid: 501)
        check(staged.contains(firstAccountDirectory + "/defenseclaw-gateway")
              && staged.contains(GatewayAdminTrust.stagingRoot + "/defenseclaw-gateway")
              && !staged.contains(secondAccountDirectory + "/defenseclaw-gateway")
              && staged.allSatisfy { $0.contains(GatewayAdminTrust.stagingRoot) },
              "Only this account's and the legacy root-only copies are the helper's executables")
    }

    /// The ownership repair changes only DefenseClaw's own names in the home
    /// (and what their folders hold), only folders and single-link regular
    /// files owned by the repaired owner, through their own descriptors; it
    /// never follows a symlink and skips hard links and special files. This
    /// account stands in for root and a recorder stands in for fchown.
    private static func testOwnershipRepair(root: URL, account: InvokingAccount) throws {
        let fm = FileManager.default
        let home = root.appendingPathComponent("repair-home", isDirectory: true)
        let outside = root.appendingPathComponent("outside", isDirectory: true)
        for directory in [home, outside, home.appendingPathComponent("hooks", isDirectory: true),
                          home.appendingPathComponent("hooks/nested", isDirectory: true),
                          home.appendingPathComponent("Documents", isDirectory: true),
                          home.appendingPathComponent(".venv", isDirectory: true)] {
            try fm.createDirectory(at: directory, withIntermediateDirectories: false,
                                   attributes: [.posixPermissions: NSNumber(value: 0o700)])
        }
        for name in ["config.yaml", "gateway.pid", "hook_contract_lock.json", "hooks/.hook-codex.token",
                     "hooks/nested/state.json", "Documents/notes.txt", ".venv/pyvenv.cfg", "unrelated.txt"] {
            try Data("x".utf8).write(to: home.appendingPathComponent(name))
            _ = chmod(home.appendingPathComponent(name).path, 0o600)
        }
        let secret = outside.appendingPathComponent("system-file")
        try Data("not DefenseClaw's".utf8).write(to: secret)
        try fm.createSymbolicLink(at: home.appendingPathComponent("gateway.log"), withDestinationURL: secret)
        try fm.createSymbolicLink(at: home.appendingPathComponent("cache"), withDestinationURL: outside)
        check(link(secret.path, home.appendingPathComponent("device.key").path) == 0, "Could not prepare the hard-link fixture")
        check(mkfifo(home.appendingPathComponent("watchdog.pid").path, 0o600) == 0, "Could not prepare the named-pipe fixture")

        let installation = try GatewayAdminInstallation(home: home.path, config: home.path + "/config.yaml", account: account)
        var changed: [String] = []
        var descriptorsWereOpen = true
        let outcome = try GatewayAdminOwnershipRepair.restore(
            home: installation.descriptor, from: getuid(), to: (getuid(), getgid()),
            change: { descriptor, relative in
                var metadata = stat()
                descriptorsWereOpen = descriptorsWereOpen && fstat(descriptor, &metadata) == 0
                changed.append(relative)
                return 0
            })
        check(descriptorsWereOpen, "Every change must go through an open descriptor")
        check(Set(changed) == [".", "config.yaml", "gateway.pid", "hook_contract_lock.json", "hooks",
                               "hooks/.hook-codex.token", "hooks/nested", "hooks/nested/state.json"],
              "Only DefenseClaw's own files and folders are returned: \(changed)")
        check(!changed.contains(where: { $0.hasPrefix("Documents") || $0.hasPrefix(".venv") || $0 == "unrelated.txt" }),
              "Nothing outside DefenseClaw's own names is ever changed")
        check(!changed.contains(where: { ["gateway.log", "cache", "device.key", "watchdog.pid"].contains($0) }),
              "Symlinks, hard links and special files must never be changed")
        check(Set(outcome.skipped) == ["device.key", "watchdog.pid"], "Skipped root-owned items are reported: \(outcome.skipped)")
        check(outcome.restored.count == changed.count && !outcome.incomplete, "The outcome must match the changes")
        check(outcome.summary.contains("Returned 8 root-owned files and folders"), "The summary must count the repair: \(outcome.summary)")

        let bounded = try GatewayAdminOwnershipRepair.restore(
            home: installation.descriptor, from: getuid(), to: (getuid(), getgid()), maximumEntries: 2,
            change: { _, _ in 0 })
        check(bounded.incomplete, "A walk over its entry budget must report itself incomplete")
        let untouched = try GatewayAdminOwnershipRepair.restore(
            home: installation.descriptor, from: getuid() &+ 1, to: (getuid(), getgid()),
            change: { _, relative in fatalError("A file of another owner was changed: \(relative)") })
        check(untouched.restored.isEmpty && untouched.summary.contains("No root-owned"), "Nothing else is changed")
    }

    /// Nothing changes while a root gateway the helper did not start runs;
    /// helper-started processes are stopped first; files are returned only
    /// once none runs; then the private copy is deleted.
    private static func testRepairOrder() throws {
        typealias Live = GatewayAdminRootProcess.Live
        let watchdog = Live(record: "watchdog.pid", pid: 41, startIdentity: "1.000001")
        let gateway = Live(record: "gateway.pid", pid: 42, startIdentity: "1.000002")
        var calls: [String] = []
        var found = GatewayAdminRootProcess.Found(helperStarted: [watchdog, gateway])
        var stops = true
        func perform() throws -> (Int32, String) {
            try GatewayAdminRepair.perform(
                liveRootProcesses: { calls.append("live?"); return found },
                stop: { processes in
                    calls.append("stop " + processes.map(\.record).joined(separator: ","))
                    if stops { found = GatewayAdminRootProcess.Found() }
                    return stops
                },
                restoreOwnership: {
                    calls.append("restore")
                    return GatewayAdminOwnershipRepair.Outcome(restored: ["gateway.pid"])
                },
                removeStagedGateway: { calls.append("remove") })
        }
        var result = try perform()
        check(result.0 == 0 && calls == ["live?", "stop watchdog.pid,gateway.pid", "live?", "restore", "remove"],
              "The watchdog then the gateway are stopped before files are returned and the copy deleted: \(calls)")
        check(result.1.contains("Stopped the gateway") && result.1.contains("Returned 1"), "The repair reports what it did")

        calls = []; found = GatewayAdminRootProcess.Found(helperStarted: [gateway]); stops = false
        result = try perform()
        check(result.0 != 0 && calls == ["live?", "stop gateway.pid"], "A gateway that did not stop keeps its files untouched")

        calls = []; found = GatewayAdminRootProcess.Found(helperStarted: [gateway], other: [watchdog]); stops = true
        result = try perform()
        check(result.0 == 75 && calls == ["live?"] && result.1.contains("sudo defenseclaw-gateway stop"),
              "Nothing is stopped or changed while a root gateway the helper did not start runs")

        calls = []; found = GatewayAdminRootProcess.Found()
        result = try perform()
        check(result.0 == 0 && calls == ["live?", "restore", "remove"], "Leftover root files are returned when nothing runs")
    }

    private static func testRootProcessRecord(root: URL) throws {
        check(GatewayAdminRootProcess.record(from: Data("1234\n".utf8)) == GatewayAdminRootProcess.Record(pid: 1234), "The plain PID format is read")
        let json = Data(#"{"pid": 4321, "executable": "/x/defenseclaw-gateway", "start_identity": "1700000000.123456"}"#.utf8)
        check(GatewayAdminRootProcess.record(from: json)
              == GatewayAdminRootProcess.Record(pid: 4321, executable: "/x/defenseclaw-gateway", startIdentity: "1700000000.123456"),
              "The JSON PID envelope is read")
        for bad in ["", "abc", "-1", "0", #"{"pid": "12"}"#, #"{"pid": 1.5}"#, #"[1]"#] {
            check(GatewayAdminRootProcess.record(from: Data(bad.utf8)) == nil, "A malformed PID record was accepted: \(bad)")
        }
        check(GatewayAdminRootProcess.owner(of: getpid()) == getuid(), "The process owner comes from the kernel")
        let identity = GatewayAdminRootProcess.startIdentity(of: getpid()) ?? ""
        check(GatewayAdminRootProcess.isComparableIdentity(identity), "The start identity uses the daemon's sec.usec form: \(identity)")
        check(!GatewayAdminRootProcess.isComparableIdentity("Thu Nov  5 10:00:00 2026"), "A legacy lstart string is not compared")

        let staged: Set<String> = ["/staged/defenseclaw-gateway"]
        let record = GatewayAdminRootProcess.Record(pid: 7, executable: "/staged/defenseclaw-gateway", startIdentity: "5.000006")
        func classify(_ record: GatewayAdminRootProcess.Record, owner: uid_t = 0, path: String = "/staged/defenseclaw-gateway",
                      started: String = "5.000006") -> GatewayAdminRootProcess.Kind? {
            GatewayAdminRootProcess.classify(record, staged: staged, owner: { _ in owner }, executable: { _ in path },
                                             startIdentity: { _ in started })?.0
        }
        check(classify(record) == .helperStarted, "A root process running the helper's copy is the helper's gateway")
        check(classify(record, owner: 501) == nil, "A gateway run as the account is not a root gateway")
        check(classify(record, started: "9.000001") == nil, "A reused PID (other start identity) is never the gateway")
        check(classify(record, path: "/usr/sbin/cron") == nil, "A reused PID of another root program is not the gateway")
        let sudoRecord = GatewayAdminRootProcess.Record(pid: 7, executable: "/Users/a/.local/bin/defenseclaw-gateway")
        check(classify(sudoRecord, path: "/Users/a/.local/bin/defenseclaw-gateway") == .other,
              "A root gateway started outside the helper is reported, not stopped")
        check(classify(.init(pid: 7), path: "/x/defenseclaw-gateway") == .other, "A legacy integer record matches by program name")

        // REVIEW-2 NH-1: a record the account wrote (not root-owned, or hard-linked) never selects a process to signal.
        check(GatewayAdminRootProcess.place(.helperStarted, trusted: true) == .helperStarted,
              "A root-owned single-link record of the helper's gateway is signalled")
        check(GatewayAdminRootProcess.place(.helperStarted, trusted: false) == .other,
              "An untrusted record naming the helper's copy makes the repair refuse instead of signalling")
        check(GatewayAdminRootProcess.place(.other, trusted: true) == .other, "A foreign root gateway is never signalled")
        let forged = root.appendingPathComponent("forged-records", isDirectory: true)
        try FileManager.default.createDirectory(at: forged, withIntermediateDirectories: false)
        try Data(#"{"pid": 1, "start_identity": "1.000001"}"#.utf8).write(to: forged.appendingPathComponent("gateway.pid"))
        let forgedDescriptor = open(forged.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        defer { close(forgedDescriptor) }
        let forgedRecord = GatewayAdminRootProcess.readRecord(in: forgedDescriptor, name: "gateway.pid")
        check(forgedRecord?.record.pid == 1 && forgedRecord?.trusted == false,
              "A PID record owned by the account is read but not trusted")

        let missing = root.appendingPathComponent("no-records", isDirectory: true)
        try FileManager.default.createDirectory(at: missing, withIntermediateDirectories: false)
        let descriptor = open(missing.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        defer { close(descriptor) }
        check(GatewayAdminRootProcess.live(in: descriptor, uid: getuid()).isEmpty, "A home without PID records has no root gateway")
    }

    /// The stop signals only while the process is still the verified one,
    /// escalates to SIGKILL after the grace period, and reports failure when
    /// the process outlives both.
    private static func testStop() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["60"]
        try child.run()
        let live = GatewayAdminRootProcess.Live(record: "gateway.pid", pid: child.processIdentifier, startIdentity: "")
        var signals: [Int32] = []
        check(GatewayAdminStop.stop([live], isSame: { _ in child.isRunning }, signal: { pid, signal in
            signals.append(signal)
            return Darwin.kill(pid, signal)
        }, grace: .seconds(5)), "A verified process is stopped")
        check(signals == [SIGTERM] && !child.isRunning, "SIGTERM is enough for a process that exits")

        signals = []
        check(!GatewayAdminStop.stop([live], isSame: { _ in true }, signal: { _, signal in signals.append(signal); return 0 },
                                     grace: .milliseconds(200), killGrace: .milliseconds(200)),
              "A process that outlives SIGKILL is reported as not stopped")
        check(signals == [SIGTERM, SIGKILL], "SIGKILL follows the grace period")

        signals = []
        check(GatewayAdminStop.stop([live], isSame: { _ in false }, signal: { _, signal in signals.append(signal); return 0 }),
              "A process that is no longer the verified one counts as stopped")
        check(signals.isEmpty, "A process that is no longer the verified one is never signalled")
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
