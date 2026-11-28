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

extension GatewayAdminAgentConfigRepair {
    /// Runs after a listed file passed its checks, before it is moved into
    /// the holding folder (main.swift calls it in GATEWAY_ADMIN_HELPER_TESTING builds only).
    static var fileCheckedForTesting: ((String) -> Void)?
}

extension GatewayAdminOwnershipRepair {
    /// Runs after a walked file passed its checks, before it is moved into
    /// the holding folder (main.swift calls it in GATEWAY_ADMIN_HELPER_TESTING builds only).
    static var walkFileCheckedForTesting: ((String) -> Void)?
}

extension GatewayAdminHandover {
    /// Runs after a file to hand over was opened, before its descriptor is
    /// checked (main.swift calls it in GATEWAY_ADMIN_HELPER_TESTING builds
    /// only), with the name the walk shows.
    static var openedForTesting: ((String) -> Void)?
    /// Runs right after a file was moved into the holding folder; true
    /// stops the repair there, as if the helper died (GAP-1972).
    static var movedForTesting: ((String) -> Bool)?
}

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
        if CommandLine.arguments.count == 3, CommandLine.arguments[2] == "--real-root" {
            try testRealRootAgentConfigRepair(root: URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true))
            print("Gateway administrator helper: \(checks) real-root checks passed")
            return
        }
        guard CommandLine.arguments.count == 2, getuid() != 0 else {
            fatalError("Run these tests as a normal user with a private fixture directory.")
        }
        let account = try InvokingAccount(uid: getuid())
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        // The holding folder's parent: a private folder of this account
        // reached without a link (the helper's is /private/var/db).
        let holdingParent = root.resolvingSymlinksInPath().appendingPathComponent("var-db", isDirectory: true)
        try FileManager.default.createDirectory(at: holdingParent, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        GatewayAdminHandover.holdingParent = holdingParent.path
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
        try testAgentConfigRepair(root: root, account: account)
        try testAgentConfigFolderRules(root: root)
        try testAgentConfigFileEdgeCases(root: root)
        try testHardLinkUnlinkedAtOpen(root: root)
        try testHeldFileRecovery(root: root)
        try testAgentConfigFolderWalkSwap(root: root)
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
        // GAP-2003: a walk past its deadline stops where it is and says to
        // repair again, so the helper answers inside the app's reply budget;
        // the next repair returns the rest.
        let late = try GatewayAdminOwnershipRepair.restore(
            home: installation.descriptor, from: getuid(), to: (getuid(), getgid()), until: ContinuousClock.now,
            change: { _, relative in fatalError("A walk past its deadline changed \(relative)") })
        check(late.unfinished && late.incomplete && late.restored.isEmpty,
              "A walk past its deadline must stop before it changes anything and report itself unfinished")
        check(late.summary.contains("repair again"), "An unfinished repair must say to repair again: \(late.summary)")
        let resumed = try GatewayAdminOwnershipRepair.restore(
            home: installation.descriptor, from: getuid(), to: (getuid(), getgid()),
            until: ContinuousClock.now.advanced(by: .seconds(60)), change: { _, _ in 0 })
        check(!resumed.unfinished && !resumed.incomplete && resumed.restored.count == changed.count,
              "A walk inside its deadline returns everything: \(resumed.restored)")
        let lateConfig = GatewayAdminAgentConfigRepair.restore(
            home: installation.descriptor, from: getuid(), to: (getuid(), getgid()), paths: ["hooks/nested/state.json"],
            until: ContinuousClock.now, change: { _, relative in fatalError("A late agent config walk changed \(relative)") })
        check(lateConfig.restored.isEmpty, "An agent config repair past its deadline changes nothing")
        check(GatewayAdminPolicy.repairWalkSeconds > 0
              && GatewayAdminPolicy.repairWalkSeconds + 30 <= GatewayAdminPolicy.repairReplySeconds,
              "The helper's walk deadline must leave the reply time inside the app's budget")
        let untouched = try GatewayAdminOwnershipRepair.restore(
            home: installation.descriptor, from: getuid() &+ 1, to: (getuid(), getgid()),
            change: { _, relative in fatalError("A file of another owner was changed: \(relative)") })
        check(untouched.restored.isEmpty && untouched.summary.contains("No root-owned"), "Nothing else is changed")
    }

    /// v1.1.36 port: agent config files outside the DefenseClaw home. With the
    /// account as the "root" owner every folder is entered, so only the file
    /// rules decide; with another account uid, an owned folder on the way is a
    /// "root-owned" folder and is returned whole, once.
    private static func testAgentConfigRepair(root: URL, account: InvokingAccount) throws {
        let fm = FileManager.default
        let home = root.appendingPathComponent("agent-home", isDirectory: true)
        let outside = root.appendingPathComponent("agent-outside", isDirectory: true)
        for directory in ["", ".claude", ".codex", ".copilot", ".copilot/hooks", ".hermes", ".kiro", ".kiro/agents", ".kiro/hooks"] {
            try fm.createDirectory(at: home.appendingPathComponent(directory, isDirectory: true),
                                   withIntermediateDirectories: false,
                                   attributes: [.posixPermissions: NSNumber(value: 0o700)])
        }
        try fm.createDirectory(at: outside, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        _ = chmod(home.appendingPathComponent(".hermes").path, 0o770)
        let secret = outside.appendingPathComponent("system-file")
        try Data("not the account's".utf8).write(to: secret)
        for name in [".claude/settings.json", ".copilot/hooks/defenseclaw.json", ".hermes/config.yaml",
                     ".kiro/agents/defenseclaw.json", ".kiro/hooks/defenseclaw.json"] {
            try Data("{}".utf8).write(to: home.appendingPathComponent(name))
            _ = chmod(home.appendingPathComponent(name).path, 0o600)
        }
        _ = chmod(home.appendingPathComponent(".copilot/hooks/defenseclaw.json").path, 0o620)
        check(link(secret.path, home.appendingPathComponent(".codex/config.toml").path) == 0, "Could not prepare the hard-link fixture")
        try fm.createSymbolicLink(at: home.appendingPathComponent(".cursor"), withDestinationURL: outside)
        try Data("{}".utf8).write(to: outside.appendingPathComponent("hooks.json"))

        let descriptor = try GatewayAdminAgentConfigRepair.openAccountHome(home.path, uid: getuid())
        defer { close(descriptor) }
        var changed: [String] = []
        var descriptorsWereOpen = true
        let files = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid(), getgid()),
            change: { opened, relative in
                var metadata = stat()
                descriptorsWereOpen = descriptorsWereOpen && fstat(opened, &metadata) == 0
                changed.append(relative)
                return 0
            })
        check(descriptorsWereOpen, "Every agent config change must go through an open descriptor")
        check(Set(changed) == ["~/.claude/settings.json", "~/.kiro/agents/defenseclaw.json", "~/.kiro/hooks/defenseclaw.json"],
              "Only listed single-link regular files under private folders are returned: \(changed)")
        check(files.skipped == ["~/.codex/config.toml", "~/.copilot/hooks/defenseclaw.json"],
              "Hard-linked and group-writable files are reported, not changed: \(files.skipped)")
        check(!changed.contains(where: { $0.hasPrefix("~/.cursor") || $0.hasPrefix("~/.hermes") }),
              "A linked folder is never followed and a shared-writable folder is never entered")
        check(!files.incomplete, "Missing agent configs are not an incomplete repair")

        changed = []
        let folders = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid() &+ 1, getgid()),
            change: { _, relative in changed.append(relative); return 0 })
        check(changed.filter { $0 == "~/.kiro" }.count == 1 && changed.contains("~/.kiro/agents/defenseclaw.json")
              && changed.contains("~/.kiro/hooks/defenseclaw.json"),
              "A root-owned folder on the way is returned whole, once: \(changed)")
        check(changed.contains("~/.claude") && !changed.contains(where: { $0.hasPrefix("~/.cursor") }),
              "Folder returns stay inside the account home: \(changed)")
        check(folders.skipped.contains("~/.codex/config.toml"), "A hard link inside a returned folder stays unchanged")

        let unlisted = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid() &+ 1, to: (getuid(), getgid()),
            change: { _, relative in fatalError("A file of another owner was changed: \(relative)") })
        check(unlisted.restored.isEmpty, "Files of other owners are never changed")

        rejects("A shared-writable account home is refused") {
            _ = chmod(home.path, 0o770)
            defer { _ = chmod(home.path, 0o700) }
            close(try GatewayAdminAgentConfigRepair.openAccountHome(home.path, uid: getuid()))
        }
        rejects("An account home reached through a link is refused") {
            let alias = root.appendingPathComponent("agent-home-link")
            try? fm.createSymbolicLink(at: alias, withDestinationURL: home)
            close(try GatewayAdminAgentConfigRepair.openAccountHome(alias.path, uid: getuid()))
        }
        rejects("Another account's home is refused") {
            close(try GatewayAdminAgentConfigRepair.openAccountHome(home.path, uid: getuid() &+ 1))
        }
        check(GatewayAdminAgentConfigRepair.relativePaths.allSatisfy { !$0.hasPrefix("/") && !$0.contains("..") },
              "The fixed agent config list stays relative to the account home")
    }

    private static func makeFolders(_ base: URL, _ names: [String], mode: mode_t = 0o700) throws {
        for name in names {
            let url = name.isEmpty ? base : base.appendingPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: NSNumber(value: mode)])
        }
    }

    private static func makeFile(_ url: URL, mode: mode_t = 0o600) throws {
        try Data("{}".utf8).write(to: url)
        check(chmod(url.path, mode) == 0, "Could not set the mode of \(url.lastPathComponent)")
    }

    /// GAP-0141: a root-owned agent config folder returned whole follows the
    /// per-file rules (no setuid, setgid, group or other write; no folder
    /// others can write), never follows a link or opens a named pipe for
    /// reading, and is returned only after everything in it was inspected,
    /// so a walk cut short leaves it root-owned (listed by Go) instead of
    /// returning it with unlisted root-owned children. This account stands in
    /// for root; the repaired account is another uid, so its folders count as
    /// root-owned.
    private static func testAgentConfigFolderRules(root: URL) throws {
        let home = root.appendingPathComponent("agent-folder-home", isDirectory: true)
        let outside = root.appendingPathComponent("agent-folder-outside", isDirectory: true)
        try makeFolders(home, ["", ".kiro", ".kiro/agents", ".kiro/settings", ".codex", ".copilot"])
        try makeFolders(home, [".copilot/hooks"], mode: 0o770)
        try makeFolders(outside, [""])
        _ = chmod(home.appendingPathComponent(".copilot/hooks").path, 0o770)
        try makeFile(home.appendingPathComponent(".kiro/agents/defenseclaw.json"))
        try makeFile(home.appendingPathComponent(".copilot/hooks/defenseclaw.json"))
        try makeFile(home.appendingPathComponent(".kiro/settings/cli.json"), mode: 0o620)
        try makeFile(home.appendingPathComponent(".kiro/other-write.json"), mode: 0o602)
        try makeFile(home.appendingPathComponent(".kiro/setuid-tool"), mode: 0o4700)
        check(mkfifo(home.appendingPathComponent(".kiro/pipe").path, 0o600) == 0, "Could not prepare the named-pipe fixture")
        try makeFile(outside.appendingPathComponent("target.json"))
        try FileManager.default.createSymbolicLink(at: home.appendingPathComponent(".kiro/linked.json"),
                                                   withDestinationURL: outside.appendingPathComponent("target.json"))
        try FileManager.default.createSymbolicLink(at: home.appendingPathComponent(".kiro/linked-folder"),
                                                   withDestinationURL: outside)

        let descriptor = try GatewayAdminAgentConfigRepair.openAccountHome(home.path, uid: getuid())
        defer { close(descriptor) }
        var changed: [String] = []
        let rules = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid() &+ 1, getgid()),
            paths: [".kiro/agents/defenseclaw.json", ".kiro/hooks/defenseclaw.json", ".kiro/settings/cli.json"],
            change: { _, relative in changed.append(relative); return 0 })
        check(Set(changed) == ["~/.kiro", "~/.kiro/agents", "~/.kiro/agents/defenseclaw.json", "~/.kiro/settings"],
              "Only private folders and single-link files without special bits are returned: \(changed)")
        check(Set(rules.skipped) == ["~/.kiro/settings/cli.json", "~/.kiro/other-write.json",
                                     "~/.kiro/setuid-tool", "~/.kiro/pipe"],
              "Shared-writable, setuid and special files are reported, not changed: \(rules.skipped)")
        check(!changed.contains(where: { $0.hasPrefix("~/.kiro/linked") }), "A link is never followed")
        check(changed.last == "~/.kiro" && !rules.incomplete,
              "A whole folder is returned after its contents: \(changed)")
        check(rules.summary.contains("items other accounts can write") && rules.summary.contains("setuid"),
              "The summary names every reason an item was left: \(rules.summary)")

        // A root-owned folder others can write is not entered, and the
        // folder holding it stays root-owned.
        changed = []
        let shared = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid() &+ 1, getgid()), paths: [".copilot/hooks/defenseclaw.json"],
            change: { _, relative in changed.append(relative); return 0 })
        check(changed.isEmpty, "Nothing under or above a shared-writable folder is returned: \(changed)")
        check(shared.skipped == ["~/.copilot/hooks"] && shared.incomplete,
              "A shared-writable folder is reported and the walk is incomplete: \(shared)")

        // Deeper than the walk goes: the folder must stay root-owned.
        var deep = home.appendingPathComponent(".codex", isDirectory: true)
        for _ in 0...(GatewayAdminOwnershipRepair.maximumDepth + 1) {
            deep = deep.appendingPathComponent("d", isDirectory: true)
            try makeFolders(deep, [""])
        }
        try makeFile(home.appendingPathComponent(".codex/config.toml"))
        changed = []
        let cut = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid() &+ 1, getgid()), paths: [".codex/config.toml"],
            change: { _, relative in changed.append(relative); return 0 })
        check(cut.incomplete, "A folder walk cut short must report itself incomplete")
        check(!changed.contains("~/.codex") && !changed.contains("~/.codex/d"),
              "A folder whose walk was cut short must stay root-owned: \(changed)")

        // A failed change of a child keeps the folder root-owned.
        try makeFolders(home, [".claude", ".claude/projects"])
        try makeFile(home.appendingPathComponent(".claude/settings.json"))
        changed = []
        let failed = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid() &+ 1, getgid()), paths: [".claude/settings.json"],
            change: { _, relative in
                changed.append(relative)
                return relative == "~/.claude/settings.json" ? -1 : 0
            })
        check(failed.incomplete && !changed.contains("~/.claude"),
              "A folder with a child that could not be returned stays root-owned: \(changed)")
    }

    /// GAP-0141: the listed file itself: a symlink, a named pipe and a
    /// setuid file are never changed, and a file swapped between its checks
    /// and its open (another inode, or a symlink) is never changed.
    private static func testAgentConfigFileEdgeCases(root: URL) throws {
        let fm = FileManager.default
        let home = root.appendingPathComponent("agent-file-home", isDirectory: true)
        let outside = root.appendingPathComponent("agent-file-outside", isDirectory: true)
        try makeFolders(home, ["", ".claude", ".cursor", ".gemini", ".gemini/config", ".hermes"])
        try makeFolders(outside, [""])
        try makeFile(outside.appendingPathComponent("target.json"))
        try fm.createSymbolicLink(at: home.appendingPathComponent(".cursor/hooks.json"),
                                  withDestinationURL: outside.appendingPathComponent("target.json"))
        check(mkfifo(home.appendingPathComponent(".gemini/config/hooks.json").path, 0o600) == 0,
              "Could not prepare the named-pipe fixture")
        try makeFile(home.appendingPathComponent(".hermes/config.yaml"), mode: 0o4600)
        try makeFile(home.appendingPathComponent(".claude/settings.json"))

        let descriptor = try GatewayAdminAgentConfigRepair.openAccountHome(home.path, uid: getuid())
        defer { close(descriptor) }
        var changed: [String] = []
        let edges = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid(), getgid()),
            paths: [".cursor/hooks.json", ".gemini/config/hooks.json", ".hermes/config.yaml"],
            change: { _, relative in changed.append(relative); return 0 })
        check(changed.isEmpty, "A symlinked, named-pipe or setuid agent config is never changed: \(changed)")
        check(edges.skipped == ["~/.hermes/config.yaml"] && !edges.incomplete,
              "A setuid file is reported; links and pipes are left: \(edges.skipped)")

        let settings = home.appendingPathComponent(".claude/settings.json")
        let moved = home.appendingPathComponent(".claude/settings.moved")
        for swapIn in ["file", "symlink"] {
            var swappedAtCheck = false
            GatewayAdminAgentConfigRepair.fileCheckedForTesting = { shown in
                guard shown == "~/.claude/settings.json" else { return }
                swappedAtCheck = true
                guard rename(settings.path, moved.path) == 0 else { fatalError("Could not move the swap fixture") }
                if swapIn == "file" {
                    try? Data("{}".utf8).write(to: settings)
                    _ = chmod(settings.path, 0o600)
                } else {
                    try? fm.createSymbolicLink(at: settings, withDestinationURL: outside.appendingPathComponent("target.json"))
                }
            }
            changed = []
            let swapped = GatewayAdminAgentConfigRepair.restore(
                home: descriptor, from: getuid(), to: (getuid(), getgid()), paths: [".claude/settings.json"],
                change: { _, relative in changed.append(relative); return 0 })
            GatewayAdminAgentConfigRepair.fileCheckedForTesting = nil
            check(swappedAtCheck, "The repair must reach the swap point between a file's checks and its open")
            check(changed.isEmpty, "A file swapped (\(swapIn)) after its checks must not be changed: \(changed)")
            check(swapIn == "file" ? swapped.skipped == ["~/.claude/settings.json"] : swapped.incomplete,
                  "A swap (\(swapIn)) is reported: \(swapped)")
            _ = unlink(settings.path)
            check(rename(moved.path, settings.path) == 0, "Could not restore the swap fixture")
        }
    }

    /// GAP-1964: the race of testAgentConfigFolderWalkSwap at the exact
    /// window, every time. A root file outside the account's folder (this
    /// account stands in for root) has its only name in the folder when the
    /// walk inspects it (one link), gets its outside name back before the
    /// open, and the folder name is unlinked right after the open: the opened
    /// file is that inode and reads one link again, yet it is the outside
    /// file. Before the fix the walk handed it over (both the folder walk and
    /// a listed file); now the file is held in the helper's own folder before
    /// the descriptor check, so it reads two links and stays as it is.
    private static func testHardLinkUnlinkedAtOpen(root: URL) throws {
        let home = root.appendingPathComponent("open-window-home", isDirectory: true)
        let outside = root.appendingPathComponent("open-window-outside", isDirectory: true)
        try makeFolders(home, ["", ".claude", ".kiro", ".kiro/agents"])
        try makeFolders(outside, [""])
        try makeFile(home.appendingPathComponent(".kiro/agents/defenseclaw.json"))
        let descriptor = try GatewayAdminAgentConfigRepair.openAccountHome(home.path, uid: getuid())
        defer { close(descriptor) }
        // (listed path, name in the folder, the label the walk shows, the
        // account the files go to): a root-owned folder walked whole, then a
        // listed file in the account's own folder.
        let cases: [(String, String, String, uid_t)] = [
            (".kiro/agents/defenseclaw.json", ".kiro/window.json", "window.json", getuid() &+ 1),
            (".claude/settings.json", ".claude/settings.json", "~/.claude/settings.json", getuid()),
        ]
        for (path, inFolder, label, account) in cases {
            let secret = outside.appendingPathComponent("system-file").path
            let linked = home.appendingPathComponent(inFolder).path
            try makeFile(URL(fileURLWithPath: secret))
            var secretStatus = stat()
            check(lstat(secret, &secretStatus) == 0, "Could not inspect the outside fixture")
            check(rename(secret, linked) == 0, "Could not move the outside fixture into the folder")
            var reachedCheck = false
            var reachedOpen = false
            GatewayAdminOwnershipRepair.walkFileCheckedForTesting = { relative in
                guard relative == label else { return }
                reachedCheck = true
                guard link(linked, secret) == 0 else { fatalError("Could not give the outside file its name back") }
            }
            GatewayAdminAgentConfigRepair.fileCheckedForTesting = GatewayAdminOwnershipRepair.walkFileCheckedForTesting
            GatewayAdminHandover.openedForTesting = { shown in
                guard shown == label else { return }
                reachedOpen = true
                _ = unlink(linked)
            }
            var handed: [String] = []
            let outcome = GatewayAdminAgentConfigRepair.restore(
                home: descriptor, from: getuid(), to: (account, getgid()), paths: [path],
                change: { file, shown in
                    var status = stat()
                    if fstat(file, &status) == 0, status.st_ino == secretStatus.st_ino, status.st_dev == secretStatus.st_dev {
                        handed.append(shown)
                    }
                    return 0
                })
            GatewayAdminOwnershipRepair.walkFileCheckedForTesting = nil
            GatewayAdminAgentConfigRepair.fileCheckedForTesting = nil
            GatewayAdminHandover.openedForTesting = nil
            check(reachedCheck && reachedOpen, "The repair must reach both ends of the open window for \(inFolder)")
            check(handed.isEmpty, "A hard link unlinked right after the open handed a file outside the folder over: "
                + "\(handed) \(outcome)")
            check(outcome.skipped == ["~/" + inFolder],
                  "The held file with a second name is reported and left as it is: \(outcome)")
            var after = stat()
            check(lstat(secret, &after) == 0 && after.st_ino == secretStatus.st_ino,
                  "The outside file keeps its own name")
            check(lstat(linked, &after) == 0 && after.st_ino == secretStatus.st_ino,
                  "The folder name is moved back: \(inFolder)")
            check(unlink(linked) == 0 && unlink(secret) == 0, "Could not remove the open-window fixture")
            check(GatewayAdminDirectory.names(of: descriptor)?.contains { $0.hasPrefix(".defenseclaw-handover-") } == false,
                  "The holding folder is removed after the repair")
        }
    }

    /// GAP-1972, GAP-1973: a held file sits in no folder the account can
    /// write (there the account could rename a leftover holding folder and
    /// swap it in for a later one); a repair stopped right after the move, or
    /// a file whose name and kept name were both taken, is returned by the
    /// next repair; a file put back next to a new file at its name is reported
    /// as returned there and the repair is complete. GATEWAY_ADMIN_HELD_CASE
    /// runs one case (fail-before runs).
    private static func testHeldFileRecovery(root: URL) throws {
        let only = ProcessInfo.processInfo.environment["GATEWAY_ADMIN_HELD_CASE"]
        func wanted(_ name: String) -> Bool { only == nil || only == name }
        let home = root.appendingPathComponent("held-home", isDirectory: true)
        try makeFolders(home, ["", ".claude"])
        let listed = home.appendingPathComponent(".claude/settings.json").path
        let kept = listed + ".defenseclaw-kept"
        let shown = "~/.claude/settings.json"
        let descriptor = try GatewayAdminAgentConfigRepair.openAccountHome(home.path, uid: getuid())
        defer { close(descriptor) }
        var changed: [String] = []
        func repair() -> GatewayAdminOwnershipRepair.Outcome {
            GatewayAdminAgentConfigRepair.restore(
                home: descriptor, from: getuid(), to: (getuid(), getgid()), paths: [".claude/settings.json"],
                change: { _, name in changed.append(name); return 0 })
        }
        func exists(_ path: String) -> Bool {
            var status = stat()
            return lstat(path, &status) == 0
        }
        func holdingFolder() -> [String] {
            (try? FileManager.default.contentsOfDirectory(atPath: GatewayAdminHandover.holdingPath)) ?? []
        }

        if wanted("placement") {
            try makeFile(URL(fileURLWithPath: listed))
            var original = stat()
            check(lstat(listed, &original) == 0, "Could not inspect the held fixture")
            var inAccountTree: [String] = []
            var inHoldingFolder = false
            GatewayAdminHandover.openedForTesting = { name in
                guard name == shown else { return }
                if let items = FileManager.default.enumerator(atPath: home.path) {
                    for case let item as String in items {
                        var status = stat()
                        if lstat(home.appendingPathComponent(item).path, &status) == 0,
                           status.st_ino == original.st_ino, status.st_dev == original.st_dev {
                            inAccountTree.append(item)
                        }
                    }
                }
                inHoldingFolder = holdingFolder().contains { $0.hasSuffix(".held") }
            }
            let outcome = repair()
            GatewayAdminHandover.openedForTesting = nil
            check(inAccountTree.isEmpty && inHoldingFolder, "A held file must sit in no folder the account can write, "
                + "where it can rename a leftover holding folder and swap it in for a later one: \(inAccountTree)")
            check(outcome.restored == [shown] && exists(listed) && !outcome.incomplete, "The held file goes back: \(outcome)")
            check(unlink(listed) == 0, "Could not remove the held fixture")
        }
        if wanted("stopped") {
            try makeFile(URL(fileURLWithPath: listed))
            GatewayAdminHandover.movedForTesting = { $0 == shown }
            _ = repair()
            GatewayAdminHandover.movedForTesting = nil
            check(!exists(listed), "The stopped repair must hold the file")
            changed = []
            let next = repair()
            check(exists(listed) && next.restored == [shown] && changed == [shown] && !next.incomplete,
                  "The next repair must return a file a repair stopped right after the move left held: \(next)")
            check(unlink(listed) == 0, "Could not remove the held fixture")
        }
        if wanted("taken") {
            try makeFile(URL(fileURLWithPath: listed))
            GatewayAdminHandover.openedForTesting = { name in
                guard name == shown else { return }
                if !exists(listed) { try? makeFile(URL(fileURLWithPath: listed)) }
                if !exists(kept) { try? makeFile(URL(fileURLWithPath: kept)) }
            }
            let blocked = repair()
            GatewayAdminHandover.openedForTesting = nil
            check(blocked.incomplete && blocked.restored.isEmpty && blocked.summary.contains(GatewayAdminHandover.holdingPath)
                  && blocked.summary.contains(shown),
                  "A file whose name and kept name were both taken stays held and is reported: \(blocked.summary)")
            check(unlink(listed) == 0 && unlink(kept) == 0, "Could not remove the blocking names")
            let freed = repair()
            check(exists(listed) && freed.restored == [shown] && !freed.incomplete,
                  "The next repair must return a held file once its name is free: \(freed)")
            check(unlink(listed) == 0, "Could not remove the held fixture")
        }
        if wanted("kept") {
            try makeFile(URL(fileURLWithPath: listed))
            GatewayAdminHandover.openedForTesting = { name in
                guard name == shown, !exists(listed) else { return }
                try? makeFile(URL(fileURLWithPath: listed))
            }
            let fallback = repair()
            GatewayAdminHandover.openedForTesting = nil
            check(!fallback.incomplete && fallback.restored == [shown + ".defenseclaw-kept"] && exists(kept)
                  && fallback.summary.contains(shown + ".defenseclaw-kept") && !fallback.summary.contains("left root-owned"),
                  "A file put back next to a new file at its name is reported as returned there: \(fallback)")
            check(unlink(listed) == 0 && unlink(kept) == 0, "Could not remove the kept fixtures")
        }
        if wanted("resumed") {
            // A repair that stopped after it changed the owner: the held file
            // is the account's already, though its record names root.
            try makeFile(URL(fileURLWithPath: listed))
            GatewayAdminHandover.movedForTesting = { $0 == shown }
            _ = repair()
            GatewayAdminHandover.movedForTesting = nil
            let records = holdingFolder().filter { $0.hasSuffix(".record") }
            check(records.count == 1, "The stopped repair must leave one record: \(holdingFolder())")
            let recordPath = GatewayAdminHandover.holdingPath + "/" + (records.first ?? "")
            if let data = FileManager.default.contents(atPath: recordPath),
               var record = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                record["owner"] = 4242
                try JSONSerialization.data(withJSONObject: record).write(to: URL(fileURLWithPath: recordPath))
            }
            let next = repair()
            check(exists(listed) && next.restored == [shown] && !next.incomplete && holdingFolder().isEmpty,
                  "A file whose owner already changed goes back to the account's folder: \(next)")
            check(unlink(listed) == 0, "Could not remove the held fixture")
        }
        if wanted("unclaimed") {
            // The folder a repair stopped in moved or was removed: the held file is
            // reported by its shown name, and returned once its folder is repaired again.
            try makeFile(URL(fileURLWithPath: listed))
            GatewayAdminHandover.movedForTesting = { $0 == shown }
            _ = repair()
            GatewayAdminHandover.movedForTesting = nil
            let elsewhere = root.appendingPathComponent("held-elsewhere", isDirectory: true)
            try makeFolders(elsewhere, [""])
            let other = open(elsewhere.path, O_RDONLY | O_DIRECTORY)
            defer { close(other) }
            check(GatewayAdminHandover.unclaimed(account: getuid(), roots: [other]) == [shown],
                  "A held file of a folder that is no longer repaired is reported")
            check(GatewayAdminHandover.unclaimed(account: getuid(), roots: [descriptor, other]).isEmpty,
                  "A held file of a folder still repaired is not reported as unclaimed")
            check(GatewayAdminHandover.unclaimed(account: getuid() &+ 1, roots: [other]).isEmpty,
                  "Another account's held files are not reported")
            let next = repair()
            check(exists(listed) && next.restored == [shown] && !next.incomplete && holdingFolder().isEmpty,
                  "The held file goes back at the next repair of its folder: \(next)")
            check(unlink(listed) == 0, "Could not remove the held fixture")
        }
        if wanted("defenseclaw-home") {
            // The DefenseClaw home is walked without a shared handover: its own held
            // files come back at the end of the next walk of that folder.
            let dcHome = root.appendingPathComponent("held-dc-home", isDirectory: true)
            try makeFolders(dcHome, [""])
            let config = dcHome.appendingPathComponent("config.yaml")
            try makeFile(config)
            let fd = open(dcHome.path, O_RDONLY | O_DIRECTORY)
            defer { close(fd) }
            GatewayAdminHandover.movedForTesting = { $0 == "config.yaml" }
            _ = try GatewayAdminOwnershipRepair.restore(home: fd, from: getuid(), to: (getuid(), getgid()))
            GatewayAdminHandover.movedForTesting = nil
            check(!exists(config.path), "The stopped walk must hold the file")
            let next = try GatewayAdminOwnershipRepair.restore(home: fd, from: getuid(), to: (getuid(), getgid()))
            check(exists(config.path) && next.restored.contains("config.yaml") && !next.incomplete && holdingFolder().isEmpty,
                  "The next walk of the DefenseClaw home returns what the stopped one held: \(next)")
        }
        check(holdingFolder().isEmpty, "Every held file went back and its record was removed: \(holdingFolder())")
        if wanted("placement") {
            // Empty, the holding folder goes; with a file held in it, it stays.
            GatewayAdminHandover.movedForTesting = { $0 == shown }
            try makeFile(URL(fileURLWithPath: listed))
            _ = repair()
            GatewayAdminHandover.movedForTesting = nil
            check(!GatewayAdminHandover.removeEmptyHoldingFolder() && exists(GatewayAdminHandover.holdingPath),
                  "A holding folder with a held file stays")
            _ = repair()
            check(unlink(listed) == 0, "Could not remove the held fixture")
        }
        check(GatewayAdminHandover.removeEmptyHoldingFolder() && !exists(GatewayAdminHandover.holdingPath),
              "An empty holding folder is removed")
    }

    /// GAP-0141 review: a file inside a root-owned agent config folder that
    /// the walk returns is changed only when it had one link when inspected
    /// and the opened file is that inode. Before, the walk checked the link
    /// count only through the opened descriptor: the account could hard-link
    /// a root file (a LaunchDaemon plist) into the folder and unlink the link
    /// between the open and the fstat, so the count read 1 and the root file
    /// was handed over. This account stands in for root; the repaired account
    /// is another uid, so the folder counts as root-owned and is walked.
    private static func testAgentConfigFolderWalkSwap(root: URL) throws {
        let home = root.appendingPathComponent("agent-walk-home", isDirectory: true)
        let outside = root.appendingPathComponent("agent-walk-outside", isDirectory: true)
        try makeFolders(home, ["", ".kiro", ".kiro/agents"])
        try makeFolders(outside, [""])
        let listed = home.appendingPathComponent(".kiro/agents/defenseclaw.json")
        let moved = home.appendingPathComponent(".kiro/agents/defenseclaw.moved")
        let secret = outside.appendingPathComponent("system-file")
        let linked = home.appendingPathComponent(".kiro/linked.json")
        try makeFile(listed)
        try makeFile(secret)
        var secretStatus = stat()
        check(lstat(secret.path, &secretStatus) == 0, "Could not inspect the hard-link fixture")
        let secretInode = secretStatus.st_ino
        let secretDevice = secretStatus.st_dev
        func handsOverSecret(_ opened: Int32) -> Bool {
            var status = stat()
            return fstat(opened, &status) == 0 && status.st_ino == secretInode && status.st_dev == secretDevice
        }
        let descriptor = try GatewayAdminAgentConfigRepair.openAccountHome(home.path, uid: getuid())
        defer { close(descriptor) }

        // A hard link (two links when inspected) is reported and never opened.
        check(link(secret.path, linked.path) == 0, "Could not prepare the hard-link fixture")
        var opened: [String] = []
        GatewayAdminOwnershipRepair.walkFileCheckedForTesting = { relative in opened.append(relative) }
        var changed: [String] = []
        var handedLinked = false
        let hardLinked = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid() &+ 1, getgid()), paths: [".kiro/agents/defenseclaw.json"],
            change: { file, relative in
                if handsOverSecret(file) { handedLinked = true }
                changed.append(relative)
                return 0
            })
        GatewayAdminOwnershipRepair.walkFileCheckedForTesting = nil
        check(!handedLinked && !opened.contains("linked.json"),
              "A file with two links when inspected must be neither opened nor handed over: \(opened)")
        check(hardLinked.skipped == ["~/.kiro/linked.json"] && changed.contains("~/.kiro/agents/defenseclaw.json"),
              "The hard link is reported and the rest of the folder is returned: \(hardLinked) \(changed)")
        check(unlink(linked.path) == 0, "Could not remove the hard-link fixture")

        // The attack itself, with no test hook (run first, so it decides a
        // run of the helper before this fix): another thread hard-links the
        // file outside the folder into it and unlinks the link again while the
        // walk runs. A link count read in the folder can show one link for
        // that link (GAP-1964, CI walk 18938), so the walk moves a file into
        // its holding folder before the descriptor check: held, the outside
        // file reads two links and is never handed over.
        let race = home.appendingPathComponent(".kiro/race.json").path
        let secretPath = secret.path
        let finished = DispatchSemaphore(value: 0)
        let toggler = Thread {
            while !Thread.current.isCancelled {
                _ = link(secretPath, race)
                _ = unlink(race)
            }
            finished.signal()
        }
        toggler.start()
        var handedOver = 0
        var walks = 0
        let maximumWalks = ProcessInfo.processInfo.environment["GATEWAY_ADMIN_RACE_WALKS"].flatMap { Int($0) } ?? 20_000
        while walks < maximumWalks && handedOver == 0 {
            walks += 1
            _ = GatewayAdminAgentConfigRepair.restore(
                home: descriptor, from: getuid(), to: (getuid() &+ 1, getgid()), paths: [".kiro/agents/defenseclaw.json"],
                change: { file, _ in
                    if handsOverSecret(file) { handedOver += 1 }
                    return 0
                })
        }
        toggler.cancel()
        finished.wait()
        _ = unlink(race)
        // A link the toggler made while the walk held the file is kept next
        // to it, never replaced.
        _ = unlink(race + ".defenseclaw-kept")
        check(handedOver == 0, "A hard link unlinked between the open and the fstat handed a file outside the folder over "
            + "(walk \(walks))")

        // A file swapped in between the checks and the open (another inode,
        // one link) is never changed.
        var swappedAtCheck = false
        GatewayAdminOwnershipRepair.walkFileCheckedForTesting = { relative in
            guard relative == "agents/defenseclaw.json" else { return }
            swappedAtCheck = true
            guard rename(listed.path, moved.path) == 0 else { fatalError("Could not move the swap fixture") }
            try? Data("{}".utf8).write(to: listed)
            _ = chmod(listed.path, 0o600)
        }
        changed = []
        let swapped = GatewayAdminAgentConfigRepair.restore(
            home: descriptor, from: getuid(), to: (getuid() &+ 1, getgid()), paths: [".kiro/agents/defenseclaw.json"],
            change: { _, relative in changed.append(relative); return 0 })
        GatewayAdminOwnershipRepair.walkFileCheckedForTesting = nil
        check(swappedAtCheck, "The folder walk must reach the swap point between a file's checks and its open")
        check(!changed.contains("~/.kiro/agents/defenseclaw.json") && swapped.skipped == ["~/.kiro/agents/defenseclaw.json"],
              "A file swapped after its checks must be reported, not changed: \(swapped) \(changed)")
        _ = unlink(listed.path)
        check(rename(moved.path, listed.path) == 0, "Could not restore the swap fixture")
    }

    /// GAP-0141 real-root cases: run as root by sudo (the runner script does
    /// it only in CI with passwordless sudo). Root creates the leftovers and
    /// the helper's real fchown returns them to the sudo account.
    private static func testRealRootAgentConfigRepair(root: URL) throws {
        let environment = ProcessInfo.processInfo.environment
        guard getuid() == 0, let uid = environment["SUDO_UID"].flatMap({ uid_t($0) }), uid != 0,
              let gid = environment["SUDO_GID"].flatMap({ gid_t($0) }) else {
            fatalError("The real-root cases run as root under sudo, with SUDO_UID and SUDO_GID set.")
        }
        let base = root.appendingPathComponent("real-root", isDirectory: true)
        let home = base.appendingPathComponent("home", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: base) }
        try makeFolders(base, ["", "home"])
        check(chown(home.path, uid, gid) == 0, "Could not give the fixture home to the sudo account")
        try makeFolders(home, [".claude", ".claude/projects"])
        try makeFolders(home, [".codex"])
        check(chown(home.appendingPathComponent(".codex").path, uid, gid) == 0, "Could not prepare the account folder")
        try makeFile(home.appendingPathComponent(".claude/settings.json"))
        try makeFile(home.appendingPathComponent(".claude/projects/state.json"))
        try makeFile(home.appendingPathComponent(".claude/setuid-tool"), mode: 0o4755)
        try makeFile(home.appendingPathComponent(".claude/world.json"), mode: 0o666)
        try makeFile(home.appendingPathComponent(".codex/config.toml"))
        try makeFile(base.appendingPathComponent("system-file"))
        check(link(base.appendingPathComponent("system-file").path, home.appendingPathComponent(".claude/linked").path) == 0,
              "Could not prepare the hard-link fixture")

        let descriptor = open(home.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        check(descriptor >= 0, "Could not open the fixture home")
        defer { close(descriptor) }
        let outcome = GatewayAdminAgentConfigRepair.restore(home: descriptor, to: (uid, gid),
                                                            paths: [".claude/settings.json", ".codex/config.toml"])
        func owner(_ relative: String, in folder: URL? = nil) -> uid_t {
            var status = stat()
            guard lstat((folder ?? home).appendingPathComponent(relative).path, &status) == 0 else {
                fatalError("lstat \(relative)")
            }
            return status.st_uid
        }
        for relative in [".claude", ".claude/settings.json", ".claude/projects", ".claude/projects/state.json",
                         ".codex/config.toml"] {
            check(owner(relative) == uid, "\(relative) must be returned to the account")
        }
        for relative in [".claude/setuid-tool", ".claude/world.json", ".claude/linked"] {
            check(owner(relative) == 0, "\(relative) must stay root-owned")
        }
        check(owner("system-file", in: base) == 0, "A hard-linked file outside the home must stay root-owned")
        check(!outcome.incomplete && outcome.skipped.count == 3, "The outcome must report the left items: \(outcome)")

        // A root-owned folder others can write keeps the folder holding it
        // root-owned (root's real fchown).
        try makeFolders(home, [".cursor", ".cursor/shared"])
        _ = chmod(home.appendingPathComponent(".cursor/shared").path, 0o777)
        try makeFile(home.appendingPathComponent(".cursor/hooks.json"))
        try makeFile(home.appendingPathComponent(".cursor/shared/state.json"))
        let shared = GatewayAdminAgentConfigRepair.restore(home: descriptor, to: (uid, gid), paths: [".cursor/hooks.json"])
        check(owner(".cursor") == 0 && owner(".cursor/shared") == 0 && owner(".cursor/shared/state.json") == 0,
              "A shared-writable root folder and the folder holding it must stay root-owned")
        check(shared.incomplete && shared.skipped == ["~/.cursor/shared"], "The held-back folder is reported: \(shared)")
        check(shared.summary.contains("other accounts can write it"), "The summary says why: \(shared.summary)")
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

        // GAP-2003: a walk that stopped at its deadline has its own exit code,
        // so the app offers the repair again; other incomplete outcomes keep 1.
        for (outcome, code) in [
            (GatewayAdminOwnershipRepair.Outcome(incomplete: true, unfinished: true), GatewayAdminPolicy.repairUnfinishedExitCode),
            (GatewayAdminOwnershipRepair.Outcome(incomplete: true), 1),
            (GatewayAdminOwnershipRepair.Outcome(restored: ["gateway.pid"]), 0),
        ] {
            let reply = try GatewayAdminRepair.perform(
                liveRootProcesses: { GatewayAdminRootProcess.Found() }, stop: { _ in true },
                restoreOwnership: { outcome }, removeStagedGateway: {})
            check(reply.0 == code, "A repair outcome must answer \(code), not \(reply.0): \(outcome)")
        }
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
