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

        let virtualenvBin = home.appendingPathComponent(".venv/bin", isDirectory: true)
        try FileManager.default.createDirectory(at: virtualenvBin, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        let searchPath = GatewayAdminTrust.scannerSearchPath(home: home.path, account: account)
        check(searchPath.hasPrefix("/usr/bin:/bin:/usr/sbin:/sbin:"), "System executables must precede user scanner paths")
        check(searchPath.split(separator: ":").contains(Substring(virtualenvBin.path)), "The safe selected scanner environment was omitted")
        _ = chmod(virtualenvBin.path, 0o777)
        let restrictedPath = GatewayAdminTrust.scannerSearchPath(home: home.path, account: account)
        check(!restrictedPath.split(separator: ":").contains(Substring(virtualenvBin.path)), "An unsafe scanner search directory was accepted")
        _ = chmod(virtualenvBin.path, 0o700)

        rejects("Malformed authorization was accepted") { try GatewayAdminTrust.validateAuthorization(Data()) }
        rejects("An unsigned file was accepted as the gateway") {
            try GatewayAdminTrust.verifySignature(at: config.path, requirement: GatewayAdminPolicy.gatewayRequirement)
        }
        check(GatewayAdminAction.allCases.map(\.rawValue).sorted() == ["restart", "start", "stop"], "Gateway action allowlist changed")
        for action in ["start --help", "watchdog start", "/bin/sh", "", "START"] {
            check(GatewayAdminAction(rawValue: action) == nil, "An unsupported operation was accepted")
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
                check(privilegedWorkCount == 1, "A failed authorization must not stage or execute the gateway")
                check(error.localizedDescription.contains(String(status)), "The safe status code must remain available for diagnosis")
            }
        }
        try testInstalledGatewayCopy(root: root, account: account)
        try testGatewayLifecycle()

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
    private static func testInstalledGatewayCopy(root: URL, account: InvokingAccount) throws {
        check(GatewayAdminTrust.installedGatewayPath(account: account) == account.home + "/.local/bin/defenseclaw-gateway",
              "The privileged source must be derived from the authenticated account")
        let firstAccountDirectory = GatewayAdminTrust.stagingDirectory(uid: 501)
        let secondAccountDirectory = GatewayAdminTrust.stagingDirectory(uid: 502)
        check(firstAccountDirectory != secondAccountDirectory, "Operator-controlled gateway copies must be isolated by authenticated UID")
        check(firstAccountDirectory == GatewayAdminTrust.stagingRoot + "/uid-501" &&
              secondAccountDirectory == GatewayAdminTrust.stagingRoot + "/uid-502",
              "Each account must use only its own fixed root-private directory")
        check(!firstAccountDirectory.contains(account.home), "The privileged destination must not derive from a user-selected path")
        let fixture = root.appendingPathComponent("runtime-copy", isDirectory: true)
        let sourceDirectory = fixture.appendingPathComponent("installed", isDirectory: true)
        let destinationDirectory = fixture.appendingPathComponent("private", isDirectory: true)
        for directory in [fixture, sourceDirectory, destinationDirectory] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                   attributes: [.posixPermissions: NSNumber(value: 0o700)])
        }
        let source = sourceDirectory.appendingPathComponent("defenseclaw-gateway")
        try FileManager.default.copyItem(atPath: CommandLine.arguments[0], toPath: source.path)
        _ = chmod(source.path, 0o700)
        let signer = Process()
        signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        signer.arguments = ["--force", "--sign", "-", source.path]
        signer.standardOutput = FileHandle.nullDevice
        signer.standardError = FileHandle.nullDevice
        try signer.run()
        signer.waitUntilExit()
        check(signer.terminationStatus == 0, "Could not prepare the ad-hoc signed native source fixture")
        let original = try Data(contentsOf: source)
        try GatewayAdminTrust.verifyGatewayIntegrity(at: source.path)
        checks += 1
        rejects("An operator's ad-hoc executable was accepted as a legacy global gateway") {
            try GatewayAdminTrust.verifyLegacyGateway(at: source.path)
        }
        let descriptor = open(destinationDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        check(descriptor >= 0, "Could not open the private fixture directory")
        defer { close(descriptor) }
        func prepare() throws -> GatewayAdminCandidate {
            try GatewayAdminTrust.prepareGatewayCopy(source: source.path, permittedOwner: account.uid,
                directory: descriptor, directoryPath: destinationDirectory.path)
        }
        let current = destinationDirectory.appendingPathComponent("defenseclaw-gateway")
        let originalCurrent = Data("previous gateway remains until activation".utf8)
        try originalCurrent.write(to: current)
        _ = chmod(current.path, 0o500)

        do {
            var candidate: GatewayAdminCandidate? = try prepare()
            let temporaryPath = candidate!.path
            check(try Data(contentsOf: current) == originalCurrent, "Preparing a candidate replaced the current gateway")
            check(try Data(contentsOf: URL(fileURLWithPath: temporaryPath)) == original, "The private copy differs from the signed source")
            check(try GatewayAdminTrust.gatewayDigest(at: temporaryPath) == GatewayAdminTrust.gatewayDigest(at: source.path),
                  "Identical immutable copies must have equal SHA-256 digests")
            check(try GatewayAdminTrust.gatewayDigest(at: temporaryPath) != GatewayAdminTrust.gatewayDigest(at: current.path),
                  "Different copies must have different SHA-256 digests")
            candidate = nil
            check(!FileManager.default.fileExists(atPath: temporaryPath), "An abandoned candidate was not cleaned up")
            check(try Data(contentsOf: current) == originalCurrent, "Candidate cleanup changed the current gateway")
        }
        do {
            let candidate = try prepare()
            let temporaryPath = candidate.path
            check(try candidate.activate() == current.path, "Activation did not use the stable private gateway path")
            check(!FileManager.default.fileExists(atPath: temporaryPath), "Activation left its temporary file behind")
            check(try Data(contentsOf: current) == original, "Activation changed the verified executable bytes")
        }
        check(try Data(contentsOf: source) == original, "Staging modified the operator's installed runtime")
        let activated = try Data(contentsOf: current)
        let entriesBeforeFailure = try FileManager.default.contentsOfDirectory(atPath: destinationDirectory.path)

        GatewayAdminTrust.sourceCopiedForTesting = {
            let handle = try FileHandle(forWritingTo: source)
            try handle.seekToEnd()
            try handle.write(contentsOf: Data("changed".utf8))
            try handle.close()
        }
        rejects("A source changed during copying was accepted") { _ = try prepare() }
        GatewayAdminTrust.sourceCopiedForTesting = nil
        try original.write(to: source)
        _ = chmod(source.path, 0o700)

        GatewayAdminTrust.sourceCopiedForTesting = {
            let replacement = sourceDirectory.appendingPathComponent("replacement")
            try original.write(to: replacement)
            _ = chmod(replacement.path, 0o700)
            guard rename(replacement.path, source.path) == 0 else { fatalError("Cannot replace the isolated source fixture") }
        }
        rejects("A replaced source filename was accepted") { _ = try prepare() }
        GatewayAdminTrust.sourceCopiedForTesting = nil
        check(try Data(contentsOf: current) == activated, "Rejected source changes modified the active private copy")
        check(try FileManager.default.contentsOfDirectory(atPath: destinationDirectory.path) == entriesBeforeFailure,
              "Rejected source changes left private candidate files behind")

        let link = sourceDirectory.appendingPathComponent("linked-gateway")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: source)
        rejects("A symlink source was accepted") {
            let fd = try GatewayAdminTrust.openInstalledGateway(link.path, permittedOwner: account.uid)
            close(fd)
        }
        let linkedParent = fixture.appendingPathComponent("linked-installation")
        try FileManager.default.createSymbolicLink(at: linkedParent, withDestinationURL: sourceDirectory)
        rejects("A symlink source ancestor was accepted") {
            let fd = try GatewayAdminTrust.openInstalledGateway(linkedParent.appendingPathComponent(source.lastPathComponent).path,
                                                               permittedOwner: account.uid)
            close(fd)
        }
        let pipePath = sourceDirectory.appendingPathComponent("gateway-pipe")
        check(mkfifo(pipePath.path, 0o700) == 0, "Could not prepare a named-pipe fixture")
        rejects("A named-pipe source was accepted") {
            let fd = try GatewayAdminTrust.openInstalledGateway(pipePath.path, permittedOwner: account.uid)
            close(fd)
        }
        let script = sourceDirectory.appendingPathComponent("gateway-script")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: script)
        _ = chmod(script.path, 0o700)
        rejects("A script was accepted as a native gateway") {
            _ = try GatewayAdminTrust.prepareGatewayCopy(source: script.path, permittedOwner: account.uid,
                directory: descriptor, directoryPath: destinationDirectory.path)
        }
        let invalid = sourceDirectory.appendingPathComponent("unsigned-native")
        try Data([0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).write(to: invalid)
        _ = chmod(invalid.path, 0o700)
        rejects("Unsigned bytes were accepted as a legacy global gateway") {
            try GatewayAdminTrust.verifyLegacyGateway(at: invalid.path)
        }
        rejects("Invalid unsigned Mach-O bytes were accepted") {
            _ = try GatewayAdminTrust.prepareGatewayCopy(source: invalid.path, permittedOwner: account.uid,
                directory: descriptor, directoryPath: destinationDirectory.path)
        }
        _ = chmod(source.path, 0o777)
        rejects("A shared-writable installed executable was accepted") { _ = try prepare() }
        _ = chmod(source.path, 0o700)
        let grantACL = Process()
        grantACL.executableURL = URL(fileURLWithPath: "/bin/chmod")
        grantACL.arguments = ["+a", "everyone allow write", source.path]
        try grantACL.run()
        grantACL.waitUntilExit()
        check(grantACL.terminationStatus == 0, "Could not prepare source ACL fixture")
        rejects("An ACL-writable source was accepted through its descriptor") { _ = try prepare() }
        check(try Data(contentsOf: current) == activated, "Rejected source validation changed the current gateway")
    }

    private static func testGatewayLifecycle() throws {
        var calls: [String] = []
        var rejectPreparation = false
        var stopCode: Int32 = 0
        var candidateMatches = true
        var rejectComparison = false
        func perform(_ action: GatewayAdminAction, current: String?) throws -> (Int32, String) {
            try GatewayAdminLifecycle.perform(action: action, currentGateway: current, prepare: {
                calls.append("prepare")
                if rejectPreparation { throw GatewayAdminFailure.refused("invalid installed runtime") }
                return "candidate"
            }, path: { $0 }, matches: { candidate, current in
                calls.append("compare " + candidate + " " + current)
                if rejectComparison { throw GatewayAdminFailure.refused("comparison unavailable") }
                return candidateMatches
            }, activate: { candidate in
                calls.append("activate " + candidate)
                return "new-private-copy"
            }, run: { action, gateway in
                calls.append(action.rawValue + " " + gateway)
                return (action == .stop ? stopCode : 0, action.rawValue + " output\n")
            })
        }
        _ = try perform(.restart, current: "current-private-copy")
        check(calls == ["prepare", "stop current-private-copy", "activate candidate", "start new-private-copy"],
              "Restart must verify first, stop the old copy, activate, and start in that order")
        calls = []
        rejectPreparation = true
        rejects("A rejected installed runtime reached gateway lifecycle work") { _ = try perform(.restart, current: "current-private-copy") }
        check(calls == ["prepare"], "A rejected candidate must preserve the running gateway")
        calls = []
        _ = try perform(.stop, current: "current-private-copy")
        check(calls == ["stop current-private-copy"], "Stop must work even when the installed runtime is missing or invalid")
        calls = []
        rejects("Start accepted an invalid installed runtime") { _ = try perform(.start, current: "current-private-copy") }
        check(calls == ["prepare"], "Start must validate the installed runtime before reusing the private copy")
        calls = []
        rejectPreparation = false
        _ = try perform(.start, current: "current-private-copy")
        check(calls == ["prepare", "compare candidate current-private-copy", "start current-private-copy"],
              "An idempotent Start must compare installed bytes without replacing the existing private runtime")
        calls = []
        candidateMatches = false
        do {
            _ = try perform(.start, current: "current-private-copy")
            fatalError("Start accepted a different installed runtime")
        } catch {
            check(error.localizedDescription.contains("Restart Gateway as Administrator"), "A changed runtime needs actionable Restart guidance")
        }
        check(calls == ["prepare", "compare candidate current-private-copy"], "A different runtime must require Restart before lifecycle work")
        calls = []
        candidateMatches = true
        rejectComparison = true
        rejects("A failed comparison reached gateway lifecycle work") { _ = try perform(.start, current: "current-private-copy") }
        check(calls == ["prepare", "compare candidate current-private-copy"], "A failed comparison must preserve the running gateway")
        calls = []
        rejectComparison = false
        stopCode = 1
        let stopped = try perform(.restart, current: "current-private-copy")
        check(stopped.0 == 1 && calls == ["prepare", "stop current-private-copy"],
              "A failed Stop must not replace or start a gateway")
        calls = []
        stopCode = 0
        _ = try perform(.start, current: nil)
        check(calls == ["prepare", "activate candidate", "start new-private-copy"], "First Start must activate only a verified candidate")
        calls = []
        _ = try perform(.restart, current: nil)
        check(calls == ["prepare", "stop candidate", "activate candidate", "start new-private-copy"],
              "First Restart must stop the selected installation before starting its private copy")
        calls = []
        _ = try perform(.stop, current: nil)
        check(calls == ["prepare", "stop candidate"], "First Stop must not persist or start a candidate")
    }

}
