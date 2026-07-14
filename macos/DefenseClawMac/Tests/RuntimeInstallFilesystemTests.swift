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

import Darwin
import CryptoKit
import Foundation

@main
struct RuntimeInstallFilesystemTests {
    static func main() {
        failedAttemptRemovesOnlyItsStagingAndRetainsSafeEmptyParent()
        failedAttemptPreservesPreexistingEmptyParent()
        failedAttemptPreservesConcurrentDataHomeContents()
        nonemptyDataHomeFailsClosedWithoutMutation()
        symlinkDataHomeFailsClosedWithoutFollowingOrMutation()
        stagingCleanupPreservesAReplacement()
        symlinkedInstallAncestorsAreRefusedWithoutExternalMutation()
        releaseAttestedGatewayCopyIsByteExact()
        fixedGatewayRequirementRejectsWrongIdentifier()
        stagedCLILinkRequiresExactTargetAndStableIdentity()
        regularFileInstallNeverReplacesConcurrentTool()
        regularFileInstallBindsOpenedSourceBytesToExpectedDigest()
        regularFilePostPublishFailuresWithdrawOwnedDestination()
        regularFilePostPublishReplacementIsPreserved()
        destinationAppearingAfterPreparationIsPreservedAndPartialActivationRollsBack()
        postPublishFailuresAtEveryBoundaryRollBackAllCustodiedTargets()
        postPublishReplacementIsPreservedAndJournalRemainsRecoverable()
        rollbackPreservesAConcurrentReplacement()
        cleanupSwapKeepsCanonicalOccupiedAndRestoresConcurrentState()
        failedCleanupSwapBackNeverDeletesDisplacedConcurrentState()
        repeatedSwapBackFailureUsesNoExchangeRestoration()
        placeholderRetirementFailureLeavesOwnedCandidateCanonical()
        quarantineFailureRestoresOwnedCandidateCanonical()
        recursiveCleanupRebindPreservesReplacementContents()
        finalPlaceholderRacePreservesConcurrentCanonicalState()
        activationRefusesParentDirectorySymlinkSwap()
        successfulNoReplaceActivationCanRemoveOnlyItsOwnTargets()
        interruptedActivationJournalRecoversEveryCutPoint()
        interruptedActivationJournalPreservesConcurrentReplacement()
        print("RuntimeInstallFilesystemTests passed")
    }

    private static func failedAttemptRemovesOnlyItsStagingAndRetainsSafeEmptyParent() {
        withTemporaryHome { home in
            let dataHome = home.appendingPathComponent(".defenseclaw")
            try injectFailure(home: home)
            expect(lexicalPathExists(dataHome), "new real data-home is retained after failure")
            expect(directoryContents(dataHome).isEmpty, "installer staging is removed for retry")
        }
    }

    private static func failedAttemptPreservesPreexistingEmptyParent() {
        withTemporaryHome { home in
            let dataHome = home.appendingPathComponent(".defenseclaw")
            try FileManager.default.createDirectory(at: dataHome, withIntermediateDirectories: false)
            try injectFailure(home: home)
            expect(lexicalPathExists(dataHome), "pre-existing empty data-home is preserved")
            expect(directoryContents(dataHome).isEmpty, "only installer staging was removed")
        }
    }

    private static func failedAttemptPreservesConcurrentDataHomeContents() {
        withTemporaryHome { home in
            let dataHome = home.appendingPathComponent(".defenseclaw")
            try injectFailure(home: home, beforeCleanup: {
                let concurrent = dataHome.appendingPathComponent("created-concurrently")
                try Data("keep".utf8).write(to: concurrent)
            })
            expect(lexicalPathExists(dataHome), "non-empty new data-home survives atomic rmdir")
            expect(
                read(dataHome.appendingPathComponent("created-concurrently")) == "keep",
                "concurrent contents are untouched"
            )
            expect(
                !lexicalPathExists(dataHome.appendingPathComponent(".venv.staging")),
                "installer-owned staging is still removed"
            )
        }
    }

    private static func nonemptyDataHomeFailsClosedWithoutMutation() {
        withTemporaryHome { home in
            let dataHome = home.appendingPathComponent(".defenseclaw")
            try FileManager.default.createDirectory(at: dataHome, withIntermediateDirectories: false)
            let state = dataHome.appendingPathComponent("future-state")
            try Data("preserve".utf8).write(to: state)
            try injectFailure(home: home)
            expect(read(state) == "preserve", "non-empty data-home contents are unchanged")
            expect(
                !lexicalPathExists(dataHome.appendingPathComponent(".venv.staging")),
                "guard prevents staging beneath a non-empty data-home"
            )
        }
    }

    private static func symlinkDataHomeFailsClosedWithoutFollowingOrMutation() {
        withTemporaryHome { home in
            let target = home.appendingPathComponent("external-state")
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
            let state = target.appendingPathComponent("keep")
            try Data("preserve".utf8).write(to: state)
            let dataHome = home.appendingPathComponent(".defenseclaw")
            try FileManager.default.createSymbolicLink(
                atPath: dataHome.path,
                withDestinationPath: target.path
            )
            try injectFailure(home: home)
            expect(lexicalPathExists(dataHome), "data-home symlink is preserved")
            expect(read(state) == "preserve", "symlink target is never followed or changed")
            expect(
                !lexicalPathExists(target.appendingPathComponent(".venv.staging")),
                "guard prevents staging through a data-home symlink"
            )
        }
    }

    private static func stagingCleanupPreservesAReplacement() {
        withTemporaryHome { home in
            let dataHome = home.appendingPathComponent(".defenseclaw")
            try FileManager.default.createDirectory(at: dataHome, withIntermediateDirectories: false)
            let staging = dataHome.appendingPathComponent(".venv.staging-random")
            let owned = try RuntimeInstallFilesystem.createOwnedDirectory(staging.path)
            try FileManager.default.removeItem(at: staging)
            try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false)
            try Data("concurrent".utf8).write(to: staging.appendingPathComponent("keep"))

            RuntimeInstallFilesystem.cleanupFailedFreshInstall(
                stagingDir: staging.path,
                stagingIdentity: owned,
                dataHome: dataHome.path,
                removeDataHomeIfEmpty: true
            )

            expect(
                read(staging.appendingPathComponent("keep")) == "concurrent",
                "failed-install cleanup preserves a same-name staging replacement"
            )
            expect(lexicalPathExists(dataHome), "non-empty data-home is preserved")
        }
    }

    private static func symlinkedInstallAncestorsAreRefusedWithoutExternalMutation() {
        for component in [".local", ".defenseclaw"] {
            withTemporaryHome { home in
                let external = home.appendingPathComponent("external-\(component.dropFirst())")
                try FileManager.default.createDirectory(at: external, withIntermediateDirectories: false)
                let ancestor = home.appendingPathComponent(component)
                try FileManager.default.createSymbolicLink(
                    atPath: ancestor.path,
                    withDestinationPath: external.path
                )
                do {
                    _ = try RuntimeInstallFilesystem.ensureRealDirectoryTree(
                        root: home.path,
                        components: component == ".local" ? [".local", "bin"] : [".defenseclaw"]
                    )
                    fail("directory reservation followed symlinked \(component)")
                } catch {
                    // expected
                }
                expect(directoryContents(external).isEmpty, "symlink target remains untouched")
                expect(lexicalPathExists(ancestor), "symlinked ancestor is preserved")
            }
        }
    }

    private static func releaseAttestedGatewayCopyIsByteExact() {
        withTemporaryHome { home in
            let bin = home.appendingPathComponent("bin")
            try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: false)
            guard let parentIdentity = RuntimeInstallFilesystem.pathIdentity(bin.path) else {
                fail("could not capture gateway staging parent")
            }
            let releaseBytes = Data("release-attested-signed-gateway-bytes".utf8)
            let source = home.appendingPathComponent("bundled-gateway")
            let staged = bin.appendingPathComponent("defenseclaw-gateway.install-random")
            try releaseBytes.write(to: source)

            let stagedIdentity = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                source: source.path,
                destination: staged.path,
                expectedParentIdentity: parentIdentity,
                mode: mode_t(0o755),
                expectedSourceSHA256: sha256(releaseBytes)
            )

            expect(
                (try? Data(contentsOf: staged)) == releaseBytes,
                "gateway staging preserves the exact release-attested bytes"
            )
            expect(
                RuntimeInstallFilesystem.pathIdentity(staged.path) == stagedIdentity,
                "gateway staging returns the identity of the exact copied inode"
            )
            expect(
                RuntimeInstallFilesystem.pathIdentity(bin.path) == parentIdentity,
                "gateway staging keeps the pinned parent identity stable"
            )
        }
    }

    private static func fixedGatewayRequirementRejectsWrongIdentifier() {
        withTemporaryHome { directory in
            let source = URL(fileURLWithPath: CommandLine.arguments[0])
            let correct = directory.appendingPathComponent("correct-gateway")
            let wrong = directory.appendingPathComponent("wrong-gateway")
            try FileManager.default.copyItem(at: source, to: correct)
            try FileManager.default.copyItem(at: source, to: wrong)
            let correctSign = try runCodesign([
                "--force", "--sign", "-", "--identifier",
                "com.cisco.defenseclaw.gateway", correct.path,
            ])
            expect(
                correctSign == 0,
                "fixed-identifier gateway fixture is signed"
            )
            let wrongSign = try runCodesign([
                "--force", "--sign", "-", "--identifier",
                "com.example.wrong-gateway", wrong.path,
            ])
            expect(
                wrongSign == 0,
                "wrong-identifier gateway fixture is signed"
            )
            let requirement = #"=identifier "com.cisco.defenseclaw.gateway""#
            let correctVerify = try runCodesign([
                "--verify", "--strict", "-R", requirement, correct.path,
            ])
            expect(
                correctVerify == 0,
                "release-owned gateway identifier satisfies the fixed requirement"
            )
            let wrongVerify = try runCodesign([
                "--verify", "--strict", "-R", requirement, wrong.path,
            ])
            expect(
                wrongVerify != 0,
                "a valid signature with the wrong identifier is refused"
            )
        }
    }

    private static func runCodesign(_ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()
        _ = output.fileHandleForReading.readDataToEndOfFile()
        return process.terminationStatus
    }

    private static func stagedCLILinkRequiresExactTargetAndStableIdentity() {
        withTemporaryHome { home in
            let bin = home.appendingPathComponent("bin")
            try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: false)
            guard let parentIdentity = RuntimeInstallFilesystem.pathIdentity(bin.path) else {
                fail("could not capture CLI staging parent")
            }
            let staged = bin.appendingPathComponent("defenseclaw.install-random")
            let expected = home.appendingPathComponent("venv/bin/defenseclaw").path
            let identity = try RuntimeInstallFilesystem.createOwnedSymbolicLink(
                staged.path,
                target: expected,
                expectedParentIdentity: parentIdentity
            )
            expect(
                RuntimeInstallFilesystem.pathIdentity(staged.path) == identity,
                "descriptor-relative CLI link creation captures its exact inode"
            )
            try FileManager.default.removeItem(at: staged)
            do {
                _ = try RuntimeInstallFilesystem.createOwnedSymbolicLink(
                    staged.path,
                    target: expected,
                    expectedParentIdentity: parentIdentity,
                    afterCreate: {
                        try FileManager.default.removeItem(at: staged)
                        try FileManager.default.createSymbolicLink(
                            atPath: staged.path,
                            withDestinationPath: "/attacker/defenseclaw"
                        )
                    }
                )
                fail("CLI link replacement during attestation was accepted")
            } catch {
                // expected
            }
            expect(
                (try? FileManager.default.destinationOfSymbolicLink(atPath: staged.path))
                    == "/attacker/defenseclaw",
                "concurrent CLI link replacement is preserved"
            )
        }
    }

    private static func regularFileInstallNeverReplacesConcurrentTool() {
        withTemporaryHome { home in
            let bin = home.appendingPathComponent("bin")
            try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: false)
            let source = home.appendingPathComponent("verified-uv")
            try Data("verified".utf8).write(to: source)
            guard let parentIdentity = RuntimeInstallFilesystem.pathIdentity(bin.path) else {
                fail("could not capture uv destination parent")
            }
            let destination = bin.appendingPathComponent("uv")
            do {
                _ = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                    source: source.path,
                    destination: destination.path,
                    expectedParentIdentity: parentIdentity,
                    mode: mode_t(0o755),
                    beforeActivate: {
                        try Data("concurrent".utf8).write(to: destination)
                    }
                )
                fail("uv publication replaced a concurrent tool")
            } catch {
                // expected
            }
            expect(read(destination) == "concurrent", "concurrent uv is preserved exactly")
            expect(
                directoryContents(bin) == ["uv"],
                "failed uv publication removes only its private staging file"
            )
        }
    }

    private static func regularFileInstallBindsOpenedSourceBytesToExpectedDigest() {
        withTemporaryHome { home in
            let bin = home.appendingPathComponent("bin")
            try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: false)
            guard let parentIdentity = RuntimeInstallFilesystem.pathIdentity(bin.path) else {
                fail("could not capture authenticated destination parent")
            }
            let magic = Data("DEFENSECLAW-PROTECTED-ARTIFACT-V1\n".utf8)
            let original = Data("authenticated-wheel".utf8)
            let replacement = Data("substituted-wheel".utf8)
            let protectedOriginal = magic + Data(original.map { $0 ^ UInt8(0xA5) })
            let protectedReplacement = magic + Data(replacement.map { $0 ^ UInt8(0xA5) })
            let source = home.appendingPathComponent("runtime.dcwheel")
            try protectedOriginal.write(to: source)
            let destination = bin.appendingPathComponent("runtime.whl")

            _ = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                source: source.path,
                destination: destination.path,
                expectedParentIdentity: parentIdentity,
                mode: mode_t(0o600),
                stripPrefix: magic,
                decodeXORByte: UInt8(0xA5),
                expectedSourceSHA256: sha256(protectedOriginal),
                afterSourceOpen: {
                    try FileManager.default.removeItem(at: source)
                    try protectedReplacement.write(to: source)
                }
            )
            expect(
                (try? Data(contentsOf: destination)) == original,
                "materialization consumes the authenticated open descriptor, not a path replacement"
            )
            expect(
                (try? Data(contentsOf: source)) == protectedReplacement,
                "concurrent source-path replacement remains separate"
            )

            let refused = bin.appendingPathComponent("refused.whl")
            do {
                _ = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                    source: source.path,
                    destination: refused.path,
                    expectedParentIdentity: parentIdentity,
                    mode: mode_t(0o600),
                    stripPrefix: magic,
                    decodeXORByte: UInt8(0xA5),
                    expectedSourceSHA256: sha256(protectedOriginal)
                )
                fail("substituted protected source passed the authenticated outer digest")
            } catch {
                // expected
            }
            expect(!lexicalPathExists(refused), "digest mismatch withdraws the private stage")

            let stripOnly = bin.appendingPathComponent("strip-only.whl")
            do {
                _ = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                    source: source.path,
                    destination: stripOnly.path,
                    expectedParentIdentity: parentIdentity,
                    mode: mode_t(0o600),
                    stripPrefix: magic,
                    expectedSourceSHA256: sha256(protectedReplacement)
                )
                fail("protected source prefix was stripped without its decode transform")
            } catch {
                // expected
            }
            expect(
                !lexicalPathExists(stripOnly),
                "incomplete protected transform makes no destination"
            )

            let decodeOnly = bin.appendingPathComponent("decode-only.whl")
            do {
                _ = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                    source: source.path,
                    destination: decodeOnly.path,
                    expectedParentIdentity: parentIdentity,
                    mode: mode_t(0o600),
                    decodeXORByte: UInt8(0xA5),
                    expectedSourceSHA256: sha256(protectedReplacement)
                )
                fail("protected source was decoded without its authenticated prefix")
            } catch {
                // expected
            }
            expect(
                !lexicalPathExists(decodeOnly),
                "prefixless protected transform makes no destination"
            )
        }
    }

    private static func regularFilePostPublishFailuresWithdrawOwnedDestination() {
        for boundary in 0...1 {
            withTemporaryHome { home in
                let bin = home.appendingPathComponent("bin")
                try FileManager.default.createDirectory(
                    at: bin,
                    withIntermediateDirectories: false
                )
                let source = home.appendingPathComponent("verified-uv")
                try Data("verified".utf8).write(to: source)
                guard let parentIdentity = RuntimeInstallFilesystem.pathIdentity(bin.path) else {
                    fail("could not capture regular-file destination parent")
                }
                let destination = bin.appendingPathComponent("uv")
                do {
                    _ = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                        source: source.path,
                        destination: destination.path,
                        expectedParentIdentity: parentIdentity,
                        mode: mode_t(0o755),
                        afterPublish: {
                            if boundary == 0 { throw InjectedFailure.boundary }
                        },
                        beforeParentSync: {
                            if boundary == 1 { throw InjectedFailure.boundary }
                        }
                    )
                    fail("injected post-publish regular-file failure was ignored")
                } catch {
                    // expected
                }
                expect(
                    !lexicalPathExists(destination),
                    "post-publish regular-file failure withdraws its owned destination"
                )
                expect(
                    directoryContents(bin).isEmpty,
                    "post-publish regular-file rollback leaves no private stage"
                )
            }
        }
    }

    private static func regularFilePostPublishReplacementIsPreserved() {
        withTemporaryHome { home in
            let bin = home.appendingPathComponent("bin")
            try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: false)
            let source = home.appendingPathComponent("verified-uv")
            try Data("verified".utf8).write(to: source)
            guard let parentIdentity = RuntimeInstallFilesystem.pathIdentity(bin.path) else {
                fail("could not capture regular-file destination parent")
            }
            let destination = bin.appendingPathComponent("uv")
            do {
                _ = try RuntimeInstallFilesystem.installRegularFileNoReplace(
                    source: source.path,
                    destination: destination.path,
                    expectedParentIdentity: parentIdentity,
                    mode: mode_t(0o755),
                    afterPublish: {
                        try FileManager.default.removeItem(at: destination)
                        try Data("concurrent".utf8).write(to: destination)
                    }
                )
                fail("post-publish regular-file replacement passed held-inode verification")
            } catch {
                // expected
            }
            expect(
                read(destination) == "concurrent",
                "regular-file rollback never deletes a post-publish replacement"
            )
            expect(
                directoryContents(bin) == ["uv"],
                "regular-file replacement leaves no installer-owned private entry"
            )
        }
    }

    private static func interruptedActivationJournalRecoversEveryCutPoint() {
        for activatedCount in 0...3 {
            withTemporaryHome { home in
                let dataHome = home.appendingPathComponent(".defenseclaw")
                let binDir = home.appendingPathComponent(".local/bin")
                try FileManager.default.createDirectory(
                    at: dataHome,
                    withIntermediateDirectories: false
                )
                try FileManager.default.createDirectory(
                    at: binDir,
                    withIntermediateDirectories: true
                )
                let venvStage = dataHome.appendingPathComponent(
                    ".venv.staging-\(UUID().uuidString)"
                )
                let gatewayStage = binDir.appendingPathComponent(
                    "defenseclaw-gateway.install-\(UUID().uuidString)"
                )
                let cliStage = binDir.appendingPathComponent(
                    "defenseclaw.install-\(UUID().uuidString)"
                )
                try FileManager.default.createDirectory(
                    at: venvStage,
                    withIntermediateDirectories: false
                )
                try Data("venv".utf8).write(
                    to: venvStage.appendingPathComponent("installed")
                )
                try Data("gateway".utf8).write(to: gatewayStage)
                try FileManager.default.createSymbolicLink(
                    atPath: cliStage.path,
                    withDestinationPath: dataHome.appendingPathComponent(
                        ".venv/bin/defenseclaw"
                    ).path
                )
                let destinations = [
                    dataHome.appendingPathComponent(".venv"),
                    binDir.appendingPathComponent("defenseclaw-gateway"),
                    binDir.appendingPathComponent("defenseclaw"),
                ]
                let stages = [venvStage, gatewayStage, cliStage]
                let targets = try RuntimeInstallFilesystem.prepareActivationTargets(
                    Array(zip(stages, destinations)).map {
                        (staged: $0.0.path, destination: $0.1.path)
                    }
                )
                let journal = dataHome.appendingPathComponent(
                    ".fresh-install-activation-journal.json"
                )
                _ = try RuntimeInstallFilesystem.prepareActivationJournal(
                    targets,
                    path: journal.path
                )
                for index in 0..<activatedCount {
                    try FileManager.default.moveItem(
                        at: stages[index],
                        to: destinations[index]
                    )
                }

                let preserved = try RuntimeInstallFilesystem.recoverFreshInstallActivation(
                    journalPath: journal.path,
                    dataHome: dataHome.path,
                    binDir: binDir.path
                )

                expect(preserved.isEmpty, "crash recovery had no concurrent state")
                expect(!lexicalPathExists(journal), "committed recovery removes its journal")
                for path in stages + destinations {
                    expect(!lexicalPathExists(path), "crash recovery removes only its staged inode")
                }
            }
        }
    }

    private static func interruptedActivationJournalPreservesConcurrentReplacement() {
        withTemporaryHome { home in
            let dataHome = home.appendingPathComponent(".defenseclaw")
            let binDir = home.appendingPathComponent(".local/bin")
            try FileManager.default.createDirectory(at: dataHome, withIntermediateDirectories: false)
            try FileManager.default.createDirectory(at: binDir, withIntermediateDirectories: true)
            let venvStage = dataHome.appendingPathComponent(
                ".venv.staging-\(UUID().uuidString)"
            )
            let gatewayStage = binDir.appendingPathComponent(
                "defenseclaw-gateway.install-\(UUID().uuidString)"
            )
            let cliStage = binDir.appendingPathComponent(
                "defenseclaw.install-\(UUID().uuidString)"
            )
            try FileManager.default.createDirectory(at: venvStage, withIntermediateDirectories: false)
            try Data("gateway".utf8).write(to: gatewayStage)
            try FileManager.default.createSymbolicLink(
                atPath: cliStage.path,
                withDestinationPath: dataHome.appendingPathComponent(".venv/bin/defenseclaw").path
            )
            let venvDestination = dataHome.appendingPathComponent(".venv")
            let gatewayDestination = binDir.appendingPathComponent("defenseclaw-gateway")
            let cliDestination = binDir.appendingPathComponent("defenseclaw")
            let targets = try RuntimeInstallFilesystem.prepareActivationTargets([
                (staged: venvStage.path, destination: venvDestination.path),
                (staged: gatewayStage.path, destination: gatewayDestination.path),
                (staged: cliStage.path, destination: cliDestination.path),
            ])
            let journal = dataHome.appendingPathComponent(
                ".fresh-install-activation-journal.json"
            )
            _ = try RuntimeInstallFilesystem.prepareActivationJournal(targets, path: journal.path)
            try FileManager.default.moveItem(at: venvStage, to: venvDestination)
            try FileManager.default.removeItem(at: venvDestination)
            try FileManager.default.createDirectory(
                at: venvDestination,
                withIntermediateDirectories: false
            )
            let concurrent = venvDestination.appendingPathComponent("concurrent")
            try Data("preserve".utf8).write(to: concurrent)

            let preserved = try RuntimeInstallFilesystem.recoverFreshInstallActivation(
                journalPath: journal.path,
                dataHome: dataHome.path,
                binDir: binDir.path
            )

            expect(preserved == [venvDestination.path], "concurrent canonical path is reported")
            expect(read(concurrent) == "preserve", "concurrent replacement survives recovery")
            expect(!lexicalPathExists(gatewayStage), "unactivated gateway stage is cleaned")
            expect(!lexicalPathExists(cliStage), "unactivated CLI stage is cleaned")
            expect(!lexicalPathExists(journal), "completed recovery retires its journal")
        }
    }

    private static func destinationAppearingAfterPreparationIsPreservedAndPartialActivationRollsBack() {
        withTemporaryHome { home in
            let fixture = try activationFixture(home: home)
            let targets = try RuntimeInstallFilesystem.prepareActivationTargets(fixture.pairs)
            try Data("concurrent".utf8).write(to: fixture.gatewayDestination)
            do {
                _ = try RuntimeInstallFilesystem.activateNoReplace(targets)
                fail("activation replaced a destination created after preparation")
            } catch {
                // Expected: the venv move is withdrawn when the gateway move
                // observes the newly-created destination.
            }
            expect(read(fixture.gatewayDestination) == "concurrent", "concurrent gateway is preserved")
            expect(!lexicalPathExists(fixture.venvDestination), "partial venv activation was rolled back")
            expect(!lexicalPathExists(fixture.cliDestination), "CLI destination stayed absent")
            expect(
                RuntimeInstallFilesystem.cleanupPreparedActivation(targets).isEmpty,
                "remaining installer-owned stages are cleanable"
            )
        }
    }

    private static func postPublishFailuresAtEveryBoundaryRollBackAllCustodiedTargets() {
        let boundaries: [RuntimeInstallFilesystem.ActivationBoundary] = [
            .afterPublish,
            .afterDestinationVerification,
            .beforeStagedParentSync,
            .beforeDestinationParentSync,
        ]
        for boundary in boundaries {
            for failingIndex in 0...2 {
                withTemporaryHome { home in
                    let fixture = try activationFixture(home: home)
                    let targets = try RuntimeInstallFilesystem.prepareActivationTargets(
                        fixture.pairs
                    )
                    let journal = fixture.venvDestination
                        .deletingLastPathComponent()
                        .appendingPathComponent("activation-journal.json")
                    do {
                        _ = try RuntimeInstallFilesystem.activateNoReplace(
                            targets,
                            journalPath: journal.path,
                            atBoundary: { index, observedBoundary in
                                if index == failingIndex, observedBoundary == boundary {
                                    throw InjectedFailure.boundary
                                }
                            }
                        )
                        fail("injected activation boundary failure was ignored")
                    } catch {
                        // expected
                    }
                    for destination in [
                        fixture.venvDestination,
                        fixture.gatewayDestination,
                        fixture.cliDestination,
                    ] {
                        expect(
                            !lexicalPathExists(destination),
                            "every successfully published target entered rollback custody"
                        )
                    }
                    expect(
                        !lexicalPathExists(journal),
                        "successful boundary rollback retires its activation journal"
                    )
                    expect(
                        RuntimeInstallFilesystem.cleanupPreparedActivation(targets).isEmpty,
                        "unpublished stages remain exactly cleanable after boundary rollback"
                    )
                }
            }
        }
    }

    private static func postPublishReplacementIsPreservedAndJournalRemainsRecoverable() {
        withTemporaryHome { home in
            let fixture = try activationFixture(home: home)
            let targets = try RuntimeInstallFilesystem.prepareActivationTargets(fixture.pairs)
            let journal = fixture.venvDestination
                .deletingLastPathComponent()
                .appendingPathComponent("activation-journal.json")
            do {
                _ = try RuntimeInstallFilesystem.activateNoReplace(
                    targets,
                    journalPath: journal.path,
                    atBoundary: { index, boundary in
                        guard index == 0, boundary == .afterPublish else { return }
                        try FileManager.default.removeItem(at: fixture.venvDestination)
                        try FileManager.default.createDirectory(
                            at: fixture.venvDestination,
                            withIntermediateDirectories: false
                        )
                        try Data("concurrent".utf8).write(
                            to: fixture.venvDestination.appendingPathComponent("keep")
                        )
                    }
                )
                fail("post-publish replacement passed held-inode verification")
            } catch {
                // expected
            }
            expect(
                read(fixture.venvDestination.appendingPathComponent("keep")) == "concurrent",
                "post-publish concurrent replacement is never deleted"
            )
            expect(
                lexicalPathExists(journal),
                "a preserved concurrent replacement keeps the durable recovery journal"
            )
            expect(
                RuntimeInstallFilesystem.cleanupPreparedActivation(targets).isEmpty,
                "unpublished stages remain exactly cleanable"
            )
            // This fixture uses generic target names, so its journal is not a
            // production recovery contract; retire the exact test-owned file.
            guard let journalIdentity = RuntimeInstallFilesystem.pathIdentity(journal.path) else {
                fail("could not capture retained test journal")
            }
            expect(
                RuntimeInstallFilesystem.cleanupOwnedPath(
                    journal.path,
                    identity: journalIdentity
                ),
                "retained test journal is exactly removable"
            )
        }
    }

    private static func rollbackPreservesAConcurrentReplacement() {
        withTemporaryHome { home in
            let fixture = try activationFixture(home: home)
            let targets = try RuntimeInstallFilesystem.prepareActivationTargets(fixture.pairs)
            do {
                _ = try RuntimeInstallFilesystem.activateNoReplace(
                    targets,
                    beforeActivating: { index in
                        guard index == 1 else { return }
                        try FileManager.default.removeItem(at: fixture.venvDestination)
                        try FileManager.default.createDirectory(
                            at: fixture.venvDestination,
                            withIntermediateDirectories: false
                        )
                        try Data("preserve".utf8).write(
                            to: fixture.venvDestination.appendingPathComponent("concurrent-state")
                        )
                        try Data("blocks-gateway".utf8).write(to: fixture.gatewayDestination)
                    }
                )
                fail("activation unexpectedly succeeded after a concurrent replacement")
            } catch {
                // Expected: rollback notices that the venv inode is no longer
                // installer-owned and puts the concurrent directory back.
            }
            expect(
                read(fixture.venvDestination.appendingPathComponent("concurrent-state")) == "preserve",
                "rollback never deletes a concurrent replacement"
            )
            expect(read(fixture.gatewayDestination) == "blocks-gateway", "blocking target is preserved")
            _ = RuntimeInstallFilesystem.cleanupPreparedActivation(targets)
        }
    }

    private static func cleanupSwapKeepsCanonicalOccupiedAndRestoresConcurrentState() {
        withTemporaryHome { home in
            let target = home.appendingPathComponent("runtime-target")
            try Data("installer".utf8).write(to: target)
            guard let owned = RuntimeInstallFilesystem.pathIdentity(target.path) else {
                fail("could not capture installer-owned target")
            }
            var createErrno: Int32 = 0
            let removed = RuntimeInstallFilesystem.cleanupOwnedPath(
                target.path,
                identity: owned,
                afterSwap: {
                    let descriptor = open(
                        target.path,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        mode_t(0o600)
                    )
                    if descriptor >= 0 {
                        close(descriptor)
                    } else {
                        createErrno = errno
                    }
                }
            )
            expect(removed, "the exact installer-owned target is removed")
            expect(createErrno == EEXIST, "canonical leaf remains occupied during ownership check")
            expect(!lexicalPathExists(target), "successful cleanup retires its canonical target")
            expect(
                directoryContents(home).isEmpty,
                "successful cleanup leaves no synthetic placeholder"
            )
        }
    }

    private static func failedCleanupSwapBackNeverDeletesDisplacedConcurrentState() {
        withTemporaryHome { home in
            let target = home.appendingPathComponent("runtime-target")
            try Data("installer".utf8).write(to: target)
            guard let owned = RuntimeInstallFilesystem.pathIdentity(target.path) else {
                fail("could not capture installer-owned target")
            }
            let removed = RuntimeInstallFilesystem.cleanupOwnedPath(
                target.path,
                identity: owned,
                afterSwap: {
                    // Remove the canonical placeholder so the attempted atomic
                    // swap-back fails. The displaced concurrent candidate must
                    // remain present under the visible cleanup name.
                    try FileManager.default.removeItem(at: target)
                    throw NSError(domain: "injected-swap-back-failure", code: 1)
                }
            )
            expect(!removed, "failed swap-back reports preservation, never success")
            expect(
                read(target) == "installer",
                "missing-placeholder failure restores the displaced candidate canonically"
            )
            expect(
                directoryContents(home) == ["runtime-target"],
                "missing-placeholder recovery leaves no synthetic cleanup entry"
            )
        }
    }

    private static func repeatedSwapBackFailureUsesNoExchangeRestoration() {
        withTemporaryHome { home in
            let target = home.appendingPathComponent("runtime-target")
            try Data("installer".utf8).write(to: target)
            guard let owned = RuntimeInstallFilesystem.pathIdentity(target.path) else {
                fail("could not capture installer-owned target")
            }
            var restorationAttempts = 0
            let removed = RuntimeInstallFilesystem.cleanupOwnedPath(
                target.path,
                identity: owned,
                restorationSwap: { _, _, _ in
                    restorationAttempts += 1
                    return -1
                }
            )
            expect(!removed, "forced restoration-exchange failure reports cleanup failure")
            expect(
                restorationAttempts == 3,
                "main swap-back and both exchange retries were fault-injected"
            )
            expect(
                read(target) == "installer",
                "no-exchange fallback restores the displaced candidate canonically"
            )
            expect(
                directoryContents(home) == ["runtime-target"],
                "no-exchange fallback retires every synthetic placeholder"
            )
        }
    }

    private static func placeholderRetirementFailureLeavesOwnedCandidateCanonical() {
        withTemporaryHome { home in
            let target = home.appendingPathComponent("runtime-target")
            try Data("installer".utf8).write(to: target)
            guard let owned = RuntimeInstallFilesystem.pathIdentity(target.path) else {
                fail("could not capture installer-owned target")
            }
            let removed = RuntimeInstallFilesystem.cleanupOwnedPath(
                target.path,
                identity: owned,
                beforePlaceholderRetire: {
                    guard let placeholder = directoryContents(home).first(where: {
                        $0.hasPrefix(".defenseclaw-cleanup-")
                    }) else {
                        fail("cleanup placeholder was unavailable at retirement boundary")
                    }
                    let privatePath = home.appendingPathComponent(placeholder)
                    try FileManager.default.removeItem(at: privatePath)
                    try Data("foreign-private".utf8).write(to: privatePath)
                }
            )
            expect(!removed, "replaced placeholder cannot be retired as installer-owned")
            expect(
                read(target) == "installer",
                "placeholder retirement failure leaves the owned candidate canonical"
            )
            let privateEntries = directoryContents(home).filter {
                $0.hasPrefix(".defenseclaw-cleanup-")
            }
            expect(privateEntries.count == 1, "foreign private replacement is preserved")
            expect(
                read(home.appendingPathComponent(privateEntries[0])) == "foreign-private",
                "retirement failure never deletes a foreign private replacement"
            )
        }
    }

    private static func quarantineFailureRestoresOwnedCandidateCanonical() {
        withTemporaryHome { home in
            let target = home.appendingPathComponent("runtime-target")
            try Data("installer".utf8).write(to: target)
            guard let owned = RuntimeInstallFilesystem.pathIdentity(target.path) else {
                fail("could not capture installer-owned target")
            }
            let removed = RuntimeInstallFilesystem.cleanupOwnedPath(
                target.path,
                identity: owned,
                afterQuarantine: {
                    throw InjectedFailure.boundary
                }
            )
            expect(!removed, "quarantine removal injection reports failure")
            expect(
                read(target) == "installer",
                "pre-removal quarantine failure restores the owned candidate canonically"
            )
            expect(
                directoryContents(home) == ["runtime-target"],
                "quarantine failure leaves no synthetic private entry"
            )
        }
    }

    private static func recursiveCleanupRebindPreservesReplacementContents() {
        withTemporaryHome { home in
            let target = home.appendingPathComponent("runtime-target")
            let nested = target.appendingPathComponent("lib/site-packages/example")
            try FileManager.default.createDirectory(
                at: nested,
                withIntermediateDirectories: true
            )
            try Data("installer-owned".utf8).write(
                to: nested.appendingPathComponent("module.py")
            )
            guard let owned = RuntimeInstallFilesystem.pathIdentity(target.path) else {
                fail("could not capture installer-owned recursive target")
            }
            let displacedOwned = home.appendingPathComponent("displaced-owned-runtime")
            let removed = RuntimeInstallFilesystem.cleanupOwnedPath(
                target.path,
                identity: owned,
                afterRecursiveRootOpen: {
                    guard let quarantineName = directoryContents(home).first(where: {
                        $0.hasPrefix(".defenseclaw-cleanup-")
                    }) else {
                        fail("recursive quarantine was unavailable at rebind boundary")
                    }
                    let quarantine = home.appendingPathComponent(quarantineName)
                    try FileManager.default.moveItem(at: quarantine, to: displacedOwned)
                    let unrelated = quarantine.appendingPathComponent("unrelated/nested")
                    try FileManager.default.createDirectory(
                        at: unrelated,
                        withIntermediateDirectories: true
                    )
                    try Data("preserve".utf8).write(
                        to: unrelated.appendingPathComponent("keep")
                    )
                }
            )

            expect(!removed, "a rebound recursive root cannot report owned cleanup success")
            expect(
                read(target.appendingPathComponent("unrelated/nested/keep")) == "preserve",
                "descriptor-bound traversal never deletes replacement directory contents"
            )
            expect(
                directoryContents(displacedOwned).isEmpty,
                "recursive traversal remained bound to the originally opened inode"
            )
        }
    }

    private static func finalPlaceholderRacePreservesConcurrentCanonicalState() {
        withTemporaryHome { home in
            let target = home.appendingPathComponent("runtime-target")
            try Data("installer".utf8).write(to: target)
            guard let owned = RuntimeInstallFilesystem.pathIdentity(target.path) else {
                fail("could not capture installer-owned target")
            }
            let removed = RuntimeInstallFilesystem.cleanupOwnedPath(
                target.path,
                identity: owned,
                afterSwap: {
                    // Replace the canonical placeholder after the initial swap
                    // but before candidate retirement. Cleanup must not unlink
                    // this concurrent object at the public name.
                    try FileManager.default.removeItem(at: target)
                    try Data("concurrent-final".utf8).write(to: target)
                }
            )
            expect(!removed, "canonical replacement prevents cleanup success")
            expect(
                read(target) == "concurrent-final",
                "final placeholder race preserves concurrent canonical state"
            )
        }
    }

    private static func activationRefusesParentDirectorySymlinkSwap() {
        withTemporaryHome { home in
            let fixture = try activationFixture(home: home)
            let targets = try RuntimeInstallFilesystem.prepareActivationTargets(fixture.pairs)
            let destinationRoot = fixture.venvDestination.deletingLastPathComponent()
            let originalRoot = home.appendingPathComponent("destinations-original")
            let externalRoot = home.appendingPathComponent("external")
            try FileManager.default.createDirectory(at: externalRoot, withIntermediateDirectories: false)
            do {
                _ = try RuntimeInstallFilesystem.activateNoReplace(
                    targets,
                    beforeActivating: { index in
                        guard index == 0 else { return }
                        try FileManager.default.moveItem(at: destinationRoot, to: originalRoot)
                        try FileManager.default.createSymbolicLink(
                            atPath: destinationRoot.path,
                            withDestinationPath: externalRoot.path
                        )
                    }
                )
                fail("activation followed a swapped parent symlink")
            } catch {
                // expected
            }
            expect(directoryContents(externalRoot).isEmpty, "external symlink target is untouched")
            expect(lexicalPathExists(destinationRoot), "concurrent parent symlink is preserved")
            expect(
                RuntimeInstallFilesystem.lexicalPathExists(fixture.pairs[0].staged),
                "staged venv was not redirected"
            )
            _ = RuntimeInstallFilesystem.cleanupPreparedActivation(targets)
        }
    }

    private static func successfulNoReplaceActivationCanRemoveOnlyItsOwnTargets() {
        withTemporaryHome { home in
            let fixture = try activationFixture(home: home)
            let targets = try RuntimeInstallFilesystem.prepareActivationTargets(fixture.pairs)
            let receipt = try RuntimeInstallFilesystem.activateNoReplace(targets)
            expect(lexicalPathExists(fixture.venvDestination), "venv activated")
            expect(read(fixture.gatewayDestination) == "gateway", "gateway activated")
            expect(lexicalPathExists(fixture.cliDestination), "CLI link activated")
            expect(
                RuntimeInstallFilesystem.rollbackActivation(receipt).isEmpty,
                "owned activation is removable after verification failure"
            )
            expect(!lexicalPathExists(fixture.venvDestination), "owned venv removed")
            expect(!lexicalPathExists(fixture.gatewayDestination), "owned gateway removed")
            expect(!lexicalPathExists(fixture.cliDestination), "owned CLI link removed")
            expect(
                directoryContents(fixture.venvDestination.deletingLastPathComponent()).isEmpty,
                "non-empty venv rollback leaves no canonical or quarantine entry"
            )
        }
    }

    private typealias ActivationFixture = (
        pairs: [(staged: String, destination: String)],
        venvDestination: URL,
        gatewayDestination: URL,
        cliDestination: URL
    )

    private static func activationFixture(home: URL) throws -> ActivationFixture {
        let stageRoot = home.appendingPathComponent("staging")
        let destinationRoot = home.appendingPathComponent("destinations")
        try FileManager.default.createDirectory(at: stageRoot, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: destinationRoot, withIntermediateDirectories: false)
        let venvStage = stageRoot.appendingPathComponent("venv")
        let gatewayStage = stageRoot.appendingPathComponent("gateway")
        let cliStage = stageRoot.appendingPathComponent("cli")
        try FileManager.default.createDirectory(at: venvStage, withIntermediateDirectories: false)
        let packageDir = venvStage.appendingPathComponent("lib/site-packages/example")
        try FileManager.default.createDirectory(at: packageDir, withIntermediateDirectories: true)
        try Data("installed-package".utf8).write(to: packageDir.appendingPathComponent("module.py"))
        try Data("gateway".utf8).write(to: gatewayStage)
        try FileManager.default.createSymbolicLink(
            atPath: cliStage.path,
            withDestinationPath: "/future/venv/bin/defenseclaw"
        )
        let venvDestination = destinationRoot.appendingPathComponent("venv")
        let gatewayDestination = destinationRoot.appendingPathComponent("gateway")
        let cliDestination = destinationRoot.appendingPathComponent("cli")
        return (
            pairs: [
                (staged: venvStage.path, destination: venvDestination.path),
                (staged: gatewayStage.path, destination: gatewayDestination.path),
                (staged: cliStage.path, destination: cliDestination.path),
            ],
            venvDestination: venvDestination,
            gatewayDestination: gatewayDestination,
            cliDestination: cliDestination
        )
    }

    /// Run the same preflight/ownership/cleanup sequence as an injected
    /// pre-activation installer failure.
    private static func injectFailure(
        home: URL,
        beforeCleanup: (() throws -> Void)? = nil
    ) throws {
        let fileManager = FileManager.default
        let dataHome = home.appendingPathComponent(".defenseclaw")
        let existedBeforeInstall = RuntimeInstallFilesystem.lexicalPathExists(dataHome.path)
        guard RuntimeInstallFilesystem.existingManagedRuntimeMarker(home: home.path) == nil else {
            return
        }
        let staging = dataHome.appendingPathComponent(".venv.staging")
        if !RuntimeInstallFilesystem.lexicalPathExists(dataHome.path) {
            try fileManager.createDirectory(at: dataHome, withIntermediateDirectories: false)
        }
        let stagingIdentity = try RuntimeInstallFilesystem.createOwnedDirectory(staging.path)
        try Data("installer-owned".utf8).write(to: staging.appendingPathComponent("payload"))
        try beforeCleanup?()
        RuntimeInstallFilesystem.cleanupFailedFreshInstall(
            stagingDir: staging.path,
            stagingIdentity: stagingIdentity,
            dataHome: dataHome.path,
            removeDataHomeIfEmpty: !existedBeforeInstall
        )
    }

    private static func withTemporaryHome(_ body: (URL) throws -> Void) {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-runtime-install-tests-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: home) }
            try body(home)
        } catch {
            fail("temporary-home test failed: \(error)")
        }
    }

    private static func lexicalPathExists(_ url: URL) -> Bool {
        RuntimeInstallFilesystem.lexicalPathExists(url.path)
    }

    private static func directoryContents(_ url: URL) -> [String] {
        do {
            return try FileManager.default.contentsOfDirectory(atPath: url.path)
        } catch {
            fail("could not read directory \(url.path): \(error)")
        }
    }

    private static func read(_ url: URL) -> String {
        do {
            return try String(contentsOf: url, encoding: .utf8)
        } catch {
            fail("could not read \(url.path): \(error)")
        }
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fail(message) }
    }

    private static func fail(_ message: String) -> Never {
        fatalError("RuntimeInstallFilesystemTests failed: \(message)")
    }

    private enum InjectedFailure: Error {
        case boundary
    }
}
