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
struct SecretAndFileSafetyTests {
    static func main() {
        credentialExecutionPlanKeepsSecretOutOfArgvAndDisplay()
        credentialExecutionPlanValidatesBothInputs()
        normalExecutionPlanPreservesArguments()
        secureWriterPreparesPrivateFileBeforeAtomicInstall()
        secureWriterRejectsAnInheritableReadACL()
        secureWriterCleansUpWithoutReplacingOnPreinstallFailure()
        print("SecretAndFileSafetyTests passed")
    }

    private static func credentialExecutionPlanKeepsSecretOutOfArgvAndDisplay() {
        let command = credentialCommand()
        let secret = "regression-secret-never-display"
        expect(command.requiresSecretStandardInput, "keys set requires secret stdin")
        expect(command.usage == "<ENV_NAME>", "keys set usage contains only the environment name")

        let plan: CommandExecutionPlan
        do {
            plan = try command.executionPlan(
                extraArguments: ["CUSTOM_API_TOKEN"],
                secretInput: secret
            )
        } catch {
            fail("valid keys set plan failed: \(error)")
        }
        expect(
            plan.arguments == ["keys", "set", "CUSTOM_API_TOKEN"],
            "keys set argv contains only the credential name"
        )
        expect(plan.standardInput == secret, "keys set secret is carried via stdin")
        expect(!plan.arguments.contains(secret), "keys set secret is absent from argv")

        let legacyInput = ["CUSTOM_API_TOKEN", "--value", secret]
        let display = command.displayCommand(extraArguments: legacyInput)
        expect(display == "defenseclaw keys set CUSTOM_API_TOKEN", "legacy secret is redacted from preview")
        expect(!display.contains(secret), "secret is absent from preview and pasteboard text")
        expect(!display.contains("--value"), "legacy value flag is absent from preview")
    }

    private static func credentialExecutionPlanValidatesBothInputs() {
        let command = credentialCommand()
        expectThrows("missing credential environment name") {
            _ = try command.executionPlan(extraArguments: [], secretInput: "secret")
        }
        expectThrows("multiple credential arguments") {
            _ = try command.executionPlan(
                extraArguments: ["CUSTOM_API_TOKEN", "--value", "secret"],
                secretInput: "different-secret"
            )
        }
        expectThrows("option token instead of credential environment name") {
            _ = try command.executionPlan(extraArguments: ["--value"], secretInput: "secret")
        }
        expectThrows("invalid credential environment name") {
            _ = try command.executionPlan(extraArguments: ["9INVALID"], secretInput: "secret")
        }
        expectThrows("missing credential secret") {
            _ = try command.executionPlan(extraArguments: ["CUSTOM_API_TOKEN"], secretInput: "")
        }
    }

    private static func normalExecutionPlanPreservesArguments() {
        guard let command = CommandRegistry.all.first(where: { $0.title == "skill search" }) else {
            fail("skill search registry command is missing")
        }
        let plan: CommandExecutionPlan
        do {
            plan = try command.executionPlan(extraArguments: ["two words"], secretInput: "ignored")
        } catch {
            fail("normal command plan failed: \(error)")
        }
        expect(plan.arguments == ["skill", "search", "two words"], "normal command argv is unchanged")
        expect(plan.standardInput == nil, "normal commands do not receive secret stdin")
    }

    private static func secureWriterPreparesPrivateFileBeforeAtomicInstall() {
        withTemporaryDirectory { directory in
            let fileManager = FileManager.default
            try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
            let target = directory.appendingPathComponent("last-run.log")
            try Data("old output".utf8).write(to: target)
            try fileManager.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)

            var observedPreparedFile = false
            try SecureFileWriter.write(
                Data("new sensitive output".utf8),
                to: target,
                preparedFileCheck: { temporary in
                    observedPreparedFile = true
                    expect(
                        temporary.deletingLastPathComponent() == target.deletingLastPathComponent(),
                        "temporary file is prepared in the destination directory"
                    )
                    expect(permissions(of: temporary) == 0o600, "temporary file is 0600 before install")
                    expect(read(target) == "old output", "destination is unchanged before atomic install")
                }
            )

            expect(observedPreparedFile, "secure writer checked the prepared inode")
            expect(read(target) == "new sensitive output", "secure writer installs the new payload")
            expect(permissions(of: target) == 0o600, "installed output remains 0600")
            expect(permissions(of: directory) == 0o700, "DefenseClaw data directory is 0700")
            let remainingFiles = try fileManager.contentsOfDirectory(atPath: directory.path)
            expect(
                remainingFiles == ["last-run.log"],
                "secure writer leaves no temporary file"
            )
        }
    }

    private static func secureWriterCleansUpWithoutReplacingOnPreinstallFailure() {
        enum ExpectedFailure: Swift.Error { case stop }

        withTemporaryDirectory { directory in
            let fileManager = FileManager.default
            let target = directory.appendingPathComponent("last-run.log")
            try Data("keep me".utf8).write(to: target)
            do {
                try SecureFileWriter.write(
                    Data("do not install".utf8),
                    to: target,
                    preparedFileCheck: { _ in throw ExpectedFailure.stop }
                )
                fail("preinstall failure should propagate")
            } catch ExpectedFailure.stop {
                // Expected.
            } catch {
                fail("unexpected secure writer failure: \(error)")
            }
            expect(read(target) == "keep me", "failed prepared file does not replace destination")
            let remainingFiles = try fileManager.contentsOfDirectory(atPath: directory.path)
            expect(
                remainingFiles == ["last-run.log"],
                "failed prepared file is removed"
            )
        }
    }

    private static func secureWriterRejectsAnInheritableReadACL() {
        withTemporaryDirectory { directory in
            try installInheritedReadACL(on: directory)
            let target = directory.appendingPathComponent("last-run.log")
            do {
                try SecureFileWriter.write(Data("sensitive output".utf8), to: target)
                fail("an inheritable read ACL should prevent secure export")
            } catch SecureFileWriter.WriteError.insecureExtendedACL(let path) {
                expect(path == directory.path, "the parent ACL is identified")
            } catch {
                fail("unexpected ACL validation failure: \(error)")
            }
            expect(!FileManager.default.fileExists(atPath: target.path), "ACL failure installs no output")
        }
    }

    private static func credentialCommand() -> CommandDefinition {
        guard let command = CommandRegistry.all.first(where: { $0.arguments == ["keys", "set"] }) else {
            fail("keys set registry command is missing")
        }
        return command
    }

    private static func withTemporaryDirectory(_ body: (URL) throws -> Void) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-secret-file-tests-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: directory) }
            try body(directory)
        } catch {
            fail("temporary directory test failed: \(error)")
        }
    }

    private static func installInheritedReadACL(on directory: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "everyone allow read,file_inherit", directory.path]
        let errorPipe = Pipe()
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(
                decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(),
                as: UTF8.self
            )
            fail("could not install inherited test ACL: \(detail)")
        }
    }

    private static func permissions(of url: URL) -> Int {
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard let value = attributes[.posixPermissions] as? NSNumber else {
                fail("missing permissions for \(url.path)")
            }
            return value.intValue
        } catch {
            fail("could not read permissions for \(url.path): \(error)")
        }
    }

    private static func read(_ url: URL) -> String {
        do {
            return try String(contentsOf: url, encoding: .utf8)
        } catch {
            fail("could not read \(url.path): \(error)")
        }
    }

    private static func expectThrows(_ label: String, _ body: () throws -> Void) {
        do {
            try body()
            fail("expected failure: \(label)")
        } catch {
            // Expected.
        }
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fail(message) }
    }

    private static func fail(_ message: String) -> Never {
        fatalError("SecretAndFileSafetyTests failed: \(message)")
    }
}
