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

/// What a fake runner was asked to run.
struct VaultRun: Sendable {
    var title: String
    var arguments: [String]
    var standardInput: String?
}

/// Records every read and change; answers with the queued results.
@MainActor final class VaultFakeCLI {
    var runs: [VaultRun] = []
    var reads: [[String]] = []
    var runResult = CLIResult(exitCode: 0, output: "")
    var listOutput = "{\"path\":\"/fixture/vault.json\",\"entries\":[]}"
    var readExit: Int32 = 0

    func runner() -> SandboxVaultStore.Runner {
        { title, arguments, input in
            self.runs.append(VaultRun(title: title, arguments: arguments, standardInput: input))
            return self.runResult
        }
    }

    func reader() -> SandboxVaultStore.Reader {
        { arguments in await self.read(arguments) }
    }

    func read(_ arguments: [String]) -> CLIResult {
        reads.append(arguments)
        return CLIResult(exitCode: readExit, output: readExit == 0 ? listOutput : "Error: the vault file is not valid\n")
    }
}

/// A reader whose first read is still in flight when the next refresh is
/// asked for (the re-read after a change).
@MainActor final class VaultRacingReads {
    var outputs: [String] = []
    var reads = 0
    var store: SandboxVaultStore?

    func reader() -> SandboxVaultStore.Reader {
        { arguments in await self.read(arguments) }
    }

    func read(_ arguments: [String]) async -> CLIResult {
        reads += 1
        let output = outputs[min(reads, outputs.count) - 1]
        if reads == 1, let store {
            await store.refresh(read: reader(), managed: false)
        }
        return CLIResult(exitCode: 0, output: output)
    }
}

@main
struct SandboxVaultTests {
    static var checks = 0
    static func expect(_ condition: Bool, _ message: String) {
        checks += 1
        if !condition { fatalError(message) }
    }

    static func json(_ value: Any) -> String {
        String(data: try! JSONSerialization.data(withJSONObject: value), encoding: .utf8)!
    }

    /// A stand-in value made at run time: plain words, nothing shaped like
    /// a real credential.
    static func fixtureValue() -> String {
        ["fixture", "value", String(Int.random(in: 100_000...999_999))].joined(separator: "-")
    }

    @MainActor static func main() async throws {
        CLIProcessGroupLauncher.execIfRequested()
        validation()
        commands()
        try decoding()
        await store()
        await hintNeverShown()
        await queuedRefresh()
        print("PASS \(checks) sandbox vault checks")
    }

    static func validation() {
        for name in ["STRIPE_API_KEY", "_x", "a1", String(repeating: "A", count: 128)] {
            expect(SandboxVault.validName(name), "valid name \(name)")
        }
        for name in ["", "1abc", "a-b", "--host", "a b", "\u{00C4}B", "a\nb", String(repeating: "A", count: 129)] {
            expect(!SandboxVault.validName(name), "invalid name refused")
        }
        expect(SandboxVault.nameProblem("  OK_NAME ") != nil, "an untrimmed name is refused (the editor trims)")
        for host in ["api.stripe.com", "api.example.com:8443", " api.example.com "] {
            expect(SandboxVault.hostProblem(host) == nil, "plausible host \(host)")
        }
        for host in ["", "https://api.example.com", "api.example.com/v1", "-api.example.com", "localhost",
                     "user@api.example.com", "*.example.com", "a b.example.com", "api.example.com?x=1"] {
            expect(SandboxVault.hostProblem(host) != nil, "implausible host refused: \(host)")
        }
        let value = fixtureValue()
        expect(SandboxVault.valueProblem(value) == nil, "one-line value accepted")
        expect(SandboxVault.normalizedValue(value + "\r\n") == value, "trailing line break dropped")
        expect(SandboxVault.normalizedValue("\n" + value) == value, "leading line break dropped")
        expect(SandboxVault.valueProblem("") != nil && SandboxVault.valueProblem("\n") != nil, "empty value refused")
        expect(SandboxVault.valueProblem(value + "\n" + value) != nil, "two lines refused")
        expect(SandboxVault.valueProblem(String(repeating: "x", count: SandboxVault.maxValueBytes + 1)) != nil, "oversize value refused")
        expect(SandboxVault.valueProblem(String(repeating: "x", count: SandboxVault.maxValueBytes)) == nil, "value at the limit accepted")

        var status = SandboxStatus()
        expect(!SandboxVault.shown(status), "hidden before the daemon answered")
        status.loaded = true
        expect(!SandboxVault.shown(status), "hidden where sandboxes are off")
        status.enabled = true
        expect(SandboxVault.shown(status), "shown where sandboxes are set up")
    }

    static func commands() {
        // The TUI's argv (vault_state.py), value never among them.
        expect(SandboxVault.listArguments == ["sandbox", "vault", "list", "--json"], "list argv")
        expect(SandboxVaultChange.add(name: "API_KEY", host: " api.example.com ").arguments
               == ["sandbox", "vault", "add", "--host", "api.example.com", "--value-stdin", "API_KEY"], "add argv")
        expect(SandboxVaultChange.replace(name: "API_KEY").arguments
               == ["sandbox", "vault", "replace", "--value-stdin", "API_KEY"], "replace argv")
        expect(SandboxVaultChange.bind(name: "API_KEY", host: "api.example.com:8443").arguments
               == ["sandbox", "vault", "bind", "--host", "api.example.com:8443", "API_KEY"], "bind argv")
        expect(SandboxVaultChange.rename(name: "API_KEY", newName: "NEW_KEY").arguments
               == ["sandbox", "vault", "rename", "API_KEY", "NEW_KEY"], "rename argv")
        expect(SandboxVaultChange.confirm(name: "API_KEY").arguments == ["sandbox", "vault", "confirm", "--yes", "API_KEY"],
               "confirm argv (the TUI's c)")
        expect(!SandboxVaultChange.confirm(name: "API_KEY").needsValue, "confirm takes no value")
        expect(SandboxVaultChange.confirm(name: "--yes").problem != nil, "confirm of a flag-shaped name refused")
        expect(SandboxVaultChange.remove(name: "API_KEY").arguments
               == ["sandbox", "vault", "remove", "--yes", "API_KEY"], "remove argv")
        expect(SandboxVaultChange.add(name: "A", host: "x").needsValue && SandboxVaultChange.replace(name: "A").needsValue
               && !SandboxVaultChange.bind(name: "A", host: "x").needsValue, "only add and replace take a value")
        expect(SandboxVaultChange.rename(name: "API_KEY", newName: "API_KEY").problem != nil, "rename to the same name refused")
        expect(SandboxVaultChange.rename(name: "API_KEY", newName: "9X").problem != nil, "rename to an invalid name refused")
        expect(SandboxVaultChange.bind(name: "API_KEY", host: "https://x.example.com").problem != nil, "bind to a URL refused")

        expect(SandboxVaultEditor.add.change(name: " API_KEY ", host: "api.example.com", newName: "")
               == .add(name: "API_KEY", host: "api.example.com"), "add editor")
        expect(SandboxVaultEditor.replace("API_KEY").change(name: "", host: "", newName: "") == .replace(name: "API_KEY"), "replace editor")
        expect(SandboxVaultEditor.bind("API_KEY", current: "old.example.com").change(name: "", host: "new.example.com", newName: "")
               == .bind(name: "API_KEY", host: "new.example.com"), "bind editor")
        expect(SandboxVaultEditor.rename("API_KEY").change(name: "", host: "", newName: "NEW_KEY")
               == .rename(name: "API_KEY", newName: "NEW_KEY"), "rename editor")
        expect(SandboxVaultEditor.add.asksValue && SandboxVaultEditor.replace("A").asksValue
               && !SandboxVaultEditor.bind("A", current: "").asksValue && !SandboxVaultEditor.rename("A").asksValue,
               "only add and replace show a SecureField")
    }

    static func decoding() throws {
        let value = fixtureValue()
        let now = Date()
        let used = ISO8601DateFormatter().string(from: now.addingTimeInterval(-7_200))
        let text = json([
            "path": "/fixture/vault.json",
            "entries": [
                ["name": "STRIPE_API_KEY", "target": "api.stripe.com:443", "status": "ready", "source": "manual",
                 "last_used_at": used, "last_used_by": "demo", "use_count": 3],
                // A command that ever printed a value must not get it shown.
                ["name": "GOOGLE_KEY", "status": "needs_host", "source": "captured", "kind": "google",
                 "captured_from": "demo (claude prompt)", "value": value],
                ["name": "GH_TOKEN", "target": "api.github.com:443", "status": "exposed", "source": "captured",
                 "last_used_at": "2026-11-22T10:00:00.123456789Z"],
                ["name": "GH_TOKEN", "status": "ready"],
                ["name": "--bad name", "status": "ready"],
                "not an object",
            ],
        ])
        let list = try SandboxVault.decodeList(text)
        expect(list.path == "/fixture/vault.json", "path kept")
        expect(list.entries.map(\.name) == ["GH_TOKEN", "GOOGLE_KEY", "STRIPE_API_KEY"], "valid unique entries, sorted")
        expect(!String(describing: list).contains(value), "no value reaches the model")
        expect(list.summary == "3 secrets for your sandboxes · 1 needs a host · 1 exposed: rotate · values are never shown", "summary")
        let ready = list.entries[2], captured = list.entries[1], exposed = list.entries[0]
        expect(ready.statusText == "ready" && captured.statusText == "needs a host" && exposed.statusText == "exposed: rotate", "status texts")
        expect(ready.lastUsedText(now: now) == "2h ago (demo)", "last used")
        expect(captured.lastUsedText(now: now) == "never", "never used")
        expect(exposed.lastUsedAt != nil, "fractional-second timestamps parse")
        expect(ready.useCount == 3 && ready.sourceText == "added by you", "manual entry")
        expect(captured.sourceText == "captured from demo (claude prompt)" && captured.hostText == "—", "captured entry")
        expect(captured.detailText.contains("no host yet") && captured.attention.contains("no host yet"), "needs_host explains")
        expect(exposed.attention.contains("rotate"), "exposed says rotate")
        expect(ready.detailText == "$STRIPE_API_KEY in a sandbox started with --vault STRIPE_API_KEY; sent only to api.stripe.com:443; added by you",
               "detail line")
        expect(ready.attention.isEmpty, "a ready entry asks for nothing")

        let empty = try SandboxVault.decodeList("{\"path\":\"\",\"entries\":[]}")
        expect(empty.entries.isEmpty && empty.summary.hasPrefix("0 secrets"), "empty vault")

        // A captured entry waits for the person's confirmation.
        let pending = try SandboxVault.decodeList(json(["path": "/fixture/vault.json", "entries": [
            ["name": "AWS_KEY", "target": "api.example.com:443", "status": "unconfirmed", "source": "captured",
             "captured_from": "demo (claude prompt)"],
            ["name": "OK_KEY", "target": "api.example.com:443", "status": "ready", "source": "manual"],
        ]]))
        let unconfirmed = pending.entries[0]
        expect(unconfirmed.unconfirmed && !unconfirmed.ready && unconfirmed.statusText == "unconfirmed", "unconfirmed status")
        expect(!pending.entries[1].unconfirmed, "a manual entry needs no confirmation")
        expect(pending.summary == "2 secrets for your sandboxes · 1 unconfirmed · values are never shown", "summary counts unconfirmed")
        expect(unconfirmed.attention.contains("captured from demo (claude prompt)") && unconfirmed.attention.contains("confirm"),
               "unconfirmed explains")
        let dialog = SandboxVault.confirmText(unconfirmed)
        expect(dialog.contains(SandboxVault.confirmCaution), "the dialog carries the caution")
        expect(SandboxVault.confirmCaution.contains("looks like your prompt") && SandboxVault.confirmCaution.contains("you gave it"),
               "the caution says why")
        expect(dialog.hasSuffix("Runs: defenseclaw sandbox vault confirm --yes AWS_KEY"), "the dialog shows the command")
        expect(dialog.contains("Host: api.example.com:443") && dialog.contains("send it to api.example.com:443 only"),
               "the dialog names the host")
        expect(dialog.contains("Kind: \(unconfirmed.kind.isEmpty ? "unknown" : unconfirmed.kind)"), "the dialog names the kind")
        var hostless = unconfirmed
        hostless.target = ""
        hostless.kind = "api_key"
        let noHost = SandboxVault.confirmText(hostless)
        expect(noHost.contains("Kind: api_key") && noHost.contains("Host: none yet")
               && noHost.contains("needs one (Set host…) before a sandbox can use it"), "a hostless entry needs a host first")
        for bad in ["", "not json", "[]", "{\"entries\":{}}", "{\"path\":\"x\"}"] {
            expect((try? SandboxVault.decodeList(bad)) == nil, "refuse malformed list: \(bad)")
        }
        expect((try? SandboxVault.decodeList(String(repeating: " ", count: SandboxVault.maxListBytes + 1))) == nil, "bounded input")

        let unsupported = CLIResult(exitCode: 2, output: "Usage: defenseclaw sandbox\nError: No such command 'vault'.\n")
        expect(SandboxVault.failureMessage(unsupported, action: "Reading the vault", managed: false).contains("update DefenseClaw"),
               "an older runtime is named")
        let refused = CLIResult(exitCode: 1, output: "Error: not allowed here\n")
        let managed = SandboxVault.failureMessage(refused, action: "Reading the vault", managed: true)
        expect(managed.contains("exit 1") && managed.contains("not allowed here") && managed.contains("managed by your organization"),
               "a managed refusal says so")
        expect(!SandboxVault.failureMessage(refused, action: "Reading the vault", managed: false).contains("managed"),
               "an unmanaged failure does not mention management")
        expect(SandboxVault.failureMessage(CLIResult(exitCode: 130, output: "", cancelled: true), action: "Reading the vault", managed: false)
               .contains("cancelled"), "cancel")
    }

    /// confirm prints the last 4 characters of the value: neither the card
    /// nor Activity shows any vault command's output.
    @MainActor static func hintNeverShown() async {
        let hint = "WXYZ"
        let said = "AWS_KEY\nKind           api_key\nCaptured from  demo\nEnds with      \u{2026}\(hint)\n"
            + "Host           api.example.com\nconfirmed AWS_KEY\n"
        let cli = VaultFakeCLI()
        let store = SandboxVaultStore()
        cli.runResult = CLIResult(exitCode: 0, output: said)
        var ok = await store.perform(.confirm(name: "AWS_KEY"), run: cli.runner(), read: cli.reader(), managed: false)
        expect(ok && store.message == "Confirmed AWS_KEY." && !store.messageFailed, "confirm says Confirmed NAME")
        let changes: [SandboxVaultChange] = [
            .add(name: "A_KEY", host: "api.example.com"), .replace(name: "A_KEY"), .bind(name: "A_KEY", host: "api.example.com"),
            .rename(name: "A_KEY", newName: "B_KEY"), .remove(name: "B_KEY"), .confirm(name: "B_KEY"),
        ]
        for change in changes {
            ok = await store.perform(change, value: change.needsValue ? fixtureValue() : nil,
                                     run: cli.runner(), read: cli.reader(), managed: false)
            expect(ok && store.message == change.successText && !(store.message ?? "").contains(hint),
                   "\(change.title): fixed message, no output")
        }
        // A failure keeps a redacted line: never one with the hint, even last.
        cli.runResult = CLIResult(exitCode: 1, output: said + "Error: the vault is locked\n")
        ok = await store.perform(.confirm(name: "AWS_KEY"), run: cli.runner(), read: cli.reader(), managed: false)
        expect(!ok && store.messageFailed && (store.message ?? "").contains("the vault is locked")
               && !(store.message ?? "").contains(hint), "a failure shows the error line only")
        cli.runResult = CLIResult(exitCode: 1, output: "Ends with \u{2026}\(hint)\n")
        ok = await store.perform(.confirm(name: "AWS_KEY"), run: cli.runner(), read: cli.reader(), managed: false)
        expect(!ok && !(store.message ?? "").contains(hint), "a hint as the last line is dropped")
        // What Activity keeps.
        let kept = SandboxVault.activityOutput(CLIResult(exitCode: 0, output: said))
        expect(!kept.contains(hint) && kept.contains("exit 0") && kept.contains("does not keep"), "Activity: status only")
        let failed = SandboxVault.activityOutput(CLIResult(exitCode: 1, output: said + "Error: the vault is locked\n"))
        expect(failed.contains("Exit 1") && failed.contains("the vault is locked") && !failed.contains(hint),
               "Activity: exit and the redacted line")
        expect(!SandboxVault.activityOutput(CLIResult(exitCode: 2, output: "x \u{2026}\(hint)")).contains(hint), "Activity: hint dropped")
        expect(SandboxVault.activityOutput(CLIResult(exitCode: 130, output: said, cancelled: true)).hasPrefix("Cancelled"),
               "Activity: cancel")
    }

    /// The re-read after a change is not dropped while a read is in flight.
    @MainActor static func queuedRefresh() async {
        let reads = VaultRacingReads()
        let store = SandboxVaultStore()
        reads.store = store
        reads.outputs = [
            json(["path": "/fixture/vault.json", "entries": [["name": "OLD_KEY", "status": "ready", "source": "manual"]]]),
            json(["path": "/fixture/vault.json", "entries": [["name": "NEW_KEY", "status": "ready", "source": "manual"]]]),
        ]
        await store.refresh(read: reads.reader(), managed: false)
        expect(reads.reads == 2, "a refresh asked for during a read runs once more")
        expect(store.list?.entries.map(\.name) == ["NEW_KEY"] && !store.loading, "the newer read wins")
        await store.refresh(read: reads.reader(), managed: false)
        expect(reads.reads == 3 && !store.loading, "no read is left queued")
    }

    @MainActor static func store() async {
        let cli = VaultFakeCLI()
        let store = SandboxVaultStore()
        cli.listOutput = json(["path": "/fixture/vault.json", "entries": [["name": "API_KEY", "status": "needs_host", "source": "manual"]]])
        await store.refresh(read: cli.reader(), managed: false)
        expect(store.list?.entries.count == 1 && store.error.isEmpty && store.loaded, "refresh reads the list")
        expect(cli.reads == [SandboxVault.listArguments], "one list read")

        // Add: the value goes to stdin only.
        let value = fixtureValue()
        cli.runResult = CLIResult(exitCode: 0, output: "added NEW_KEY\n")
        var ok = await store.perform(.add(name: "NEW_KEY", host: "api.example.com"), value: value + "\n",
                                     run: cli.runner(), read: cli.reader(), managed: false)
        expect(ok && cli.runs.count == 1, "add ran")
        expect(cli.runs[0].standardInput == value, "the value travels on stdin, one line")
        expect(!cli.runs[0].arguments.contains { $0.contains(value) } && !cli.runs[0].title.contains(value), "never in argv or the title")
        expect(!(store.message ?? "").contains(value) && !store.messageFailed, "never in the message")
        expect(store.message == "Added NEW_KEY for api.example.com. Start a sandbox with --vault NEW_KEY to use it.",
               "a fixed success message, not the command output")
        expect(!String(describing: store.list as Any).contains(value), "never in the list")
        expect(cli.reads.count == 2, "a change re-reads the list")

        // Bind and remove take no value.
        ok = await store.perform(.bind(name: "API_KEY", host: "api.example.com"), run: cli.runner(), read: cli.reader(), managed: false)
        expect(ok && cli.runs.last?.standardInput == nil, "bind sends no stdin")
        ok = await store.perform(.remove(name: "API_KEY"), value: value, run: cli.runner(), read: cli.reader(), managed: false)
        expect(ok && cli.runs.last?.standardInput == nil, "remove ignores a stray value")
        let reads = cli.reads.count
        ok = await store.perform(.confirm(name: "API_KEY"), value: value, run: cli.runner(), read: cli.reader(), managed: false)
        expect(ok && cli.runs.last?.arguments == ["sandbox", "vault", "confirm", "--yes", "API_KEY"]
               && cli.runs.last?.standardInput == nil, "confirm runs the CLI's confirm with --yes and no stdin")
        expect(cli.runs.last?.title == "Vault: confirm API_KEY is your own secret", "confirm Activity title")
        expect(cli.reads.count == reads + 1, "confirm re-reads the list")

        // Refused before any command runs.
        let before = cli.runs.count
        ok = await store.perform(.replace(name: "API_KEY"), value: value + "\n" + value, run: cli.runner(), read: cli.reader(), managed: false)
        expect(!ok && store.messageFailed && !(store.message ?? "").contains(value), "a two-line value is refused without echo")
        ok = await store.perform(.replace(name: "API_KEY"), value: nil, run: cli.runner(), read: cli.reader(), managed: false)
        expect(!ok && store.messageFailed, "replace without a value is refused")
        ok = await store.perform(.add(name: "NEW_KEY", host: "https://api.example.com"), value: value, run: cli.runner(), read: cli.reader(), managed: false)
        expect(!ok && store.messageFailed, "an add with a URL host is refused")
        ok = await store.perform(.rename(name: "API_KEY", newName: "--yes"), run: cli.runner(), read: cli.reader(), managed: false)
        expect(!ok, "a flag-shaped name is refused")
        expect(cli.runs.count == before, "no refused change reached the CLI")

        // A failed change says why, and on a managed computer says so.
        cli.runResult = CLIResult(exitCode: 1, output: "Error: no entry named API_KEY\n")
        ok = await store.perform(.replace(name: "API_KEY"), value: value, run: cli.runner(), read: cli.reader(), managed: true)
        expect(!ok && store.messageFailed, "failure reported")
        expect((store.message ?? "").contains("no entry named API_KEY") && (store.message ?? "").contains("managed by your organization"),
               "managed failure note")
        expect(!(store.message ?? "").contains(value), "the failure never echoes the value")

        // A failed read keeps the last good list and says why.
        cli.readExit = 1
        await store.refresh(read: cli.reader(), managed: false)
        expect(store.list != nil && store.error.contains("exit 1") && store.error.contains("not valid"), "read failure explained")

        // An installation switch drops everything read.
        store.reset()
        expect(store.list == nil && store.error.isEmpty && store.message == nil && !store.loaded, "reset clears the card")
    }
}
