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

// The sandbox credential vault (Preview), as the TUI's Vault tab shows it
// (cli/defenseclaw/tui/services/vault_state.py). Reads run
// `defenseclaw sandbox vault list --json`; every change is a
// `defenseclaw sandbox vault ...` command. A secret value goes to the command
// on standard input (--value-stdin), never on its command line; the model
// never holds one, and the list never carries one.

import Foundation
import Observation

/// One vault entry as `sandbox vault list --json` prints it. There is no
/// value field: decoding drops one if a command ever printed it.
struct SandboxVaultEntry: Identifiable, Hashable, Sendable {
    var name: String
    var target = ""
    /// ready | needs_host | exposed | unconfirmed
    var status = ""
    /// manual | captured
    var source = ""
    var kind = ""
    var capturedFrom = ""
    var lastUsedAt: Date?
    var lastUsedBy = ""
    var useCount = 0

    var id: String { name }
    var statusText: String { SandboxVault.statusText(status) }
    var hostText: String { target.isEmpty ? "—" : target }
    var ready: Bool { status == "ready" }
    /// Captured from a sandbox and not yet confirmed as the person's own.
    var unconfirmed: Bool { status == "unconfirmed" }

    var sourceText: String {
        source == "captured" ? "captured from \(capturedFrom.isEmpty ? "a sandbox" : capturedFrom)" : "added by you"
    }

    func lastUsedText(now: Date = Date()) -> String {
        guard let lastUsedAt else { return "never" }
        let seconds = max(0, Int(now.timeIntervalSince(lastUsedAt)))
        let ago: String
        if seconds >= 86_400 { ago = "\(seconds / 86_400)d ago" }
        else if seconds >= 3_600 { ago = "\(seconds / 3_600)h ago" }
        else if seconds >= 60 { ago = "\(seconds / 60)m ago" }
        else { ago = "just now" }
        return lastUsedBy.isEmpty ? ago : "\(ago) (\(lastUsedBy))"
    }

    /// The TUI's detail line: how a sandbox uses the secret and where it goes.
    var detailText: String {
        let where_ = target.isEmpty ? "no host yet: set one before a sandbox can use it" : "sent only to \(target)"
        return "$\(name) in a sandbox started with --vault \(name); \(where_); \(sourceText)"
    }

    /// What to do about an entry that is not ready (the CLI list's notes).
    var attention: String {
        switch status {
        case "needs_host": return "\(name) has no host yet: set the one host it may be sent to."
        case "exposed": return "\(name) may have been seen by an agent's model: rotate it with its issuer, then replace the value."
        case "unconfirmed": return "\(name) was \(sourceText): confirm it only if it is a secret you gave the agent."
        default: return ""
        }
    }
}

struct SandboxVaultList: Sendable, Equatable {
    var path = ""
    var entries: [SandboxVaultEntry] = []

    var counts: (ready: Int, needsHost: Int, exposed: Int, unconfirmed: Int) {
        (entries.filter { $0.status == "ready" }.count,
         entries.filter { $0.status == "needs_host" }.count,
         entries.filter { $0.status == "exposed" }.count,
         entries.filter { $0.status == "unconfirmed" }.count)
    }

    /// The TUI's summary line.
    var summary: String {
        let n = entries.count
        var parts = ["\(n) secret\(n == 1 ? "" : "s") for your sandboxes"]
        let c = counts
        if c.needsHost > 0 { parts.append("\(c.needsHost) need\(c.needsHost == 1 ? "s" : "") a host") }
        if c.exposed > 0 { parts.append("\(c.exposed) exposed: rotate") }
        if c.unconfirmed > 0 { parts.append("\(c.unconfirmed) unconfirmed") }
        return parts.joined(separator: " · ") + " · values are never shown"
    }
}

enum SandboxVaultError: LocalizedError, Equatable {
    case invalid(String)
    var errorDescription: String? {
        switch self { case .invalid(let message): return message }
    }
}

/// A change the panel asks for. The value of add and replace is not part of
/// the change: it is handed to `SandboxVaultStore.perform` and goes to stdin.
enum SandboxVaultChange: Equatable, Sendable {
    case add(name: String, host: String)
    case replace(name: String)
    case bind(name: String, host: String)
    case rename(name: String, newName: String)
    case remove(name: String)
    case confirm(name: String)

    var needsValue: Bool {
        switch self {
        case .add, .replace: return true
        default: return false
        }
    }

    var name: String {
        switch self {
        case .add(let name, _), .replace(let name), .bind(let name, _), .rename(let name, _), .remove(let name), .confirm(let name): return name
        }
    }

    /// The TUI's argv for each change. Names and hosts are validated first,
    /// so neither can be read as a flag.
    var arguments: [String] {
        switch self {
        case .add(let name, let host): return ["sandbox", "vault", "add", "--host", Self.trim(host), "--value-stdin", name]
        case .replace(let name): return ["sandbox", "vault", "replace", "--value-stdin", name]
        case .bind(let name, let host): return ["sandbox", "vault", "bind", "--host", Self.trim(host), name]
        case .rename(let name, let newName): return ["sandbox", "vault", "rename", name, Self.trim(newName)]
        case .remove(let name): return ["sandbox", "vault", "remove", "--yes", name]
        case .confirm(let name): return ["sandbox", "vault", "confirm", "--yes", name]
        }
    }

    var title: String {
        switch self {
        case .add(let name, let host): return "Vault: add \(name) for \(Self.trim(host))"
        case .replace(let name): return "Vault: replace the value of \(name)"
        case .bind(let name, let host): return "Vault: send \(name) only to \(Self.trim(host))"
        case .rename(let name, let newName): return "Vault: rename \(name) to \(Self.trim(newName))"
        case .remove(let name): return "Vault: remove \(name)"
        case .confirm(let name): return "Vault: confirm \(name) is your own secret"
        }
    }

    /// What the card says after the change landed. It is fixed text, never
    /// the command's output: `confirm` prints the last 4 characters of the
    /// value, and no vault output is shown or kept by the app.
    var successText: String {
        switch self {
        case .add(let name, let host): return "Added \(name) for \(Self.trim(host)). Start a sandbox with --vault \(name) to use it."
        case .replace(let name): return "Replaced the value of \(name). Sandboxes created from now on use the new value; "
            + "delete a sandbox created with the old one and start a new one."
        case .bind(let name, let host): return "\(name) may now be sent to \(Self.trim(host)) only."
        case .rename(let name, let newName): return "Renamed \(name) to \(Self.trim(newName))."
        case .remove(let name): return "Removed \(name). Sandboxes created with it keep it until you delete them; "
            + "revoke it with its issuer if it may have leaked."
        case .confirm(let name): return "Confirmed \(name)."
        }
    }

    /// Why the change cannot run as typed, or nil.
    var problem: String? {
        switch self {
        case .add(let name, let host): return SandboxVault.nameProblem(name) ?? SandboxVault.hostProblem(host)
        case .replace(let name), .remove(let name), .confirm(let name): return SandboxVault.nameProblem(name)
        case .bind(let name, let host): return SandboxVault.nameProblem(name) ?? SandboxVault.hostProblem(host)
        case .rename(let name, let newName):
            if let problem = SandboxVault.nameProblem(name) ?? SandboxVault.nameProblem(Self.trim(newName)) { return problem }
            return Self.trim(newName) == name ? "The new name is the same as the old one; nothing changed." : nil
        }
    }

    private static func trim(_ text: String) -> String { text.trimmingCharacters(in: .whitespacesAndNewlines) }
}

/// Which change the editor sheet asks for.
enum SandboxVaultEditor: Identifiable, Hashable {
    case add
    case replace(String)
    case bind(String, current: String)
    case rename(String)

    var id: String {
        switch self {
        case .add: return "add"
        case .replace(let name): return "replace|\(name)"
        case .bind(let name, _): return "bind|\(name)"
        case .rename(let name): return "rename|\(name)"
        }
    }

    var title: String {
        switch self {
        case .add: return "Add a secret"
        case .replace(let name): return "Replace the value of \(name)"
        case .bind(let name, _): return "Set the host of \(name)"
        case .rename(let name): return "Rename \(name)"
        }
    }

    var asksName: Bool { self == .add }
    var asksHost: Bool {
        switch self {
        case .add, .bind: return true
        default: return false
        }
    }
    var asksValue: Bool {
        switch self {
        case .add, .replace: return true
        default: return false
        }
    }
    var asksNewName: Bool {
        if case .rename = self { return true }
        return false
    }

    /// The change for what was typed; the value is not part of it.
    func change(name: String, host: String, newName: String) -> SandboxVaultChange {
        switch self {
        case .add: return .add(name: name.trimmingCharacters(in: .whitespacesAndNewlines), host: host)
        case .replace(let current): return .replace(name: current)
        case .bind(let current, _): return .bind(name: current, host: host)
        case .rename(let current): return .rename(name: current, newName: newName)
        }
    }
}

enum SandboxVault {
    /// The vault shows where the Sandboxes panel shows sandboxes: they are
    /// set up for this account (ready, or unavailable for a while).
    static func shown(_ status: SandboxStatus) -> Bool { status.loaded && status.enabled }

    static let listArguments = ["sandbox", "vault", "list", "--json"]
    /// The CLI's limit on one value (internal/vault MaxValueBytes).
    static let maxValueBytes = 16 << 10
    static let maxListBytes = 1 << 20
    static let emptyText = "Your vault is empty. Add a secret here; a secret a sandboxed agent is given also lands here. "
        + "Start a sandbox with --vault NAME to use one."
    static let aboutText = "Each secret is bound to the one host it may be sent to. A sandbox started with --vault NAME "
        + "sees only a placeholder in $NAME; OpenShell puts the real value on requests to that host. Values are never shown."
    /// Why a captured secret needs the person's confirmation (the TUI's c).
    static let confirmCaution = "An agent in a sandbox can make a call that looks like your prompt: confirm only a secret you gave it."

    /// The Confirm dialog's text: where the secret came from, its kind and
    /// host, the caution, how to see its last 4 characters first, and the
    /// command that runs.
    static func confirmText(_ entry: SandboxVaultEntry) -> String {
        let kind = entry.kind.isEmpty ? "unknown" : entry.kind
        let use = entry.target.isEmpty
            ? "It has no host yet: it needs one (Set host…) before a sandbox can use it."
            : "Sandboxes may then send it to \(entry.target) only."
        return "\(entry.name) was \(entry.sourceText). Kind: \(kind). Host: \(entry.target.isEmpty ? "none yet" : entry.target). "
            + "\(use) \(confirmCaution) "
            + "To check its last 4 characters first, run in Terminal: defenseclaw sandbox vault confirm \(entry.name). "
            + "Runs: defenseclaw " + SandboxVaultChange.confirm(name: entry.name).arguments.joined(separator: " ")
    }

    static func statusText(_ status: String) -> String {
        switch status {
        case "ready": return "ready"
        case "needs_host": return "needs a host"
        case "exposed": return "exposed: rotate"
        case "unconfirmed": return "unconfirmed"
        case "": return "unknown"
        default: return status
        }
    }

    /// internal/vault namePattern: ^[A-Za-z_][A-Za-z0-9_]{0,127}$
    static func validName(_ name: String) -> Bool {
        guard let first = name.unicodeScalars.first, name.unicodeScalars.count <= 128 else { return false }
        func ascii(_ s: Unicode.Scalar) -> Bool { s.isASCII && (CharacterSet.letters.contains(s) || s == "_") }
        guard ascii(first) else { return false }
        return name.unicodeScalars.allSatisfy { ascii($0) || ($0.isASCII && CharacterSet.decimalDigits.contains($0)) }
    }

    static func nameProblem(_ name: String) -> String? {
        if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "Enter a name: the variable the sandbox sees, for example STRIPE_API_KEY."
        }
        return validName(name) ? nil : "Use letters, digits and _ in the name, starting with a letter or _."
    }

    /// The TUI's _plausible_host: a host or host:port, no scheme, path,
    /// user, wildcard, space, query or fragment. The CLI checks the rest.
    static func hostProblem(_ host: String) -> String? {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.isEmpty { return "Enter the one host the value may be sent to, for example api.stripe.com." }
        let plausible = !host.contains("://") && !host.contains(where: { "/*@ ?#\t\n\r".contains($0) })
            && host.contains(".") && !host.hasPrefix("-")
        return plausible ? nil : "Give only a host such as api.stripe.com (or host:port), without https:// or a path."
    }

    /// A pasted value loses the line breaks around it (the TUI's _one_line);
    /// the CLI reads one line, so a value with a break inside is refused.
    static func normalizedValue(_ value: String) -> String {
        value.trimmingCharacters(in: CharacterSet(charactersIn: "\r\n"))
    }

    static func valueProblem(_ value: String) -> String? {
        let value = normalizedValue(value)
        if value.isEmpty { return "Paste the value; nothing changed." }
        if value.contains(where: { $0 == "\n" || $0 == "\r" }) { return "The value is one line: paste only the value." }
        if value.utf8.count > maxValueBytes { return "The value is longer than the vault allows (16 KiB)." }
        return nil
    }

    // MARK: Decoding

    static func decodeList(_ text: String) throws -> SandboxVaultList {
        guard text.utf8.count <= maxListBytes else {
            throw SandboxVaultError.invalid("The vault list was larger than the app reads; run defenseclaw sandbox vault list in Terminal.")
        }
        guard let data = text.data(using: .utf8),
              let doc = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw SandboxVaultError.invalid("defenseclaw sandbox vault list --json printed something that is not JSON.")
        }
        guard let raw = doc["entries"] as? [Any] else {
            throw SandboxVaultError.invalid("defenseclaw sandbox vault list --json has no entries list.")
        }
        var entries: [SandboxVaultEntry] = []
        var seen = Set<String>()
        for item in raw {
            // A value never reaches the model, whatever the command printed:
            // only the named metadata fields are read.
            guard let e = item as? [String: Any], let name = e["name"] as? String,
                  validName(name), seen.insert(name).inserted else { continue }
            entries.append(SandboxVaultEntry(
                name: name,
                target: string(e["target"]),
                status: string(e["status"]),
                source: string(e["source"]),
                kind: string(e["kind"]),
                capturedFrom: string(e["captured_from"]),
                lastUsedAt: date(e["last_used_at"]),
                lastUsedBy: string(e["last_used_by"]),
                useCount: max(0, (e["use_count"] as? NSNumber)?.intValue ?? 0)
            ))
        }
        return SandboxVaultList(path: string(doc["path"]), entries: entries.sorted { $0.name < $1.name })
    }

    private static func string(_ value: Any?) -> String {
        guard let text = value as? String else { return "" }
        return String(text.filter { !$0.isNewline }.prefix(256))
    }

    static func date(_ value: Any?) -> Date? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: text) { return date }
        return ISO8601DateFormatter().date(from: text)
    }

    // MARK: Failures

    /// A failed command, said plainly. A managed computer gets a note that
    /// the vault may be refused there and how to see why.
    static func failureMessage(_ result: CLIResult, action: String, managed: Bool) -> String {
        var message: String
        if result.cancelled { message = "\(action) was cancelled or timed out." }
        else if result.outputTruncated { message = "\(action): the answer was larger than the app reads." }
        else if result.exitCode == 127 { message = "\(action): the defenseclaw command is not installed." }
        else if result.exitCode == 75 { message = "\(action): wait for the current change or upgrade to finish." }
        else if unsupported(result.output) {
            message = "This DefenseClaw has no sandbox vault yet: update DefenseClaw to use it."
        } else {
            let detail = redactedLine(result.output)
            message = "\(action) failed (exit \(result.exitCode))" + (detail.isEmpty ? "." : ": \(detail)")
        }
        if managed {
            message += " This computer is managed by your organization, which may not allow the vault here; "
                + "run defenseclaw sandbox vault list in Terminal to see why."
        }
        return message
    }

    static func unsupported(_ output: String) -> Bool {
        let lower = output.lowercased()
        return lower.contains("no such command 'vault'") || lower.contains("no such command \"vault\"")
            || lower.contains("unknown command \"vault\"") || lower.contains("unknown command 'vault'")
    }

    /// The last line of a vault command's output that says nothing about a
    /// value: `confirm` prints "Ends with …" and the last 4 characters, so
    /// such a line is dropped wherever it is.
    static func redactedLine(_ output: String) -> String {
        let kept = output.split(whereSeparator: \.isNewline).filter { line in
            !line.localizedCaseInsensitiveContains("ends with") && !line.contains("\u{2026}")
        }
        return lastLine(kept.joined(separator: "\n"))
    }

    /// What Activity keeps of a vault command: its exit status and, when it
    /// failed, the redacted last line. The streamed output is not kept.
    static func activityOutput(_ result: CLIResult) -> String {
        let note = "The app does not keep the output of vault commands."
        if result.cancelled { return "Cancelled. \(note)\n" }
        if result.succeeded { return "Done (exit 0). \(note)\n" }
        let detail = redactedLine(result.output)
        return "Exit \(result.exitCode)" + (detail.isEmpty ? "." : ": \(detail)") + " \(note)\n"
    }

    static func lastLine(_ output: String) -> String {
        let line = output.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .last(where: { !$0.isEmpty }) ?? ""
        return String(line.prefix(240))
    }
}

/// The Vault card's state: the last list read and the outcome of the last
/// change. It never holds a value: perform takes one and passes it on.
@MainActor @Observable
final class SandboxVaultStore {
    /// Reads `defenseclaw <args>` (read only, no Activity row).
    typealias Reader = @Sendable ([String]) async -> CLIResult
    /// Runs a change: title, argv, standard input (Activity row, mutation).
    /// The row keeps only `SandboxVault.activityOutput`, never the output.
    typealias Runner = @MainActor (String, [String], String?) async -> CLIResult

    private(set) var list: SandboxVaultList?
    private(set) var fetchedAt: Date?
    private(set) var loading = false
    private(set) var busy = false
    private(set) var error = ""
    var message: String?
    var messageFailed = false
    private var generation = 0
    /// A refresh asked for while one was in flight (the re-read after a
    /// change): the read in flight may predate the change, so one more runs.
    private var queuedRefresh: (read: Reader, managed: Bool)?

    var loaded: Bool { list != nil || !error.isEmpty }

    /// Drop what was read (an installation switch).
    func reset() {
        generation += 1
        list = nil; fetchedAt = nil; error = ""; message = nil; messageFailed = false
        loading = false; busy = false; queuedRefresh = nil
    }

    /// Read the list. A call while a read is in flight is not dropped: one
    /// more read runs after it, so a change is never shown with stale data.
    func refresh(read: @escaping Reader, managed: Bool) async {
        guard !loading else {
            queuedRefresh = (read, managed)
            return
        }
        loading = true
        let epoch = generation
        var next: (read: Reader, managed: Bool)? = (read, managed)
        while let current = next {
            queuedRefresh = nil
            let result = await current.read(SandboxVault.listArguments)
            guard epoch == generation else { return }
            apply(result, managed: current.managed)
            next = queuedRefresh
        }
        loading = false
    }

    private func apply(_ result: CLIResult, managed: Bool) {
        guard result.succeeded else {
            error = SandboxVault.failureMessage(result, action: "Reading the vault", managed: managed)
            return
        }
        do {
            list = try SandboxVault.decodeList(result.output)
            fetchedAt = Date()
            error = ""
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Run one change. `value` (add and replace only) goes to the command's
    /// standard input and nowhere else; the caller clears its field before
    /// calling. Returns whether the change landed.
    @discardableResult
    func perform(_ change: SandboxVaultChange, value: String? = nil, run: Runner, read: @escaping Reader, managed: Bool) async -> Bool {
        guard !busy else { return false }
        if let problem = change.problem { return refuse(problem) }
        var input: String?
        if change.needsValue {
            guard let value else { return refuse("Paste the value; nothing changed.") }
            if let problem = SandboxVault.valueProblem(value) { return refuse(problem) }
            input = SandboxVault.normalizedValue(value)
        }
        busy = true
        let epoch = generation
        let result = await run(change.title, change.arguments, input)
        input = nil
        guard epoch == generation else { return false }
        busy = false
        if result.succeeded {
            message = change.successText
            messageFailed = false
        } else {
            message = SandboxVault.failureMessage(result, action: change.title, managed: managed)
            messageFailed = true
        }
        await refresh(read: read, managed: managed)
        return result.succeeded
    }

    private func refuse(_ problem: String) -> Bool {
        message = problem
        messageFailed = true
        return false
    }
}
