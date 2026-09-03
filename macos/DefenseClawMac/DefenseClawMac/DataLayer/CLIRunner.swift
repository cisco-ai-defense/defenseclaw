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

// Direct argv execution for DefenseClaw commands. Catalog actions, setup,
// diagnostics, and the command palette all share this runner so arguments are
// never interpolated through a shell.

import Darwin
import Foundation

struct CLIResult: Sendable {
    var exitCode: Int32
    var output: String
    var cancelled: Bool = false
    var outputTruncated: Bool = false
    var succeeded: Bool { exitCode == 0 && !cancelled && !outputTruncated }
}

struct CatalogListCLIResult: Sendable {
    var result: CLIResult
    var usedIsolatedAuditStore: Bool
    var selectedBinaryPath: String?
}

enum CLICancellationDisposition: Sendable, Equatable {
    case requested
    case alreadyRequested
    case finishing
    case notFound
}

/// Re-enters the signed app executable as a tiny process launcher. Establishing
/// a process group before `execv` makes every descendant independently
/// reachable even if an intermediate process forks and exits during
/// cancellation. The same entry point is used by standalone runner tests.
enum CLIProcessGroupLauncher {
    private static let marker = "--defenseclaw-internal-command-launcher-v1"

    static func execIfRequested(arguments: [String] = CommandLine.arguments) {
        guard arguments.count >= 3, arguments[1] == marker else { return }
        let target = arguments[2]
        guard target.hasPrefix("/"),
              wasInvokedBySameExecutableParent(),
              setpgid(0, 0) == 0 else {
            failAndExit()
        }

        var pointers: [UnsafeMutablePointer<CChar>?] = ([target] + arguments.dropFirst(3)).map {
            strdup(String($0))
        }
        pointers.append(nil)
        defer {
            for pointer in pointers.compactMap({ $0 }) { free(pointer) }
        }
        execv(target, &pointers)
        failAndExit()
    }

    static func configure(
        _ process: Process,
        target: String,
        arguments: [String]
    ) -> Bool {
        guard let executableURL = Bundle.main.executableURL else { return false }
        process.executableURL = executableURL
        process.arguments = [marker, target] + arguments
        return true
    }

    /// The marker is an internal protocol, not a public command-execution
    /// surface. Only a running copy of this exact executable may create the
    /// launcher child; direct invocations from a shell or another local process
    /// fail before the target is executed.
    private static func wasInvokedBySameExecutableParent() -> Bool {
        guard let executableURL = Bundle.main.executableURL else { return false }
        let canonicalExecutable = executableURL.resolvingSymlinksInPath()

        var parentPathBuffer = [CChar](
            repeating: 0,
            count: 4_096
        )
        let parentPathLength = parentPathBuffer.withUnsafeMutableBytes { buffer in
            proc_pidpath(getppid(), buffer.baseAddress, UInt32(buffer.count))
        }
        guard parentPathLength > 0 else { return false }

        let parentPath = parentPathBuffer.withUnsafeBufferPointer { buffer in
            String(cString: buffer.baseAddress!)
        }
        let canonicalParent = URL(fileURLWithPath: parentPath).resolvingSymlinksInPath()
        guard canonicalParent.path == canonicalExecutable.path else { return false }

        guard let parentAttributes = try? FileManager.default.attributesOfItem(
                  atPath: canonicalParent.path
              ),
              let executableAttributes = try? FileManager.default.attributesOfItem(
                  atPath: canonicalExecutable.path
              ),
              let parentDevice = parentAttributes[.systemNumber] as? NSNumber,
              let parentFile = parentAttributes[.systemFileNumber] as? NSNumber,
              let executableDevice = executableAttributes[.systemNumber] as? NSNumber,
              let executableFile = executableAttributes[.systemFileNumber] as? NSNumber else {
            return false
        }
        return parentDevice == executableDevice && parentFile == executableFile
    }

    private static func failAndExit() -> Never {
        let message = "DefenseClaw internal command launcher failed.\n"
        message.withCString { pointer in
            _ = Darwin.write(STDERR_FILENO, pointer, strlen(pointer))
        }
        Darwin._exit(126)
    }
}

/// Coordinates direct-process termination with the detached pipe reader.
/// Descendants may inherit stdout/stderr and keep the pipe open after the
/// command exits, so EOF alone is not a reliable completion signal.
private final class CLIOutputReadControl: @unchecked Sendable {
    private let lock = NSLock()
    private var parentExited = false

    func markParentExited() {
        lock.lock()
        parentExited = true
        lock.unlock()
    }

    var hasParentExited: Bool {
        lock.lock()
        defer { lock.unlock() }
        return parentExited
    }
}

private struct CLIProcessIdentity: Hashable, Sendable {
    let pid: pid_t
    let startSeconds: UInt64
    let startMicroseconds: UInt64
}

/// Signals the command's dedicated process group. PID/start-time descendant
/// tracking remains a fallback for environments that cannot establish the
/// group, and prevents signaling an unrelated process after PID reuse.
private final class CLIProcessTree: @unchecked Sendable {
    private let rootPID: pid_t
    private let lock = NSLock()
    private var processGroupID: pid_t?
    private var identities: [pid_t: CLIProcessIdentity] = [:]

    init(rootPID: pid_t) {
        self.rootPID = rootPID
        self.processGroupID = nil
        refreshProcessGroup()
        if let identity = Self.identity(for: rootPID) {
            identities[rootPID] = identity
        }
    }

    /// Waits until the signed launcher has established the dedicated group.
    /// A command that already exited needs no cancellation tracking; a live
    /// command that never establishes its group is rejected fail-closed.
    func waitUntilReady(process: Process) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        for _ in 0..<1_000 {
            refreshProcessGroup()
            if processGroupID != nil { return true }
            if !process.isRunning { return true }
            usleep(1_000)
        }
        refreshProcessGroup()
        return processGroupID != nil || !process.isRunning
    }

    @discardableResult
    func send(_ signal: Int32) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        // Process.run() returns after the signed launcher starts, so the
        // launcher may establish its group just after this tracker is created.
        refreshProcessGroup()
        if let processGroupID {
            // A negative PID addresses the process group, including children
            // reparented after an earlier cancellation signal.
            errno = 0
            if Darwin.kill(-processGroupID, signal) == 0 || errno == EPERM {
                return true
            }
            return false
        }

        discoverDescendants()
        var signalledProcess = false

        // Signal descendants before the direct child so they cannot disappear
        // from the ancestry graph before being captured.
        let descendants = identities.values
            .filter { $0.pid != rootPID }
            .sorted { $0.pid < $1.pid }
        for identity in descendants where Self.matches(identity) {
            errno = 0
            if Darwin.kill(identity.pid, signal) == 0 || errno == EPERM {
                signalledProcess = true
            }
        }
        if let root = identities[rootPID], Self.matches(root) {
            errno = 0
            if Darwin.kill(root.pid, signal) == 0 || errno == EPERM {
                signalledProcess = true
            }
        }
        return signalledProcess
    }

    private func refreshProcessGroup() {
        guard processGroupID == nil else { return }
        if getpgid(rootPID) == rootPID {
            processGroupID = rootPID
            return
        }
        errno = 0
        if Darwin.kill(-rootPID, 0) == 0 || errno == EPERM {
            // The leader may have exited quickly while descendants retain the
            // intended group. A signal-0 probe proves the group still exists.
            processGroupID = rootPID
        }
    }

    private func discoverDescendants() {
        if identities[rootPID] == nil, let root = Self.identity(for: rootPID) {
            identities[rootPID] = root
        }
        var queue = Array(identities.values)
        var visited: Set<CLIProcessIdentity> = []
        while let parent = queue.popLast() {
            guard visited.insert(parent).inserted, Self.matches(parent) else { continue }
            for pid in Self.childPIDs(of: parent.pid) {
                guard let child = Self.identity(for: pid) else { continue }
                let isNew = identities[pid] != child
                identities[pid] = child
                if isNew { queue.append(child) }
            }
        }
    }

    private static func childPIDs(of parent: pid_t) -> [pid_t] {
        let requiredBytes = proc_listchildpids(parent, nil, 0)
        guard requiredBytes > 0 else { return [] }
        let stride = MemoryLayout<pid_t>.stride
        let capacity = min(max(Int(requiredBytes) / stride + 16, 16), 32_768)
        var pids = [pid_t](repeating: 0, count: capacity)
        let count = pids.withUnsafeMutableBytes { buffer in
            proc_listchildpids(parent, buffer.baseAddress, Int32(buffer.count))
        }
        guard count > 0 else { return [] }
        return Array(pids.prefix(min(Int(count), pids.count))).filter { $0 > 0 }
    }

    private static func identity(for pid: pid_t) -> CLIProcessIdentity? {
        guard pid > 0 else { return nil }
        var info = proc_bsdinfo()
        let count = withUnsafeMutablePointer(to: &info) { pointer in
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                pointer,
                Int32(MemoryLayout<proc_bsdinfo>.size)
            )
        }
        guard count == MemoryLayout<proc_bsdinfo>.size else { return nil }
        return CLIProcessIdentity(
            pid: pid,
            startSeconds: info.pbi_start_tvsec,
            startMicroseconds: info.pbi_start_tvusec
        )
    }

    private static func matches(_ identity: CLIProcessIdentity) -> Bool {
        Self.identity(for: identity.pid) == identity
    }
}

enum CLIOutputLimits {
    /// Large enough for normal machine-readable scans while preventing an
    /// accidental or hostile subprocess from retaining arbitrary output.
    static let maximumOutputBytes = 4 * 1_024 * 1_024
    /// Reserve room for truncation markers while still allowing compact JSON
    /// scans to use almost the entire result budget on one line.
    static let maximumLineBytes = maximumOutputBytes - 1_024
    static let readChunkBytes = 64 * 1_024
    static let maximumStreamedBytes = 300_000
    static let maximumStreamedLines = 4_096
}

private struct CapturedCLIOutput: Sendable {
    var output: String
    var truncated: Bool
}

private enum CLIUTF8 {
    /// Returns the longest prefix that fits the byte budget without splitting
    /// a UTF-8 scalar. Input Strings are valid UTF-8, so at most three bytes
    /// need to be backed off from the initial cutoff.
    static func prefix(_ value: String, maximumBytes: Int) -> String {
        guard maximumBytes > 0 else { return "" }
        let utf8 = value.utf8
        guard utf8.count > maximumBytes else { return value }
        var cutoff = utf8.index(utf8.startIndex, offsetBy: maximumBytes)
        while cutoff > utf8.startIndex {
            if let stringIndex = String.Index(cutoff, within: value) {
                return String(value[..<stringIndex])
            }
            cutoff = utf8.index(before: cutoff)
        }
        return ""
    }
}

/// Incrementally turns raw pipe bytes into bounded lines and a bounded result.
/// Reading raw chunks is intentional: `FileHandle.AsyncBytes.lines` retains a
/// complete newline-less line before yielding it.
private struct BoundedCLIOutputCollector: Sendable {
    private static let lineTruncationMarker = " [line truncated]"
    private static let outputTruncationMarker = "\n[output truncated: limit exceeded]\n"

    private var output = Data()
    private var pendingLine = Data()
    private var discardingLineRemainder = false
    private var outputLimitReached = false
    private(set) var truncated = false

    mutating func consume(_ chunk: Data, emitLines: Bool) -> [String] {
        guard !outputLimitReached else { return [] }

        var emitted: [String] = []
        var cursor = chunk.startIndex
        while cursor < chunk.endIndex, !outputLimitReached {
            if let newline = chunk[cursor...].firstIndex(of: 0x0A) {
                appendToPendingLine(chunk[cursor..<newline])
                if let line = finishPendingLine(), emitLines { emitted.append(line) }
                cursor = chunk.index(after: newline)
            } else {
                appendToPendingLine(chunk[cursor...])
                break
            }
        }
        return emitted
    }

    mutating func finish(emitLines: Bool) -> (lines: [String], capture: CapturedCLIOutput) {
        var lines: [String] = []
        if !pendingLine.isEmpty || discardingLineRemainder,
           let line = finishPendingLine(), emitLines {
            lines.append(line)
        }
        return (
            lines,
            CapturedCLIOutput(
                output: String(decoding: output, as: UTF8.self),
                truncated: truncated
            )
        )
    }

    mutating func appendStreamError(_ message: String, emitLines: Bool) -> [String] {
        // A read failure means the captured output is incomplete even if the
        // child later reports exit 0. Parsers must not accept it as success.
        truncated = true
        var lines: [String] = []
        if !pendingLine.isEmpty || discardingLineRemainder,
           let line = finishPendingLine(), emitLines {
            lines.append(line)
        }
        if let line = appendCompletedLine("[output stream error: \(message)]"), emitLines {
            lines.append(line)
        }
        return lines
    }

    private mutating func appendToPendingLine(_ bytes: Data.SubSequence) {
        guard !discardingLineRemainder else { return }
        let available = CLIOutputLimits.maximumLineBytes - pendingLine.count
        guard bytes.count <= available else {
            if available > 0 { pendingLine.append(contentsOf: bytes.prefix(available)) }
            discardingLineRemainder = true
            truncated = true
            return
        }
        pendingLine.append(contentsOf: bytes)
    }

    private mutating func finishPendingLine() -> String? {
        var line = String(decoding: pendingLine, as: UTF8.self)
        if discardingLineRemainder { line += Self.lineTruncationMarker }
        pendingLine.removeAll(keepingCapacity: true)
        discardingLineRemainder = false
        return appendCompletedLine(line)
    }

    private mutating func appendCompletedLine(_ line: String) -> String? {
        guard !outputLimitReached else { return nil }
        let recordString = line + "\n"
        let record = Data(recordString.utf8)
        let remaining = CLIOutputLimits.maximumOutputBytes - output.count
        guard record.count <= remaining else {
            truncated = true
            outputLimitReached = true

            let marker = Data(Self.outputTruncationMarker.utf8)
            let maximumPayloadBytes = CLIOutputLimits.maximumOutputBytes - marker.count
            if output.count > maximumPayloadBytes {
                let safeOutput = CLIUTF8.prefix(
                    String(decoding: output, as: UTF8.self),
                    maximumBytes: maximumPayloadBytes
                )
                output = Data(safeOutput.utf8)
            }
            let recordPrefix = CLIUTF8.prefix(
                recordString,
                maximumBytes: maximumPayloadBytes - output.count
            )
            output.append(Data(recordPrefix.utf8))
            output.append(marker)

            let streamedPrefix = recordPrefix.trimmingCharacters(in: .newlines)
            let streamedMarker = Self.outputTruncationMarker.trimmingCharacters(in: .newlines)
            return streamedPrefix.isEmpty
                ? streamedMarker
                : streamedPrefix + "\n" + streamedMarker
        }
        output.append(record)
        return line
    }
}

/// Streaming is only for live UI feedback; the bounded `CLIResult` remains the
/// source of truth for parsers and final status. Limiting callback traffic also
/// prevents a subprocess from scheduling unbounded main-actor updates.
private struct BoundedCLILineStreamer: Sendable {
    private static let marker = "[additional live output omitted]"

    private var emittedBytes = 0
    private var emittedLines = 0
    private var stopped = false

    var acceptsLines: Bool { !stopped }

    mutating func linesToEmit(from lines: [String]) -> [String] {
        guard !stopped else { return [] }
        var result: [String] = []
        for line in lines {
            let recordBytes = line.utf8.count + 1
            let remainingBytes = CLIOutputLimits.maximumStreamedBytes - emittedBytes
            let markerRecordBytes = Self.marker.utf8.count + 1
            guard emittedLines < CLIOutputLimits.maximumStreamedLines,
                  recordBytes + markerRecordBytes <= remainingBytes else {
                stopped = true
                let prefixBudget = max(remainingBytes - markerRecordBytes - 1, 0)
                let prefix = CLIUTF8.prefix(line, maximumBytes: prefixBudget)
                if !prefix.isEmpty {
                    result.append(prefix + "\n" + Self.marker)
                } else {
                    result.append(Self.marker)
                }
                break
            }
            result.append(line)
            emittedBytes += recordBytes
            emittedLines += 1
        }
        return result
    }
}

actor CLIRunner {
    private static let isolatedCatalogResources = Set(["skill", "mcp", "plugin"])
    private static let isolatedCatalogDirectoryPrefix = "DefenseClaw-catalog-read-only-"
    private static let auditStoreMalformedLine =
        "Failed to open audit store: database disk image is malformed"
    /// User override (App Settings ▸ Connection) wins; otherwise search standard locations.
    static let pathOverrideKey = "defenseclawBinaryPath"

    private struct ActiveRun {
        let token: UUID
        let process: Process
        let processTree: CLIProcessTree
        let mutation: Bool
        var cancellationRequested: Bool
    }

    private enum RunState {
        case reserved(cancelRequested: Bool)
        case running(ActiveRun)
    }

    private var cachedPaths: [String: String] = [:]
    private var runStates: [UUID: RunState] = [:]
    private var installationContext: InstallationContext

    init(context: InstallationContext = .resolve()) {
        self.installationContext = context
    }

    func rebind(to context: InstallationContext) {
        guard installationContext != context else { return }
        if installationContext.permitsMutation, !context.permitsMutation {
            let activeMutations = runStates.compactMap { runID, state -> (UUID, UUID)? in
                guard case .running(let active) = state, active.mutation else { return nil }
                return (runID, active.token)
            }
            for (runID, token) in activeMutations {
                _ = requestCancellation(executionID: runID, token: token)
            }
        }
        installationContext = context
        cachedPaths.removeAll()
    }

    /// Reserve an Activity run before its visible row is published so a
    /// cancellation racing process launch is retained instead of discarded.
    func reserve(runID: UUID) -> Bool {
        guard runStates[runID] == nil else { return false }
        runStates[runID] = .reserved(cancelRequested: false)
        return true
    }

    func locateBinary() -> String? {
        locateBinary(named: "defenseclaw")
    }

    /// Prefer the selected installation's interpreter, then the interpreter
    /// adjacent to the resolved CLI. The second path covers source and PATH
    /// installs whose venv does not live below DEFENSECLAW_HOME.
    func locateRuntimePython() -> String? {
        Self.runtimePythonCandidates(
            contextPythonPath: installationContext.runtimePythonURL.path,
            selectedCLIPath: locateBinary()
        ).first(where: FileManager.default.isExecutableFile(atPath:))
    }

    nonisolated static func runtimePythonCandidates(
        contextPythonPath: String,
        selectedCLIPath: String?
    ) -> [String] {
        var candidates = [contextPythonPath]
        if let selectedCLIPath, !selectedCLIPath.isEmpty {
            let resolvedCLI = URL(fileURLWithPath: selectedCLIPath)
                .resolvingSymlinksInPath()
            let siblingPython = resolvedCLI
                .deletingLastPathComponent()
                .appendingPathComponent("python", isDirectory: false)
                .path
            if !candidates.contains(siblingPython) {
                candidates.append(siblingPython)
            }
        }
        return candidates
    }

    func locateBinary(named name: String) -> String? {
        // Absolute paths (e.g. the DefenseClaw venv python) pass through.
        if name.hasPrefix("/") {
            return FileManager.default.isExecutableFile(atPath: name) ? name : nil
        }
        // Override outranks the cache: a path freshly set in Settings must
        // win immediately even while the previously cached binary still
        // exists (the cache otherwise pins the old install forever).
        if name == "defenseclaw",
           let override = UserDefaults.standard.string(forKey: Self.pathOverrideKey),
           FileManager.default.isExecutableFile(atPath: override) {
            cachedPaths[name] = override
            return override
        }
        if let cached = cachedPaths[name], FileManager.default.isExecutableFile(atPath: cached) {
            return cached
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var candidates: [String] = []
        if name == "defenseclaw" {
            candidates.append(installationContext.runtimeCLIURL.path)
        }
        candidates += [
            "\(home)/.local/bin/\(name)",
            "/opt/homebrew/bin/\(name)",
            "/usr/local/bin/\(name)",
        ]
        for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate) {
            cachedPaths[name] = candidate
            return candidate
        }
        if let found = which(name) {
            cachedPaths[name] = found
            return found
        }
        return nil
    }

    /// Augmented-PATH lookup for an arbitrary tool (scanner probe fallback).
    /// Subprocess-backed — callers cache the result; never run on the pulse.
    func locateTool(_ name: String) -> String? {
        which(name)
    }

    /// Catalog list commands currently initialize the runtime's writable audit
    /// store before dispatch. If that store is corrupt, preserve catalog
    /// availability by re-running only the allowlisted read-only list command
    /// with a private, ephemeral DefenseClaw home. The real config and venv
    /// remain pinned, while audit-backed status/history is intentionally absent.
    func runReadOnlyCatalogList(resource: String) async -> CatalogListCLIResult {
        guard Self.isolatedCatalogResources.contains(resource) else {
            return CatalogListCLIResult(
                result: CLIResult(exitCode: 64, output: "Unsupported isolated catalog resource."),
                usedIsolatedAuditStore: false,
                selectedBinaryPath: nil
            )
        }

        let sourceContext = installationContext
        guard let selectedBinary = locateBinary() else {
            return CatalogListCLIResult(
                result: CLIResult(
                    exitCode: 127,
                    output: "defenseclaw binary not found. Set its path in Settings ▸ Connection."
                ),
                usedIsolatedAuditStore: false,
                selectedBinaryPath: nil
            )
        }
        let arguments = [resource, "list", "--json"]
        let primary = await run(binary: selectedBinary, arguments: arguments, mutation: false)
        guard installationContext == sourceContext else {
            return CatalogListCLIResult(
                result: CLIResult(
                    exitCode: 75,
                    output: "DefenseClaw installation changed while loading the catalog. Refresh to retry."
                ),
                usedIsolatedAuditStore: false,
                selectedBinaryPath: selectedBinary
            )
        }
        guard !primary.succeeded, Self.isAuditStoreCorruption(primary.output) else {
            return CatalogListCLIResult(
                result: primary,
                usedIsolatedAuditStore: false,
                selectedBinaryPath: selectedBinary
            )
        }

        let sourceConfig = await run(
            binary: selectedBinary,
            arguments: ["config", "show", "--source", "--format", "json"],
            mutation: false
        )
        guard installationContext == sourceContext, sourceConfig.succeeded else {
            return CatalogListCLIResult(
                result: primary,
                usedIsolatedAuditStore: false,
                selectedBinaryPath: selectedBinary
            )
        }

        let fileManager = FileManager.default
        let temporaryHome = fileManager.temporaryDirectory.appendingPathComponent(
            Self.isolatedCatalogDirectoryPrefix + UUID().uuidString,
            isDirectory: true
        )
        do {
            try fileManager.createDirectory(
                at: temporaryHome,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: NSNumber(value: Int16(0o700))]
            )
        } catch {
            return CatalogListCLIResult(
                result: CLIResult(
                    exitCode: 73,
                    output: "Could not create a private read-only catalog workspace: \(error.localizedDescription)"
                ),
                usedIsolatedAuditStore: false,
                selectedBinaryPath: selectedBinary
            )
        }
        defer { try? fileManager.removeItem(at: temporaryHome) }

        let isolatedConfigURL = temporaryHome.appendingPathComponent("config.json", isDirectory: false)
        guard let isolatedConfig = Self.isolatedCatalogConfig(
            sourceJSON: sourceConfig.output,
            temporaryHome: temporaryHome,
            pluginDirectory: sourceContext.dataDirectory.appendingPathComponent(
                "plugins",
                isDirectory: true
            )
        ), fileManager.createFile(
            atPath: isolatedConfigURL.path,
            contents: isolatedConfig,
            attributes: [.posixPermissions: NSNumber(value: Int16(0o600))]
        ) else {
            return CatalogListCLIResult(
                result: primary,
                usedIsolatedAuditStore: false,
                selectedBinaryPath: selectedBinary
            )
        }

        let isolatedContext = InstallationContext(
            source: .environmentHome,
            accessMode: .invalidReadOnly("Isolated read-only catalog view."),
            homeRoot: temporaryHome,
            configURL: isolatedConfigURL,
            dataDirectory: temporaryHome,
            auditDBURL: temporaryHome.appendingPathComponent("audit.db", isDirectory: false),
            environmentURL: temporaryHome.appendingPathComponent(".env", isDirectory: false),
            gatewayJSONLURL: temporaryHome.appendingPathComponent("gateway.jsonl", isDirectory: false),
            gatewayLogURL: temporaryHome.appendingPathComponent("gateway.log", isDirectory: false),
            gatewayErrorLogURL: nil,
            watchdogLogURL: temporaryHome.appendingPathComponent("watchdog.log", isDirectory: false),
            venvURL: sourceContext.venvURL
        )
        let isolatedRunner = CLIRunner(context: isolatedContext)
        let fallback = await isolatedRunner.run(
            binary: selectedBinary,
            arguments: arguments,
            mutation: false
        )
        guard installationContext == sourceContext else {
            return CatalogListCLIResult(
                result: CLIResult(
                    exitCode: 75,
                    output: "DefenseClaw installation changed while loading the catalog. Refresh to retry."
                ),
                usedIsolatedAuditStore: false,
                selectedBinaryPath: selectedBinary
            )
        }
        return CatalogListCLIResult(
            result: fallback,
            usedIsolatedAuditStore: fallback.succeeded,
            selectedBinaryPath: selectedBinary
        )
    }

    nonisolated static func isAuditStoreCorruption(_ output: String) -> Bool {
        output.components(separatedBy: .newlines).contains {
            $0.trimmingCharacters(in: .whitespacesAndNewlines) == auditStoreMalformedLine
        }
    }

    private nonisolated static func isolatedCatalogConfig(
        sourceJSON: String,
        temporaryHome: URL,
        pluginDirectory: URL
    ) -> Data? {
        guard sourceJSON.utf8.count <= CLIOutputLimits.maximumOutputBytes,
              let sourceData = sourceJSON
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .data(using: .utf8),
              var config = try? JSONSerialization.jsonObject(with: sourceData) as? [String: Any],
              (config["config_version"] as? NSNumber)?.intValue == 8 else {
            return nil
        }

        config = removingInlineSecrets(from: config)
        config["data_dir"] = temporaryHome.path
        config["quarantine_dir"] = temporaryHome.appendingPathComponent("quarantine").path
        config["policy_dir"] = temporaryHome.appendingPathComponent("policies").path
        if config["plugin_dir"] == nil {
            config["plugin_dir"] = pluginDirectory.path
        }
        // Catalog inventory needs no telemetry sink. Keeping an operator's
        // destinations here could emit from the isolated helper or reach a
        // path outside its private workspace.
        config["observability"] = [String: Any]()

        return try? JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
    }

    private nonisolated static func removingInlineSecrets(
        from dictionary: [String: Any]
    ) -> [String: Any] {
        dictionary.reduce(into: [String: Any]()) { result, entry in
            let lowerKey = entry.key.lowercased()
            let namesEnvironmentVariable = lowerKey.hasSuffix("_env")
            let namesInlineSecret = !namesEnvironmentVariable && [
                "api_key", "token", "password", "secret", "credential",
            ].contains { lowerKey == $0 || lowerKey.hasSuffix("_\($0)") }
            guard !namesInlineSecret else { return }

            if let nested = entry.value as? [String: Any] {
                result[entry.key] = removingInlineSecrets(from: nested)
            } else if let array = entry.value as? [[String: Any]] {
                result[entry.key] = array.map(removingInlineSecrets(from:))
            } else {
                result[entry.key] = entry.value
            }
        }
    }

    private func which(_ name: String) -> String? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        proc.arguments = [name]
        proc.environment = Self.subprocessEnvironment(
            protected: installationContext.protectedSubprocessEnvironment
        )
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        guard (try? proc.run()) != nil else { return nil }
        proc.waitUntilExit()
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return proc.terminationStatus == 0 && !out.isEmpty ? out : nil
    }

    /// Finder/LaunchServices apps do not inherit the user's interactive shell
    /// PATH. Preserve any path supplied by the parent process, then add the
    /// standard macOS package-manager and Docker Desktop locations used by the
    /// DefenseClaw CLI and its helper tools.
    static func subprocessEnvironment(
        inheriting environment: [String: String] = ProcessInfo.processInfo.environment,
        home: String = FileManager.default.homeDirectoryForCurrentUser.path,
        protected: [String: String] = [:]
    ) -> [String: String] {
        var result = environment
        let inherited = (environment["PATH"] ?? "")
            .split(separator: ":")
            .map(String.init)
        let fallbacks = [
            "\(home)/.local/bin",
            "\(home)/bin",
            "\(home)/.docker/bin",
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/opt/local/bin",
            "/opt/local/sbin",
            "/Applications/Docker.app/Contents/Resources/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
        ]
        var seen = Set<String>()
        let merged = (inherited + fallbacks).filter { directory in
            !directory.isEmpty && seen.insert(directory).inserted
        }
        result["PATH"] = merged.joined(separator: ":")
        for (key, value) in protected where !key.isEmpty {
            result[key] = value
        }
        return result
    }

    /// Runs `defenseclaw <args>`, streaming combined output lines to `onLine`.
    func run(
        arguments: [String],
        environment: [String: String] = [:],
        mutation: Bool = true,
        runID: UUID? = nil,
        onLine: (@Sendable (String) async -> Void)? = nil
    ) async -> CLIResult {
        await run(
            binary: "defenseclaw",
            arguments: arguments,
            environment: environment,
            mutation: mutation,
            runID: runID,
            onLine: onLine
        )
    }

    /// Runs a DefenseClaw executable with optional stdin. `standardInput` is
    /// used for hidden-prompt flows such as `keys set`, keeping secrets out of
    /// argv and process listings.
    func run(
        binary binaryName: String,
        arguments: [String],
        standardInput: String? = nil,
        environment: [String: String] = [:],
        mutation: Bool = true,
        runID: UUID? = nil,
        onLine: (@Sendable (String) async -> Void)? = nil
    ) async -> CLIResult {
        let executionID = runID ?? UUID()
        if runID != nil {
            switch runStates[executionID] {
            case .reserved(let cancelRequested):
                runStates[executionID] = nil
                if cancelRequested {
                    return CLIResult(
                        exitCode: 130,
                        output: "Command cancelled before launch.\n",
                        cancelled: true
                    )
                }
            case .running:
                return CLIResult(
                    exitCode: 125,
                    output: "A command with this run identifier is already active.\n"
                )
            case nil:
                break
            }
        }
        if mutation, !installationContext.permitsMutation {
            let reason = installationContext.accessMode.reason ?? "This installation is read only."
            return CLIResult(exitCode: 77, output: "Operation refused by the Mac app: \(reason)")
        }
        guard let binary = locateBinary(named: binaryName) else {
            let setting = binaryName == "defenseclaw" ? " Set its path in Settings ▸ Connection." : ""
            return CLIResult(exitCode: 127, output: "\(binaryName) binary not found.\(setting)")
        }
        let proc = Process()
        guard CLIProcessGroupLauncher.configure(proc, target: binary, arguments: arguments) else {
            return CLIResult(exitCode: 126, output: "Internal command launcher is unavailable.")
        }
        var env = Self.subprocessEnvironment()
        env["NO_COLOR"] = "1"
        for (key, value) in environment where !key.isEmpty {
            env[key] = value
        }
        // Installation identity is security-sensitive. Apply it last so a
        // wizard's secret environment cannot redirect a command elsewhere.
        for (key, value) in installationContext.protectedSubprocessEnvironment {
            env[key] = value
        }
        proc.environment = env

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        let inputPipe = standardInput == nil ? nil : Pipe()
        proc.standardInput = inputPipe

        do {
            try proc.run()
        } catch {
            return CLIResult(exitCode: 126, output: "Failed to launch \(binary): \(error.localizedDescription)")
        }
        let runToken = UUID()
        let processTree = CLIProcessTree(rootPID: proc.processIdentifier)
        guard processTree.waitUntilReady(process: proc) else {
            processTree.send(SIGKILL)
            proc.waitUntilExit()
            try? pipe.fileHandleForReading.close()
            try? inputPipe?.fileHandleForWriting.close()
            return CLIResult(
                exitCode: 126,
                output: "Internal command launcher did not establish an isolated process group."
            )
        }
        runStates[executionID] = .running(ActiveRun(
            token: runToken,
            process: proc,
            processTree: processTree,
            mutation: mutation,
            cancellationRequested: false
        ))

        if let standardInput, let inputPipe {
            inputPipe.fileHandleForWriting.write(Data((standardInput + "\n").utf8))
            try? inputPipe.fileHandleForWriting.close()
        }

        let readControl = CLIOutputReadControl()
        let terminationTask = Task.detached(priority: .utility) {
            proc.waitUntilExit()
            readControl.markParentExited()
            return proc.terminationStatus
        }

        // Keep process waiting and pipe reads off the actor so Cancel remains
        // responsive. poll(2) also bounds a descendant-held output pipe after
        // the direct command has exited.
        let outputTask = Task.detached(priority: .utility) {
            var collector = BoundedCLIOutputCollector()
            var streamer = BoundedCLILineStreamer()
            var lineContinuation: AsyncStream<String>.Continuation?
            var lineDeliveryTask: Task<Void, Never>?
            if let onLine {
                let stream = AsyncStream<String> { lineContinuation = $0 }
                lineDeliveryTask = Task.detached {
                    for await line in stream { await onLine(line) }
                }
            }
            let emitLines = lineContinuation != nil
            var readBuffer = [UInt8](repeating: 0, count: CLIOutputLimits.readChunkBytes)
            var parentExitObservedAt: ContinuousClock.Instant?
            readLoop: while true {
                if readControl.hasParentExited {
                    let now = ContinuousClock.now
                    if let observedAt = parentExitObservedAt,
                       now - observedAt >= .milliseconds(500) {
                        break readLoop
                    }
                    if parentExitObservedAt == nil { parentExitObservedAt = now }
                }

                var descriptor = pollfd(
                    fd: pipe.fileHandleForReading.fileDescriptor,
                    events: Int16(POLLIN | POLLHUP | POLLERR),
                    revents: 0
                )
                let pollResult = Darwin.poll(&descriptor, 1, 100)
                if pollResult == 0 {
                    if readControl.hasParentExited { break readLoop }
                    continue readLoop
                }
                if pollResult < 0 {
                    if errno == EINTR { continue readLoop }
                    let message = String(cString: strerror(errno))
                    let lines = collector.appendStreamError(message, emitLines: emitLines)
                    if lineContinuation != nil {
                        for line in streamer.linesToEmit(from: lines) {
                            lineContinuation?.yield(line)
                        }
                    }
                    break readLoop
                }

                let byteCount = readBuffer.withUnsafeMutableBytes { buffer in
                    Darwin.read(
                        pipe.fileHandleForReading.fileDescriptor,
                        buffer.baseAddress,
                        buffer.count
                    )
                }
                switch byteCount {
                case 0:
                    break readLoop
                case ..<0 where errno == EINTR:
                    continue readLoop
                case ..<0:
                    let message = String(cString: strerror(errno))
                    let lines = collector.appendStreamError(message, emitLines: emitLines)
                    if lineContinuation != nil {
                        for line in streamer.linesToEmit(from: lines) {
                            lineContinuation?.yield(line)
                        }
                    }
                    break readLoop
                default:
                    let chunk = Data(readBuffer.prefix(byteCount))
                    if lineContinuation != nil {
                        let lines = collector.consume(
                            chunk,
                            emitLines: emitLines && streamer.acceptsLines
                        )
                        for line in streamer.linesToEmit(
                            from: lines
                        ) {
                            lineContinuation?.yield(line)
                        }
                    } else {
                        _ = collector.consume(chunk, emitLines: false)
                    }
                }
            }
            let finished = collector.finish(emitLines: emitLines)
            if lineContinuation != nil {
                for line in streamer.linesToEmit(from: finished.lines) {
                    lineContinuation?.yield(line)
                }
            }
            lineContinuation?.finish()
            if let lineDeliveryTask { await lineDeliveryTask.value }
            try? pipe.fileHandleForReading.close()
            return finished.capture
        }

        let completion = await withTaskCancellationHandler {
            let captured = await outputTask.value
            let exitCode = await terminationTask.value
            return (captured, exitCode)
        } onCancel: {
            Task {
                await self.requestCancellation(executionID: executionID, token: runToken)
            }
        }
        let explicitlyCancelled: Bool
        if case .running(let active) = runStates[executionID], active.token == runToken {
            explicitlyCancelled = active.cancellationRequested
            runStates[executionID] = nil
        } else {
            explicitlyCancelled = false
        }
        return CLIResult(
            exitCode: completion.1,
            output: completion.0.output,
            cancelled: Task.isCancelled || explicitlyCancelled,
            outputTruncated: completion.0.truncated
        )
    }

    /// Request bounded cancellation of an Activity-owned process. Repeated
    /// requests share one escalation ladder and cannot target a later run that
    /// happens to reuse the same public identifier.
    @discardableResult
    func cancel(runID: UUID) -> CLICancellationDisposition {
        requestCancellation(executionID: runID, token: nil)
    }

    private func requestCancellation(
        executionID: UUID,
        token expectedToken: UUID?
    ) -> CLICancellationDisposition {
        guard let state = runStates[executionID] else { return .notFound }
        switch state {
        case .reserved(let cancelRequested):
            guard !cancelRequested else { return .alreadyRequested }
            runStates[executionID] = .reserved(cancelRequested: true)
            return .requested
        case .running(var active):
            if let expectedToken, active.token != expectedToken { return .notFound }
            guard !active.cancellationRequested else { return .alreadyRequested }
            guard active.process.isRunning else { return .finishing }
            active.cancellationRequested = true
            runStates[executionID] = .running(active)
            active.processTree.send(SIGINT)
            scheduleCancellationEscalation(processTree: active.processTree)
            return .requested
        }
    }

    private func scheduleCancellationEscalation(processTree: CLIProcessTree) {
        Task.detached {
            try? await Task.sleep(for: .milliseconds(500))
            // If the group is already gone, stop here. In particular, do not
            // retain its numeric PGID long enough for a later SIGKILL to reach
            // an unrelated process group that reuses the identifier.
            guard processTree.send(SIGTERM) else { return }
            try? await Task.sleep(for: .seconds(1))
            processTree.send(SIGKILL)
        }
    }

    /// Lightweight doctor probe (TUI Shift+D) — parsed into check rows.
    func doctor() async -> [DoctorCheck] {
        let result = await run(arguments: ["doctor"], mutation: true)
        guard !result.outputTruncated, result.succeeded || !result.output.isEmpty else {
            return [DoctorCheck(name: "defenseclaw doctor", result: .fail, detail: result.output)]
        }
        var checks: [DoctorCheck] = []
        for line in result.output.split(separator: "\n").map(String.init) {
            let lower = line.lowercased()
            let outcome: DoctorCheck.Result
            if lower.contains("fail") || lower.contains("✗") || lower.contains("error") {
                outcome = .fail
            } else if lower.contains("warn") || lower.contains("⚠") {
                outcome = .warn
            } else if lower.contains("pass") || lower.contains("✓")
                        || lower.hasPrefix("ok ") || lower.hasSuffix(" ok")
                        || lower.contains("[ok]") {
                outcome = .pass
            } else {
                continue
            }
            let name = line
                .replacingOccurrences(of: "✓", with: "")
                .replacingOccurrences(of: "⚠", with: "")
                .replacingOccurrences(of: "✗", with: "")
                .trimmingCharacters(in: .whitespaces)
            checks.append(DoctorCheck(name: String(name.prefix(80)), result: outcome, detail: line))
        }
        if checks.isEmpty {
            checks.append(DoctorCheck(
                name: "doctor",
                result: result.succeeded ? .pass : .fail,
                detail: String(result.output.suffix(400))
            ))
        }
        return checks
    }
}
