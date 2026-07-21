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
    var succeeded: Bool { exitCode == 0 && !outputTruncated }
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
    /// User override (App Settings ▸ Connection) wins; otherwise search standard locations.
    static let pathOverrideKey = "defenseclawBinaryPath"

    private var cachedPaths: [String: String] = [:]
    private var runningProcesses: [UUID: Process] = [:]
    private var cancellationRequests = Set<UUID>()
    private var installationContext: InstallationContext

    init(context: InstallationContext = .resolve()) {
        self.installationContext = context
    }

    func rebind(to context: InstallationContext) {
        guard installationContext != context else { return }
        if installationContext.permitsMutation, !context.permitsMutation {
            for (runID, process) in runningProcesses where process.isRunning {
                cancellationRequests.insert(runID)
                process.interrupt()
            }
        }
        installationContext = context
        cachedPaths.removeAll()
    }

    func locateBinary() -> String? {
        locateBinary(named: "defenseclaw")
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
        if mutation, !installationContext.permitsMutation {
            let reason = installationContext.accessMode.reason ?? "This installation is read only."
            return CLIResult(exitCode: 77, output: "Operation refused by the Mac app: \(reason)")
        }
        guard let binary = locateBinary(named: binaryName) else {
            let setting = binaryName == "defenseclaw" ? " Set its path in Settings ▸ Connection." : ""
            return CLIResult(exitCode: 127, output: "\(binaryName) binary not found.\(setting)")
        }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: binary)
        proc.arguments = arguments
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
        if let runID { runningProcesses[runID] = proc }

        if let standardInput, let inputPipe {
            inputPipe.fileHandleForWriting.write(Data((standardInput + "\n").utf8))
            try? inputPipe.fileHandleForWriting.close()
        }

        // A detached reader keeps draining the pipe even if the calling Task is
        // cancelled. Stopping reads early can otherwise leave the child blocked
        // on a full pipe while its parent waits for termination.
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
            readLoop: while true {
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

        let captured = await withTaskCancellationHandler {
            await outputTask.value
        } onCancel: {
            if proc.isRunning { proc.interrupt() }
        }
        proc.waitUntilExit()
        let explicitlyCancelled = runID.map { cancellationRequests.remove($0) != nil } ?? false
        let cancelled = Task.isCancelled || explicitlyCancelled
        if let runID { runningProcesses[runID] = nil }
        return CLIResult(
            exitCode: proc.terminationStatus,
            output: captured.output,
            cancelled: cancelled,
            outputTruncated: captured.truncated
        )
    }

    /// Interrupt an Activity-owned process. The process remains registered
    /// until its output stream closes, so the final exit status is retained.
    func cancel(runID: UUID) {
        guard let process = runningProcesses[runID], process.isRunning else { return }
        cancellationRequests.insert(runID)
        process.interrupt()
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
