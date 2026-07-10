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

import Foundation

struct CLIResult: Sendable {
    var exitCode: Int32
    var output: String
    var cancelled: Bool = false
    var succeeded: Bool { exitCode == 0 }
}

actor CLIRunner {
    /// User override (App Settings ▸ Connection) wins; otherwise search standard locations.
    static let pathOverrideKey = "defenseclawBinaryPath"

    private var cachedPaths: [String: String] = [:]
    private var runningProcesses: [UUID: Process] = [:]
    private var cancellationRequests = Set<UUID>()

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
        let candidates = [
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
        proc.environment = Self.subprocessEnvironment()
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
        home: String = FileManager.default.homeDirectoryForCurrentUser.path
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
        return result
    }

    /// Runs `defenseclaw <args>`, streaming combined output lines to `onLine`.
    func run(
        arguments: [String],
        environment: [String: String] = [:],
        runID: UUID? = nil,
        onLine: (@Sendable (String) async -> Void)? = nil
    ) async -> CLIResult {
        await run(
            binary: "defenseclaw",
            arguments: arguments,
            environment: environment,
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
        runID: UUID? = nil,
        onLine: (@Sendable (String) async -> Void)? = nil
    ) async -> CLIResult {
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
        proc.environment = env

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        let inputPipe = standardInput == nil ? nil : Pipe()
        proc.standardInput = inputPipe

        var collected = ""
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

        do {
            for try await line in pipe.fileHandleForReading.bytes.lines {
                collected += line + "\n"
                await onLine?(line)
            }
        } catch {
            collected += "\n[output stream error: \(error.localizedDescription)]\n"
        }
        proc.waitUntilExit()
        let cancelled = runID.map { cancellationRequests.remove($0) != nil } ?? false
        if let runID { runningProcesses[runID] = nil }
        return CLIResult(exitCode: proc.terminationStatus, output: collected, cancelled: cancelled)
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
        let result = await run(arguments: ["doctor"])
        guard result.succeeded || !result.output.isEmpty else {
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
