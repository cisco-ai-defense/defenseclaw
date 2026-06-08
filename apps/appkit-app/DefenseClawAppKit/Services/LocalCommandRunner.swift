import Foundation

struct LocalCommandResult: Equatable {
    let executable: String
    let arguments: [String]
    let exitCode: Int32
    let standardOutput: String
    let standardError: String

    var commandLine: String {
        ([executable] + arguments).joined(separator: " ")
    }

    var combinedOutput: String {
        [standardOutput, standardError]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
    }
}

actor LocalCommandRunner {
    func run(_ executable: String, arguments: [String]) async throws -> LocalCommandResult {
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        let resolved = resolveExecutable(executable, arguments: arguments)

        process.executableURL = resolved.url
        process.arguments = resolved.arguments
        process.currentDirectoryURL = FileManager.default.homeDirectoryForCurrentUser
        process.standardOutput = output
        process.standardError = error

        try process.run()
        async let stdout = readPipe(output)
        async let stderr = readPipe(error)
        process.waitUntilExit()
        let stdoutText = await stdout
        let stderrText = await stderr

        return LocalCommandResult(
            executable: executable,
            arguments: arguments,
            exitCode: process.terminationStatus,
            standardOutput: redact(stdoutText),
            standardError: redact(stderrText)
        )
    }

    private func resolveExecutable(_ executable: String, arguments: [String]) -> (url: URL, arguments: [String]) {
        if executable.contains("/") {
            return (URL(fileURLWithPath: executable), arguments)
        }

        var candidates: [String] = []
        if let resourcePath = Bundle.main.resourcePath {
            candidates.append("\(resourcePath)/\(executable)")
            candidates.append("\(resourcePath)/bin/\(executable)")
        }
        candidates.append(contentsOf: [
            "\(NSHomeDirectory())/.local/bin/\(executable)",
            "/opt/homebrew/bin/\(executable)",
            "/usr/local/bin/\(executable)",
            "/usr/bin/\(executable)",
            "/bin/\(executable)"
        ])

        if let path = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) {
            return (URL(fileURLWithPath: path), arguments)
        }

        return (URL(fileURLWithPath: "/usr/bin/env"), [executable] + arguments)
    }

    private nonisolated func readPipe(_ pipe: Pipe) async -> String {
        await Task.detached(priority: .utility) {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8) ?? ""
        }.value
    }

    private func redact(_ text: String) -> String {
        let patterns = [
            #"(?i)(api[_-]?key|token|secret|password)(\s*[:=]\s*)([^\s"']+)"#,
            #"(?i)(Authorization:\s*Bearer\s+)([A-Za-z0-9._~+/=-]+)"#
        ]

        var redacted = text
        redacted = redacted.replacingOccurrences(
            of: patterns[0],
            with: "$1$2[redacted]",
            options: .regularExpression
        )
        redacted = redacted.replacingOccurrences(
            of: patterns[1],
            with: "$1[redacted]",
            options: .regularExpression
        )
        return redacted
    }
}
