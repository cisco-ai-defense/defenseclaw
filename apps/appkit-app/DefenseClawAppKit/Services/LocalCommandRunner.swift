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

        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments
        process.standardOutput = output
        process.standardError = error

        try process.run()
        process.waitUntilExit()

        let stdout = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        return LocalCommandResult(
            executable: executable,
            arguments: arguments,
            exitCode: process.terminationStatus,
            standardOutput: redact(stdout),
            standardError: redact(stderr)
        )
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
