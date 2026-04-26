import Foundation

public struct ProcessRunner: Sendable {
    private let binaryPath: String

    public init(binaryPath: String = "defenseclaw") {
        self.binaryPath = binaryPath
    }

    public struct CommandResult: Sendable {
        public let exitCode: Int32
        public let stdout: String
        public let stderr: String
        public var succeeded: Bool { exitCode == 0 }
    }

    public func run(_ args: [String]) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
                process.arguments = [self.binaryPath] + args
                let stdoutPipe = Pipe()
                let stderrPipe = Pipe()
                process.standardOutput = stdoutPipe
                process.standardError = stderrPipe
                do {
                    try process.run()
                    process.waitUntilExit()
                    let result = CommandResult(
                        exitCode: process.terminationStatus,
                        stdout: String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
                        stderr: String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                    )
                    continuation.resume(returning: result)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    public func doctor() async throws -> String {
        let r = try await run(["doctor"])
        return r.stdout
    }
    public func initialize() async throws -> CommandResult { try await run(["init"]) }
    public func setupGateway() async throws -> CommandResult { try await run(["setup", "gateway"]) }
    public func setupGuardrail() async throws -> CommandResult { try await run(["setup", "guardrail"]) }
    public func scanSkill(path: String) async throws -> CommandResult { try await run(["skill", "scan", path]) }
    public func scanMCP(url: String) async throws -> CommandResult { try await run(["mcp", "scan", url]) }
    public func scanCode(path: String) async throws -> CommandResult { try await run(["codeguard", "scan", path]) }
    public func aibomScan() async throws -> CommandResult { try await run(["aibom", "scan"]) }
    public func policyApply(template: String) async throws -> CommandResult { try await run(["policy", "apply", template]) }
    public func policyReset() async throws -> CommandResult { try await run(["policy", "reset"]) }
    public func policyTest() async throws -> CommandResult { try await run(["policy", "test"]) }
    public func statusCommand() async throws -> CommandResult { try await run(["status"]) }
}
