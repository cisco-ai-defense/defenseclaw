import XCTest
@testable import DefenseClawKit

final class ProcessRunnerTests: XCTestCase {
    func testRunEchoCommand() async throws {
        let runner = ProcessRunner(binaryPath: "echo")
        let result = try await runner.run(["hello", "world"])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines), "hello world")
    }

    func testRunFailingCommand() async throws {
        let runner = ProcessRunner(binaryPath: "false")
        let result = try await runner.run([])
        XCTAssertNotEqual(result.exitCode, 0)
        XCTAssertFalse(result.succeeded)
    }

    func testCommandResultProperties() {
        let success = ProcessRunner.CommandResult(exitCode: 0, stdout: "ok", stderr: "")
        XCTAssertTrue(success.succeeded)
        let failure = ProcessRunner.CommandResult(exitCode: 1, stdout: "", stderr: "error")
        XCTAssertFalse(failure.succeeded)
    }
}
