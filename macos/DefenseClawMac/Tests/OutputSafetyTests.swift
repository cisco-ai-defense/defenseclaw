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

// Minimal standalone-test dependency for CLIRunner.doctor(). The production
// target supplies the richer model from DataLayer/Models.swift.
struct DoctorCheck {
    enum Result { case pass, warn, fail }
    var name: String
    var result: Result
    var detail: String
}

actor StreamedLineRecorder {
    private var lines: [String] = []

    func append(_ line: String) { lines.append(line) }
    func snapshot() -> [String] { lines }
}

@main
struct OutputSafetyTests {
    static func main() async {
        await capturesNormalOutput()
        await truncatesANewlineLessLine()
        await capsTotalOutputAndReportsFailure()
        await taskCancellationInterruptsChildAndDrainsPipe()
        await explicitRunIDCancellationInterruptsChild()
        await pendingCancellationIsHonoredAndConsumed()
        await ignoredSignalsEscalateToForcedTermination()
        await closedOutputDoesNotBlockCancellation()
        await inheritedPipeDoesNotHoldRunOpen()
        await continuouslyWritingDescendantDoesNotHoldRunOpen()
        cancelledResultIsNotSuccessful()
        parsesBoundedInventoryDocuments()
        rejectsOversizedAndAdversarialInventoryOutput()
        print("CLI output and inventory parser safety tests passed")
    }

    private static func capturesNormalOutput() async {
        let result = await CLIRunner().run(
            binary: "/usr/bin/python3",
            arguments: ["-c", "import sys; sys.stdout.write('alpha\\nbeta')"]
        )
        expect(result.succeeded, "normal command succeeds")
        expect(!result.outputTruncated, "normal command is not truncated")
        expect(result.output == "alpha\nbeta\n", "normal output is preserved")
    }

    private static func truncatesANewlineLessLine() async {
        let count = CLIOutputLimits.maximumLineBytes + 4_096
        let recorder = StreamedLineRecorder()
        let result = await CLIRunner().run(
            binary: "/usr/bin/python3",
            arguments: ["-c", "import sys; sys.stdout.write('x' * \(count))"]
        ) { line in
            await recorder.append(line)
        }
        let streamedLines = await recorder.snapshot()
        expect(result.exitCode == 0, "long-line child exits normally")
        expect(result.outputTruncated, "long line sets truncation state")
        expect(!result.succeeded, "truncated machine output is not a success")
        expect(result.output.contains("[line truncated]"), "long line carries an explicit marker")
        expect(
            result.output.utf8.count <= CLIOutputLimits.maximumOutputBytes,
            "long-line retained output is bounded"
        )
        expect(streamedLines.count == 1, "long line emits one bounded live update")
        expect(
            streamedLines[0].utf8.count <= CLIOutputLimits.maximumStreamedBytes,
            "live output callback is byte bounded"
        )
        expect(
            streamedLines[0].contains("[additional live output omitted]"),
            "live output carries an omission marker"
        )
    }

    private static func capsTotalOutputAndReportsFailure() async {
        let count = CLIOutputLimits.maximumOutputBytes + 1_024 * 1_024
        let result = await CLIRunner().run(
            binary: "/usr/bin/python3",
            arguments: [
                "-c",
                "import sys; sys.stdout.write(('y' * 80 + '\\n') * (\(count) // 81 + 1))",
            ]
        )
        expect(result.exitCode == 0, "large-output child is fully drained")
        expect(result.outputTruncated, "total output cap sets truncation state")
        expect(!result.succeeded, "capped output cannot be treated as complete")
        expect(
            result.output.utf8.count <= CLIOutputLimits.maximumOutputBytes,
            "retained command output stays within the byte cap"
        )
        expect(result.output.contains("[output truncated:"), "total cap carries an explicit marker")
    }

    private static func taskCancellationInterruptsChildAndDrainsPipe() async {
        let runner = CLIRunner()
        let recorder = StreamedLineRecorder()
        let interruptionSentinel = "sigint-handler-output-drained"
        let childProgram = """
        import signal
        import sys
        import time

        def handle_interrupt(_signal, _frame):
            print("\(interruptionSentinel)", flush=True)
            sys.exit(130)

        signal.signal(signal.SIGINT, handle_interrupt)
        signal.alarm(8)
        print("ready", flush=True)
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: ["-c", childProgram]
            ) { line in
                await recorder.append(line)
            }
        }
        let childStarted = await waitForLine("ready", in: recorder)
        expect(childStarted, "child starts before the cancellation check")
        task.cancel()
        let result = await task.value
        expect(result.cancelled, "Task cancellation is reflected in the result")
        expect(result.output.contains("ready"), "output produced before cancellation is drained")
        expect(
            result.output.contains(interruptionSentinel),
            "output produced by the SIGINT handler is drained before return"
        )
    }

    private static func explicitRunIDCancellationInterruptsChild() async {
        let runner = CLIRunner()
        let recorder = StreamedLineRecorder()
        let runID = UUID()
        let interruptionSentinel = "explicit-run-id-sigint-drained"
        let childProgram = """
        import signal
        import sys
        import time

        def handle_interrupt(_signal, _frame):
            print("\(interruptionSentinel)", flush=True)
            sys.exit(130)

        signal.signal(signal.SIGINT, handle_interrupt)
        signal.alarm(8)
        print("ready", flush=True)
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: ["-c", childProgram],
                runID: runID
            ) { line in
                await recorder.append(line)
            }
        }
        let childStarted = await waitForLine("ready", in: recorder)
        expect(childStarted, "explicit run-ID child starts before cancellation")
        let disposition = await runner.cancel(runID: runID)
        expect(disposition == .requested, "explicit run-ID cancellation is accepted")
        let result = await task.value
        expect(result.cancelled, "explicit run-ID cancellation is reflected in the result")
        expect(!result.succeeded, "an explicitly cancelled command is not successful")
        expect(
            result.output.contains(interruptionSentinel),
            "explicit cancellation drains output from the SIGINT handler"
        )
    }

    private static func pendingCancellationIsHonoredAndConsumed() async {
        let runner = CLIRunner()
        let runID = UUID()
        let reserved = await runner.reserve(runID: runID)
        expect(reserved, "Activity run ID can be reserved before publication")
        let disposition = await runner.cancel(runID: runID)
        expect(disposition == .requested, "cancellation against a reservation is retained")

        let cancelled = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", "print('must-not-launch')"],
            runID: runID
        )
        expect(cancelled.cancelled, "reserved cancellation prevents process launch")
        expect(!cancelled.output.contains("must-not-launch"), "cancelled reservation does not execute the child")

        let reused = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", "print('run-id-reused')"],
            runID: runID
        )
        expect(reused.succeeded, "pre-launch cancellation is consumed after one run")
        expect(reused.output.contains("run-id-reused"), "a consumed run ID can be reused safely")
    }

    private static func ignoredSignalsEscalateToForcedTermination() async {
        let runner = CLIRunner()
        let recorder = StreamedLineRecorder()
        let runID = UUID()
        let childProgram = """
        import signal
        import time

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.alarm(8)
        print("ready", flush=True)
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: ["-c", childProgram],
                runID: runID
            ) { line in
                await recorder.append(line)
            }
        }
        let childStarted = await waitForLine("ready", in: recorder)
        expect(childStarted, "signal-ignoring child starts before cancellation")
        let started = ContinuousClock.now
        let disposition = await runner.cancel(runID: runID)
        expect(disposition == .requested, "signal-ignoring child accepts cancellation")
        let result = await task.value
        let elapsed = ContinuousClock.now - started
        expect(result.cancelled, "forced termination remains a cancelled result")
        expect(elapsed < .seconds(4), "ignored signals escalate to forced termination promptly")
    }

    private static func closedOutputDoesNotBlockCancellation() async {
        let runner = CLIRunner()
        let runID = UUID()
        let marker = FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-closed-output-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: marker) }
        let childProgram = """
        import os
        import signal
        import sys
        import time

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.alarm(8)
        print("ready", flush=True)
        os.close(1)
        os.close(2)
        with open(sys.argv[1], "w", encoding="utf-8") as marker:
            marker.write("output-closed")
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: ["-c", childProgram, marker.path],
                runID: runID
            )
        }
        let outputClosed = await waitForFile(marker)
        expect(outputClosed, "child closes output before cancellation is requested")
        let started = ContinuousClock.now
        let disposition = await runner.cancel(runID: runID)
        expect(disposition == .requested, "runner actor remains available after output closes")
        let result = await task.value
        let elapsed = ContinuousClock.now - started
        expect(result.cancelled, "closed-output child is cancelled")
        expect(elapsed < .seconds(4), "closed output cannot block cancellation on waitUntilExit")
    }

    private static func inheritedPipeDoesNotHoldRunOpen() async {
        let runner = CLIRunner()
        let childProgram = """
        import subprocess
        import sys

        subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(3)"],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        print("direct-parent-exited", flush=True)
        """
        let started = ContinuousClock.now
        let result = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", childProgram]
        )
        let elapsed = ContinuousClock.now - started
        expect(result.succeeded, "direct parent exit remains successful")
        expect(result.output.contains("direct-parent-exited"), "direct parent output is drained")
        expect(elapsed < .seconds(2), "descendant-held pipe does not hold the direct run open")
    }

    private static func continuouslyWritingDescendantDoesNotHoldRunOpen() async {
        let runner = CLIRunner()
        let childProgram = """
        import subprocess
        import sys

        writer = (
            "import time\\n"
            "end = time.monotonic() + 3\\n"
            "while time.monotonic() < end:\\n"
            " print('descendant-output', flush=True)\\n"
            " time.sleep(0.005)"
        )
        subprocess.Popen(
            [sys.executable, "-c", writer],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        print("continuous-parent-exited", flush=True)
        """
        let started = ContinuousClock.now
        let result = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", childProgram]
        )
        let elapsed = ContinuousClock.now - started
        expect(result.succeeded, "continuously writing descendant does not change the parent result")
        expect(result.output.contains("continuous-parent-exited"), "direct parent output survives bounded drain")
        expect(elapsed < .seconds(2), "post-exit drain has a hard ceiling under continuous output")
    }

    private static func cancelledResultIsNotSuccessful() {
        let result = CLIResult(exitCode: 0, output: "", cancelled: true)
        expect(!result.succeeded, "exit zero cannot override a cancelled result")
    }

    private static func waitForLine(
        _ expected: String,
        in recorder: StreamedLineRecorder,
        attempts: Int = 100
    ) async -> Bool {
        for _ in 0..<attempts {
            if (await recorder.snapshot()).contains(expected) { return true }
            try? await Task.sleep(nanoseconds: 30_000_000)
        }
        return false
    }

    private static func waitForFile(_ url: URL, attempts: Int = 100) async -> Bool {
        for _ in 0..<attempts {
            if FileManager.default.fileExists(atPath: url.path) { return true }
            try? await Task.sleep(nanoseconds: 30_000_000)
        }
        return false
    }

    private static func parsesBoundedInventoryDocuments() {
        let mixed = """
        scanner diagnostic
        {"connector":"codex","summary":{"total":1}}
        trailing diagnostic
        """
        let parsed = InventoryOutputParser.parse(mixed)
        expect(parsed?.documents.count == 1, "bounded inventory document parses")
        expect(parsed?.documents.first?["connector"] as? String == "codex", "connector is retained")
        expect(parsed?.diagnostics.contains("scanner diagnostic") == true, "diagnostics are retained")

        let array = "notice [not JSON] then [{\"connector\":\"cursor\"}]"
        expect(
            InventoryOutputParser.firstJSONArrayData(in: array) != nil,
            "array parser skips an invalid diagnostic candidate"
        )

        let unmatchedObjectOpeners = String(repeating: "{", count: 12)
            + " diagnostic then {\"connector\":\"claudecode\",\"summary\":{}}"
        expect(
            InventoryOutputParser.parse(unmatchedObjectOpeners)?.documents.first?["connector"]
                as? String == "claudecode",
            "object parser finds valid JSON after unmatched openers without rescanning"
        )

        let unmatchedArrayOpeners = String(repeating: "[", count: 12)
            + " diagnostic then [{\"connector\":\"codex\"}]"
        expect(
            InventoryOutputParser.firstJSONArrayData(in: unmatchedArrayOpeners) != nil,
            "array parser finds valid JSON after unmatched openers without rescanning"
        )
    }

    private static func rejectsOversizedAndAdversarialInventoryOutput() {
        let oversized = String(repeating: " ", count: InventoryOutputParser.maximumInputBytes + 1)
            + "{\"connector\":\"codex\"}"
        expect(InventoryOutputParser.parse(oversized) == nil, "oversized parser input is rejected")
        expect(
            InventoryOutputParser.firstJSONArrayData(in: oversized) == nil,
            "oversized array parser input is rejected"
        )

        let adversarial = String(repeating: "{", count: 100_000)
        expect(InventoryOutputParser.parse(adversarial) == nil, "candidate and work budgets terminate")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
