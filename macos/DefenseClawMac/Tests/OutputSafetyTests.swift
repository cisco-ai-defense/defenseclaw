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
        var childStarted = false
        for _ in 0..<100 {
            if (await recorder.snapshot()).contains("ready") {
                childStarted = true
                break
            }
            try? await Task.sleep(nanoseconds: 30_000_000)
        }
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
