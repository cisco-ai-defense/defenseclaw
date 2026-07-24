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

import Darwin
import Foundation

// Minimal standalone-test dependency for CLIRunner.doctor(). The app target
// supplies the production model from DataLayer/Models.swift.
struct DoctorCheck {
    enum Result { case pass, warn, fail }
    var name: String
    var result: Result
    var detail: String
}

@main
struct CLICancellationTests {
    static func main() async {
        await explicitCancellationInterruptsChild()
        await pendingCancellationIsHonoredAndConsumed()
        await ignoredSignalsEscalateToForcedTermination()
        await closedOutputDoesNotBlockCancellation()
        await inheritedPipeDoesNotHoldRunOpen()
        cancelledResultIsNotSuccessful()
        print("CLICancellationTests passed")
    }

    private static func explicitCancellationInterruptsChild() async {
        let runner = CLIRunner()
        let runID = UUID()
        let marker = temporaryMarker("explicit")
        defer { try? FileManager.default.removeItem(at: marker) }
        let childProgram = """
        import signal
        import sys
        import time

        def handle_interrupt(_signal, _frame):
            print("explicit-sigint-drained", flush=True)
            sys.exit(130)

        signal.signal(signal.SIGINT, handle_interrupt)
        signal.alarm(8)
        with open(sys.argv[1], "w", encoding="utf-8") as ready:
            ready.write("ready")
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: ["-c", childProgram, marker.path],
                runID: runID
            )
        }
        let childStarted = await waitForFile(marker)
        expect(childStarted, "explicit-cancellation child starts")
        let disposition = await runner.cancel(runID: runID)
        expect(disposition == .requested, "explicit cancellation is accepted")
        let result = await task.value
        expect(result.cancelled, "explicit cancellation marks the result cancelled")
        expect(!result.succeeded, "cancelled command is not successful")
        expect(result.output.contains("explicit-sigint-drained"), "SIGINT output is drained")
    }

    private static func pendingCancellationIsHonoredAndConsumed() async {
        let runner = CLIRunner()
        let runID = UUID()
        let reserved = await runner.reserve(runID: runID)
        expect(reserved, "run ID can be reserved")
        let cancellation = await runner.cancel(runID: runID)
        expect(cancellation == .requested, "reserved run accepts cancellation")

        let cancelled = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", "print('must-not-launch')"],
            runID: runID
        )
        expect(cancelled.cancelled, "pre-launch cancellation prevents launch")
        expect(!cancelled.output.contains("must-not-launch"), "cancelled child did not execute")

        let reused = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", "print('run-id-reused')"],
            runID: runID
        )
        expect(reused.succeeded, "pre-launch cancellation is consumed once")
        expect(reused.output.contains("run-id-reused"), "run ID can be reused safely")
    }

    private static func ignoredSignalsEscalateToForcedTermination() async {
        let runner = CLIRunner()
        let runID = UUID()
        let marker = temporaryMarker("forced")
        defer { try? FileManager.default.removeItem(at: marker) }
        let childProgram = """
        import signal
        import sys
        import time

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.alarm(8)
        with open(sys.argv[1], "w", encoding="utf-8") as ready:
            ready.write("ready")
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: ["-c", childProgram, marker.path],
                runID: runID
            )
        }
        let childStarted = await waitForFile(marker)
        expect(childStarted, "signal-ignoring child starts")
        let started = ContinuousClock.now
        let cancellation = await runner.cancel(runID: runID)
        expect(cancellation == .requested, "forced cancellation is accepted")
        let result = await task.value
        expect(result.cancelled, "forced termination remains cancelled")
        expect(ContinuousClock.now - started < .seconds(4), "signals escalate promptly")
    }

    private static func closedOutputDoesNotBlockCancellation() async {
        let runner = CLIRunner()
        let runID = UUID()
        let marker = temporaryMarker("closed-output")
        defer { try? FileManager.default.removeItem(at: marker) }
        let childProgram = """
        import os
        import signal
        import sys
        import time

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.alarm(8)
        os.close(1)
        os.close(2)
        with open(sys.argv[1], "w", encoding="utf-8") as ready:
            ready.write("ready")
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: ["-c", childProgram, marker.path],
                runID: runID
            )
        }
        let childStarted = await waitForFile(marker)
        expect(childStarted, "closed-output child starts")
        let cancellation = await runner.cancel(runID: runID)
        expect(cancellation == .requested, "runner remains responsive after EOF")
        let result = await task.value
        expect(result.cancelled, "closed-output child is cancelled")
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
        expect(result.succeeded, "direct parent exit succeeds")
        expect(result.output.contains("direct-parent-exited"), "direct parent output is retained")
        expect(ContinuousClock.now - started < .seconds(2), "descendant-held pipe is bounded")
    }

    private static func cancelledResultIsNotSuccessful() {
        expect(!CLIResult(exitCode: 0, output: "", cancelled: true).succeeded,
               "exit zero cannot override cancellation")
    }

    private static func temporaryMarker(_ name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-\(name)-\(UUID().uuidString)")
    }

    private static func waitForFile(_ url: URL, attempts: Int = 100) async -> Bool {
        for _ in 0..<attempts {
            if FileManager.default.fileExists(atPath: url.path) { return true }
            try? await Task.sleep(for: .milliseconds(30))
        }
        return false
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fputs("FAILED: \(message)\n", stderr)
            exit(1)
        }
    }
}
