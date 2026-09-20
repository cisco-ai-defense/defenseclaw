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
        CLIProcessGroupLauncher.execIfRequested()
        await launcherRejectsExternalInvocation()
        await launcherPreservesArgumentsAndStandardInput()
        await explicitCancellationInterruptsChild()
        await pendingCancellationIsHonoredAndConsumed()
        await ignoredSignalsEscalateToForcedTermination()
        await cancelledParentDoesNotLeaveDescendant()
        await forkedReparentedGrandchildIsKilled()
        await closedOutputDoesNotBlockCancellation()
        await inheritedPipeDoesNotHoldRunOpen()
        await standardInputIsWrittenAndClosed()
        cancelledResultIsNotSuccessful()
        print("CLICancellationTests passed")
    }

    private static func launcherRejectsExternalInvocation() async {
        let marker = temporaryMarker("external-launcher")
        defer { try? FileManager.default.removeItem(at: marker) }
        guard let executable = Bundle.main.executableURL?.path else {
            expect(false, "test executable path is available")
            return
        }

        let program = """
        import subprocess
        import sys

        result = subprocess.run([
            sys.argv[1],
            "--defenseclaw-internal-command-launcher-v1",
            "/usr/bin/touch",
            sys.argv[2],
        ])
        sys.exit(0 if result.returncode == 126 else 1)
        """
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-c", program, executable, marker.path]
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            expect(false, "external-launcher rejection probe starts")
            return
        }

        expect(process.terminationStatus == 0, "external launcher invocation is rejected")
        expect(!FileManager.default.fileExists(atPath: marker.path), "external target is not executed")
    }

    private static func launcherPreservesArgumentsAndStandardInput() async {
        let runner = CLIRunner()
        let program = """
        import os
        import sys

        print(f"group={os.getpid() == os.getpgrp()}")
        print(f"argument={sys.argv[1]}")
        print(f"input={sys.stdin.readline().strip()}")
        """
        let result = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", program, "two words"],
            standardInput: "standard input",
            mutation: false
        )
        expect(result.succeeded, "launcher preserves normal command success")
        expect(result.output.contains("group=True"), "launcher establishes a dedicated process group")
        expect(result.output.contains("argument=two words"), "launcher preserves exact argv entries")
        expect(result.output.contains("input=standard input"), "launcher preserves standard input")
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
                mutation: false,
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
            mutation: false,
            runID: runID
        )
        expect(cancelled.cancelled, "pre-launch cancellation prevents launch")
        expect(!cancelled.output.contains("must-not-launch"), "cancelled child did not execute")

        let reused = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", "print('run-id-reused')"],
            mutation: false,
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
                mutation: false,
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

    private static func cancelledParentDoesNotLeaveDescendant() async {
        let runner = CLIRunner()
        let runID = UUID()
        let parentMarker = temporaryMarker("tree-parent")
        let childMarker = temporaryMarker("tree-child")
        defer {
            try? FileManager.default.removeItem(at: parentMarker)
            try? FileManager.default.removeItem(at: childMarker)
        }
        let childProgram = """
        import signal
        import sys
        import time

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        with open(sys.argv[1], "w", encoding="utf-8") as ready:
            ready.write("ready")
        time.sleep(30)
        """
        let parentProgram = """
        import signal
        import subprocess
        import sys
        import time

        child = subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[3]])
        with open(sys.argv[2], "w", encoding="utf-8") as marker:
            marker.write(str(child.pid))

        def handle_interrupt(_signal, _frame):
            sys.exit(130)

        signal.signal(signal.SIGINT, handle_interrupt)
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: ["-c", parentProgram, childProgram, parentMarker.path, childMarker.path],
                mutation: false,
                runID: runID
            )
        }
        let parentStarted = await waitForFile(parentMarker)
        let childStarted = await waitForFile(childMarker)
        expect(parentStarted, "process-tree parent starts")
        expect(childStarted, "process-tree descendant starts")
        guard let childPID = try? String(contentsOf: parentMarker, encoding: .utf8),
              let pid = pid_t(childPID.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            expect(false, "process-tree descendant PID is recorded")
            return
        }
        defer { _ = Darwin.kill(pid, SIGKILL) }

        let cancellation = await runner.cancel(runID: runID)
        expect(cancellation == .requested, "process-tree cancellation is accepted")
        let result = await task.value
        expect(result.cancelled, "process-tree cancellation marks the parent result cancelled")
        let childExited = await waitForProcessExit(pid)
        expect(childExited, "process-tree escalation terminates the descendant")
    }

    private static func forkedReparentedGrandchildIsKilled() async {
        let runner = CLIRunner()
        let runID = UUID()
        let workerMarker = temporaryMarker("race-worker")
        let grandchildMarker = temporaryMarker("race-grandchild")
        defer {
            try? FileManager.default.removeItem(at: workerMarker)
            try? FileManager.default.removeItem(at: grandchildMarker)
        }
        let grandchildProgram = """
        import os
        import signal
        import sys
        import time

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        with open(sys.argv[1], "w", encoding="utf-8") as marker:
            marker.write(str(os.getpid()))
        time.sleep(30)
        """
        let workerProgram = """
        import signal
        import subprocess
        import sys
        import time

        def handle_interrupt(_signal, _frame):
            subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[2]])
            sys.exit(130)

        signal.signal(signal.SIGINT, handle_interrupt)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        with open(sys.argv[3], "w", encoding="utf-8") as marker:
            marker.write("ready")
        time.sleep(30)
        """
        let rootProgram = """
        import signal
        import subprocess
        import sys
        import time

        subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]])
        signal.signal(signal.SIGINT, lambda _signal, _frame: sys.exit(130))
        time.sleep(30)
        """
        let task = Task {
            await runner.run(
                binary: "/usr/bin/python3",
                arguments: [
                    "-c",
                    rootProgram,
                    workerProgram,
                    grandchildProgram,
                    grandchildMarker.path,
                    workerMarker.path,
                ],
                mutation: false,
                runID: runID
            )
        }
        let workerStarted = await waitForFile(workerMarker)
        expect(workerStarted, "fork-race worker starts")
        let cancellation = await runner.cancel(runID: runID)
        expect(cancellation == .requested, "fork-race cancellation is accepted")
        let result = await task.value
        expect(result.cancelled, "fork-race result remains cancelled")
        let grandchildStarted = await waitForFile(grandchildMarker)
        expect(grandchildStarted, "signaled worker forks a grandchild before exiting")

        guard let value = try? String(contentsOf: grandchildMarker, encoding: .utf8),
              let grandchildPID = pid_t(value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            expect(false, "fork-race grandchild PID is recorded")
            return
        }
        defer { _ = Darwin.kill(grandchildPID, SIGKILL) }
        let grandchildExited = await waitForProcessExit(grandchildPID, attempts: 180)
        expect(grandchildExited, "process-group escalation terminates the reparented grandchild")
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
                mutation: false,
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
            arguments: ["-c", childProgram],
            mutation: false
        )
        expect(result.succeeded, "direct parent exit succeeds")
        expect(result.output.contains("direct-parent-exited"), "direct parent output is retained")
        expect(ContinuousClock.now - started < .seconds(2), "descendant-held pipe is bounded")
    }

    private static func standardInputIsWrittenAndClosed() async {
        let runner = CLIRunner()
        let result = await runner.run(
            binary: "/usr/bin/python3",
            arguments: ["-c", "import sys; print(sys.stdin.readline().strip()); print('eof' if not sys.stdin.read() else 'open')"],
            standardInput: "y"
        )
        expect(result.succeeded, "stdin-backed command succeeds")
        expect(result.output.contains("y\neof"), "stdin value is written and the pipe is closed")
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

    private static func waitForProcessExit(_ pid: pid_t, attempts: Int = 120) async -> Bool {
        for _ in 0..<attempts {
            if Darwin.kill(pid, 0) == -1, errno == ESRCH { return true }
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
