// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// agentHookWait is the longest a tool call may wait for DefenseClaw.
const agentHookWait = 5 * time.Second

// slowStartHelperArg makes TestSlowStartHookHelper the child process of
// TestASlowStartingHookAnswersWithinItsBudgetFromTheProcessStart.
const slowStartHelperArg = "hookexec-slow-start-hook"

// GAP-0155, GAP-0167, GAP-0171: the deadline of a tool call runs late on a
// loaded host (managed Windows blocks came 1.1-1.75 s after a 4 s budget,
// 5.1-5.75 s in all). The answer budget and process cap leave margin inside
// the agent's 5 s limit.
func TestTheAnswerBudgetsLeaveMarginForALateDeadline(t *testing.T) {
	if margin := agentHookWait - hookAnswerBudget; margin < 1500*time.Millisecond {
		t.Fatalf("answer budget %s leaves %s of the agent's %s, want at least 1.5 s for a late deadline", hookAnswerBudget, margin, agentHookWait)
	}
	if margin := agentHookWait - hookProgressCeiling; margin < time.Second {
		t.Fatalf("progress ceiling %s leaves %s of the agent's %s, want at least 1 s", hookProgressCeiling, margin, agentHookWait)
	}
	if margin := agentHookWait - managedAnswerDeadlineCap; margin < time.Second {
		t.Fatalf("managed process cap %s leaves %s of the agent's %s, want at least 1 s", managedAnswerDeadlineCap, margin, agentHookWait)
	}
	if managedAnswerDeadlineCap < hookAnswerBudget || managedAnswerDeadlineCap > hookProgressCeiling {
		t.Fatalf("managed process cap %s must cover answer budget %s and meet progress ceiling %s", managedAnswerDeadlineCap, hookAnswerBudget, hookProgressCeiling)
	}
	if hookProgressCeiling < hookAnswerBudget {
		t.Fatalf("progress ceiling %s is shorter than the answer budget %s", hookProgressCeiling, hookAnswerBudget)
	}
}

// TestSlowStartHookHelper is a hook process that starts slowly: it sleeps
// (the launch and initialization on a loaded host) before it arms its answer
// watchdog from the time the system created it, and its gateway never
// answers.
func TestSlowStartHookHelper(t *testing.T) {
	args := flag.Args()
	if len(args) != 2 || args[0] != slowStartHelperArg {
		t.Skip("helper process of TestASlowStartingHookAnswersWithinItsBudgetFromTheProcessStart")
	}
	slowStart, err := time.ParseDuration(args[1])
	if err != nil {
		os.Exit(97)
	}
	time.Sleep(slowStart)
	watchdog := ArmAnswerWatchdog(Options{
		Connector:         "claudecode",
		ManagedEnterprise: true,
		StartedAt:         ProcessStartTime(),
		Stdout:            os.Stdout,
		Stderr:            os.Stderr,
		Exit:              os.Exit,
	}, []byte(preToolUsePayload))
	if watchdog == nil {
		os.Exit(98)
	}
	// The gateway never answers; the watchdog ends the process.
	time.Sleep(time.Minute)
	os.Exit(99)
}

// GAP-0155, GAP-0167, GAP-0171: a hook process whose launch and
// initialization take seconds still blocks the call within its budget
// counted from the moment the system created the process, not from the
// moment its code got to the call: the agent waits for the whole process.
// A hook that counted from its own code would block 2 s + 3.5 s after the
// launch, past the agent's 5 s.
func TestASlowStartingHookAnswersWithinItsBudgetFromTheProcessStart(t *testing.T) {
	const slowStart = 2 * time.Second
	var output bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestSlowStartHookHelper$", slowStartHelperArg, slowStart.String())
	cmd.Stdout, cmd.Stderr = &output, &output
	launched := time.Now()
	err := cmd.Run()
	took := time.Since(launched)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != blockExit {
		t.Fatalf("slow-start hook ended with %v, want the managed block (exit %d)\n%s", err, blockExit, output.String())
	}
	if !strings.Contains(output.String(), managedGatewayNoAnswerReason) {
		t.Fatalf("slow-start hook output %q, want the managed block naming %s", output.String(), managedGatewayNoAnswerReason)
	}
	if took < slowStart {
		t.Fatalf("the hook answered after %s, before its slow start of %s ended", took, slowStart)
	}
	if limit := managedAnswerDeadlineCap + 700*time.Millisecond; took > limit {
		t.Fatalf("the slow-start hook blocked %s after its launch, want by %s: the deadline must count from the process start", took, limit)
	}
}

// A hook that reaches the call only after its deadline (a start longer than
// the budget) blocks at once: the watchdog does not start a new budget.
func TestAHookArmedAfterItsDeadlineBlocksAtOnce(t *testing.T) {
	answer := &firstWriteRecorder{}
	exited := make(chan int, 1)
	armed := time.Now()
	watchdog := ArmAnswerWatchdog(Options{
		Connector:         "claudecode",
		ManagedEnterprise: true,
		StartedAt:         armed.Add(-managedAnswerDeadlineCap - 300*time.Millisecond),
		Stdout:            answer,
		Stderr:            answer,
		Exit:              func(code int) { exited <- code },
	}, []byte(preToolUsePayload))
	if watchdog == nil {
		t.Fatal("no watchdog for a managed PreToolUse call")
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("a hook past its deadline did not block")
	}
	out, first := answer.read()
	if late := first.Sub(armed); late > 300*time.Millisecond {
		t.Fatalf("the block came %s after the watchdog was armed past its deadline, want at once", late)
	}
	if !strings.Contains(out, managedGatewayNoAnswerReason) {
		t.Fatalf("output %q, want the managed block naming %s", out, managedGatewayNoAnswerReason)
	}
}
