// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"strings"
	"testing"
	"time"
)

// GAP-0326: after a 100 s gateway outage an unattended --task run reported
// task_end exit 0 although its step 2 never ran: the hooks failed closed in
// the outage, and the agent still exited 0. The relay now gives each run a
// fault file (DEFENSECLAW_TASK_FAULTS) in which the hooks record each call
// the gateway did not answer, and a run with faults is not a success.

func faultRun(t *testing.T, code string, extraEnv map[string]string) (TaskEnd, *eventLog) {
	t.Helper()
	cfg := stallConfig("fault")
	cfg.Relay.Env = map[string]string{"CODE": code}
	for k, v := range extraEnv {
		cfg.Relay.Env[k] = v
	}
	var log eventLog
	end := runWithin(t, 30*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), cfg, TaskRequest{Prompt: "x"},
			HeadlessOptions{Stall: time.Hour, Tick: time.Hour, Usage: flat}, log.emit)
	})
	return end, &log
}

func TestGAP0326AgentExitZeroAfterAnOutageIsNotASuccess(t *testing.T) {
	end, log := faultRun(t, "0", nil)
	if end.ExitCode != 75 || end.Stalled {
		t.Fatalf("an agent that exited 0 after an unanswered hook call: end %+v, want exit 75 (interrupted), not a success", end)
	}
	for _, want := range []string{"did not answer 1 hook call", "PostToolUse at 2026-11-15T06:32:10Z", "may not have run", "exit code 75"} {
		if !strings.Contains(end.Cause, want) {
			t.Fatalf("cause %q does not say %q", end.Cause, want)
		}
	}
	if got := log.text("error"); !strings.Contains(got, "defenseclaw: "+end.Cause) {
		t.Fatalf("logs do not show the cause; error events: %q", got)
	}
	// The template's environment cannot redirect the file away from the relay.
	end, _ = faultRun(t, "0", map[string]string{"DEFENSECLAW_TASK_FAULTS": "/dev/null"})
	if end.ExitCode != 75 {
		t.Fatalf("a template DEFENSECLAW_TASK_FAULTS hid the outage: end %+v", end)
	}
}

func TestGAP0326AgentFailureAfterAnOutageKeepsItsCode(t *testing.T) {
	end, _ := faultRun(t, "3", nil)
	if end.ExitCode != 3 || !strings.Contains(end.Cause, "did not answer 1 hook call") || strings.Contains(end.Cause, "exit code 75") {
		t.Fatalf("an agent that failed after an outage: end %+v, want its own exit 3 and the outage cause", end)
	}
}

func TestGAP0326TaskWithoutFaultsIsUnchanged(t *testing.T) {
	cfg := stallConfig("faults-env")
	var log eventLog
	end := runWithin(t, 30*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), cfg, TaskRequest{Prompt: "x"},
			HeadlessOptions{Stall: time.Hour, Tick: time.Hour, Usage: flat}, log.emit)
	})
	if end.ExitCode != 0 || end.Cause != "" {
		t.Fatalf("a clean run: end %+v, want exit 0 and no cause", end)
	}
	if !strings.Contains(log.text("stdout"), "faults=set") {
		t.Fatalf("the agent did not get DEFENSECLAW_TASK_FAULTS: %q", log.text("stdout"))
	}
}
