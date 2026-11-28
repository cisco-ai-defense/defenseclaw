// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// R11 probes on head 91a569f939 (relay watchdog, real /proc usage).

package relay

import (
	"context"
	"testing"
	"time"
)

func r11Run(t *testing.T, script string, o HeadlessOptions, limit time.Duration) (TaskEnd, time.Duration) {
	t.Helper()
	var log eventLog
	start := time.Now()
	end := runWithin(t, limit, func() TaskEnd {
		return RunHeadless(context.Background(), shConfig(script), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	return end, time.Since(start)
}

// The same probes as on base: they end now.
func TestR11HeadSilentAgentEnds(t *testing.T) {
	end, took := r11Run(t, `echo started; exec sleep 30`, HeadlessOptions{Stall: 2 * time.Second, Tick: 200 * time.Millisecond}, 20*time.Second)
	t.Logf("R11 head silent: %+v after %s", end, took)
	if end.ExitCode != ExitStalled || !end.Stalled {
		t.Fatalf("silent agent: %+v", end)
	}
}

func TestR11HeadChildHoldsStdoutEnds(t *testing.T) {
	end, took := r11Run(t, `sleep 30 & echo $! > `+stopAfter(t)+`; echo hi; exit 0`, HeadlessOptions{Stall: time.Minute}, 15*time.Second)
	t.Logf("R11 head held stdout: %+v after %s", end, took)
	if end.ExitCode != 0 || end.Stalled {
		t.Fatalf("held stdout: %+v", end)
	}
}

// A CPU-busy, silent child in the agent's own process group is progress.
func TestR11BusyChildSameGroupIsProgress(t *testing.T) {
	script := `sh -c 'end=$(($(date +%s)+10)); while [ $(date +%s) -lt $end ]; do :; done'; echo done`
	end, took := r11Run(t, script, HeadlessOptions{Stall: 3 * time.Second, Tick: 500 * time.Millisecond}, 30*time.Second)
	t.Logf("R11 busy child, same group: %+v after %s", end, took)
	if end.Stalled {
		t.Errorf("a CPU-busy child in the agent's group was taken for a stall: %+v", end)
	}
}

// The same busy child in a session of its own (Claude Code 2.1.322 spawns its
// Bash tool shell with detached:true, which is setsid): is it progress?
func TestR11BusyChildOwnSessionIsProgress(t *testing.T) {
	script := `setsid sh -c 'end=$(($(date +%s)+10)); while [ $(date +%s) -lt $end ]; do :; done'; echo done`
	end, took := r11Run(t, script, HeadlessOptions{Stall: 3 * time.Second, Tick: 500 * time.Millisecond}, 30*time.Second)
	t.Logf("R11 busy child, own session: %+v after %s", end, took)
	if end.Stalled {
		t.Errorf("R11 FINDING: a CPU-busy child in its own session (setsid) is not counted: the task was ended as stalled: %+v", end)
	}
}
