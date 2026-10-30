// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-1474: a per-user gateway started before the deployment keeps running
// beside the managed one; status names it, and not the managed gateway.
func TestStatusWarnsAboutARunningPerUserGateway(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	proc := h.env.P("/proc")
	for pid, exe := range map[string]string{
		"4100": "/home/alice/.local/bin/defenseclaw-gateway",
		"4101": filepath.Join(h.env.Layout.BinDir, "defenseclaw-gateway"),
		"4102": "/usr/bin/bash",
	} {
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(exe, filepath.Join(proc, pid, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	got := h.run(Options{Action: ActionStatus})
	requireOK(t, got)
	message := messagesOf(got.Warnings, codePerUserGatewayRunning)
	if !strings.Contains(message, "(pid 4100)") || !strings.Contains(message, "kill 4100") ||
		strings.Contains(message, "4101") || strings.Contains(message, "4102") {
		t.Fatalf("status must name only the per-user gateway: %+v", got.Warnings)
	}
	if err := os.RemoveAll(filepath.Join(proc, "4100")); err != nil {
		t.Fatal(err)
	}
	if got := h.run(Options{Action: ActionVerify}); hasWarning(got, codePerUserGatewayRunning) {
		t.Fatalf("the warning stays after the per-user gateway stopped: %+v", got.Warnings)
	}
}

// GAP-2245: macOS ps prints argv[0], so the managed binary run by its bare
// name (a repair in progress) must be matched by its executable path, not
// reported as a per-user gateway.
func TestStatusMatchesMacOSGatewaysByExecutablePath(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	managedGateway := filepath.Join(h.env.Layout.BinDir, "defenseclaw-gateway")
	// The LaunchAgents run the sandbox daemon from the package's copy of the
	// managed gateway (GAP-0007).
	launchAgent := filepath.Join(h.env.Layout.BinDir, "launch-agents", strings.Repeat("ab", 32), "defenseclaw-gateway")
	// status skips its own process: keep the listed pids clear of the pid of
	// the test binary (a macOS runner once ran it as pid 4203).
	base := 4200
	if own := os.Getpid(); own >= base && own <= base+6 {
		base = own + 10
	}
	pid := func(n int) string { return fmt.Sprint(base + n) }
	h.runner.ps = strings.Join([]string{
		pid(0) + " 0 defenseclaw-gateway",                           // the managed binary, run by bare name
		pid(1) + " 499 " + managedGateway,                           // the managed gateway
		pid(2) + " 501 /Users/alice/.local/bin/defenseclaw-gateway", // a per-user gateway
		pid(3) + " 502 defenseclaw-gateway",                         // a per-user gateway run by bare name
		pid(4) + " 503 defenseclaw-gateway",                         // exited before its path was read
		pid(5) + " 0 /bin/zsh",
		pid(6) + " 504 " + launchAgent, // an account's managed sandbox daemon
	}, "\n")
	execs := map[int]string{
		base:     managedGateway,
		base + 1: managedGateway,
		base + 2: "/Users/alice/.local/bin/defenseclaw-gateway",
		base + 3: "/Users/bob/.local/bin/defenseclaw-gateway",
		base + 6: launchAgent,
	}
	h.env.ProcessExecPath = func(pid int) (string, error) {
		if exe, ok := execs[pid]; ok {
			return exe, nil
		}
		return "", os.ErrNotExist
	}
	got := h.run(Options{Action: ActionStatus})
	requireOK(t, got)
	message := messagesOf(got.Warnings, codePerUserGatewayRunning)
	for _, want := range []string{"(pid " + pid(2) + ")", "(pid " + pid(3) + ")"} {
		if !strings.Contains(message, want) {
			t.Fatalf("status must name the per-user gateway %s: %+v", want, got.Warnings)
		}
	}
	for _, other := range []string{pid(0), pid(1), pid(4), pid(5), pid(6)} {
		if strings.Contains(message, other) {
			t.Fatalf("status names pid %s, which is not a per-user gateway: %+v", other, got.Warnings)
		}
	}
}

// A Claude Code session left open through uninstall --keep-state and a
// reinstall ran without hooks while status, verify and the ensure result
// reported a healthy deployment: an agent reads its hooks when it starts
// (GAP-0411). Sessions older than the activation are named.
func TestStatusNamesAgentSessionsOlderThanTheActivation(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	record, err := h.env.loadDeployment()
	if err != nil || record == nil {
		t.Fatalf("no deployment: %v", err)
	}
	// Status compares sessions with activation, which can follow installation
	// by several seconds on a busy host.
	activated, err := time.Parse(time.RFC3339Nano, record.ActivatedAt)
	if err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", activated.Add(-time.Hour).Unix()))
	agent := func(pid, cmdline string, ticks int64) {
		writeHostFile(t, h, "/proc/"+pid+"/cmdline", cmdline)
		writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (claude) S 1 %s %s%d 0 0", pid, pid, strings.Repeat("0 ", 16), ticks))
	}
	agent("4321", "claude\x00--resume\x00", 100)          // started an hour before the activation
	agent("4322", "claude\x00--resume\x00", 3600*100+600) // started after it
	// Hermes runs its bootstrap with `python3 -I -c`. A Codex session that
	// started before the activation loads no hook later, even when its
	// app-server daemon started after the install (private #12): it is
	// named, the newer daemon is not.
	agent("4323", "/home/u/.hermes/tools/python/bin/python3\x00-I\x00-c\x00import os\nfrom hermes_cli.main import main\x00", 100)
	agent("4324", "/home/u/.codex/packages/app-server-daemon/releases/0.161.0/codex\x00app-server\x00--listen\x00unix://\x00", 3600*100+600)
	agent("4325", "codex\x00", 100)
	result := h.run(Options{Action: ActionStatus})
	got := messagesOf(result.Warnings, codeAgentSessionsRestart)
	if !strings.Contains(got, "claude (pid 4321)") || !strings.Contains(got, "hermes (pid 4323)") || !strings.Contains(got, "codex (pid 4325)") ||
		strings.Contains(got, "(pid 4322)") || strings.Contains(got, "(pid 4324)") {
		t.Fatalf("status does not name exactly the older sessions: %q", got)
	}
	if p := result.EnforcementPending; p == nil || p.Count != 3 || strings.Join(p.Connectors, ",") != "claudecode,codex,hermes" {
		t.Fatalf("enforcement_pending = %+v, want 3 sessions of claudecode, codex and hermes", p)
	}
	// A Codex background server started before the install keeps the
	// requirements it read then: its sessions ran with no decision, and a
	// new session refuses it until it restarts (GAP-0988, GAP-0983).
	agent("4324", "/home/u/.codex/packages/app-server-daemon/releases/0.161.0/codex\x00app-server\x00--listen\x00unix://\x00", 100)
	got = messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart)
	if !strings.Contains(got, "the Codex background server (pid 4324)") || !strings.Contains(got, "codex (pid 4325)") ||
		!strings.Contains(got, "codex app-server daemon restart") {
		t.Fatalf("status does not name the old Codex background server, its session and the restart: %q", got)
	}
}

// GAP-1077: Claude Code sessions that were open while an administrator
// edited the DefenseClaw drop-in kept the broken hook command after ensure
// put it back, and ran calls with no decision while status named nothing.
// Those sessions are named until they restart; newer ones are not.
func TestStatusNamesClaudeSessionsOpenWhileTheDropInWasChanged(t *testing.T) {
	h := newTestHost(t, "linux")
	offset := time.Duration(0)
	h.env.Now = func() time.Time { return time.Now().Add(offset) }
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	record, err := h.env.loadDeployment()
	if err != nil || record == nil {
		t.Fatalf("no deployment: %v", err)
	}
	activated, err := time.Parse(time.RFC3339Nano, record.ActivatedAt)
	if err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", activated.Unix()))
	claude := func(pid string, ticks int64) {
		writeHostFile(t, h, "/proc/"+pid+"/cmdline", "claude\x00")
		writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (claude) S 1 %s %s%d 0 0", pid, pid, strings.Repeat("0 ", 16), ticks))
	}
	claude("5001", 60*100) // a minute after the activation
	if got := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart); got != "" {
		t.Fatalf("a session started after the activation is named: %q", got)
	}
	offset = 10 * time.Minute
	writeHostFile(t, h, claudeDropIn, strings.ReplaceAll(h.read(claudeDropIn), "/bin/defenseclaw-hook", "/binx/defenseclaw-hook"))
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	claude("5002", (11*60)*100) // started after DefenseClaw put the drop-in back
	got := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart)
	if !strings.Contains(got, "claude (pid 5001)") || !strings.Contains(got, "drop-in was changed or removed") || strings.Contains(got, "5002") {
		t.Fatalf("status does not name exactly the session open through the drop-in change: %q", got)
	}
}

// startClockServices runs onStart before each service start.
type startClockServices struct {
	ServiceManager
	onStart func()
}

func (s startClockServices) Start(ctx context.Context, unit Unit) error {
	s.onStart()
	return s.ServiceManager.Start(ctx, unit)
}

// GAP-1367: a first install fell back to InstalledAt, which the run takes
// when it plans, so an agent session started while it published the hooks
// and started the services (it read no DefenseClaw hooks) was not named.
// The activation time is taken once the services started.
func TestStatusNamesAgentSessionsStartedDuringTheFirstInstall(t *testing.T) {
	h := newTestHost(t, "linux")
	offset := time.Duration(0)
	h.env.Now = func() time.Time { return time.Now().Add(offset) }
	// The services start two minutes after the run planned.
	h.env.Services = startClockServices{ServiceManager: h.services, onStart: func() { offset = 2 * time.Minute }}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	record, err := h.env.loadDeployment()
	if err != nil || record == nil {
		t.Fatalf("no deployment: %v", err)
	}
	planned, err := time.Parse(time.RFC3339, record.InstalledAt)
	if err != nil {
		t.Fatal(err)
	}
	if activated, err := time.Parse(time.RFC3339Nano, record.ActivatedAt); err != nil || activated.Sub(planned) < 2*time.Minute {
		t.Fatalf("installed_at %q activated_at %q, want the activation time after the services started", record.InstalledAt, record.ActivatedAt)
	}
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", planned.Unix()))
	agent := func(pid string, ticks int64) {
		writeHostFile(t, h, "/proc/"+pid+"/cmdline", "claude\x00")
		writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (claude) S 1 %s %s%d 0 0", pid, pid, strings.Repeat("0 ", 16), ticks))
	}
	agent("4331", 60*100)  // a minute after the plan, before the services started
	agent("4332", 180*100) // after the activation
	got := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart)
	if !strings.Contains(got, "claude (pid 4331)") || strings.Contains(got, "4332") {
		t.Fatalf("status does not name exactly the session started during the install: %q", got)
	}
}

// A staged install has no active hooks. Sessions started during staging
// still need a restart after the first ensure activates the deployment.
func TestStatusNamesAgentSessionsStartedDuringNoStartStaging(t *testing.T) {
	h := newTestHost(t, "darwin")
	offset := time.Duration(0)
	h.env.Now = func() time.Time { return time.Now().Add(offset) }
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), NoStart: true}))
	offset = 10 * time.Minute
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	h.runner.ps = "4321 501 00:05:00 claude --resume"
	got := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart)
	if !strings.Contains(got, "claude (pid 4321)") {
		t.Fatalf("status omitted session started during staging: %q", got)
	}
}
