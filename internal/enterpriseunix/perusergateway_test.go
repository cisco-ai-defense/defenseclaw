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
	h.runner.ps = strings.Join([]string{
		"4200 0 defenseclaw-gateway",                           // the managed binary, run by bare name
		"4201 499 " + managedGateway,                           // the managed gateway
		"4202 501 /Users/alice/.local/bin/defenseclaw-gateway", // a per-user gateway
		"4203 502 defenseclaw-gateway",                         // a per-user gateway run by bare name
		"4204 503 defenseclaw-gateway",                         // exited before its path was read
		"4205 0 /bin/zsh",
	}, "\n")
	execs := map[int]string{
		4200: managedGateway,
		4201: managedGateway,
		4202: "/Users/alice/.local/bin/defenseclaw-gateway",
		4203: "/Users/bob/.local/bin/defenseclaw-gateway",
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
	for _, want := range []string{"(pid 4202)", "(pid 4203)"} {
		if !strings.Contains(message, want) {
			t.Fatalf("status must name the per-user gateway %s: %+v", want, got.Warnings)
		}
	}
	for _, pid := range []string{"4200", "4201", "4204", "4205"} {
		if strings.Contains(message, pid) {
			t.Fatalf("status names pid %s, which is not a per-user gateway: %+v", pid, got.Warnings)
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
	activated, err := time.Parse(time.RFC3339, record.InstalledAt)
	if err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", activated.Add(-time.Hour).Unix()))
	agent := func(pid string, ticks int64) {
		writeHostFile(t, h, "/proc/"+pid+"/cmdline", "claude\x00--resume\x00")
		writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (claude) S 1 %s %s%d 0 0", pid, pid, strings.Repeat("0 ", 16), ticks))
	}
	agent("4321", 100)          // started an hour before the activation
	agent("4322", 3600*100+600) // started after it
	got := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart)
	if !strings.Contains(got, "claude (pid 4321)") || strings.Contains(got, "4322") {
		t.Fatalf("status does not name exactly the older agent session: %q", got)
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
