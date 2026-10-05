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
	"os"
	"path/filepath"
	"strings"
	"testing"
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
