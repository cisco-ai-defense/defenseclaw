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
