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

// The gateway writes .openclaw/openclaw.json (0644) and its hook scripts
// (0700) into its own data folder as it runs. A fresh package install failed
// its own verify on them and the daily verify service ended failed
// (GAP-0223). Those modes are accepted as written; anything looser is still
// reported, and repair does not strip the scripts' execute bit.
func TestVerifyAcceptsTheModesTheGatewayWritesInItsDataFolder(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	account := h.accounts.accounts[h.env.Layout.ServiceUser]
	service := [2]int{account.UID, account.GID}
	l := h.env
	write := func(rel string, mode os.FileMode) string {
		canonical := filepath.Join(l.Layout.DataDir, rel)
		path := l.P(canonical)
		for dir := filepath.Dir(path); dir != l.P(l.Layout.DataDir); dir = filepath.Dir(dir) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			h.owners[dir] = service
		}
		if err := os.WriteFile(path, []byte("x\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		h.owners[path] = service
		return canonical
	}
	openclaw := write(".openclaw/openclaw.json", 0o644)
	script := write("hooks/inspect-request.sh", 0o700)
	token := write("hooks/.hook-claudecode.token", 0o600)
	if problems := h.env.stateModeProblems(account); len(problems) != 0 {
		t.Fatalf("modes the gateway writes are reported: %v", problems)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if mode := h.mode(script); mode != 0o700 {
		t.Fatalf("repair left the hook script at %04o", mode)
	}
	if mode := h.mode(openclaw); mode != 0o644 {
		t.Fatalf("repair left openclaw.json at %04o", mode)
	}

	for canonical, mode := range map[string]os.FileMode{openclaw: 0o666, script: 0o755, token: 0o644} {
		if err := os.Chmod(h.env.P(canonical), mode); err != nil {
			t.Fatal(err)
		}
	}
	if problems := h.env.stateModeProblems(account); len(problems) != 1 || !strings.Contains(problems[0], "3 entries") {
		t.Fatalf("looser modes are not all reported: %v", problems)
	}
}
