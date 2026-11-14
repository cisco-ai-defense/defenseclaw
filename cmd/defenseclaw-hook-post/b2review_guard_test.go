// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// S8 b2 review P2-1: on the guard leg every exit other than 0 and 2 is a
// block, as the 1.0.9 guard mapped hook-user's exit: Claude Code reads any
// other status as a non-blocking error, so the tool would run.
func TestB2ReviewGuardLegacyScriptExitIsABlock(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"exit 1", "#!/bin/sh\nexit 1\n"},
		{"exit 3", "#!/bin/sh\nexit 3\n"},
		{"killed", "#!/bin/sh\nkill -9 $$\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newGuardAccount(t)
			write(t, filepath.Join(a.home, "hooks", "claude-code-hook.sh"), tc.body, 0o700)
			// Another inherited data folder takes the legacy script branch.
			t.Setenv("DEFENSECLAW_HOME", filepath.Join(a.account, "other"))
			// A signal death is already a block in runLegacyScript; any
			// other status is turned into one by the guard.
			r := guardCall(a, a.args(""), guardPayload)
			if r.code != 2 || (tc.name != "killed" && !strings.Contains(r.errOut, "could not start")) {
				t.Fatalf("guard exit %d stderr %q, want the block (2)", r.code, r.errOut)
			}
		})
	}
}

// S8 b2 review M4: the guard finds the account's trusted gateway as hook-user
// does, so with the gateway down a call follows the account's outage tier
// (open here) and starts the gateway, exactly as the native hook.
func TestB2ReviewGuardUsesTheTrustedGateway(t *testing.T) {
	results := map[string]string{}
	for _, side := range []string{"guard", "native"} {
		a := newGuardAccount(t)
		gateway := filepath.Join(a.bin, "defenseclaw-gateway")
		write(t, gateway, "#!/bin/sh\ncase \"$1\" in\nhook-outage-mode) printf open;;\nstart) printf '%s' \"$1 $2\" > \"$DEFENSECLAW_HOME/started\";;\nesac\n", 0o700)
		write(t, filepath.Join(a.home, "hooks", ".gateway-helper"), gateway+"\n", 0o600)
		write(t, filepath.Join(a.home, "config.yaml"), "fixture\n", 0o600)
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close() // down
		r := downChild(t, a, addr, side)
		if strings.Contains(r, "permissionDecision") && strings.Contains(r, `\\\"deny\\\"`) {
			t.Fatalf("%s: denied with the open outage tier: %s", side, r)
		}
		started := ""
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if data, err := os.ReadFile(filepath.Join(a.home, "started")); err == nil {
				started = string(data)
				break
			}
		}
		if started != "start --hook-cold-start" {
			t.Fatalf("%s: the gateway was not started (cold start %q)", side, started)
		}
		results[side] = strings.ReplaceAll(r, a.account, "ACCOUNT")
	}
	if results["guard"] != results["native"] {
		t.Fatalf("guard and native hook differ:\n%s\n%s", results["guard"], results["native"])
	}
}
