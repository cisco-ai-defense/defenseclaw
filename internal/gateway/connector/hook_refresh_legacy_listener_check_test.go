// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestRefreshGivesA104HardeningScriptTheListenerCheckOldHooksCall: going back
// from 1.0.4 to 1.0.2 or 1.0.3 leaves those hook scripts with the 1.0.4
// _hardening.sh (an older gateway never replaces a newer helper), which has
// no defenseclaw_api_listener_foreign. Upgrading from there, every hook call
// in the install window printed "defenseclaw_api_listener_foreign: command
// not found" (GAP-1532, macOS T4 R01). After the installer's fail-mode
// refresh the helper defines it again and answers as this release's does.
func TestRefreshGivesA104HardeningScriptTheListenerCheckOldHooksCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell hooks")
	}
	released104, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.4", "_hardening.sh"))
	if err != nil {
		t.Fatal(err)
	}
	oldHook, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.3", "copilot-hook.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(oldHook), legacyListenerCheckFunc+" ") {
		t.Fatal("fixture: the 1.0.3 hook does not call the listener check")
	}
	data := filepath.Join(t.TempDir(), "data")
	hookDir := filepath.Join(data, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hookDir, "_hardening.sh")
	if err := os.WriteFile(path, released104, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg.claudecode"), hookRuntimeFlatRecord("claudecode", "open", ""), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	// check runs the old hook's pre-send call the way it does (set -euo
	// pipefail, helper sourced from its folder) with this account's gateway
	// stopped (no gateway.pid) and the API port free.
	check := func(t *testing.T) string {
		t.Helper()
		cmd := exec.Command("bash", "-c", `set -euo pipefail; . "$1/_hardening.sh"
if `+legacyListenerCheckFunc+` "127.0.0.1:$2"; then echo foreign; else echo send; fi`, "hook", hookDir, strconv.Itoa(port))
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + filepath.Join(t.TempDir(), "home"), "DEFENSECLAW_HOME=" + data}
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	if got := check(t); !strings.Contains(got, "command not found") {
		t.Fatalf("fixture: the 1.0.4 helper already answers the old call: %q", got)
	}

	// The 1.0.4 helper alone (no older script in the folder) is left as it is.
	if kept, err := keepListenerCheckInLegacyHardening(hookDir); err != nil || kept {
		t.Fatalf("no old script: kept=%v err=%v, want untouched", kept, err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, "copilot-hook.sh"), oldHook, 0o700); err != nil {
		t.Fatal(err)
	}

	refresh, err := RefreshHookFailModes(hookDir, func(string) string { return "closed" })
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(refresh.Scripts, "_hardening.sh") {
		t.Fatalf("refresh scripts = %v, want _hardening.sh", refresh.Scripts)
	}
	if got := check(t); got != "send\n" {
		t.Fatalf("old hook call after the refresh = %q, want send (gateway stopped, port free) and no error", got)
	}

	// A second refresh appends nothing.
	before, _ := os.ReadFile(path)
	if _, err := RefreshHookFailModes(hookDir, func(string) string { return "closed" }); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a second refresh changed _hardening.sh again")
	}

	// Helpers that define the function (1.0.2, 1.0.3, this release) are left
	// as they are.
	current, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"current": current} {
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
		if kept, err := keepListenerCheckInLegacyHardening(hookDir); err != nil || kept {
			t.Fatalf("%s helper: kept=%v err=%v, want untouched", name, kept, err)
		}
	}
	for _, release := range []string{"1.0.2", "1.0.3"} {
		body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, "_hardening.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
		if kept, err := keepListenerCheckInLegacyHardening(hookDir); err != nil || kept {
			t.Fatalf("%s helper: kept=%v err=%v, want untouched", release, kept, err)
		}
	}
}
