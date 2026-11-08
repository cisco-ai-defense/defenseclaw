// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The shell hook replaces HOME with a scratch folder; the helper it runs for a
// per-user tool call is handed the account home the shell saved, so the
// helper's late-call scan finds the protected files of the account (GAP-0850).
func TestHostHookGivesTheHelperTheAccountHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	scratch := filepath.Join(dir, "scratch")
	binDir := filepath.Join(home, ".local", "bin")
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	for _, d := range []string{binDir, hookDir, scratch} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(dir, "native-env")
	binary := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s|%s\\n' \"${_DC_HOOK_POST_ACCOUNT_HOME:-none}\" \"$HOME\" > \"$DC_NATIVE_MARKER\"\nprintf '{\"action\":\"allow\"}\\n200'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	recordGatewayHelperForTest(t, hookDir, binary)
	script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; API_ADDR=127.0.0.1:18961
defenseclaw_api_listener_unproven() { return 1; }
curl() { echo leaked; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 4 '{"hook_event_name":"PreToolUse"}' -H 'Authorization: Bearer secret' >/dev/null && echo sent`
	cmd := exec.Command("bash", "-c", script, "bash", helper, hookDir)
	// HOME is the scratch folder, as it is once the shell hook has replaced it.
	cmd.Env = append(os.Environ(), "HOME="+scratch, "DEFENSECLAW_AGENT_HOME="+home, "DC_NATIVE_MARKER="+marker)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "sent" {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if want := home + "|" + scratch; strings.TrimSpace(string(got)) != want {
		t.Fatalf("helper saw account home and HOME %q, want %q", strings.TrimSpace(string(got)), want)
	}
}
