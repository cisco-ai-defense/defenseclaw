// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0677 (review 3): the words of a call past a reading bound are looked
// up as the user, and the answer rides in the evidence, also for a payload
// over MaxPayloadBytes (up to maxOversizePayloadBytes).
func TestBoundCallReachesProtectedLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX links")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "output")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, row := range []struct {
		command string
		want    bool
	}{
		{`echo x > output`, true},
		{`p=output; bash -c "echo x > \"$p\""`, true},
		{`echo x > "./output"`, true},
		{`echo x > plain.txt`, false},
		{`echo x > missing.txt`, false},
		{`echo "$unknown" > $other`, false},
	} {
		if got := BoundCallReachesProtectedLink(row.command, cwd, home); got != row.want {
			t.Errorf("BoundCallReachesProtectedLink(%q) = %v, want %v", row.command, got, row.want)
		}
	}
	// A run of distinct words past the cap is not shown to reach nothing.
	var many strings.Builder
	for i := 0; i < maxBoundLinkWords+10; i++ {
		many.WriteString("w" + strings.Repeat("x", i%7) + string(rune(0x4e00+i)) + " ")
	}
	if !BoundCallReachesProtectedLink(many.String(), cwd, home) {
		t.Error("a call with more words than the cap must not read as reaching nothing")
	}

	payload := func(command string, pad int) []byte {
		body, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash",
			"tool_input": map[string]string{"command": command + strings.Repeat(" #", pad)},
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, row := range []struct {
		name         string
		payload      []byte
		decision, cw bool
	}{
		{"over the payload bound, link", payload("echo x > output", MaxPayloadBytes), true, true},
		{"over the payload bound, ordinary", payload("echo x > plain.txt", MaxPayloadBytes), false, true},
		{"past the oversize bound", payload("echo x > output", maxOversizePayloadBytes), false, false},
	} {
		targets, ok := Decode(Resolve(row.payload))
		if !ok || targets[TruncatedKey] != "1" {
			t.Fatalf("%s: not incomplete evidence: %v", row.name, ok)
		}
		if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != row.decision {
			t.Errorf("%s: protected-target decision = %v, want %v", row.name, got, row.decision)
		}
		if got := targets[CWDKey] != ""; got != row.cw {
			t.Errorf("%s: directory sent = %v, want %v", row.name, got, row.cw)
		}
	}
}
