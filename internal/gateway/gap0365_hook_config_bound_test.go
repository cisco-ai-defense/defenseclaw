// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP0365HookConfigWritePastTheGuardBound: a hook-config write in a call
// over 8,192 bytes (one large data word before or after it) is judged as the
// same call with a short data word: the write rule is named in every pack
// and the action is the short twin's. The guard placed commands only up to a
// private 8,192-byte bound, below the hook payload cap every hookpaths
// reader uses, so the large call named no finding (substrate-1:GAP-0365).
func TestGAP0365HookConfigWritePastTheGuardBound(t *testing.T) {
	home, _ := shellProtectedFileHome(t)
	for _, dir := range []string{".cache", ".claude"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	settings := "../.claude/settings.json"
	// The rkguest2 big-call shapes (evidence substrate-1/rkguest2), with the
	// data word as a parameter.
	shapes := []struct {
		id    string
		shape func(data string) string
	}{
		{"settings-first", func(data string) string { return "cd .cache && echo '{}' > " + settings + " && echo " + data }},
		{"settings-last", func(data string) string { return "cd .cache && echo " + data + " && echo '{}' > " + settings }},
		{"settings-tee", func(data string) string { return "cd .cache && echo " + data + " | tee " + settings }},
	}
	sizes := []int{8200, 9000, 64 << 10}
	for _, cell := range []string{"default", "permissive", "strict", "managed", "managed-strict"} {
		posture, managed := cell, false
		switch cell {
		case "managed":
			posture, managed = "default", true
		case "managed-strict":
			posture, managed = "strict", true
		}
		for _, shape := range shapes {
			shortAction, shortRules := shellProtectedFileRoute(t, home, home, "claudecode", posture, managed, shape.shape("x"))
			if !strings.Contains(strings.Join(shortRules, ","), agentHookConfigWriteRuleID) {
				t.Fatalf("%s %s short twin: %s %v, want %s", shape.id, cell, shortAction, shortRules, agentHookConfigWriteRuleID)
			}
			for _, size := range sizes {
				command := shape.shape(strings.Repeat("A", size))
				if len(command) <= 8192 {
					t.Fatalf("%s: %d bytes is not past the old bound", shape.id, len(command))
				}
				action, rules := shellProtectedFileRoute(t, home, home, "claudecode", posture, managed, command)
				if action != shortAction || !strings.Contains(strings.Join(rules, ","), agentHookConfigWriteRuleID) {
					t.Errorf("%s %s %d bytes: %s %v, want %s with %s (the short twin)",
						shape.id, cell, len(command), action, rules, shortAction, agentHookConfigWriteRuleID)
				}
			}
		}
	}
}
