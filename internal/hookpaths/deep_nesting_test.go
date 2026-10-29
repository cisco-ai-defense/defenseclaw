// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The hook client read a tool call with ~/ through the active-user tilde
// twin, whose parser recursed per level of ( before any nesting bound: cat
// ~/a.txt and 180 KiB of ( overflowed the 1 GB goroutine stack, a fatal
// error in the hook process (GAP-2556, the GAP-2537 class). Such a body is
// described as incomplete evidence at once, a body that hides its ( behind
// JSON escapes is still refused by every parser, and ordinary nesting keeps
// its targets. The stack bound makes the old recursion fail on every OS.
func TestResolveConnectorBoundsDeepNesting(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	home := t.TempDir()
	for _, unit := range []string{"(", "$(", "$((", "{ ", "\"$(", "["} {
		command := "cat ~/a.txt\n" + strings.Repeat(unit, (180<<10)/len(unit)) + "\ncat ~/.defenseclaw/config.yaml"
		payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": home,
			"tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		for _, connector := range []string{"claudecode", "codex"} {
			start := time.Now()
			targets, ok := Decode(ResolveConnector(connector, "", "PreToolUse", payload))
			if took := time.Since(start); took > 3*time.Second {
				t.Errorf("%s unit %q: resolved in %s", connector, unit, took)
			}
			if !ok || targets[TruncatedKey] != "1" {
				t.Errorf("%s unit %q: targets %v, want incomplete evidence", connector, unit, targets)
			}
		}
		escaped := strings.ReplaceAll(string(payload), "(", `\u0028`)
		escaped = strings.ReplaceAll(escaped, "{ ", `\u007b `)
		escaped = strings.ReplaceAll(escaped, "[", `\u005b`)
		if len(escaped) <= MaxPayloadBytes {
			_ = ResolveConnector("claudecode", "", "PreToolUse", []byte(escaped))
		}
		if _, _, ok := actionfacts.ActiveUserTildeTwin(command, home, "alice"); ok {
			t.Errorf("unit %q: tilde twin of a deep command", unit)
		}
	}
	nested := strings.Repeat("( ", 8) + "cat ~/a.txt > out.txt" + strings.Repeat(" )", 8)
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": home,
		"tool_input": map[string]any{"command": nested}})
	if err != nil {
		t.Fatal(err)
	}
	if targets, _ := Decode(ResolveConnector("claudecode", "", "PreToolUse", payload)); targets[TruncatedKey] == "1" {
		t.Errorf("8-level subshell: incomplete evidence %v", targets)
	}
}
