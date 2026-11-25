// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// TestGUESTFU10KitBoundsCommandWordWalks: hookpaths.CommandPathWords returns
// every word of a command on rel follow-up 10 (rel-1-0-10:GAP-1243), where it
// returned at most 64 when the kit's link proofs came in (substrate-1
// GAP-0546). The kit walks at most maxCommandWordWalks distinct words of one
// call and marks the facts truncated past them; a link among the first words
// is still placed. No call here reads a key, so a word that follows no
// link gets no fact (commandWordFact) and the bound, not maxPathFacts, cuts.
func TestGUESTFU10KitBoundsCommandWordWalks(t *testing.T) {
	_, app := gap0545Home(t)
	readme := filepath.Join(app, "README.md")
	var plain []string
	for index := 0; index < 70; index++ { // past the 64-word bound (maxCommandWordWalks)
		plain = append(plain, fmt.Sprintf("f%d", index))
	}
	for _, row := range []struct {
		command string
		placed  bool
	}{
		{"cat readme-link " + strings.Join(plain, " "), true},
		{"cat " + strings.Join(plain, " ") + " readme-link", false},
	} {
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": app, "tool_name": "Bash",
			"tool_input": map[string]any{"command": row.command}})
		f := CollectFacts("claudecode", "PreToolUse", payload, 1<<20)
		if f == nil || !f.Truncated {
			t.Fatalf("%.40s...: facts %+v, want truncated", row.command, f)
		}
		if got := gap0545HasWord(f, "readme-link", readme); got != row.placed {
			t.Fatalf("%.40s...: readme-link placed %v, want %v (facts %+v)", row.command, got, row.placed, f.Paths)
		}
	}
}
