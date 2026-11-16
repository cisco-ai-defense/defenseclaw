// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// The hook client must inspect all operands past ActionFacts' argv bound.
func BenchmarkCertfixGAP0483ResolveTouch2000(b *testing.B) {
	home := b.TempDir()
	b.Setenv("HOME", home)
	project := filepath.Join(home, "project")
	words := make([]string, 2001)
	words[0] = "touch"
	for i := 1; i < len(words); i++ {
		words[i] = fmt.Sprintf("lo%d.txt", i)
	}
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": project,
		"tool_input": map[string]string{"command": strings.Join(words, " ")},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if got := Resolve(payload); got == "" {
			b.Fatal("no client evidence")
		}
	}
}
