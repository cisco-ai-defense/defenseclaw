// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkGAP0362BenignHookResolve measures the client evidence pass for a
// copy into an ordinary file after a leading cd and assignment.
func BenchmarkGAP0362BenignHookResolve(b *testing.B) {
	home := filepath.Join(b.TempDir(), "home")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("marker\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	b.Setenv("HOME", home)
	b.Chdir(project)
	payload, err := json.Marshal(map[string]any{
		"session_id": "benchmark-session", "hook_event_name": "PreToolUse", "tool_name": "Bash",
		"cwd": project, "tool_input": map[string]any{"command": `cd ~/proj && f=out.txt; cp a.txt $f`},
	})
	if err != nil {
		b.Fatal(err)
	}
	if _, ok := Decode(Resolve(payload)); !ok {
		b.Fatal("client evidence did not decode")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		Resolve(payload)
	}
}
