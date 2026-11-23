// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The actor kit runs in Linux actor images only; its tests resolve paths for Linux.
//go:build linux

package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0479: at SessionStart the kit reports a Claude Code project settings
// file that declares hooks (which the actor's managed settings ignore), so
// the gateway can record the attempt. Only the path, the digest, the event
// names and the hook count travel: never the hook command or an env value.
// At the base CollectFacts reported nothing for such a file.
func TestCollectFactsReportsIgnoredProjectHooksGAP0479(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"touch /tmp/sub-J19-foreign-ran"}]}],` +
		`"PostToolUse":[{"hooks":[{"type":"command","command":"touch /tmp/ran2"},{"type":"command","command":"true"}]}],"Stop":[]}}`)
	if err := os.WriteFile(filepath.Join(repo, ".claude", "settings.json"), settings, 0o644); err != nil {
		t.Fatal(err)
	}
	// A local file with no hooks (only env) is not reported.
	if err := os.WriteFile(filepath.Join(repo, ".claude", "settings.local.json"), []byte(`{"env":{"VENDOR_TOKEN":"s3cr3t-value"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "SessionStart", "cwd": repo})
	f := CollectFacts("claudecode", "SessionStart", payload, 1<<20)
	if f == nil || len(f.ProjectHooks) != 1 {
		t.Fatalf("facts %+v: want one project_hooks entry", f)
	}
	ph := f.ProjectHooks[0]
	sum := sha256.Sum256(settings)
	if ph.Path != filepath.Join(repo, ".claude", "settings.json") || ph.SHA256 != hex.EncodeToString(sum[:]) || ph.Hooks != 3 ||
		strings.Join(ph.Events, ",") != "PostToolUse,PreToolUse" {
		t.Fatalf("project hooks %+v", ph)
	}
	wire, _ := json.Marshal(f)
	for _, leak := range []string{"touch /tmp", "s3cr3t-value", "VENDOR_TOKEN"} {
		if strings.Contains(string(wire), leak) {
			t.Fatalf("the facts carry %q: %s", leak, wire)
		}
	}

	// Only at SessionStart, and only for a connector whose project hooks
	// the managed settings ignore.
	pre, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}})
	if f := CollectFacts("claudecode", "PreToolUse", pre, 1<<20); f != nil && len(f.ProjectHooks) != 0 {
		t.Fatalf("PreToolUse reported project hooks: %+v", f.ProjectHooks)
	}
	if f := CollectFacts("codex", "SessionStart", payload, 1<<20); f != nil && len(f.ProjectHooks) != 0 {
		t.Fatalf("codex reported Claude project hooks: %+v", f.ProjectHooks)
	}
	// A file that is not JSON declares nothing the agent loads.
	if err := os.WriteFile(filepath.Join(repo, ".claude", "settings.json"), []byte(`{"hooks":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if f := CollectFacts("claudecode", "SessionStart", payload, 1<<20); f != nil && len(f.ProjectHooks) != 0 {
		t.Fatalf("an unparseable settings file was reported: %+v", f.ProjectHooks)
	}
}
