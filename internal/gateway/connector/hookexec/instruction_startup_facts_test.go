// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A managed gateway may be unable to read the caller's home. The native
// SessionStart hook must send the identities the caller actually loaded.
func TestManagedCodexSessionStartSendsLoadedInstructionIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(project, "AGENTS.md")
	if err := os.WriteFile(file, []byte("loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{
		"hook_event_name": "SessionStart", "session_id": "loaded", "cwd": project,
	})
	if err != nil {
		t.Fatal(err)
	}
	header := make(http.Header)
	setHookRequestFacts(header, Options{Connector: "codex", Event: "SessionStart", ManagedEnterprise: true}, body)
	facts, ok := hookpaths.Decode(header.Get(hookpaths.Header))
	if !ok {
		t.Fatalf("managed Codex SessionStart omitted client identity evidence: %v", header)
	}
	var loaded map[string]string
	if err := json.Unmarshal([]byte(facts["\x00startup-instructions"]), &loaded); err != nil ||
		loaded[file] != hookpaths.FileIdentity(file) {
		t.Fatalf("managed Codex startup identities = %v, err = %v", loaded, err)
	}
}
