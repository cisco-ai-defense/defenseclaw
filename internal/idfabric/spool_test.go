// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSpoolFileNameRejectsPathTraversal(t *testing.T) {
	at := time.Date(2026, 9, 2, 15, 12, 33, 412_000_000, time.UTC)
	tests := []struct {
		name      string
		source    Source
		wantParts []string
	}{
		{
			name: "connector and event are traversal sequences",
			source: Source{
				Model:     SchemaModelAgentEvent,
				Connector: "../../etc",
				Event:     "../../../root/.ssh/authorized_keys",
			},
			wantParts: []string{"agentevent", "etc"},
		},
		{
			name: "event carries separators and a null byte",
			source: Source{
				Model:     SchemaModelAgentEvent,
				Connector: "codex",
				Event:     "pre\\tool\x00use/../x",
			},
			wantParts: []string{"agentevent", "codex"},
		},
		{
			name: "normal event is preserved",
			source: Source{
				Model:     SchemaModelAgentEvent,
				Connector: "claudecode",
				Event:     "session_start",
			},
			wantParts: []string{"agentevent", "claudecode", "session_start"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := spoolFileName(tc.source, at)
			if err != nil {
				t.Fatalf("spoolFileName: %v", err)
			}
			if strings.ContainsAny(got, `/\`) {
				t.Fatalf("filename contains a path separator: %q", got)
			}
			if strings.Contains(got, "..") {
				t.Fatalf("filename contains a traversal sequence: %q", got)
			}
			if strings.ContainsRune(got, 0) {
				t.Fatalf("filename contains a null byte: %q", got)
			}
			if filepath.Base(got) != got {
				t.Fatalf("filename is not a bare base name: %q", got)
			}
			if !strings.HasSuffix(got, ".json") {
				t.Fatalf("filename lost its extension: %q", got)
			}
			if !strings.Contains(got, "20260902T151233.412Z") {
				t.Fatalf("filename lost its timestamp: %q", got)
			}
			for _, part := range tc.wantParts {
				if !strings.Contains(got, part) {
					t.Errorf("filename %q missing %q", got, part)
				}
			}
		})
	}
}

// TestSpoolDirIsPerUserNotTheDefenseClawHome pins the fix for capture failing
// in managed enterprise mode. The managed home is an Administrators-owned
// machine root with no ACE for Users, so a spool resolved from it is
// uncreatable by the hook's own user. Resolution must depend only on per-user
// state, never on a caller-supplied home.
func TestSpoolDirIsPerUserNotTheDefenseClawHome(t *testing.T) {
	t.Setenv(SpoolDirEnv, "")
	userHome := t.TempDir()
	setHome(t, userHome)
	if runtime.GOOS == "windows" {
		t.Setenv("LOCALAPPDATA", filepath.Join(userHome, "AppData", "Local"))
	}
	t.Setenv("XDG_STATE_HOME", "")

	dir, err := SpoolDir()
	if err != nil {
		t.Fatalf("SpoolDir: %v", err)
	}
	if !strings.HasPrefix(dir, userHome) {
		t.Errorf("SpoolDir = %q, want a path under the user home %q", dir, userHome)
	}
	if filepath.Base(dir) != SpoolDirName {
		t.Errorf("SpoolDir leaf = %q, want %q", filepath.Base(dir), SpoolDirName)
	}
	// ~/.defenseclaw is the unmanaged home, and the Unix hook scripts branch
	// on its existence. The spool must not create it.
	if strings.Contains(dir, ".defenseclaw") {
		t.Errorf("SpoolDir = %q, must not live under the unmanaged home", dir)
	}

	spool, err := NewSpool()
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	if spool.Dir() != dir {
		t.Errorf("NewSpool dir = %q, want %q", spool.Dir(), dir)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("spool directory was not created: %v", err)
	}
}

func TestSpoolWriteIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(SpoolDirEnv, filepath.Join(dir, "spool"))

	spool, err := NewSpool()
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	record := AgentEvent{
		Metadata: NewMetadata(SchemaModelAgentEvent, "v0.0.0-test", time.Now().UTC()),
	}
	path, err := spool.Write(
		Source{Model: SchemaModelAgentEvent, Connector: "codex", Event: "session_start"},
		time.Now().UTC(),
		record,
	)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if filepath.Dir(path) != spool.Dir() {
		t.Fatalf("record escaped the spool directory: %q", path)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// Windows does not model POSIX permission bits; the DACL applied by
	// safefile is asserted by that package's own tests.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %v, want 0600", info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
	if decoded["schema_model"] != string(SchemaModelAgentEvent) {
		t.Errorf("schema_model = %v, want %v", decoded["schema_model"], SchemaModelAgentEvent)
	}
}
