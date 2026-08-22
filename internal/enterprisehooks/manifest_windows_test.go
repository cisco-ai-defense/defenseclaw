//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadManifestWindowsRejectsNameOnlyTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user: alice
    connector: codex
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "requires explicit user_home") {
		t.Fatalf("LoadManifest error = %v, want name-only Windows target rejection", err)
	}
}

func TestLoadManifestWindowsRejectsMissingOrServiceSID(t *testing.T) {
	tests := []struct {
		name string
		sid  string
		want string
	}{
		{name: "missing", want: "requires explicit sid"},
		{name: "local_system", sid: "S-1-5-18", want: "not an interactive user"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "targets.yaml")
			body := "version: 1\ntargets:\n  - user_home: 'C:\\\\Users\\\\alice'\n"
			if tc.sid != "" {
				body += "    sid: " + tc.sid + "\n"
			}
			body += "    connector: codex\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadManifest(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadManifest error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadManifestWindowsRejectsDuplicateSIDTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: codex
    agent_version: codex-cli 0.142.0
  - user_home: 'C:\Profiles\renamed'
    sid: s-1-5-21-1-2-3-1001
    connector: codex
    agent_version: codex-cli 0.142.0
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "duplicates enabled target") {
		t.Fatalf("LoadManifest error = %v, want duplicate SID target rejection", err)
	}
}

func TestLoadManifestWindowsRejectsCanonicalSIDAliasTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: codex
    agent_version: codex-cli 0.142.0
  - user_home: 'C:\Profiles\renamed'
    sid: S-1-5-021-001-002-003-01001
    connector: codex
    agent_version: codex-cli 0.142.0
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "duplicates enabled target") {
		t.Fatalf("LoadManifest error = %v, want canonical SID alias rejection", err)
	}
}

func TestLoadManifestWindowsRejectsMissingAgentVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: codex
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "requires explicit agent_version") {
		t.Fatalf("LoadManifest error = %v, want explicit agent_version rejection", err)
	}
}
