//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestLoadManifestRetriesFirstWindowsNameLookup(t *testing.T) {
	body := []byte("version: 1\ntargets:\n  - user: checked\n    connector: codex\n    enabled: false\n")
	for _, delayed := range []bool{false, true} {
		name := "present"
		if delayed {
			name = "appears during read"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "targets.yaml")
			var created bool
			var writeErr error
			if delayed {
				t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
					if !created {
						created = true
						writeErr = os.WriteFile(path, body, 0o600)
					}
				}))
			} else if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			manifest, _, err := LoadManifestWithSHA256(path)
			if delayed && (!created || writeErr != nil) {
				t.Fatalf("retry did not publish the fixture: created = %v, err = %v", created, writeErr)
			}
			if err != nil || len(manifest.Targets) != 1 || manifest.Targets[0].User != "checked" {
				t.Fatalf("manifest = %+v, err = %v", manifest, err)
			}
		})
	}
}

func TestLoadManifestRetriesPublishedNameBeyondFixedAttempts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	body := []byte("version: 1\ntargets: []\n")
	waits := 0
	var publishErr error
	t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
		waits++
		if waits == 64 {
			publishErr = os.WriteFile(path, body, 0o600)
		}
	}))
	manifest, _, err := LoadManifestWithSHA256(path)
	if publishErr != nil || err != nil || waits < 64 || manifest.Version != 1 || len(manifest.Targets) != 0 {
		t.Fatalf("manifest=%+v waits=%d publication=%v err=%v", manifest, waits, publishErr, err)
	}
}

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

func TestLoadManifestWindowsAcceptsEntraIDTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\entra-user'
    sid: S-1-12-1-1111111111-2222222222-3333333333-4000000000
    connector: codex
    agent_version: codex-cli 0.142.0
`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].SID != "S-1-12-1-1111111111-2222222222-3333333333-4000000000" {
		t.Fatalf("manifest = %+v, want one Microsoft Entra ID target", manifest)
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

// TestLoadManifestWindowsAcceptsMissingAgentVersion is the Secure Client
// version fallback (#1163).
func TestLoadManifestWindowsAcceptsMissingAgentVersion(t *testing.T) {
	useWindowsSecureClientForTest(t)
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
	if err != nil {
		t.Fatalf("LoadManifest error = %v, want version fallback", err)
	}
}

// Outside Secure Client a target still needs explicit version evidence.
func TestLoadManifestWindowsRejectsMissingAgentVersionOutsideSecureClient(t *testing.T) {
	setStandaloneProfileForTest(t, true)
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

func TestLoadManifestWindowsAcceptsEnabledDeferredTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: codex
    agent_version: codex-cli 0.142.0
    enabled: true
    deferred: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(manifest.Targets) != 1 || !manifest.Targets[0].IsEnabled() ||
		!manifest.Targets[0].IsDeferred() {
		t.Fatalf("manifest = %+v, want one enabled deferred target", manifest)
	}
}
