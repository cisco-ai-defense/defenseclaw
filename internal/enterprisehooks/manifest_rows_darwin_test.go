//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadManifestIsolatesBadRowsOnDarwin(t *testing.T) {
	cases := map[string]struct {
		body        string
		wantUsers   []string
		wantSkipped []int
	}{
		"missing connector and duplicate": {
			body: `version: 1
targets:
  - user: "alice"
    connector: "claudecode"
  - user: "bob"
  - user: "carol"
    connector: "codex"
  - user: "alice"
    connector: "claudecode"
`,
			wantUsers:   []string{"alice", "carol"},
			wantSkipped: []int{1, 3},
		},
		"unknown field and wrong type": {
			body: `version: 1
targets:
  - user: "alice"
    connector: "claudecode"
  - user: "bob"
    connector: "codex"
    surprise: true
  - user: "carol"
    connector: "cursor"
    uid: "not-a-number"
  - user: "dave"
    connector: "codex"
`,
			wantUsers:   []string{"alice", "dave"},
			wantSkipped: []int{1, 2},
		},
		"deferred row is Windows-only": {
			body: `version: 1
targets:
  - user: "alice"
    connector: "claudecode"
    deferred: true
  - user: "bob"
    connector: "claudecode"
`,
			wantUsers:   []string{"bob"},
			wantSkipped: []int{0},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "targets.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			manifest, digest, err := LoadManifestWithSHA256(path)
			if err != nil {
				t.Fatalf("one bad row failed the whole manifest: %v", err)
			}
			if len(digest) != 64 {
				t.Fatalf("digest = %q", digest)
			}
			var users []string
			for _, target := range manifest.Targets {
				users = append(users, target.User)
			}
			if strings.Join(users, ",") != strings.Join(tc.wantUsers, ",") {
				t.Fatalf("kept users = %v, want %v", users, tc.wantUsers)
			}
			if len(manifest.Skipped) != len(tc.wantSkipped) {
				t.Fatalf("skipped = %+v, want rows %v", manifest.Skipped, tc.wantSkipped)
			}
			for i, row := range manifest.Skipped {
				if row.Index != tc.wantSkipped[i] || row.Reason == "" {
					t.Fatalf("skipped[%d] = %+v, want row %d", i, row, tc.wantSkipped[i])
				}
			}
		})
	}
}

func TestLoadManifestStillRejectsUnusableDocumentOnDarwin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ntargets: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("a document that does not parse at all was accepted")
	}
}

func TestLoadManifestRejectsUnknownTopLevelKeyOnDarwin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	body := "version: 1\ntargetz:\n  - user: \"alice\"\n    connector: \"claudecode\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if manifest, err := LoadManifest(path); err == nil {
		t.Fatalf("a manifest with an unknown top-level key was accepted: %+v", manifest)
	}
}
