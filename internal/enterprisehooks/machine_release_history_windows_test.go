// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The guardian service reads the history from the StateRoot its service
// environment pins (<StateRoot>\hook-guardian-state); a pinned value that is
// not that exact folder is refused, never read as another StateRoot.
func TestWindowsMachineReleaseHistoryPathFollowsTheGuardianStateRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, filepath.Join(root, "hook-guardian-state"))
	path, err := windowsMachineReleaseHistoryPath()
	if want := filepath.Join(root, "install", "release_history.json"); err != nil || path != want {
		t.Fatalf("path=%q err=%v, want %q", path, err, want)
	}
	for _, bad := range []string{
		filepath.Join(root, "runtime"),
		"hook-guardian-state",
		filepath.Join(root, "hook-guardian-state") + `\`,
		" " + filepath.Join(root, "hook-guardian-state"),
	} {
		t.Setenv(managed.HookGuardianAuthorizationDirEnv, bad)
		if path, err := windowsMachineReleaseHistoryPath(); err == nil {
			t.Fatalf("%q: path=%q, want a refusal", bad, path)
		}
	}
}

// A history that does not parse, has another schema or is too large is an
// error, which the release check reads as no other release.
func TestWindowsMachineRanReleaseRefusesAMalformedHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release_history.json")
	previousPath, previousTrust := windowsMachineReleaseHistoryPath, windowsMachineReleaseHistoryTrustCheck
	t.Cleanup(func() {
		windowsMachineReleaseHistoryPath, windowsMachineReleaseHistoryTrustCheck = previousPath, previousTrust
	})
	windowsMachineReleaseHistoryPath = func() (string, error) { return path, nil }
	windowsMachineReleaseHistoryTrustCheck = func(string) error { return nil }
	for _, tc := range []struct {
		label, body string
		ran, err    bool
	}{
		{"names it", `{"schema_version":1,"releases":["1.0.9","1.0.10"]}`, true, false},
		{"with a BOM", "\ufeff" + `{"schema_version":1,"releases":["1.0.10"]}`, true, false},
		{"does not name it", `{"schema_version":1,"releases":["1.0.9"]}`, false, false},
		{"another schema", `{"schema_version":2,"releases":["1.0.10"]}`, false, true},
		{"not JSON", `1.0.10`, false, true},
	} {
		if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		ran, err := windowsMachineRanRelease("1.0.10")
		if ran != tc.ran || (err != nil) != tc.err {
			t.Fatalf("%s: ran=%t err=%v, want ran=%t error=%t", tc.label, ran, err, tc.ran, tc.err)
		}
	}
	big := make([]byte, windowsMachineReleaseHistoryLimit+1)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if ran, err := windowsMachineRanRelease("1.0.10"); ran || err == nil {
		t.Fatalf("an oversized history: ran=%t err=%v, want an error", ran, err)
	}
	if ran, err := windowsMachineRanRelease("  "); ran || err != nil {
		t.Fatalf("an empty release: ran=%t err=%v, want no and no error", ran, err)
	}
}
