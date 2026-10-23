// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterprisepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// policyViewDropInDir creates connector's merged drop-in folder with
// DefenseClaw's drop-in and returns the folder.
func policyViewDropInDir(t *testing.T, opts Options, connector string) string {
	t.Helper()
	var dir string
	var err error
	switch connector {
	case ConnectorClaudeCode:
		dir, err = ClaudeManagedDir(opts)
		dir = filepath.Join(dir, "managed-settings.d")
	case ConnectorCopilot:
		dir, err = CopilotPolicyDir(opts)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, DefenseClawDropInName), []byte(`{"hooks": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Review loop round 2 (P2): the digest hashes and counts only the drop-ins
// the vendor readers load. A hidden draft (also a symlink one), a non-JSON
// file, a folder or many hidden temporary files are skipped by Claude Code,
// Copilot and DefenseClaw's readers, so they neither abort the pin (install,
// ensure, describe) nor change the digest; a new visible drop-in still does.
func TestPolicyViewDigestSkipsDropInsTheVendorIgnores(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, connector := range []string{ConnectorClaudeCode, ConnectorCopilot} {
			t.Run(goos+"/"+connector, func(t *testing.T) {
				opts := Options{GOOS: goos, Root: t.TempDir(), SkipTrustChecks: true}
				dir := policyViewDropInDir(t, opts, connector)
				base, err := PolicyViewDigest(opts, connector)
				if err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "draft.json")
				if err := os.WriteFile(outside, []byte(`{"hooks": {"PreToolUse": []}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(dir, ".draft.json")); err != nil {
					t.Fatal(err)
				}
				if draft, err := PolicyViewDigest(opts, connector); err != nil || draft != base {
					t.Fatalf("a hidden draft symlink the vendor skips changed=%v or aborted the policy-view digest: %v", draft != base, err)
				}
				for name, data := range map[string]string{".backup.json": "{}", "README.txt": "notes", "90-defenseclaw.json.bak": "{}"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Mkdir(filepath.Join(dir, "archive.json"), 0o700); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 130; i++ {
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf(".tmp-%03d.json", i)), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if connector == ConnectorClaudeCode {
					if _, err := readClaudeFileSources(opts); err != nil {
						t.Fatalf("the Claude reader refused the ignored entries: %v", err)
					}
				}
				ignored, err := PolicyViewDigest(opts, connector)
				if err != nil {
					t.Fatalf("ignored drop-in entries aborted the policy-view digest: %v", err)
				}
				if ignored != base {
					t.Fatal("ignored drop-in entries changed the policy-view digest")
				}
				if err := os.WriteFile(filepath.Join(dir, ".backup.json"), []byte(`{"hooks": {"x": 1}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if again, err := PolicyViewDigest(opts, connector); err != nil || again != base {
					t.Fatalf("editing a hidden draft changed the digest: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dir, "99-override.json"), []byte(`{"hooks": {}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if added, err := PolicyViewDigest(opts, connector); err != nil || added == base {
					t.Fatalf("a new effective drop-in kept the digest: %v", err)
				}
			})
		}
	}
}

// The drop-in budget counts policy files only: 128 is the most a pin binds.
func TestPolicyViewDigestBoundsEffectiveDropIns(t *testing.T) {
	opts := Options{GOOS: "linux", Root: t.TempDir(), SkipTrustChecks: true}
	dir := policyViewDropInDir(t, opts, ConnectorClaudeCode)
	for i := 0; i < 128; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%03d.json", i)), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := PolicyViewDigest(opts, ConnectorClaudeCode); err == nil {
		t.Fatal("129 policy drop-ins were pinned")
	}
}

// Copilot skips a policy file it does not trust, and so does the Copilot
// reader (a detail, not a conflict): such a drop-in is recorded as present,
// not read, and never aborts the pin. Claude Code's reader refuses it, and
// DefenseClaw's own drop-in must always be readable, so both still fail.
func TestPolicyViewDigestUntrustedDropInFollowsTheVendorReader(t *testing.T) {
	for _, connector := range []string{ConnectorClaudeCode, ConnectorCopilot} {
		t.Run(connector, func(t *testing.T) {
			opts := Options{GOOS: "linux", Root: t.TempDir(), SkipTrustChecks: true}
			dir := policyViewDropInDir(t, opts, connector)
			base, err := PolicyViewDigest(opts, connector)
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "other.json")
			if err := os.WriteFile(outside, []byte(`{"hooks": {}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			// A symlink is not a regular file: readPolicyFile refuses it.
			if err := os.Symlink(outside, filepath.Join(dir, "50-other.json")); err != nil {
				t.Fatal(err)
			}
			got, err := PolicyViewDigest(opts, connector)
			switch connector {
			case ConnectorCopilot:
				if err != nil || got == base {
					t.Fatalf("untrusted Copilot drop-in: digest changed=%v err=%v; want a new digest and no error", got != base, err)
				}
				if err := os.WriteFile(outside, []byte(`{"hooks": {"changed": 1}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if again, err := PolicyViewDigest(opts, connector); err != nil || again != got {
					t.Fatalf("an untrusted Copilot drop-in was read: %v", err)
				}
				if err := os.Remove(filepath.Join(dir, "50-other.json")); err != nil {
					t.Fatal(err)
				}
				own := filepath.Join(dir, DefenseClawDropInName)
				if err := os.Remove(own); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, own); err != nil {
					t.Fatal(err)
				}
				if _, err := PolicyViewDigest(opts, connector); err == nil {
					t.Fatal("an untrusted DefenseClaw Copilot drop-in was pinned")
				}
			default:
				if _, readErr := readClaudeFileSources(opts); readErr == nil || err == nil {
					t.Fatalf("Claude untrusted drop-in: reader err=%v digest err=%v; want both to refuse", readErr, err)
				}
			}
		})
	}
}
