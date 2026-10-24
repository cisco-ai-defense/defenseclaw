// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyViewDigestBindsVendorContentAndAbsence(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			opts := Options{GOOS: goos, Root: t.TempDir(), SkipTrustChecks: true}
			path, err := CodexRequirementsPath(opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("managed_dir = '/opt/defenseclaw/bin'\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			first, err := PolicyViewDigest(opts, ConnectorCodex)
			if err != nil || len(first) != 64 {
				t.Fatalf("initial digest %q: %v", first, err)
			}
			if err := os.WriteFile(path, []byte("hooks = {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			hidden, err := PolicyViewDigest(opts, ConnectorCodex)
			if err != nil || hidden == first {
				t.Fatalf("changed policy kept digest: %q, %v", hidden, err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			missing, err := PolicyViewDigest(opts, ConnectorCodex)
			if err != nil || missing == first || missing == hidden {
				t.Fatalf("hidden policy kept digest: %q, %v", missing, err)
			}
			if goos == "darwin" {
				pref := rooted(opts, "/Library/Managed Preferences/com.openai.codex.plist")
				if err := os.MkdirAll(filepath.Dir(pref), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(pref, []byte("private override"), 0o600); err != nil {
					t.Fatal(err)
				}
				overridden, err := PolicyViewDigest(opts, ConnectorCodex)
				if err != nil || overridden == missing {
					t.Fatalf("macOS private policy source kept digest: %q, %v", overridden, err)
				}
			}
		})
	}
}

func TestPolicyViewDigestIncludesMergedDropIns(t *testing.T) {
	opts := Options{GOOS: "linux", Root: t.TempDir(), SkipTrustChecks: true}
	dir, err := ClaudeManagedDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	dropins := filepath.Join(dir, "managed-settings.d")
	if err := os.MkdirAll(dropins, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(dropins, DefenseClawDropInName)
	if err := os.WriteFile(managed, []byte(`{"hooks": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := PolicyViewDigest(opts, ConnectorClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dropins, "99-override.json")
	if err := os.WriteFile(extra, []byte(`{"hooks": {"PreToolUse": []}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := PolicyViewDigest(opts, ConnectorClaudeCode)
	if err != nil || second == first {
		t.Fatalf("new effective drop-in kept digest: %q, %v", second, err)
	}
}

func TestPolicyViewDigestIncludesUppercaseCopilotDropIn(t *testing.T) {
	opts := Options{GOOS: "linux", Root: t.TempDir(), SkipTrustChecks: true}
	dir, err := CopilotPolicyDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := PolicyViewDigest(opts, ConnectorCopilot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "99-override.JSON"), []byte(`{"hooks": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := PolicyViewDigest(opts, ConnectorCopilot)
	if err != nil || before == after {
		t.Fatalf("new Copilot drop-in kept policy-view digest: %q, %v", after, err)
	}
}

func TestPolicyViewDigestIncludesOpenCodePlugin(t *testing.T) {
	opts := Options{GOOS: "linux", Root: t.TempDir(), SkipTrustChecks: true, OpenCodePluginPath: "/opt/defenseclaw/share/opencode/defenseclaw.js"}
	config, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config, opts.openCodeArtifactFile()} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := PolicyViewDigest(opts, ConnectorOpenCode)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.openCodeArtifactFile(), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := PolicyViewDigest(opts, ConnectorOpenCode)
	if err != nil || before == after {
		t.Fatalf("changed managed plugin kept policy-view digest: %q, %v", after, err)
	}
}
