// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// oss-outage-open round i loop 2 (P1, config filename alias): the hooks of
// a folder load <folder>/config.yaml. When that file is the configured
// DEFENSECLAW_CONFIG under another name (a config.yaml link or hard link to
// policy.yaml, or a configured link that resolves into a folder with hooks),
// those hooks can open an outage there, so hook-data-dir must name that
// folder for install.sh to lock. Before the fix it compared only the
// configured basename with config.yaml and skipped the folder.
func TestHookDataDirsNowLocksEveryFolderWhoseConfigIsTheConfiguredFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		// layout returns the configured DEFENSECLAW_CONFIG and the folder
		// whose hooks load it as config.yaml.
		layout func(t *testing.T, base string) (configured, hookFolder string)
	}{
		{name: "config.yaml is a link to the configured policy.yaml", layout: func(t *testing.T, base string) (string, string) {
			cfg := filepath.Join(base, "cfg")
			writeAliasConfig(t, filepath.Join(cfg, "policy.yaml"))
			aliasLink(t, "policy.yaml", filepath.Join(cfg, "config.yaml"))
			return filepath.Join(cfg, "policy.yaml"), cfg
		}},
		{name: "config.yaml is a hard link to the configured policy.yaml", layout: func(t *testing.T, base string) (string, string) {
			cfg := filepath.Join(base, "cfg")
			writeAliasConfig(t, filepath.Join(cfg, "policy.yaml"))
			if err := os.Link(filepath.Join(cfg, "policy.yaml"), filepath.Join(cfg, "config.yaml")); err != nil {
				t.Skipf("hard link: %v", err)
			}
			return filepath.Join(cfg, "policy.yaml"), cfg
		}},
		{name: "the configured file is a link into a folder with hooks", layout: func(t *testing.T, base string) (string, string) {
			real := filepath.Join(base, "real")
			writeAliasConfig(t, filepath.Join(real, "config.yaml"))
			cfg := filepath.Join(base, "cfg")
			if err := os.MkdirAll(cfg, 0o700); err != nil {
				t.Fatal(err)
			}
			aliasLink(t, filepath.Join(real, "config.yaml"), filepath.Join(cfg, "policy.yaml"))
			return filepath.Join(cfg, "policy.yaml"), real
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			configured, folder := tc.layout(t, base)
			if err := os.MkdirAll(filepath.Join(folder, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			installer := filepath.Join(base, "installer-home")
			if err := os.MkdirAll(installer, 0o700); err != nil {
				t.Fatal(err)
			}
			isolateOutageHostMarkers(t)
			stubOutageInstallFolders(t, func() string { return "" }, func() (string, bool) { return "", false })
			t.Setenv("HOME", base)
			t.Setenv("USERPROFILE", base)
			t.Setenv("DEFENSECLAW_HOME", installer)
			t.Setenv("DEFENSECLAW_CONFIG", configured)
			dirs, err := hookDataDirsNow()
			if err != nil {
				t.Fatal(err)
			}
			// An agent's environment: no installer override.
			hooks := filepath.Join(folder, "hooks")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("HOME", filepath.Join(base, "agent-home"))
			t.Setenv("USERPROFILE", filepath.Join(base, "agent-home"))
			if mode := hookOutageFailModeNow("opencode", hooks); mode != "open" {
				t.Fatalf("precondition: the hook in %s does not open an outage (%q)", folder, mode)
			}
			held := false
			for _, dir := range dirs {
				if pathidentity.Same(dir, folder) {
					held = true
				}
			}
			if !held {
				t.Fatalf("hooks in %s open an outage, but hook-data-dir names only %q", folder, dirs)
			}
			if err := os.MkdirAll(filepath.Join(folder, ".install.lock"), 0o700); err != nil {
				t.Fatal(err)
			}
			if mode := hookOutageFailModeNow("opencode", hooks); mode != "closed" {
				t.Fatalf("hook-outage-mode with the lock install.sh holds = %q, want closed", mode)
			}
		})
	}
}

func writeAliasConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(outageNowDefaultConfig), 0o600); err != nil {
		t.Fatal(err)
	}
}

func aliasLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
}
