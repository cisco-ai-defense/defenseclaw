//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The per-user worker of a standalone install keeps a dotfile link inside
// the home and writes DefenseClaw's hooks into the file it names; the
// removal takes them out of that file again and the link stays. Install
// replaced the link with a regular file and left the linked file without
// the hooks (rel-1-0-3 GAP-0205, rel-1-0-2 GAP-0642). A link out of the
// home is still refused on a first install and replaced, never followed,
// on a repair.
func TestStandaloneInstallWritesThroughAnInHomeConfigLink(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	withStandaloneUnix(t, true, nil)
	previousPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = ""
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousPath })
	t.Setenv("CODEX_HOME", "")
	options := func(home string, repair bool) InstallOptions {
		return InstallOptions{
			ConnectorName: "codex", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
			APIAddr: "127.0.0.1:18970", APIToken: "test-token", AgentVersion: "codex-cli 0.142.0",
			GuardrailMode: "action", AllowMissingHookConfigRepair: repair, Registry: connector.NewDefaultRegistry(),
		}
	}
	for _, repair := range []bool{false, true} {
		name := "first install"
		if repair {
			name = "repair"
		}
		t.Run(name, func(t *testing.T) {
			home := newTestHome(t)
			t.Setenv("HOME", home)
			dotfile := filepath.Join(home, "dotfiles", "codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(dotfile), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dotfile, []byte("model = \"gpt-5\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(home, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			const relative = "../dotfiles/codex/config.toml"
			if err := os.Symlink(relative, link); err != nil {
				t.Fatal(err)
			}
			linkKept := func(t *testing.T, what string) []byte {
				t.Helper()
				if target, err := os.Readlink(link); err != nil || target != relative {
					t.Fatalf("%s replaced the in-home link: %q, %v", what, target, err)
				}
				data, err := os.ReadFile(dotfile)
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			if _, err := Install(context.Background(), options(home, repair)); err != nil {
				t.Fatalf("Install through an in-home link: %v", err)
			}
			if data := linkKept(t, "install"); !bytes.Contains(data, []byte("codex-hook.sh")) || !bytes.Contains(data, []byte("model = \"gpt-5\"")) {
				t.Fatalf("the linked file lacks DefenseClaw's hooks or lost its settings: %q", data)
			}
			if _, err := Verify(context.Background(), options(home, false)); err != nil {
				t.Fatalf("Verify through an in-home link: %v", err)
			}
			if err := RemoveUserHooks(context.Background(), options(home, false)); err != nil {
				t.Fatalf("RemoveUserHooks through an in-home link: %v", err)
			}
			if data := linkKept(t, "removal"); strings.Contains(strings.ToLower(string(data)), "defenseclaw") || !bytes.Contains(data, []byte("model = \"gpt-5\"")) {
				t.Fatalf("the removal left DefenseClaw's entries or lost settings: %q", data)
			}
		})
	}

	t.Run("outside link", func(t *testing.T) {
		home := newTestHome(t)
		t.Setenv("HOME", home)
		outside := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(outside, []byte("outside = true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(home, ".codex", "config.toml")
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), options(home, false)); err == nil || !strings.Contains(err.Error(), "refusing symlink hook config") {
			t.Fatalf("first install through an outside link = %v", err)
		}
		if _, err := Install(context.Background(), options(home, true)); err != nil {
			t.Fatalf("repair of an outside link: %v", err)
		}
		if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("the repair kept the outside link: %v", err)
		}
		if data, err := os.ReadFile(outside); err != nil || string(data) != "outside = true\n" {
			t.Fatalf("the outside file changed: %q, %v", data, err)
		}
	})
}
