// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// shellHookInstallHeldScript is the install check a rendered shell hook runs
// (the _DC_HOOK_HOME it was rendered with, the lock rule and
// defenseclaw_install_held), from the hook file at path.
func shellHookInstallHeldScript(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	var home string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "_DC_HOOK_HOME=") {
			home = line
			break
		}
	}
	if home == "" {
		t.Fatalf("%s names no _DC_HOOK_HOME", path)
	}
	start := strings.Index(text, "# defenseclaw_install_lock_held DATA returns 0 (true)")
	held := strings.Index(text, "defenseclaw_install_held() {")
	if start < 0 || held < start {
		t.Fatalf("%s has no install check", path)
	}
	end := strings.Index(text[held:], "\n}\n")
	if end < 0 {
		t.Fatalf("%s: defenseclaw_install_held does not end", path)
	}
	return home + "\n" + text[start:held+end+3]
}

// shellHookInstallHeldFunction is the defenseclaw_install_held of the file
// at path.
func shellHookInstallHeldFunction(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, "defenseclaw_install_held() {")
	if start < 0 {
		t.Fatalf("%s has no defenseclaw_install_held", path)
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("%s: defenseclaw_install_held does not end", path)
	}
	return text[start : start+end+3]
}

// oss-outage-open round k (rule 2): a per-user shell hook found the
// installer's lock only from its own path (the folder above its hooks
// folder) and from DEFENSECLAW_HOME or ~/.defenseclaw, so a hard link, a
// symlink or a copy of a locked hook in another folder, run with another
// home, saw no lock while the install had stopped the gateway, and a
// default-tier outage opened mid-upgrade. Every per-user render now names
// the data directory it was rendered into (_DC_HOOK_HOME), which install.sh
// always locks, so every alias of the file is held by that install's lock,
// whatever folder it runs from; with no install it is not held.
func TestShellHookAliasesAreHeldByTheInstallThatRenderedThem(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	home := testenv.PrivateTempDir(t)
	hookDir := filepath.Join(home, "hooks")
	if err := writeHookScriptsCommonWithOptions(hookDir, "127.0.0.1:18970", "golden-token", "closed",
		connectorHookScripts["claudecode"], false, "claudecode", true); err != nil {
		t.Fatal(err)
	}
	identity, _ := installLockIdentityOf(t, os.Getpid())
	lock := filepath.Join(home, ".install.lock")
	entries, err := os.ReadDir(hookDir)
	if err != nil {
		t.Fatal(err)
	}
	hooks := 0
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(hookDir, entry.Name()))
		if err != nil || !strings.HasSuffix(entry.Name(), ".sh") || strings.HasPrefix(entry.Name(), "_") ||
			!strings.Contains(string(raw), "defenseclaw_install_held() {") {
			continue
		}
		hooks++
		for _, alias := range []string{"hard link", "symlink", "copy"} {
			t.Run(entry.Name()+"/"+alias, func(t *testing.T) {
				elsewhere := testenv.PrivateTempDir(t)
				if err := os.Mkdir(filepath.Join(elsewhere, "hooks"), 0o700); err != nil {
					t.Fatal(err)
				}
				source := filepath.Join(hookDir, entry.Name())
				target := filepath.Join(elsewhere, "hooks", entry.Name())
				switch alias {
				case "hard link":
					err = os.Link(source, target)
				case "symlink":
					err = os.Symlink(source, target)
				default:
					err = os.WriteFile(target, raw, 0o700)
				}
				if err != nil {
					t.Fatal(err)
				}
				// The alias runs from its own folder, with another home.
				script := shellHookInstallHeldScript(t, target) +
					"_DC_HOOK_DATA_DIR=\"$1\"\nDEFENSECLAW_HOME=\"$2\"\nif defenseclaw_install_held; then echo held; else echo none; fi\n"
				run := func() string {
					out, err := exec.Command(bash, "-c", script, "hook", elsewhere, testenv.PrivateTempDir(t)).CombinedOutput()
					if err != nil {
						t.Fatalf("bash: %v: %s", err, out)
					}
					return strings.TrimSpace(string(out))
				}
				if got := run(); got != "none" {
					t.Fatalf("with no install the alias is %q, want none", got)
				}
				if err := os.Mkdir(lock, 0o700); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(lock)
				for name, value := range map[string]string{"pid": strconv.Itoa(os.Getpid()) + "\n", "proc-start": identity + "\n"} {
					if err := os.WriteFile(filepath.Join(lock, name), []byte(value), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if got := run(); got != "held" {
					t.Fatalf("while the install that rendered it runs, the alias is %q, want held", got)
				}
			})
		}
	}
	// A hook sources _hardening.sh, whose defenseclaw_install_held then
	// answers: it must be the same check, with the same _DC_HOOK_HOME.
	helper := shellHookInstallHeldFunction(t, filepath.Join(hookDir, "_hardening.sh"))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "-hook.sh") || strings.HasPrefix(entry.Name(), "inspect-") {
			if got := shellHookInstallHeldFunction(t, filepath.Join(hookDir, entry.Name())); got != helper {
				t.Errorf("%s checks the install otherwise than _hardening.sh", entry.Name())
			}
		}
	}
	if hooks < 5 {
		t.Fatalf("found %d per-user shell hooks with the install check, want every one", hooks)
	}
}
