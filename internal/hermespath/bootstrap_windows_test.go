// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hermespath

import (
	"os"
	"path/filepath"
	"testing"
)

func writeHermesLayoutFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Hermes 0.21.5 and later install through the bootstrap installer: the
// launcher lives in <LocalAppData>\hermes\bin, each release runs from a
// leased installs\<id>\environments\<id>\venv, and hermes-agent keeps only
// the checkout and the install stamp.
func TestManagedExecutableFollowsTheBootstrapLayout(t *testing.T) {
	profile := t.TempDir()
	root := filepath.Join(profile, "AppData", "Local", "hermes")
	legacy := filepath.Join(root, "hermes-agent", "venv", "Scripts", "hermes.exe")
	launcher := filepath.Join(root, "bin", "hermes.exe")

	if got := ManagedExecutablePathForUserHome(profile); got != legacy {
		t.Fatalf("no install: path = %q, want the historical %q", got, legacy)
	}

	writeHermesLayoutFile(t, filepath.Join(root, "hermes-agent", "install-stamp.json"), `{"schemaVersion":2,"baseVersion":"0.21.5","payload":"bootstrap"}`)
	writeHermesLayoutFile(t, launcher, "MZ launcher")
	writeHermesLayoutFile(t, filepath.Join(root, "installs", "04a441694ca8a16e", "environments", "401a1ded57e044b79c54bbb9cf9de7cf", "venv", "Scripts", "hermes.exe"), "MZ leased")
	if got := ManagedExecutablePathForUserHome(profile); got != launcher {
		t.Fatalf("bootstrap install: path = %q, want the launcher %q", got, launcher)
	}
	version, err := InstalledVersionForManagedExecutable(launcher)
	if err != nil || version != "0.21.5" {
		t.Fatalf("bootstrap install version = %q, %v; want 0.21.5 from the install stamp", version, err)
	}

	writeHermesLayoutFile(t, legacy, "MZ venv")
	if got := ManagedExecutablePathForUserHome(profile); got != legacy {
		t.Fatalf("both layouts: path = %q, want the virtual-environment image %q first", got, legacy)
	}

	for _, other := range []string{
		filepath.Join(root, "tools", "hermes.exe"),
		filepath.Join(root, "bin", "hermes-acp.exe"),
		filepath.Join(root, "installs", "04a441694ca8a16e", "environments", "401a1ded57e044b79c54bbb9cf9de7cf", "venv", "Scripts", "hermes.exe"),
	} {
		if _, err := InstalledVersionForManagedExecutable(other); err == nil {
			t.Fatalf("%s is not an admitted Hermes image but produced a version", other)
		}
	}
}
