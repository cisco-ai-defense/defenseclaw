// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveServiceCredentialRejectsBadNamesAndMissing(t *testing.T) {
	for _, name := range []string{"", "../key", "Key", "a/b", "a.b", strings.Repeat("a", 64)} {
		if _, _, err := ResolveServiceCredential(name, t.TempDir()); err == nil {
			t.Errorf("name %q must be rejected", name)
		}
	}
	if _, _, err := ResolveServiceCredential("ai-defense-api-key", t.TempDir()); !errors.Is(err, ErrNoServiceCredential) {
		t.Fatalf("missing credential error = %v, want ErrNoServiceCredential", err)
	}
	if _, _, err := ResolveServiceCredential("ai-defense-api-key", ""); !errors.Is(err, ErrNoServiceCredential) {
		t.Fatalf("empty secrets dir error = %v, want ErrNoServiceCredential", err)
	}
}

func TestResolveServiceCredentialRefusesUntrustedFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root unix owner")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ai-defense-api-key"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveServiceCredential("ai-defense-api-key", dir); err == nil || errors.Is(err, ErrNoServiceCredential) {
		t.Fatalf("a user-owned credential must be refused, got %v", err)
	}
}

func TestSystemdCredentialsDirectoryMustBeUnderRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd credentials are unix-only")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	if _, _, err := ResolveServiceCredential("ai-defense-api-key", ""); err == nil || errors.Is(err, ErrNoServiceCredential) {
		t.Fatalf("CREDENTIALS_DIRECTORY outside /run/credentials must be refused, got %v", err)
	}
}

func TestReadBoundedCredential(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got, err := readBoundedCredential(write("ok", []byte("  key-123\n"))); err != nil || string(got) != "key-123" {
		t.Fatalf("readBoundedCredential = %q, %v", got, err)
	}
	for name, data := range map[string][]byte{
		"empty":     []byte(" \n"),
		"multiline": []byte("a\nb"),
		"nul":       []byte("a\x00b"),
		"oversize":  []byte(strings.Repeat("k", ServiceCredentialLimit+1)),
	} {
		if _, err := readBoundedCredential(write(name, data)); err == nil {
			t.Errorf("%s credential must be rejected", name)
		}
	}
}

func TestStandaloneSecretsDirForConfig(t *testing.T) {
	cases := map[string][2]string{
		"linux":   {"/etc/defenseclaw/config.yaml", "/etc/defenseclaw/secrets"},
		"darwin":  {"/opt/cisco/defenseclaw/etc/config.yaml", "/opt/cisco/defenseclaw/etc/secrets"},
		"windows": {`C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`, `C:\ProgramData\Cisco\DefenseClaw\secrets`},
	}
	for goos, tc := range cases {
		if got := StandaloneSecretsDirForConfig(goos, tc[0]); got != tc[1] {
			t.Errorf("%s: StandaloneSecretsDirForConfig(%q) = %q, want %q", goos, tc[0], got, tc[1])
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		layout, _ := StandaloneLayoutFor(goos)
		if got := StandaloneSecretsDirForConfig(goos, layout.ConfigPath); got != layout.SecretsDir {
			t.Errorf("%s: derived secrets dir %q != layout %q", goos, got, layout.SecretsDir)
		}
	}
	win, _ := StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if got := StandaloneSecretsDirForConfig("windows", win.ConfigPath); got != win.SecretsDir {
		t.Errorf("windows: derived secrets dir %q != layout %q", got, win.SecretsDir)
	}
}
