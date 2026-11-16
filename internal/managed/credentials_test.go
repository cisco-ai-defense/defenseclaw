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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

// A stored credential the gateway's read refuses (an extra reader ACE, an
// untrusted owner, empty, too large, not one line) is missing for bundle
// verify and apply, so a required reference refuses; only a failed
// operating-system call (the caller cannot read the store) is unchecked.
// The error text of the failed check is kept (review of GAP-0009).
func TestStoredCredentialValue(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	stored := write("stored", []byte("key-123\n"))
	refuse := func(err error) func(string) error { return func(string) error { return err } }
	pass := func(string) error { return nil }
	extraReader := errors.New(`C:\ProgramData\Cisco\DefenseClaw\secrets\llm-key: principal S-1-5-32-545 may read the protected credential; only LocalSystem, Administrators and the gateway service may`)
	type tc struct {
		name      string
		path      string
		checks    []func(string) error
		present   bool
		unchecked bool
	}
	cases := []tc{
		{"stored and usable", stored, []func(string) error{pass, pass}, true, false},
		{"extra Users read ACE", stored, []func(string) error{pass, refuse(extraReader)}, false, false},
		{"untrusted owner", stored, []func(string) error{refuse(errors.New("owner S-1-5-21-1-2-3-1001 is not trusted for protected credential")), pass}, false, false},
		{"empty file", write("empty", nil), nil, false, false},
		{"whitespace only", write("blank", []byte(" \n")), nil, false, false},
		{"oversized file", write("big", []byte(strings.Repeat("k", ServiceCredentialLimit+1))), nil, false, false},
		{"two lines", write("lines", []byte("a\nb")), nil, false, false},
		{"security descriptor unreadable", stored, []func(string) error{pass, refuse(fmt.Errorf("%s: inspect Windows security descriptor: %w", stored, syscall.EACCES))}, false, true},
		{"leaf access denied", stored, []func(string) error{refuse(fmt.Errorf("%s: %w", stored, &fs.PathError{Op: "lstat", Path: stored, Err: syscall.EACCES}))}, false, true},
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		locked := write("locked", []byte("key-123"))
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, tc{"open denied", locked, nil, false, true})
	}
	for _, c := range cases {
		value, readErr := readStoredCredential("llm-key", c.path, c.checks...)
		value, err := ServiceCredentialValue(value, readErr)
		if (value != nil) != c.present || (err != nil) != c.unchecked {
			t.Errorf("%s: value %v, err %v (read %v)", c.name, value != nil, err, readErr)
		}
		if c.present && string(value) != "key-123" {
			t.Errorf("%s: value %q", c.name, value)
		}
		if !c.present && !c.unchecked && !errors.Is(readErr, ErrUnusableServiceCredential) {
			t.Errorf("%s: %v does not wrap ErrUnusableServiceCredential", c.name, readErr)
		}
		if c.unchecked && errors.Is(readErr, ErrUnusableServiceCredential) {
			t.Errorf("%s: %v must not be unusable", c.name, readErr)
		}
	}
	readErr := credentialVerdict(extraReader)
	if readErr.Error() != extraReader.Error() || !errors.Is(readErr, extraReader) {
		t.Fatalf("verdict %q lost the check's text or chain", readErr)
	}
	for name, err := range map[string]error{
		"not stored":       ErrNoServiceCredential,
		"wrapped unusable": fmt.Errorf("credential llm-key: %w", ErrUnusableServiceCredential),
	} {
		value := []byte("key-123")
		if got, err := ServiceCredentialValue(value, err); got != nil || err != nil || string(value) == "key-123" {
			t.Errorf("%s: value %q, err %v, input %q; want missing and the input cleared", name, got, err, value)
		}
	}
	if got, err := ServiceCredentialValue(nil, fmt.Errorf("inspect credential llm-key: %w", &fs.PathError{Op: "lstat", Err: syscall.EACCES})); got != nil || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("unreadable store: value %q, err %v; want unchecked", got, err)
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
