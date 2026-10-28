// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The Linux and macOS credential reader of bundle verify (and of the apply,
// which shares Env.SecretValue) runs the gateway's read checks: a stored
// credential is present only when the gateway could use it. An empty,
// multi-line, oversized or other-readable file, one that fails the path
// trust check, a link, a folder and a name that is not a credential name are
// missing; a store the caller cannot read is an error, so verify warns
// instead of refusing.
func TestManagedBundleSecretValueUsesTheGatewayChecks(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor(enterpriseunix.CurrentGOOS())
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, layout.SecretsDir)
	untrusted := filepath.Join(dir, "untrusted-key")
	previous := newUnixLifecycleEnv
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		// The temporary root is not root-owned: trust every path but one,
		// which stands for a file the managed trust check refuses.
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Trust: func(path string, _ enterpriseunix.TrustKind) error {
			if path == untrusted {
				return errors.New("owner uid 501 is not trusted")
			}
			return nil
		}}, nil
	}
	if err := os.MkdirAll(filepath.Join(dir, "a-directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]struct {
		body string
		mode os.FileMode
	}{
		"ai-defense-api-key": {"key-1\n", 0o600},
		"group-readable":     {"key-2", 0o640},
		"empty-key":          {"", 0o600},
		"blank-key":          {" \n", 0o600},
		"multi-line":         {"key-1\nkey-2\n", 0o600},
		"too-large":          {strings.Repeat("k", managed.ServiceCredentialLimit+1), 0o600},
		"other-readable":     {"key-3", 0o644},
		"untrusted-key":      {"key-4", 0o600},
		".splunk-hec-token":  {"key-5", 0o600},
	}
	for name, file := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(file.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "ai-defense-api-key"), filepath.Join(dir, "linked-key")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"ai-defense-api-key": true, "group-readable": true,
		"empty-key": false, "blank-key": false, "multi-line": false, "too-large": false, "other-readable": false,
		"untrusted-key": false, "splunk-hec-token": false, ".splunk-hec-token": false, "a-directory": false,
		"linked-key": false, "not-stored": false,
	} {
		if value, err := managedBundleSecretValue(name); err != nil || (value != nil) != want {
			t.Errorf("%s: value %v, err %v; want %v", name, value != nil, err, want)
		}
	}
	if os.Geteuid() == 0 {
		return
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := managedBundleSecretValue("ai-defense-api-key"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("unreadable store: %v", err)
	}
}
