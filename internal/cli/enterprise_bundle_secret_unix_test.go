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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The Linux and macOS presence reader of bundle verify is the listing
// `enterprise secret status` reads, the one the apply checks: a credential
// is present when the store lists it (an empty file too: no credential is
// opened), an entry that is not a regular file is not, and a store the
// caller cannot list is an error, so verify warns instead of refusing.
func TestManagedBundleSecretPresentUsesTheStoreListing(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor(enterpriseunix.CurrentGOOS())
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	previous := newUnixLifecycleEnv
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout}, nil
	}
	dir := filepath.Join(root, layout.SecretsDir)
	if err := os.MkdirAll(filepath.Join(dir, "a-directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"ai-defense-api-key": "", ".splunk-hec-token": "x"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]bool{"ai-defense-api-key": true, "splunk-hec-token": false, "a-directory": false} {
		if present, err := managedBundleSecretPresent(name); err != nil || present != want {
			t.Fatalf("%s: present %v, err %v; want %v", name, present, err, want)
		}
	}
	if os.Geteuid() == 0 {
		return
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := managedBundleSecretPresent("ai-defense-api-key"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("unreadable store: %v", err)
	}
}
