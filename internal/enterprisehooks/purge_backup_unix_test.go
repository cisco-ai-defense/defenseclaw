// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func writePurgeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0727 (owner 2026-10-23): a machine uninstall never deletes or moves an
// account's own data. When ~/.defenseclaw holds the account's own per-user
// install from before the managed deployment enrolled it, the purge leaves
// the folder and the install's binaries exactly as they are, makes no
// ~/.defenseclaw-backup-* folder (#1299 moved the data there), and reports
// it as kept.
func TestPurgeUserStateKeepsAPerUserInstallFromBeforeTheEnrollment(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	files := map[string]string{
		"config.yaml":               "gateway: {}\n",
		".env":                      "SAMPLE_KEY=placeholder\n",
		"audit.db":                  "sqlite",
		"policies/custom.yaml":      "rules: []\n",
		"hooks/claude-code-hook.sh": "managed",
		"session-facts.json":        "{}",
	}
	for rel, body := range files {
		writePurgeTestFile(t, filepath.Join(dataDir, rel), body)
	}
	launcher := filepath.Join(home, ".local", "bin", "defenseclaw")
	writePurgeTestFile(t, launcher, "#!/bin/sh\n")
	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	if !summary.Kept || summary.Data || summary.Binaries {
		t.Fatalf("summary = %+v, want the account's own install kept", summary)
	}
	for rel, body := range files {
		if got, err := os.ReadFile(filepath.Join(dataDir, rel)); err != nil || string(got) != body {
			t.Fatalf("the purge changed %s: %q %v", rel, got, err)
		}
	}
	if _, err := os.Lstat(launcher); err != nil {
		t.Fatalf("the purge removed the account's own launcher: %v", err)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".defenseclaw-backup-") {
			t.Fatalf("the purge moved data to %s", entry.Name())
		}
	}
}

// A home with only what the managed enrollment wrote (no per-user install)
// is purged as before.
func TestPurgeUserStateRemovesManagedOnlyState(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	for _, rel := range []string{"hooks/codex-hook.sh", "session-facts.json", "foreign-hooks-backup/codex/x.json", "logs/hook.log"} {
		writePurgeTestFile(t, filepath.Join(dataDir, rel), "managed")
	}
	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	if !summary.Data || summary.Kept {
		t.Fatalf("summary = %+v, want the managed state purged", summary)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("~/.defenseclaw stayed: %v", err)
	}
}
