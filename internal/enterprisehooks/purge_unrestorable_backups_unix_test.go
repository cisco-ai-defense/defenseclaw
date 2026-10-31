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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-2 GAP-0576: what an earlier failed install leaves in the
// ~/.defenseclaw of an account without an own install (a hook script, its
// hook token and hook config, and a connector backup record that names no
// file) is purged; the record, which no teardown can restore anything
// from, is kept beside the home with its bytes and named.
func TestPurgeUserStateRemovesAFailedInstallsLeftovers(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	record := `{"orphan":true}` + "\n"
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "hooks", "claude-code-hook.sh"), "#!/bin/sh\nexit 0\n", 0o700)
	writeOwnInstallTestFile(t, filepath.Join(dataDir, ".hook-claudecode.token"), "sample-not-a-secret\n", 0o600)
	writeOwnInstallTestFile(t, filepath.Join(dataDir, ".hookcfg-claudecode.json"), `{"orphan":true}`+"\n", 0o600)
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "connector_backups", "claudecode", "settings.json.json"), record, 0o600)
	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil || !summary.Data || summary.Kept {
		t.Fatalf("PurgeUserState = %+v, %v; want the leftovers purged", summary, err)
	}
	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("~/.defenseclaw stays: %v", err)
	}
	kept := filepath.Join(home, ".defenseclaw-unrestorable-connector-backups", "claudecode")
	if len(summary.KeptUnrestorableConnectorBackups) != 1 || summary.KeptUnrestorableConnectorBackups[0] != kept {
		t.Fatalf("kept folders %v, want %s", summary.KeptUnrestorableConnectorBackups, kept)
	}
	if got, err := os.ReadFile(filepath.Join(kept, "settings.json.json")); err != nil || string(got) != record {
		t.Fatalf("the record was not kept byte for byte: %q %v", got, err)
	}
}

// A record that carries a backup version or a path is a backup DefenseClaw
// reads: it is never moved aside.
func TestUnrestorableConnectorBackupKeepsReadableRecords(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]bool{
		`{"version":1,"path":"/home/sample/.claude/settings.json"}`: false,
		`{"version":0}`:                    false,
		`{"path":"/home/sample/.codex/x"}`: false,
		`{"orphan":true}`:                  true,
		`not json`:                         true,
	} {
		path := filepath.Join(dir, "r.json")
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := unrestorableConnectorBackup(path); got != body {
			t.Fatalf("unrestorableConnectorBackup(%s) = %t, want %t", name, got, body)
		}
	}
}
