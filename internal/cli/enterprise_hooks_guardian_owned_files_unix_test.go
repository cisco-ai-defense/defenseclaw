// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0044: the standalone Unix pass records the fingerprints of the files
// of each target it verified, so status can see one overwritten after it.
func TestWriteEnterpriseHookGuardianOwnedFilesRecordsVerifiedTargetsOnly(t *testing.T) {
	dataDir := t.TempDir()
	home := t.TempDir()
	token := filepath.Join(home, ".hook-hermes.token")
	missing := filepath.Join(home, ".hook-optional")
	if err := os.WriteFile(token, []byte("issued\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []enterpriseHookReconcileRow{
		{User: "u", Connector: "Hermes", OK: true},
		{User: "u", Connector: "codex", Error: "verify failed"},
		{User: "v", Connector: "hermes", Pending: true},
	}
	owned := map[int][]string{0: {token, missing}, 1: {token}, 2: {token}}
	if err := writeEnterpriseHookGuardianOwnedFiles(io.Discard, dataDir, rows, map[int]int{0: 501}, owned); err != nil {
		t.Fatal(err)
	}
	record, err := enterprisehooks.ReadGuardianOwnedFilesRecord(filepath.Join(dataDir, enterprisehooks.GuardianOwnedFilesFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Targets) != 1 {
		t.Fatalf("targets = %+v, want only the verified one", record.Targets)
	}
	target := record.Targets[0]
	if target.User != "u" || target.UID != 501 || target.Connector != "hermes" || len(target.Files) != 1 || target.Files[0].Path != token {
		t.Fatalf("target = %+v", target)
	}
	if info, err := os.Stat(filepath.Join(dataDir, enterprisehooks.GuardianOwnedFilesFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode = %v, %v; want root-only 0600", info, err)
	}
	if changed := target.ChangedFiles(enterprisehooks.OwnedFileFingerprint); len(changed) != 0 {
		t.Fatalf("changed = %v right after the pass", changed)
	}
}
