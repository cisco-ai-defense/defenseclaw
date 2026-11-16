//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0626: the pending restores of a pass that could not read the record
// were keyed by the spelling of its path, so a later readable pass that
// spelled the data directory another way did not record them.
func TestEnterpriseHookGuardianRestoresPendingSurvivesAnotherSpelling(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	shortenGuardianRestoreBackoff(t)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	const sid = "S-1-5-21-1-2-3-1001"
	at := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	rows := []enterpriseHookReconcileRow{{SID: sid, Connector: "hermes", OK: true}}
	previous := enterpriseHookGuardianRestoreRecordReader
	t.Cleanup(func() { enterpriseHookGuardianRestoreRecordReader = previous })
	sharing := errors.New("sharing violation")
	enterpriseHookGuardianRestoreRecordReader = func(string) (enterpriseHookGuardianRestoreRecord, error) {
		return enterpriseHookGuardianRestoreRecord{}, sharing
	}
	if err := recordEnterpriseHookGuardianRestores(io.Discard, strings.ToUpper(dataDir), rows, []enterpriseHookGuardianRestore{
		{SID: sid, Connector: "hermes", RestoredAt: at.Format(time.RFC3339Nano)},
	}); !errors.Is(err, sharing) {
		t.Fatalf("unreadable pass: %v, want the sharing error", err)
	}
	enterpriseHookGuardianRestoreRecordReader = previous
	if err := recordEnterpriseHookGuardianRestores(io.Discard, `\\?\`+filepath.Clean(dataDir), rows, nil); err != nil {
		t.Fatalf("readable pass: %v", err)
	}
	if restores := guardianRestoresForTest(t, dataDir); !restores[enterpriseHookGuardianRestoreKey(sid, "hermes")].Equal(at) {
		t.Fatalf("restores = %v, want the pending restore of the other spelling", restores)
	}
}
