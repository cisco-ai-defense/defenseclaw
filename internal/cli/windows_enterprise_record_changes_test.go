// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The result of a repair that kept a changed record aside names each kept
// file, and only the ones kept during this run (GAP-0602).
func TestWindowsEnterpriseKeptRecordChangesNameThisRunsFilesOnly(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Minute)
	stamp := func(at time.Time) string { return at.UTC().Format("20060102T150405") + "000Z" }
	old := filepath.Join(dir, "deployment.json.rejected-20200101T000000000Z-aaaaaaaaaaaa")
	kept := filepath.Join(dir, "deployment.json.rejected-"+stamp(time.Now())+"-bbbbbbbbbbbb")
	attestation := filepath.Join(dir, "agent-application-control-attestation.json.rejected-"+stamp(time.Now())+"-cccccccccccc")
	// The kept file's own times are old: a rename keeps them.
	past := time.Now().Add(-48 * time.Hour)
	for _, path := range []string{old, kept, attestation} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, past, past); err != nil {
			t.Fatal(err)
		}
	}
	changes := windowsEnterpriseKeptRecordChanges(dir, started)
	if len(changes) != 2 {
		t.Fatalf("changes = %q, want the deployment record and the attestation of this run", changes)
	}
	joined := strings.Join(changes, "\n")
	if strings.Contains(joined, old) || !strings.Contains(joined, kept) || !strings.Contains(joined, attestation) {
		t.Fatalf("changes = %q", changes)
	}
	if !strings.Contains(joined, "attest again with enterprise windows repair --attest-agent-application-control") {
		t.Fatalf("the attestation change does not say how to attest again: %q", changes)
	}
}
