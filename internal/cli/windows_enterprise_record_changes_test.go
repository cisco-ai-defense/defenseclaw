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

type warningRecorder struct{ warnings [][2]string }

func (w *warningRecorder) AddWarning(code, message string) {
	w.warnings = append(w.warnings, [2]string{code, message})
}

// Review D4: status and verify warn by name about a kept copy that still
// carries another account's access, with the exact fix; a stamped copy and a
// host with none are silent.
func TestWindowsEnterpriseKeptRecordWarningsNameTheUnprotectedCopy(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "deployment.json.rejected-20261109T000000000Z-aaaaaaaaaaaa")
	stamped := filepath.Join(dir, "agent-application-control-attestation.json.rejected-20261109T000000000Z-bbbbbbbbbbbb")
	for _, path := range []string{open, stamped, filepath.Join(dir, "deployment.json")} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	original := windowsEnterpriseKeptRecordUntrusted
	t.Cleanup(func() { windowsEnterpriseKeptRecordUntrusted = original })
	windowsEnterpriseKeptRecordUntrusted = func(path string) bool { return path == open }
	var recorded warningRecorder
	addWindowsEnterpriseKeptRecordWarnings(&recorded, dir)
	if len(recorded.warnings) != 1 || recorded.warnings[0][0] != "kept_record_unprotected" {
		t.Fatalf("warnings = %q, want one kept_record_unprotected", recorded.warnings)
	}
	message := recorded.warnings[0][1]
	for _, want := range []string{open, `icacls "` + open + `" /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)"`, `icacls "` + open + `" /setowner *S-1-5-32-544`, "/repair"} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q lacks %q", message, want)
		}
	}
	if strings.Contains(message, stamped) || strings.Contains(message, "<path>") {
		t.Errorf("message names the stamped copy or holds a template: %q", message)
	}
	// A host with no kept copy, or only stamped ones, says nothing.
	windowsEnterpriseKeptRecordUntrusted = func(string) bool { return false }
	var quiet warningRecorder
	addWindowsEnterpriseKeptRecordWarnings(&quiet, dir)
	addWindowsEnterpriseKeptRecordWarnings(&quiet, filepath.Join(dir, "absent"))
	if len(quiet.warnings) != 0 {
		t.Errorf("warnings = %q, want none", quiet.warnings)
	}
}
