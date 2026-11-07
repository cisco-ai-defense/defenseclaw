// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0754: the parent reads the progress lines of a worker while the worker
// still writes them, so the output may end in the middle of a line.
func TestParseEnterpriseHookWorkerOutputReadsProgressThenAnswer(t *testing.T) {
	var out bytes.Buffer
	writer := &enterpriseHookWorkerProgressWriter{out: &out}
	writer.begin(enterpriseHookWorkerTarget{Index: 4}, true)
	writer.end(enterpriseHookWorkerTargetResult{Index: 4, OK: true, Repaired: true})
	writer.begin(enterpriseHookWorkerTarget{Index: 5}, true)
	got := parseEnterpriseHookWorkerOutput(out.Bytes())
	if got.answered || got.repairing != 1 || len(got.repaired) != 1 || got.repaired[0].Index != 4 || !got.restoring[5] {
		t.Fatalf("output = %+v, want one repair under way and target 4 kept", got)
	}
	writer.end(enterpriseHookWorkerTargetResult{Index: 5, OK: true}) // verified, not repaired: nothing to keep
	fmt.Fprintf(&out, `{"version":%d,"targets":[{"index":4,"ok":true,"repaired":true}]}`+"\n", enterpriseHookWorkerProtocolVersion)
	got = parseEnterpriseHookWorkerOutput(out.Bytes())
	if !got.answered || got.repairing != 0 || len(got.response.Targets) != 1 {
		t.Fatalf("output = %+v, want the answer after two ended repairs", got)
	}
}

func TestParseEnterpriseHookWorkerOutputIgnoresACutLine(t *testing.T) {
	var out bytes.Buffer
	writer := &enterpriseHookWorkerProgressWriter{out: &out}
	writer.begin(enterpriseHookWorkerTarget{Index: 2}, true)
	writer.end(enterpriseHookWorkerTargetResult{Index: 2, OK: true, Repaired: true})
	cut := out.Len()
	writer.begin(enterpriseHookWorkerTarget{Index: 3}, true)
	got := parseEnterpriseHookWorkerOutput(out.Bytes()[:out.Len()-3])
	if got.repairing != 0 || len(got.repaired) != 1 || got.repaired[0].Index != 2 || got.restoring[3] || got.err == nil {
		t.Fatalf("output cut at %d = %+v, want the complete lines only", cut, got)
	}
}

// A repair that began and has no end line is a target under repair, never a
// healthy one: the parse keeps only what the worker ended, and names the
// targets whose repair rewrites hook files (a configuration-only repair has
// no restore to look for).
func TestParseEnterpriseHookWorkerOutputNamesUnfinishedRestoresWithoutKeepingThem(t *testing.T) {
	var out bytes.Buffer
	writer := &enterpriseHookWorkerProgressWriter{out: &out}
	writer.begin(enterpriseHookWorkerTarget{Index: 1}, false) // configuration only
	writer.begin(enterpriseHookWorkerTarget{Index: 2}, true)
	writer.end(enterpriseHookWorkerTargetResult{Index: 2, Error: "failed"}) // ended without a restore
	writer.begin(enterpriseHookWorkerTarget{Index: 3}, true)
	got := parseEnterpriseHookWorkerOutput(out.Bytes())
	if got.repairing != 2 || len(got.repaired) != 0 || got.restoring[1] || !got.restoring[2] || !got.restoring[3] {
		t.Fatalf("output = %+v, want two repairs under way, none kept, restores named for 2 and 3", got)
	}
}

// The restore evidence is the owned files: an unchanged file is no restore, a
// changed one is, and a healthy answer keeps what its worker said.
func TestRestoreFilesMarkOnlyTargetsWhoseFilesChanged(t *testing.T) {
	dir := t.TempDir()
	tampered, same, healthy := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	for _, path := range []string{tampered, same, healthy} {
		if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := enterpriseHookWorkerRestoreFiles{
		1: {tampered: enterpriseHookOwnedFileFingerprint(tampered)},
		2: {same: enterpriseHookOwnedFileFingerprint(same)},
		3: {healthy: enterpriseHookOwnedFileFingerprint(healthy)},
	}
	for _, path := range []string{tampered, healthy} {
		if err := os.WriteFile(path, []byte("restored"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	restoring := map[int]bool{1: true, 2: true, 3: true}
	got := files.withRestores([]enterpriseHookWorkerTargetResult{{Index: 2, Error: "failed"}, {Index: 3, OK: true}}, restoring, errors.New("worker ended"))
	if len(got) != 3 ||
		got[0].Index != 1 || !got[0].Repaired || got[0].OK || got[0].Error != "worker ended" ||
		got[1].Index != 2 || got[1].Repaired || got[1].OK ||
		got[2].Index != 3 || got[2].Repaired || !got[2].OK {
		t.Fatalf("results = %+v, want 1 restored but failed, 2 untouched, 3 as the worker said", got)
	}
}

// A writer the parent did not ask for drops everything.
func TestEnterpriseHookWorkerProgressWriterIsNilSafe(t *testing.T) {
	var writer *enterpriseHookWorkerProgressWriter
	writer.begin(enterpriseHookWorkerTarget{Index: 1}, true)
	writer.end(enterpriseHookWorkerTargetResult{Index: 1, OK: true, Repaired: true})
}
