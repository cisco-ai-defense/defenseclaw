// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"fmt"
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
	if got.answered || got.repairing != 1 || len(got.repaired) != 2 || got.repaired[0].Index != 4 || got.repaired[1].Index != 5 {
		t.Fatalf("output = %+v, want one repair under way and targets 4 and 5 kept", got)
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
	if got.repairing != 0 || len(got.repaired) != 1 || got.repaired[0].Index != 2 || got.err == nil {
		t.Fatalf("output cut at %d = %+v, want the complete lines only", cut, got)
	}
}

// A repair that began and has no end line is a restore, unless the install
// only changes configuration or it ended without one.
func TestParseEnterpriseHookWorkerOutputKeepsAnUnfinishedRestoreOnly(t *testing.T) {
	var out bytes.Buffer
	writer := &enterpriseHookWorkerProgressWriter{out: &out}
	writer.begin(enterpriseHookWorkerTarget{Index: 1}, false) // configuration only
	writer.begin(enterpriseHookWorkerTarget{Index: 2}, true)
	writer.end(enterpriseHookWorkerTargetResult{Index: 2, Error: "failed"}) // ended without a restore
	writer.begin(enterpriseHookWorkerTarget{Index: 3}, true)
	got := parseEnterpriseHookWorkerOutput(out.Bytes())
	if got.repairing != 2 || len(got.repaired) != 1 || got.repaired[0].Index != 3 || !got.repaired[0].Repaired || got.repaired[0].Result == nil {
		t.Fatalf("output = %+v, want only target 3 kept", got)
	}
}

// A writer the parent did not ask for drops everything.
func TestEnterpriseHookWorkerProgressWriterIsNilSafe(t *testing.T) {
	var writer *enterpriseHookWorkerProgressWriter
	writer.begin(enterpriseHookWorkerTarget{Index: 1}, true)
	writer.end(enterpriseHookWorkerTargetResult{Index: 1, OK: true, Repaired: true})
}
