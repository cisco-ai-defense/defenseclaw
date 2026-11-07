// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"fmt"
	"testing"
)

// GAP-0754: the parent reads a worker's progress lines while the worker still
// writes them, so the output may end in the middle of a line.
func TestParseEnterpriseHookWorkerOutputReadsProgressThenAnswer(t *testing.T) {
	var out bytes.Buffer
	writer := &enterpriseHookWorkerProgressWriter{out: &out}
	writer.begin()
	writer.end(enterpriseHookWorkerTargetResult{Index: 4, OK: true, Repaired: true})
	writer.begin()
	got := parseEnterpriseHookWorkerOutput(out.Bytes())
	if got.answered || got.repairing != 1 || len(got.repaired) != 1 || got.repaired[0].Index != 4 {
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
	writer.begin()
	writer.end(enterpriseHookWorkerTargetResult{Index: 2, OK: true, Repaired: true})
	cut := out.Len()
	writer.begin()
	got := parseEnterpriseHookWorkerOutput(out.Bytes()[:out.Len()-3])
	if got.repairing != 0 || len(got.repaired) != 1 || got.repaired[0].Index != 2 || got.err == nil {
		t.Fatalf("output cut at %d = %+v, want the complete lines only", cut, got)
	}
}

// A writer the parent did not ask for drops everything.
func TestEnterpriseHookWorkerProgressWriterIsNilSafe(t *testing.T) {
	var writer *enterpriseHookWorkerProgressWriter
	writer.begin()
	writer.end(enterpriseHookWorkerTargetResult{Index: 1, OK: true, Repaired: true})
}
