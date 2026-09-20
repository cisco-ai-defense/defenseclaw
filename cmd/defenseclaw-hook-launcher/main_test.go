// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestIdentityEntrypointRequiresExactArgument(t *testing.T) {
	if !isIdentityEntrypoint([]string{"--version-json"}) {
		t.Fatal("exact identity argument was not recognized")
	}
	for _, args := range [][]string{nil, {"--version-json", "extra"}, {"hook", "--version-json"}} {
		if isIdentityEntrypoint(args) {
			t.Fatalf("identity mode accepted %q", args)
		}
	}
}

func TestMachineIdentityReportsLinkedBuild(t *testing.T) {
	originalVersion, originalCommit, originalDate := version, commit, date
	t.Cleanup(func() { version, commit, date = originalVersion, originalCommit, originalDate })
	version = "1.2.3"
	commit = "0123456789abcdef0123456789abcdef01234567"
	date = "2026-07-28T00:00:00Z"
	var output bytes.Buffer
	if err := writeMachineIdentity(&output); err != nil {
		t.Fatalf("writeMachineIdentity: %v", err)
	}
	var report struct {
		SchemaVersion int    `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
		Built         string `json:"built"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	if report.SchemaVersion != 1 || report.Name != "defenseclaw-hook-launcher" ||
		report.Version != version || report.Commit != commit || report.Built != date {
		t.Fatalf("unexpected identity report: %+v", report)
	}
}
