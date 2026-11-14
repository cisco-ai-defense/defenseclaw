// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// shellRecallFixtureRow is one case of testdata/shell-recall-effects-v1.jsonl:
// a canonical command for one of the five shell-recall effect rules, written
// with reserved example hosts only. The gateway never-block test loads the
// same rows by id.
type shellRecallFixtureRow struct {
	ID      string `json:"id"`
	Rule    string `json:"rule"`
	Command string `json:"command"`
}

func loadShellRecallFixture(t testing.TB) []shellRecallFixtureRow {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "shell-recall-effects-v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var rows []shellRecallFixtureRow
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		var row shellRecallFixtureRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil || len(rows) == 0 {
		t.Fatalf("fixture rows=%d err=%v", len(rows), err)
	}
	return rows
}

func TestShellRecallFixtureRowsReportTheirRule(t *testing.T) {
	proofs := map[string]func(Facts) bool{
		"exec.escaped_binary_write":                   EscapedBinaryFileWrite,
		"account.literal_password_change_via_stdin":   LiteralStdinPasswordChange,
		"exec.download_then_run_fetched_file":         BareAddressDownloadThenRunFetchedFile,
		"source_control.clone_then_run_or_adhoc_push": GitCloneThenRunOrAdHocPush,
		"exec.inline_code_network_and_exec": func(facts Facts) bool {
			return InlineCodeNetworkAndExec(facts) || RemoteRunnerURL(facts)
		},
	}
	for _, row := range loadShellRecallFixture(t) {
		prove, ok := proofs[row.Rule]
		if !ok {
			t.Fatalf("%s: unknown rule %s", row.ID, row.Rule)
		}
		if !prove(srFacts(row.Command)) {
			t.Errorf("%s: %s does not report %q", row.ID, row.Rule, row.Command)
		}
	}
}
