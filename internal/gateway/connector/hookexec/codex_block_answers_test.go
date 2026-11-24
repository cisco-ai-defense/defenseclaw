// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// codexBlockAnswerTable is connector/testdata/codex_block_answers.json: the
// answer Codex gets for a block the hook makes itself, per contract and
// event. The rendered shell hook is held to the same table (connector
// TestCodexShellClosedAnswerMatchesTheNativeRunner).
type codexBlockAnswerTable struct {
	Reason  string `json:"reason"`
	Answers []struct {
		Contract string `json:"contract"`
		Event    string `json:"event"`
		Exit     int    `json:"exit"`
		Stdout   string `json:"stdout"`
	} `json:"answers"`
}

// GAP-1770: the native runner's block answers are the table's, event for
// event, so the shell hook can be compared with them.
func TestEmitCodexBlockMatchesTheSharedAnswerTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "codex_block_answers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table codexBlockAnswerTable
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Answers) == 0 || table.Reason == "" {
		t.Fatal("empty answer table")
	}
	for _, row := range table.Answers {
		var stdout bytes.Buffer
		code := emitCodexBlock(Options{HookContractID: row.Contract, Event: row.Event, Stdout: &stdout}, table.Reason)
		if code != row.Exit || stdout.String() != row.Stdout {
			t.Errorf("%q %s: exit %d stdout %q, want exit %d stdout %q", row.Contract, row.Event, code, stdout.String(), row.Exit, row.Stdout)
		}
	}
}
