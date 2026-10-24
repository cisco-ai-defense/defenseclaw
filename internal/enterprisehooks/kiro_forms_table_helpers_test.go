// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// kiroFormsTableRow is one row of testdata/kiro_forms_table.json, the table
// Python's cli/tests/test_kiro_forms_table.py reads too.
type kiroFormsTableRow struct {
	Name     string            `json:"name"`
	Forms    map[string]string `json:"forms"`
	Enroll   string            `json:"enroll"`
	Verdicts map[string]string `json:"verdicts"`
	Action   string            `json:"action"`
	Observe  string            `json:"observe"`
	Doctor   string            `json:"doctor"`
}

const kiroFormsTableUnreadable = "unreadable"

func loadKiroFormsTable(t *testing.T) []kiroFormsTableRow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "kiro_forms_table.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Rows []kiroFormsTableRow `json:"rows"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Rows) == 0 {
		t.Fatal("empty Kiro forms table")
	}
	return table.Rows
}

// kiroTableEnrollVersion is the row version a table row's enrolled form
// records, or "".
func kiroTableEnrollVersion(row kiroFormsTableRow) string {
	switch row.Enroll {
	case "":
		return ""
	case "cli":
		return row.Forms[row.Enroll]
	default:
		return row.Forms[row.Enroll] + KiroIDEVersionSuffix
	}
}

// kiroTableUnprotectedCodes lists the codes of the row's forms that are not
// protected, sorted.
func kiroTableUnprotectedCodes(row kiroFormsTableRow) []string {
	var codes []string
	for _, verdict := range row.Verdicts {
		if verdict != "protected" {
			codes = append(codes, verdict)
		}
	}
	sort.Strings(codes)
	return codes
}

func admittedWord(admitted bool) string {
	if admitted {
		return "admitted"
	}
	return "refused"
}
