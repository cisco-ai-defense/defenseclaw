// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// pythonFoldTable is the Python twin of SameAssetName's case folding:
// cli/defenseclaw/enforce/admission.py asset_name_key folds each character
// with this table, generated from Go's own unicode tables. Python's
// str.casefold and str.lower differ from strings.EqualFold (U+FB05 and
// U+FB06 are one letter to Go, two to Python) and follow the Unicode
// version of the interpreter, so the CLI pre-install deny check let through
// a spelling the gateway denies.
const pythonFoldTable = "../../cli/defenseclaw/enforce/_asset_name_fold.py"

var updateFoldTable = flag.Bool("update-fold-table", false, "rewrite "+pythonFoldTable+" from Go's unicode tables")

// TestPythonAssetNameFoldMatchesGo fails when the Python table and Go's
// strings.EqualFold disagree. Regenerate with
// go test ./internal/config -run TestPythonAssetNameFoldMatchesGo -update-fold-table
//
// The table is the fold of the toolchain go.mod pins, which CI and the
// release build with. Under that Go minor version the table must match byte
// for byte. A newer local toolchain has a later Unicode (Go 1.27 has Unicode
// 17 and folds U+FB05 with U+FB06), so there the test checks that every fold
// the table records still holds; byte equality there failed on a table that
// is right for the shipped gateway (rel-1-0-6 GAP-0348).
func TestPythonAssetNameFoldMatchesGo(t *testing.T) {
	pinned, running := pinnedGoMinor(t), goMinor(runtime.Version())
	want := renderPythonFoldTable()
	if *updateFoldTable {
		if running != pinned {
			t.Fatalf("regenerate %s with the pinned toolchain %s, not %s", pythonFoldTable, pinned, runtime.Version())
		}
		if err := os.WriteFile(pythonFoldTable, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.FromSlash(pythonFoldTable))
	if err != nil {
		t.Fatal(err)
	}
	if running != pinned {
		t.Logf("%s is not the pinned %s: checking that every fold of the table holds under Unicode %s",
			runtime.Version(), pinned, unicode.Version)
		for _, fold := range parsePythonFoldRuns(t, string(got)) {
			if !strings.EqualFold(string(fold[0]), string(fold[1])) {
				t.Errorf("%s folds U+%04X to U+%04X; strings.EqualFold under %s does not",
					pythonFoldTable, fold[0], fold[1], runtime.Version())
			}
		}
		return
	}
	if string(got) != want {
		t.Fatalf("%s is out of date with Go's unicode tables (Unicode %s); regenerate it with "+
			"go test ./internal/config -run TestPythonAssetNameFoldMatchesGo -update-fold-table",
			pythonFoldTable, unicode.Version)
	}
}

// pinnedGoMinor is the Go minor version (go1.26) of go.mod's toolchain line,
// else of its go line.
func pinnedGoMinor(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash("../../go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var goLine, toolchain string
	for _, line := range strings.Split(string(data), "\n") {
		switch fields := strings.Fields(line); {
		case len(fields) == 2 && fields[0] == "go":
			goLine = "go" + fields[1]
		case len(fields) == 2 && fields[0] == "toolchain":
			toolchain = fields[1]
		}
	}
	if toolchain != "" {
		goLine = toolchain
	}
	minor := goMinor(goLine)
	if minor == "" {
		t.Fatalf("go.mod pins no Go version (go line %q, toolchain %q)", goLine, toolchain)
	}
	return minor
}

// goMinor is the language version of a toolchain name (go1.27.1 is go1.27);
// a development build has none.
func goMinor(version string) string {
	parts := strings.SplitN(strings.TrimPrefix(version, "go"), ".", 3)
	if len(parts) < 2 {
		return ""
	}
	for _, part := range parts[:2] {
		if _, err := strconv.Atoi(part); err != nil {
			return ""
		}
	}
	return "go" + parts[0] + "." + parts[1]
}

// parsePythonFoldRuns reads the FOLD_RUNS of the Python table as the code
// point pairs it folds (start:count:stride:delta, start in hex).
func parsePythonFoldRuns(t *testing.T, table string) [][2]rune {
	t.Helper()
	_, body, found := strings.Cut(table, `FOLD_RUNS = """`)
	if !found {
		t.Fatalf("%s has no FOLD_RUNS", pythonFoldTable)
	}
	body, _, _ = strings.Cut(body, `"""`)
	var folds [][2]rune
	for _, item := range strings.Fields(body) {
		var start, count, stride, delta int
		if n, err := fmt.Sscanf(item, "%x:%d:%d:%d", &start, &count, &stride, &delta); n != 4 || err != nil {
			t.Fatalf("%s: run %q is not start:count:stride:delta", pythonFoldTable, item)
		}
		for i := range count {
			r := rune(start + i*stride)
			folds = append(folds, [2]rune{r, r + rune(delta)})
		}
	}
	if len(folds) == 0 {
		t.Fatalf("%s has an empty FOLD_RUNS", pythonFoldTable)
	}
	return folds
}

// foldKey is the code point each rune of a strings.EqualFold orbit folds to
// in the Python table: the lower case of the orbit's smallest member when
// that is in the orbit, else the smallest member.
func foldKey(r rune) rune {
	least := orbitMin(r)
	if lower := unicode.ToLower(least); orbitMin(lower) == least {
		return lower
	}
	return least
}

// orbitMin is the smallest rune strings.EqualFold equates with r.
func orbitMin(r rune) rune {
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		least = min(least, f)
	}
	return least
}

func renderPythonFoldTable() string {
	type run struct {
		start             rune
		count, stride, dt int
	}
	var runs []run
	for r := rune(0); r <= unicode.MaxRune; r++ {
		key := foldKey(r)
		if key == r {
			continue
		}
		delta := int(key - r)
		if n := len(runs); n > 0 {
			last := &runs[n-1]
			next := last.start + rune(last.count*last.stride)
			switch {
			case last.count == 1 && last.dt == delta:
				last.stride, last.count = int(r-last.start), 2
				continue
			case last.count > 1 && last.dt == delta && r == next:
				last.count++
				continue
			}
		}
		runs = append(runs, run{start: r, count: 1, stride: 1, dt: delta})
	}
	var b strings.Builder
	b.WriteString(`# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Case folding of Go's strings.EqualFold, for asset_name_key.

Generated from Go's unicode tables by internal/config/asset_names_fold_test.go;
do not edit. Regenerate with
go test ./internal/config -run TestPythonAssetNameFoldMatchesGo -update-fold-table
Each run is start:count:stride:delta (start in hex): count code points from
start, stride apart, each folding to itself plus delta.
"""

`)
	fmt.Fprintf(&b, "UNICODE_VERSION = %q\n\nFOLD_RUNS = \"\"\"\n", unicode.Version)
	line := ""
	for _, r := range runs {
		item := fmt.Sprintf("%x:%d:%d:%d", r.start, r.count, r.stride, r.dt)
		if len(line)+1+len(item) > 100 {
			b.WriteString(line + "\n")
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += item
	}
	if line != "" {
		b.WriteString(line + "\n")
	}
	b.WriteString("\"\"\"\n")
	return b.String()
}
