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
func TestPythonAssetNameFoldMatchesGo(t *testing.T) {
	want := renderPythonFoldTable()
	if *updateFoldTable {
		if err := os.WriteFile(pythonFoldTable, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.FromSlash(pythonFoldTable))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s is out of date with Go's unicode tables (Unicode %s); regenerate it with "+
			"go test ./internal/config -run TestPythonAssetNameFoldMatchesGo -update-fold-table",
			pythonFoldTable, unicode.Version)
	}
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
