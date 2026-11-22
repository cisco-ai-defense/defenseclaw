// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestDET111R2WrapperGrammarOracle(t *testing.T) {
	f, err := os.Open("testdata/det111_r2_wrappers.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	seen := map[string]bool{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 8 {
			t.Fatalf("oracle row has %d fields, want 8: %q", len(f), line)
		}
		name := f[0]
		if seen[name] {
			t.Fatalf("duplicate wrapper oracle row %q", name)
		}
		seen[name] = true
		row, ok := wrapperTable[name]
		if !ok {
			t.Errorf("oracle wrapper %q missing from table", name)
			continue
		}
		var skip int
		if _, err := fmt.Sscanf(f[1], "%d", &skip); err != nil {
			t.Fatalf("%s child index: %v", name, err)
		}
		if row.posSkip != skip {
			t.Errorf("%s child argv: skipped %d, want %d", name, row.posSkip, skip)
		}
		if !sameR2Set([]string{row.shorts}, strings.Fields(f[2])) {
			t.Errorf("%s short flags mismatch", name)
		}
		if !sameR2Set(strings.Fields(row.optional), strings.Fields(f[3])) {
			t.Errorf("%s attached-only options mismatch", name)
		}
		if !sameR2Set(row.valued, strings.Fields(f[4])) {
			t.Errorf("%s valued options mismatch", name)
		}
		if !sameR2Set(row.longs, strings.Fields(f[5])) {
			t.Errorf("%s long flags mismatch", name)
		}
		if !sameR2Set(row.stop, strings.Fields(f[6])) {
			t.Errorf("%s stop options mismatch", name)
		}
		if row.shellAfterSkip != (f[7] == "true") {
			t.Errorf("%s shell-after-skip mismatch", name)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 7 {
		t.Fatalf("loaded %d oracle rows, want 7", len(seen))
	}
}

func sameR2Set(a, b []string) bool {
	clean := func(values []string) []string {
		out := make([]string, 0, len(values))
		for _, v := range values {
			if v != "" {
				out = append(out, v)
			}
		}
		sort.Strings(out)
		return out
	}
	a, b = clean(a), clean(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
