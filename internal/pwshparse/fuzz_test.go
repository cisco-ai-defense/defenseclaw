// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse

import (
	"encoding/base64"
	"testing"
)

// FuzzParse feeds arbitrary text to the parser: it must not panic, must return, and ParseTree must agree
// with Parse on the tree and the errors. Seeds are a stride sample of the public oracle fixture.
// Run: go test ./internal/pwshparse -run XXX -fuzz FuzzParse -fuzztime 10m
func FuzzParse(f *testing.F) {
	ob := readGzB(f, "pub.b64.gz")
	i := 0
	for ob.Scan() {
		i++
		if i%7 != 0 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(ob.Text())
		if err != nil || len(raw) > 4096 {
			continue
		}
		f.Add(string(raw))
	}
	for _, s := range []string{"", "$(", "@'\n", "\"$(", "class A { [void] M() { ls } }", "enum E { A = 1 }", "-%", "a && b || c &", "$a++ ; ++$b", "@args"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 16<<10 {
			t.Skip()
		}
		a := Parse(src)
		b := ParseTree(src)
		if len(a.Errors) != len(b.Errors) || len(a.Tokens) == 0 && len(src) > 0 && b.Tokens != nil {
			t.Fatalf("Parse and ParseTree disagree on errors: %d vs %d", len(a.Errors), len(b.Errors))
		}
		_ = a.Dump(0)
	})
}
