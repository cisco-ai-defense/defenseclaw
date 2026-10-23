// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// A '#' that is code in some interpreter must not hide a later writer call.
func TestLiteralCodePositionHashToken(t *testing.T) {
	cases := []struct {
		language string
		code     string
		want     bool
	}{
		{"node", `class A{#p=1}; require("fs").appendFileSync("out.txt","k")`, true},
		{"perl", `$#a; open(F, ">>", "out.txt")`, true},
		{"perl", `s#a#b#; open(F, ">>", "out.txt")`, true},
		{"perl", `#open(F, ">>", "out.txt")`, false},
		{"node", `x.#y; require("fs").writeFileSync("out.txt","k")`, true},
		{"python", "# open(\"out.txt\",\"w\")\nprint(1)", false},
		{"python", "print(1)  # open(\"out.txt\",\"w\")", false},
		{"python", "#open(\"out.txt\",\"w\")", false},
	}
	for _, tc := range cases {
		marker := "appendFileSync"
		if !strings.Contains(tc.code, marker) {
			marker = "open("
			if strings.Contains(tc.code, "writeFileSync") {
				marker = "writeFileSync"
			}
		}
		if got := literalCodePosition(tc.code, strings.Index(tc.code, marker), tc.language); got != tc.want {
			t.Errorf("literalCodePosition(%q) = %v, want %v", tc.code, got, tc.want)
		}
	}
}
