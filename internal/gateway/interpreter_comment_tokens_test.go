// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// A '#' that is code in some interpreter must not hide a later writer call.
func TestInterpreterCodePositionHashToken(t *testing.T) {
	for _, tc := range []struct {
		language, code string
		want           bool
	}{
		{"node", `class A{#p=1}; require("fs").appendFileSync("out.txt","k")`, true},
		{"perl", `$#a; open(F, ">>", "out.txt")`, true},
		{"perl", `s#a#b#; open(F, ">>", "out.txt")`, true},
		{"perl", `#open(F, ">>", "out.txt")`, false},
		{"python", "# open(\"out.txt\",\"w\")\nprint(1)", false},
		{"python", "print(1)  # open(\"out.txt\",\"w\")", false},
		{"python", "#open(\"out.txt\",\"w\")", false},
	} {
		code, want := tc.code, tc.want
		marker := "open("
		if strings.Contains(code, "appendFileSync") {
			marker = "appendFileSync"
		}
		if got := interpreterCodePosition(code, strings.Index(code, marker), tc.language); got != want {
			t.Errorf("interpreterCodePosition(%q) = %v, want %v", code, got, want)
		}
	}
}
