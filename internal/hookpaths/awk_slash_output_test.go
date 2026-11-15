// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// rel-1-0-10:GAP-0654: the file-output scan of an awk program tells a regular
// expression from a division by the previous token, as the command scan does:
// a regular expression with a quote in it, after an operator, does not hide the
// print redirect that follows it.
func TestAwkOutputProofReadsARegexAfterAnOperator(t *testing.T) {
	for _, operator := range []string{"+", "-", "*", "%", "^", "<", ">", "==", "&&", "!"} {
		program := `BEGIN{ y = 1 ` + operator + ` /"/; print "a" > "out.txt"; z = 1 ` + operator + ` /"/ }`
		if output, _, _ := awkOutputProof(program, "/tmp/p", "/tmp/h"); !output {
			t.Errorf("a regular expression after %q hides the redirect", operator)
		}
	}
	for name, program := range map[string]string{
		"if header":     `BEGIN{ if (1) /"/; print "a" > "out.txt"; if (1) /"/ }`,
		"division":      `BEGIN{ x = a / 2; y = b / 3; print "a" > "out.txt" }`,
		"postfix":       `BEGIN{ x = i++ / 2; y = j++ / 3; print "a" > "out.txt" }`,
		"after a paren": `BEGIN{ x = (a) / 2; y = (b) / 3; print "a" > "out.txt" }`,
	} {
		if output, _, _ := awkOutputProof(program, "/tmp/p", "/tmp/h"); !output {
			t.Errorf("%s: the redirect is not read", name)
		}
	}
}
