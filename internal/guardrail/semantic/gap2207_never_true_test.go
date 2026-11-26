// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package semantic

import "testing"

// TestGAP2207NeverTrueFoldsConstantFalse: a program whose expression folds
// to the constant false is NeverTrue; any expression that reads the facts
// is not. Red at det111/t23e6-merge f6e151801a (no NeverTrue).
func TestGAP2207NeverTrueFoldsConstantFalse(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	const reads = "f.commands.exists(c, c.argv_complete)"
	for _, tc := range []struct {
		expression string
		never      bool
	}{
		{"false", true},
		{"false && " + reads, true},
		{reads + " && false", true},
		{"1 == 2", true},
		{"!true", true},
		{"true && false", true},
		{reads, false},
		{reads + " || false", false},
		{"true", false},
		{"false || " + reads, false},
	} {
		program, code := compiler.Compile(tc.expression)
		if code != CompileOK {
			t.Fatalf("%q: compile %v", tc.expression, code)
		}
		if got := program.NeverTrue(); got != tc.never {
			t.Errorf("%q: NeverTrue = %t, want %t", tc.expression, got, tc.never)
		}
	}
}
