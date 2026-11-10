// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"strings"
	"testing"
)

func boundTestWords(prefix string, n int) string {
	words := make([]string, n)
	for i := range words {
		words[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return strings.Join(words, " ")
}

func boundTestPlain(word string) bool { return strings.HasPrefix(word, "f") }

func TestBoundOperandsCountsOperandsOfOneStatement(t *testing.T) {
	bound := MaxOperandsPerStatement
	cases := []struct {
		name, command string
		over          bool
	}{
		{"at the bound", "touch " + boundTestWords("f", bound), false},
		{"past the bound", "touch " + boundTestWords("f", bound+1), true},
		{"statements are counted apart", strings.Repeat("touch "+boundTestWords("f", bound)+"; ", 3), false},
		{"pipeline stages are counted apart", strings.Repeat("echo "+boundTestWords("f", bound)+" | ", 3) + "wc", false},
		{"lines are counted apart", strings.Repeat("echo "+boundTestWords("f", bound)+"\n", 3), false},
		{"a quoted word is one operand", "echo \"" + boundTestWords("f", 5000) + "\"", false},
		{"an escaped blank joins a word", "echo " + strings.Repeat("a\\ b ", 800), false},
		{"parentheses end a statement", "(" + strings.Repeat("echo "+boundTestWords("f", bound)+"); (", 2) + "true)", false},
		{"the descriptor copy is no separator", "echo " + boundTestWords("f", bound) + " 2>&1", false},
		{"past the bound after a descriptor copy", "echo 2>&1 " + boundTestWords("f", bound+1), true},
	}
	for _, tc := range cases {
		reduced, over := BoundOperands(tc.command, boundTestPlain)
		if over != tc.over {
			t.Errorf("%s: over %v, want %v", tc.name, over, tc.over)
		}
		if !over && reduced != tc.command {
			t.Errorf("%s: a command within the bound changed", tc.name)
		}
	}
}

func TestBoundOperandsKeepsWhatCanNameAProtectedFile(t *testing.T) {
	bound := MaxOperandsPerStatement
	plain := boundTestWords("f", bound+10)
	cases := []struct {
		name, command string
		kept          []string
		dropped       []string
	}{
		{"later plain names are left out", "cp " + plain, []string{"f0", fmt.Sprintf("f%d", bound-2)}, []string{fmt.Sprintf("f%d", bound+9)}},
		{"a later path stays", "cp " + plain + " ../.ssh/authorized_keys", []string{"../.ssh/authorized_keys"}, []string{"f1030"}},
		{"a later variable stays", "cp " + plain + " $k", []string{"$k"}, nil},
		{"a redirect target stays", "echo " + plain + " >> link", []string{">>", "link"}, []string{"f1030"}},
		{"a redirect with its target in one word stays", "echo " + plain + " >>link", []string{">>link"}, nil},
		{"a later statement is read in full", "echo " + plain + "; echo f1 f2 ../x", []string{"f1 f2 ../x"}, nil},
	}
	for _, tc := range cases {
		reduced, over := BoundOperands(tc.command, boundTestPlain)
		if !over {
			t.Fatalf("%s: not over the bound", tc.name)
		}
		for _, word := range tc.kept {
			if !strings.Contains(reduced, word) {
				t.Errorf("%s: %q is not in the reduced command", tc.name, word)
			}
		}
		for _, word := range tc.dropped {
			if strings.Contains(reduced, " "+word+" ") || strings.HasSuffix(reduced, " "+word) {
				t.Errorf("%s: %q stayed in the reduced command", tc.name, word)
			}
		}
		if again, over := BoundOperands(reduced, boundTestPlain); over && again != reduced {
			// A reduced command may still be over the bound by the operands
			// it kept; it is judged once and its plain names are already out.
			t.Errorf("%s: a second reduction changed the command", tc.name)
		}
	}
}

func TestBoundOperandsKeepsAtMostABoundOfLaterOperands(t *testing.T) {
	bound := MaxOperandsPerStatement
	command := "cp " + boundTestWords("f", bound) + " " + boundTestWords("../x", 3*bound)
	reduced, over := BoundOperands(command, boundTestPlain)
	if !over {
		t.Fatal("not over the bound")
	}
	if got := len(strings.Fields(reduced)); got != 1+2*bound {
		t.Errorf("reduced command has %d words, want %d", got, 1+2*bound)
	}
}
