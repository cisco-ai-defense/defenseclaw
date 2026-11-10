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

func boundTestPlain(word string) bool { return strings.HasPrefix(strings.Trim(word, "\"\x27"), "f") }

func TestBoundOperandsCountsTheOperandsOfTheWholeCall(t *testing.T) {
	bound := MaxOperandsPerCall
	cases := []struct {
		name, command string
		over          bool
	}{
		{"at the bound", "touch " + boundTestWords("f", bound), false},
		{"past the bound", "touch " + boundTestWords("f", bound+1), true},
		{"statements add up", strings.Repeat("touch "+boundTestWords("f", bound/2)+"; ", 3), true},
		{"five statements of a thousand", strings.Repeat("touch "+boundTestWords("f", 1000)+"; ", 5), true},
		{"pipeline stages add up", strings.Repeat("echo "+boundTestWords("f", bound/2)+" | ", 3) + "wc", true},
		{"lines add up", strings.Repeat("echo "+boundTestWords("f", bound/2)+"\n", 3), true},
		{"many short statements within the bound", strings.Repeat("echo "+boundTestWords("f", 9)+"\n", 100), false},
		{"a quoted word is one operand", "echo \"" + boundTestWords("f", 5000) + "\"", false},
		{"an escaped blank joins a word", "echo " + strings.Repeat("a\\ b ", 800), false},
		{"parentheses end a statement", "(" + strings.Repeat("echo "+boundTestWords("f", bound/2+1)+"); (", 2) + "true)", true},
		{"the descriptor copy is no operand", "echo " + boundTestWords("f", bound) + strings.Repeat(" 2>&1", 3000), false},
		{"options are no operands", "ls " + strings.Repeat("-l ", 3000) + boundTestWords("f", bound), false},
		{"the device names are no file targets", "echo x" + strings.Repeat(" 2>/dev/null", 3000), false},
		{"a here-document body is no operand list", "cat > out.txt <<\x27EOF\x27\n" + boundTestWords("f", 5000) + "\nEOF\necho done\n", false},
		{"an indented delimiter ends a <<- body", "cat <<-EOF\n\t" + boundTestWords("f", 5000) + "\n\tEOF\n", false},
		{"the words after the body are counted", "cat <<EOF\nx\nEOF\ntouch " + boundTestWords("f", bound+1), true},
		{"redirect targets are operands", "echo x" + strings.Repeat(" > f1", bound+1), true},
		{"redirect targets written together", "echo x " + strings.Repeat(">f1", bound+1), true},
		{"redirect targets of other statements add up", strings.Repeat("echo x > f1; ", bound+1), true},
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

func TestBoundOperandsKeepsEveryWordThatCanNameAProtectedFile(t *testing.T) {
	bound := MaxOperandsPerCall
	plain := boundTestWords("f", bound+10)
	cases := []struct {
		name, command string
		kept          []string
		dropped       []string
	}{
		{"later plain names are left out", "cp " + plain, []string{"cp", "f0", fmt.Sprintf("f%d", bound-2)}, []string{fmt.Sprintf("f%d", bound+9)}},
		{"a later path stays", "cp " + plain + " ../.ssh/authorized_keys", []string{"../.ssh/authorized_keys"}, []string{"f1030"}},
		{"a later variable stays", "cp " + plain + " $k", []string{"$k"}, nil},
		{"a later quoted path stays", "cp " + plain + " \"../.ssh/authorized_keys\"", []string{"\"../.ssh/authorized_keys\""}, nil},
		{"a later quoted plain name is left out", "cp " + plain + " \"f7777\" \x27f8888\x27", nil, []string{"\"f7777\"", "\x27f8888\x27"}},
		{"a later option stays", "cp " + plain + " --target=../x", []string{"--target=../x"}, nil},
		{"a later assignment stays", "k=../.ssh/authorized_keys; echo " + plain + " >> $k", []string{"k=../.ssh/authorized_keys", ">> $k"}, []string{"f1030"}},
		{"a plain redirect target is left out with its operator", "echo " + plain + " >> f5000", nil, []string{">> f5000", "f5000"}},
		{"a plain redirect target written with its operator is left out", "echo " + plain + " >>f5000", nil, []string{">>f5000"}},
		{"another redirect target stays with its operator", "echo " + plain + " >> ../link", []string{">> ../link"}, nil},
		{"the targets written together are judged apart", "echo " + plain + " >f5000>../link", []string{">../link"}, []string{">f5000"}},
		{"the program of a later statement stays", "echo " + plain + "; touch f1 f2 ../x", []string{"touch", "../x"}, []string{" f1 ", " f2 "}},
		{"the count goes on in the next statement", "echo " + plain + "; echo fzz gzz", []string{"gzz"}, []string{"fzz"}},
		{"a path after any amount of other paths stays", "cp " + plain + " " + boundTestWords("../x", 3*bound) + " ../.ssh/authorized_keys", []string{" ../.ssh/authorized_keys"}, nil},
		{"a here-document body is kept as it is", "cat <<EOF\nf1 f2\nEOF\ntouch " + plain, []string{"f1 f2\nEOF"}, []string{"f1030"}},
		{"a descriptor copy stays", "echo " + plain + " 2>&1", []string{"2>&1"}, nil},
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
			if strings.Contains(reduced, " "+word+" ") || strings.HasSuffix(reduced, " "+word) || strings.Contains(reduced, word+"\n") {
				t.Errorf("%s: %q stayed in the reduced command", tc.name, word)
			}
		}
		if again, _ := BoundOperands(reduced, boundTestPlain); again != reduced {
			t.Errorf("%s: a second reduction changed the command", tc.name)
		}
	}
}

// A call that only has plain names past the bound loses all of them, and
// nothing else: the reduced command is the first operands of each part.
func TestBoundOperandsLeavesTheFirstOperandsAndTheStructure(t *testing.T) {
	bound := MaxOperandsPerCall
	command := "cd d && touch " + boundTestWords("f", bound) + " && echo " + boundTestWords("f", 10) + " > f9 | wc -l"
	reduced, over := BoundOperands(command, boundTestPlain)
	if !over {
		t.Fatal("not over the bound")
	}
	if got := strings.Fields(reduced); got[0] != "cd" || got[len(got)-1] != "-l" || strings.Count(reduced, "&&") != 2 ||
		strings.Contains(reduced, "f1023") || strings.Contains(reduced, "> f9") || strings.Contains(reduced, ">") {
		t.Errorf("unexpected reduction %.60s...%.40s", reduced, reduced[len(reduced)-40:])
	}
}
