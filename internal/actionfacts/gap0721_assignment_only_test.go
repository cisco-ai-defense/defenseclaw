// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// GAP-0721: a statement that only assigns (`p=$!`, `a=b c=d`) is a call with
// no program word. Once a command had left the working directory unknown, the
// relative-path check sliced the call arguments past the program word and
// panicked on a call that has none, so one ordinary command (a background
// reader with a pid variable after `cd dir && (...)`) failed the whole hook
// evaluation. The check now answers for every call shape, program word or not.
func TestGAP0721AssignmentOnlyStatementsHaveNoRelativeOperand(t *testing.T) {
	for _, source := range []string{
		"p=$!", "a=b", "a=b c=d", "a=../b", "p=$(date)", `a="x y"`, "A=1 B=2 C=3",
	} {
		t.Run(source, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("simpleRelativePathOperand(%q) panicked: %v", source, r)
				}
			}()
			if simpleRelativePathOperand(source) {
				t.Fatalf("simpleRelativePathOperand(%q) = true; an assignment has no path operand", source)
			}
		})
	}
	// An assignment with a redirect is judged by the redirect, as before.
	for _, source := range []string{"a=b >out", "> out", "3<>sock"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("simpleRelativePathOperand(%q) panicked: %v", source, r)
				}
			}()
			simpleRelativePathOperand(source)
		}()
	}
	// The benign twin keeps the check: a program with a relative operand.
	if !simpleRelativePathOperand("cat ./notes.txt") {
		t.Fatal("a relative operand must still be reported")
	}
}

// The shape of the failing trajectory row, with synthetic names: a directory
// change, then a subshell that assigns from `$!`, in the background.
func TestGAP0721PidAssignmentAfterDirectoryChangeIsDecomposed(t *testing.T) {
	for _, command := range []string{
		`cd /app && (exec 3<>/tmp/x.sock; cat <&3 & p=$!; printf "a" >&3; sleep 5; kill $p 2>/dev/null) > /tmp/out.txt 2>&1 & echo started; sleep 8; cat /tmp/out.txt`,
		`cd "$d" && p=$!; echo "$p"`,
		`cd /app && a=b c=d; ls`,
		`cd /app && (p=$!) & wait`,
	} {
		t.Run(command, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SimpleCommands(%q) panicked: %v", command, r)
				}
			}()
			input := Input{Tool: "shell", Command: command, DialectHint: DialectPOSIX}
			if got := SimpleCommands(input, Analyze(input)); len(got) == 0 {
				t.Fatalf("SimpleCommands(%q) returned no commands", command)
			}
		})
	}
}
