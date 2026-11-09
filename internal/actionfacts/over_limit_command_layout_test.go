// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// TestReadCommandLayout pins what the layout reading knows of a command text
// (GAP-0934): the comments and the here-document bodies that only feed data
// are skipped, the cd and assignment statements that run in order in the main
// shell are straight, and a text with a group, a function or a loop is not
// sequential. A construct the reading does not follow gives no layout.
func TestReadCommandLayout(t *testing.T) {
	type want struct {
		skipped    []string
		straight   []string
		sequential bool
	}
	for _, c := range []struct {
		name, text string
		want       want
		unreadable bool
	}{
		{"list", "cd /etc; F=x\nls a > f", want{straight: []string{"cd", "F=x"}, sequential: true}, false},
		{"and list", "cd /etc && ls a", want{sequential: true}, false},
		{"or list", "ls a || cd /etc", want{sequential: true}, false},
		{"pipeline", "cd /etc | cat", want{sequential: true}, false},
		{"background", "cd /etc &", want{sequential: true}, false},
		{"redirected cd", "cd /etc 2>/dev/null; ls a", want{sequential: true}, false},
		{"prefix assignment", "F=x true; ls a", want{sequential: true}, false},
		{"declaration", "export F=x G=y; ls a", want{straight: []string{"F=x", "G=y"}, sequential: true}, false},
		{"comment", "ls a # note\nls b", want{skipped: []string{"# note"}, sequential: true}, false},
		{"hash in a word", "ls a#b", want{sequential: true}, false},
		{"data document", "cat <<EOF\nx > y\nEOF\nls a", want{skipped: []string{"x > y\nEOF\n"}, sequential: true}, false},
		{"shell document", "sh <<EOF\nx > y\nEOF\nls a", want{sequential: true}, false},
		{"document in a pipe to a shell", "cat <<EOF | sh\nx\nEOF\n", want{sequential: true}, false},
		{"document in arithmetic", "((i<<EOF))\nx\nEOF\n", want{sequential: false}, false},
		{"two documents", "cat <<A <<B\n1\nA\n2\nB\n", want{skipped: []string{"1\nA\n", "2\nB\n"}, sequential: true}, false},
		{"group", "{ cd /etc; }", want{sequential: false}, false},
		{"subshell", "(cd /etc)", want{sequential: false}, false},
		{"function", "f() { cd /etc; }", want{sequential: false}, false},
		{"loop", "for d in a; do cd /etc; done", want{sequential: false}, false},
		{"condition", "if true; then cd /etc; fi", want{sequential: false}, false},
		{"trap", "trap 'cd /etc' EXIT", want{sequential: false}, false},
		{"quoted keyword is no keyword", "'if' x", want{sequential: true}, false},
		{"substitution", "echo $(date)", want{sequential: true}, false},
		{"backtick", "echo `date`", want{sequential: true}, false},
		{"expansion with an operator", "echo ${F:-x}", want{skipped: []string{"${F:-x}"}, sequential: true}, false},
		{"arithmetic", "echo $((1+1))", want{sequential: true}, false},
		{"ansi quote", "echo $'a'", want{skipped: []string{"$'a'"}, sequential: true}, false},
		{"ansi quote with an escaped quote", "echo $'a\\'b'", want{skipped: []string{"$'a\\'b'"}, sequential: true}, false},
		{"unterminated substitution", "echo $(date", want{}, true},
		{"unterminated backtick", "echo `date", want{}, true},
		{"unterminated expansion", "echo ${F:-x", want{}, true},
		{"arithmetic bracket", "echo $[1+1]", want{}, true},
		{"parenthesis in a quote of a substitution", "echo $(printf %s ')' \")\") x", want{skipped: []string{"%s", "')'", "\")\"", "x"}, sequential: true}, false},
		{"brace in a quote of an expansion", "echo ${F:-'}'} x", want{skipped: []string{"${F:-'}'}", "x"}, sequential: true}, false},
		{"nested substitution", "echo $(a $(b) c) x", want{skipped: []string{"x"}, sequential: true}, false},
		{"printed text inside a substitution", "ls $(echo 'a > b' c) d", want{skipped: []string{"'a > b'", "c"}, sequential: true}, false},
		{"comment inside a substitution", "ls $(ls a # n\n) d", want{skipped: []string{"# n"}, sequential: true}, false},
		{"printed text inside a backtick stays text", "ls `echo 'a > b'` d", want{sequential: true}, false},
		{"dollar before a closing quote", "echo \"a$\" b", want{skipped: []string{"\"a$\"", "b"}, sequential: true}, false},
		{"substitution after printed words", "printf %s cp a $(date) > f", want{skipped: []string{"%s", "cp", "a"}, sequential: true}, false},
		{"substitution before printed words", "printf %s \"$(date)\" cp a b > f", want{skipped: []string{"%s", "\"", "\"", "cp", "a", "b"}, sequential: true}, false},
		{"unrelated substitution before a printf", ": \"$(date)\"; printf %s cp a b", want{skipped: []string{"\"", "\"", "%s", "cp", "a", "b"}, sequential: true}, false},
		{"assignment of a substitution", "F=$(pwd); cd /etc", want{straight: []string{"F=$(pwd)", "cd"}, sequential: true}, false},
		{"expansion that assigns", "echo ${F:=x}", want{sequential: false}, false},
		{"expansion that assigns by a plain operator", "echo ${F=x}", want{sequential: false}, false},
		{"expansion that assigns with a subscript", "echo ${F[1]:-x}", want{sequential: false}, false},
		{"expansion with a default and a redirect", "echo ${F:-a > b }", want{skipped: []string{"${F:-a > b }"}, sequential: true}, false},
		{"expansion with a substitution inside", "echo ${F:-$(a)} x", want{skipped: []string{"${F:-", "}", "x"}, sequential: true}, false},
		{"unquoted document with a default and a redirect", "cat <<EOF\n${F:-x > y }\nEOF\n", want{skipped: []string{"${F:-x > y }\nEOF\n"}, sequential: true}, false},
		{"unquoted document with a default around a substitution", "cat <<EOF\n${F:-a > b $(date) c > d }\nEOF\n", want{skipped: []string{"${F:-a > b ", " c > d }\nEOF\n"}, sequential: true}, false},
		{"cd inside a substitution", "echo $(cd /etc; ls)", want{straight: []string{"cd"}, sequential: true}, false},
		{"cd inside a substitution with a group", "echo $(cd /etc; { ls; })", want{sequential: true}, false},
		{"cd inside a backtick", "echo `cd /etc; ls`", want{sequential: true}, false},
		{"assignment inside a nested substitution", "echo $(echo $(F=x; ls))", want{straight: []string{"F=x"}, sequential: true}, false},
		{"process substitution", "cat <(ls)", want{}, true},
		{"unterminated quote", "echo 'a", want{}, true},
		{"unterminated double quote", "echo \"a", want{}, true},
		{"substitution in a double quote", "echo \"$(date)\"", want{skipped: []string{"\"", "\""}, sequential: true}, false},
		{"backtick in a double quote", "echo \"a`date`b\"", want{skipped: []string{"\"a", "b\""}, sequential: true}, false},
		{"braced name in a double quote", "echo \"${F}\"", want{skipped: []string{"\"${F}\""}, sequential: true}, false},
		{"text of an echo", "echo 'a > b' \"c\" d", want{skipped: []string{"'a > b'", "\"c\"", "d"}, sequential: true}, false},
		{"unquoted text of a printf", "printf %s cp a b > f", want{skipped: []string{"%s", "cp", "a", "b"}, sequential: true}, false},
		{"redirect of an echo is no text", "echo a >> b", want{skipped: []string{"a"}, sequential: true}, false},
		{"unquoted document with a plain body", "cat <<EOF\nx > y\nEOF\n", want{skipped: []string{"x > y\nEOF\n"}, sequential: true}, false},
		{"unquoted document with a substitution", "cat <<EOF\n$(x > y)\nEOF\n", want{skipped: []string{"\nEOF\n"}, sequential: true}, false},
		{"unquoted document with a backtick", "cat <<EOF\n`x > y`\nEOF\n", want{skipped: []string{"\nEOF\n"}, sequential: true}, false},
		{"unquoted document with a literal after a substitution", "cat <<EOF\n$(date)\nx > y\nEOF\n", want{skipped: []string{"\nx > y\nEOF\n"}, sequential: true}, false},
		{"unquoted document with a literal before a substitution", "cat <<EOF\nx > y\n$(date)\nEOF\n", want{skipped: []string{"x > y\n", "\nEOF\n"}, sequential: true}, false},
		{"unquoted document with a quote in a substitution", "cat <<EOF\n$(printf %s ')')\nx > y\nEOF\n", want{skipped: []string{"%s", "')'", "\nx > y\nEOF\n"}, sequential: true}, false},
		{"unquoted document with printed text in a substitution", "cat <<EOF\n$(printf %s 'x > y')\nEOF\n", want{skipped: []string{"%s", "'x > y'", "\nEOF\n"}, sequential: true}, false},
		{"unquoted document with a braced expansion", "cat <<EOF\n${F:-$(date)}\nx > y\nEOF\n", want{skipped: []string{"${F:-", "}\nx > y\nEOF\n"}, sequential: true}, false},
		{"unquoted document with a substitution that does not close", "cat <<EOF\nx > y\n$(date\nEOF\n", want{skipped: []string{"x > y\n"}, sequential: true}, false},
		{"unquoted document with an escaped substitution", "cat <<EOF\n\\$(x > y)\nEOF\n", want{skipped: []string{"\\$(x > y)\nEOF\n"}, sequential: true}, false},
		{"quoted document with a substitution", "cat <<'EOF'\n$(x > y)\nEOF\n", want{skipped: []string{"$(x > y)\nEOF\n"}, sequential: true}, false},
		{"escaped delimiter document with a substitution", "cat <<\\EOF\n$(x > y)\nEOF\n", want{skipped: []string{"$(x > y)\nEOF\n"}, sequential: true}, false},
		{"quoted operand of a writer", "tee 'a > b'", want{sequential: true}, false},
		{"quoted target of a redirect", "ls a > 'b'", want{sequential: true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			layout, ok := readCommandLayout(c.text)
			if ok == c.unreadable {
				t.Fatalf("readable=%t, want %t", ok, !c.unreadable)
			}
			if !ok {
				return
			}
			var skipped, straight []string
			for _, span := range layout.skipped {
				skipped = append(skipped, c.text[span.start:span.end])
			}
			for start := range layout.straight {
				end := start
				for end < len(c.text) && !isShellWhiteSpace(c.text[end]) && c.text[end] != ';' {
					end++
				}
				straight = append(straight, c.text[start:end])
			}
			slices.Sort(straight)
			slices.Sort(c.want.straight)
			if !slices.Equal(skipped, c.want.skipped) || !slices.Equal(straight, c.want.straight) ||
				layout.sequential != c.want.sequential {
				t.Fatalf("skipped %q straight %q sequential %t, want %q %q %t",
					skipped, straight, layout.sequential, c.want.skipped, c.want.straight, c.want.sequential)
			}
		})
	}
}
