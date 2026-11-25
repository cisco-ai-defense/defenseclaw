// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"reflect"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// A kept parser gives the tree and error a new parser gives, whatever the
// kept parser read before: a parse that failed half way (an open regex, an
// open backquote, an open here-document, an open quote), comments, both
// grammars (DET111-PERF-A: parseCommandVariant reuses its parsers; the pool is
// parseWith's, substrate-1 GAP-0923).
func TestPERFAKeptParserReadsAsANewParser(t *testing.T) {
	commands := []string{
		"ls", "git status", "echo hi > out.txt", "go test ./... 2>&1 | tail -20",
		"[[ $x =~ ^(a|(b) ]] && echo", "[[ $x =~ ^(a|b)$ ]] && echo ok",
		"echo `echo \\`date\\``", "echo `unterminated", "echo $(( 1 + ",
		"cat <<'EOF'\nbody\n", "cat <<'EOF'\nbody\nEOF\necho after",
		"bash -c \"rm -rf build\" # trailing comment", "echo 'open quote",
		"f() { echo; }; f", "a=1 b=2 env | grep a", "arr=(1 2 3); echo ${arr[@]}",
		"cat <<-EOF\n\tindented\n\tEOF\n", "if true; then echo; fi", "for i in 1 2; do echo $i; done",
		"x=$(cat <<'EOF'\ninner\nEOF\n)", "echo <(ls) >(wc)", "((i++))", "echo $'\\x41'",
		strings.Repeat("(", 40) + "echo" + strings.Repeat(")", 40), "case x in a) ;; esac", "echo ${x:-$(id)}",
	}
	for at, variant := range parseVariants {
		for _, comments := range []bool{false, true} {
			for round := 0; round < 3; round++ {
				for i := range commands {
					// Each command after every other one, so a kept parser has
					// read each other command (and its failure) just before.
					for _, prev := range []string{commands[(i+round+1)%len(commands)], commands[(i+len(commands)-1-round)%len(commands)]} {
						_, _ = parseWith(at, comments, prev)
						got, gotErr := parseWith(at, comments, commands[i])
						want, wantErr := syntax.NewParser(syntax.Variant(variant), syntax.KeepComments(comments)).Parse(Reader(commands[i]), "")
						if errString(gotErr) != errString(wantErr) {
							t.Errorf("variant %v comments %v after %q: %q error %q, a new parser %q", variant, comments, prev, commands[i], errString(gotErr), errString(wantErr))
						}
						if !reflect.DeepEqual(got, want) {
							t.Errorf("variant %v comments %v after %q: %q tree differs from a new parser's", variant, comments, prev, commands[i])
						}
					}
				}
			}
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
