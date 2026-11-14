// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

func init() { bounded.PanicOnMisuse(true) }

// rel-1-0-10:GAP-0437: the recovering parser of mvdan.cc/sh indexes past
// the word after a recovered arithmetic error in an assignment. These are
// minimal shapes of an owner-trace command that crashed the gateway's
// OpenClaw routes; each must come back as ErrParserFault, not a panic.
var parserFaultShapes = []string{
	"h=$((t d",
	"h=$((t d))",
	"a=$((b c)); echo ok",
	"echo first\nh=$((t d",
}

func TestParseRecoveringContainsParserFault(t *testing.T) {
	for _, command := range parserFaultShapes {
		var trunc bounded.Truncated
		file, err := ParseRecovering(command, 8, &trunc)
		if !errors.Is(err, ErrParserFault) || file != nil {
			t.Errorf("ParseRecovering(%q) = (%v, %v), want (nil, ErrParserFault)", command, file, err)
		}
		if set := trunc.Set(); !set.Has(bounded.Nodes) || !strings.Contains(set.Reason(), "cap=nodes") {
			t.Errorf("ParseRecovering(%q) truncation = %q, want cap=nodes", command, set.Reason())
		}
		// The non-recovering grammar reads the same text as a syntax error.
		if file, ok := Parse(command); ok || file != nil {
			t.Errorf("Parse(%q) = (%v, %v), want a syntax error", command, file, ok)
		}
	}
}

// rel-1-0-10:GAP-0487: text that is not valid UTF-8 made the recovering
// parse loop forever (mvdan.cc/sh keeps lexing after its encoding error). It
// is refused before the parse, as a parser fault; the plain grammar reads it
// as a syntax error. The shapes are the corpus entry ad64e538f1aab24f of
// FuzzUnprovenProtectedWrite and its shortest looping prefix, built here.
func TestParseRecoveringInvalidUTF8IsAFaultNotALoop(t *testing.T) {
	loop := "${0:+$((0 0!" + string([]byte{0x85})
	for _, command := range []string{loop, loop + strings.Repeat(string([]byte{0x85}), 7) + "))}~/.zshrc", "echo " + string([]byte{0xff})} {
		done := make(chan error, 1)
		var trunc bounded.Truncated
		go func() {
			_, err := ParseRecovering(command, 8, &trunc)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrParserFault) || !trunc.Set().Has(bounded.Nodes) {
				t.Errorf("ParseRecovering(%q) = %v (truncation %q), want ErrParserFault with cap=nodes", command, err, trunc.Set().Reason())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("ParseRecovering(%q) did not return in 10 s", command)
		}
		if file, ok := Parse(command); ok || file != nil {
			t.Errorf("Parse(%q) = (%v, %v), want a syntax error", command, file, ok)
		}
	}
}

func TestParseRecoveringKeepsRecoveredTree(t *testing.T) {
	// A recoverable syntax error still yields its readable statements.
	file, err := ParseRecovering("echo a > out; if", 8, nil)
	if errors.Is(err, ErrParserFault) {
		t.Fatalf("ParseRecovering: unexpected parser fault")
	}
	if file == nil || len(file.Stmts) == 0 {
		t.Fatalf("ParseRecovering kept no statements (err %v)", err)
	}
	if file, err := ParseRecovering("echo ok", 8, nil); err != nil || file == nil {
		t.Fatalf("ParseRecovering(valid) = (%v, %v)", file, err)
	}
}

// FuzzParseRecovering checks that the shell parses never panic: any input
// gives a tree, a syntax error or ErrParserFault, in the recovering and the
// plain grammar.
func FuzzParseRecovering(f *testing.F) {
	for _, seed := range append(parserFaultShapes,
		"echo a > out; if", "x=$((1+2)); y=$[3*4]", "cat <<E\nbody\nE\n", "f() { g; }; f",
		"a[1]=x b+=y c=$(echo $((d e)))", "${x:-$((y z))}", "((a b))", "let 'a b'",
		"${0:+$((0 0!"+string([]byte{0x85})+"))}", "echo "+string([]byte{0xff}),
	) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, command string) {
		var trunc bounded.Truncated
		file, err := ParseRecovering(command, 8, &trunc)
		if errors.Is(err, ErrParserFault) != trunc.Any() || errors.Is(err, ErrParserFault) && file != nil {
			t.Fatalf("parser fault and truncation disagree")
		}
		_, _ = Parse(command)
		_, _ = ParseWithComments(command)
	})
}

// FuzzArithmetic is FuzzParseRecovering over the arithmetic grammar, where
// the GAP-0437 fault lives: the fuzzed text is the inside of $(( )), $[ ]
// and (( )) in assignment, word, test and command positions, closed and
// unclosed.
func FuzzArithmetic(f *testing.F) {
	for _, seed := range []string{
		"t d", "1+2", "a b c", "a=1", "a+=b", "x[1]", "a ? b : c", "a,b", "++a--",
		"$(b c)", "${d e}", "'q'", "\"q r\"", "1 2)", ")", "((", "a[$((b c))]",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, inner string) {
		for _, command := range []string{
			"h=$((" + inner, "h=$((" + inner + "))", "h+=$((" + inner + "))", "a[1]=$((" + inner,
			"echo $((" + inner, "echo $((" + inner + ")) x=y", "((" + inner, "((" + inner + "))",
			"h=$[" + inner, "echo $[" + inner + "]", "let " + inner, "[[ $((" + inner + ")) ]]",
			"f() { h=$((" + inner + ")); }; f", "h=$((" + inner + ")) cmd > out",
		} {
			var trunc bounded.Truncated
			file, err := ParseRecovering(command, 8, &trunc)
			if errors.Is(err, ErrParserFault) && file != nil {
				t.Fatalf("parser fault with a tree")
			}
			_, _ = Parse(command)
		}
	})
}
