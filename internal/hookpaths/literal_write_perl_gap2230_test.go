// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand"
	"strings"
	"testing"
)

// The readers of rel-1-0-10:GAP-2230 as they were before the S1 index and the
// one-pass loop-word and branch scans: the oracles of TestGAP2230PerlScansMatchTheirOracles.

func perlS1EnclosingOracle(tokens []perlToken, assignment, callAt int) bool {
	depth := 0
	for i := assignment; i < callAt; i++ {
		switch tokens[i].text {
		case "{":
			depth++
			if i+1 < len(tokens) {
				switch tokens[i+1].blockKind {
				case "sub", "loop":
					return false
				}
			}
		case "}":
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return true
}

func perlS1ValueSpanOracle(tokens []perlToken, call perlCall, name string) ([2]int, bool) {
	callAt := -1
	for i := range tokens {
		if tokens[i].start == call.start {
			callAt = i
			break
		}
	}
	if callAt < 0 {
		return [2]int{}, false
	}
	assignment, valueStart := -1, -1
	for i := 0; i < callAt; i++ {
		scalar, next := perlScalarAt(tokens, i)
		if scalar != name || next >= callAt || tokens[next].text != "=" ||
			!perlS1EnclosingOracle(tokens, i, callAt) || tokens[i].modifierLoop {
			continue
		}
		if i > 0 && tokens[i-1].text == string(rune(92)) {
			continue
		}
		conditional := false
		for j := i - 1; j >= 0 && tokens[j].text != ";" && tokens[j].text != "{" && tokens[j].text != "}"; j-- {
			switch tokens[j].text {
			case "if", "unless", "while", "until", "for", "foreach":
				conditional = true
			}
		}
		if conditional {
			continue
		}
		assignment, valueStart = i, next+1
	}
	if assignment < 0 {
		return [2]int{}, false
	}
	for i := valueStart; i < callAt; i++ {
		scalar, _ := perlScalarAt(tokens, i)
		if scalar == name {
			return [2]int{}, false
		}
		if perlOpaqueAt(tokens, i) {
			return [2]int{}, false
		}
	}
	valueEnd := valueStart
	for valueEnd < callAt && tokens[valueEnd].text != ";" &&
		tokens[valueEnd].text != "," && tokens[valueEnd].text != ")" {
		valueEnd++
	}
	if valueEnd == valueStart {
		return [2]int{}, false
	}
	return [2]int{tokens[valueStart].start, tokens[valueEnd-1].end}, true
}

func perlVisibilityAtOracle(tokens []perlToken, call perlCall, name string) perlFlagVisibility {
	var visibility perlFlagVisibility
	for i := 0; i+1 < len(tokens) && tokens[i].start < call.start; i++ {
		word := tokens[i].text
		module := perlFlagModule(tokens[i+1].text)
		if module < 0 {
			continue
		}
		if word == "use" {
			if module < 2 {
				visibility.loaded[module] = true
			}
			end := i + 2
			for end < len(tokens) && tokens[end].text != ";" && tokens[end].start < call.start {
				end++
			}
			if perlImportHasName(tokens, i+2, end, name) {
				visibility.imported[module] = true
			}
		}
		if word == "require" && module < 2 {
			if tokens[i].block == call.block && tokens[i].blockKind != "sub" &&
				tokens[i].blockKind != "loop" {
				straight := true
				for j := i + 2; j < len(tokens) && tokens[j].start < call.start; j++ {
					switch tokens[j].text {
					case "sub", "for", "foreach", "while", "until", "if", "unless":
						straight = false
					}
				}
				if straight {
					visibility.runtime[module] = true
				}
			} else if tokens[i].blockKind == "BEGIN" || tokens[i].blockKind == "UNITCHECK" ||
				tokens[i].blockKind == "CHECK" || tokens[i].blockKind == "INIT" {
				visibility.loaded[module] = true
			}
		}
	}
	return visibility
}

// perlModifierLoopOracle is the modifier-loop marking of perlBlockContexts
// before GAP-2230: each loop word marked its whole statement prefix again.
func perlModifierLoopOracle(tokens []perlToken) []bool {
	marked := make([]bool, len(tokens))
	stmtStart := 0
	for i := range tokens {
		switch tokens[i].text {
		case "while", "until", "for", "foreach":
			if i > stmtStart {
				for j := stmtStart; j < i; j++ {
					marked[j] = true
				}
			}
		case ";", "{", "}":
			stmtStart = i + 1
		}
	}
	return marked
}

// gap2230Pieces are the token pieces of the random programs: scalars,
// assignments, blocks, loops and conditionals, the calls that resolve a
// scalar mode or a flag, and the code the reading cannot see. Every file name
// is a plain relative name; nothing here writes outside the test.
var gap2230Pieces = []string{
	"$m", "$n", "$f", "${m}", "=", "1", "'>'", "'w'", "O_RDONLY", "O_WRONLY", "O_CREAT", "|", "+", ";", ";", ";",
	"{", "}", "sub g", "for", "foreach", "while", "until", "if", "unless", "eval", "do", "require x", "\\",
	"(", ")", ",", "print", "open(F,$m,'a')", "open(F,\"$m.txt\")", "sysopen(F,'a',$f)", "sysopen(F,'a',O_WRONLY|O_CREAT)",
	"require Fcntl;", "use Fcntl;", "use POSIX;", "use Fcntl qw(O_WRONLY);", "BEGIN {", "my",
}

func gap2230Program(r *rand.Rand) string {
	var b strings.Builder
	for n := 1 + r.Intn(60); n > 0; n-- {
		b.WriteString(gap2230Pieces[r.Intn(len(gap2230Pieces))])
		b.WriteByte(' ')
	}
	return b.String()
}

// TestGAP2230PerlScansMatchTheirOracles: the S1 index, the one-pass branch
// scan of perlVisibilityAt and the one-pass loop-word marking give the
// answers of the scans they replace, on fixed and 30000 random programs.
func TestGAP2230PerlScansMatchTheirOracles(t *testing.T) {
	programs := []string{
		"$m='>'; open(F,$m,'a');",
		"{ $m='>'; } open(F,$m,'a');",
		"$m='>'; sub g { open(F,$m,'a'); }",
		"$m='>'; if (1) { open(F,$m,'a'); }",
		"$m='>'; for (1) { open(F,$m,'a'); }",
		"$m='>' for 1; open(F,$m,'a');",
		"if (1) { $m='>'; } open(F,$m,'a');",
		"$m='>'; $m='<'; open(F,$m,'a');",
		"$m='>'; eval $x; open(F,$m,'a');",
		"$f=O_WRONLY|O_CREAT; sysopen(F,'a',$f);",
		"require Fcntl; sysopen(F,'a',O_WRONLY);",
		"require Fcntl; if (1) {} sysopen(F,'a',O_WRONLY);",
		"BEGIN { require Fcntl; } sysopen(F,'a',O_WRONLY);",
		"use Fcntl qw(O_WRONLY); sysopen(F,'a',O_WRONLY);",
	}
	r := rand.New(rand.NewSource(2230))
	for len(programs) < 30000 {
		programs = append(programs, gap2230Program(r))
	}
	names := []string{"m", "n", "f", "x"}
	flags := []string{"O_RDONLY", "O_WRONLY", "O_CREAT"}
	checked := 0
	for _, code := range programs {
		tokens, complete := perlLex(code)
		if !complete {
			continue
		}
		want := perlModifierLoopOracle(tokens)
		if _, complete = perlBlockContexts(tokens); !complete {
			continue
		}
		for i := range tokens {
			if tokens[i].modifierLoop != want[i] {
				t.Fatalf("%q: token %d modifierLoop %v, oracle %v", code, i, tokens[i].modifierLoop, want[i])
			}
		}
		s1 := &perlS1Lazy{}
		calls := perlCalls(tokens)
		// Each token start is a call start too: the flag reader asks about
		// the start of a value span (perlFlagExpressionDepth).
		for i := range tokens {
			calls = append(calls, perlCall{start: tokens[i].start, block: tokens[i].block})
		}
		calls = append(calls, perlCall{start: -1})
		for _, call := range calls {
			for _, name := range names {
				gotSpan, gotOK := perlS1ValueSpan(s1, tokens, call, name)
				wantSpan, wantOK := perlS1ValueSpanOracle(tokens, call, name)
				if gotSpan != wantSpan || gotOK != wantOK {
					t.Fatalf("%q: call at %d, $%s: span %v %v, oracle %v %v", code, call.start, name, gotSpan, gotOK, wantSpan, wantOK)
				}
				checked++
			}
			for _, flag := range flags {
				if got, want := perlVisibilityAt(s1, tokens, call, flag), perlVisibilityAtOracle(tokens, call, flag); got != want {
					t.Fatalf("%q: call at %d, %s: visibility %+v, oracle %+v", code, call.start, flag, got, want)
				}
			}
		}
	}
	if checked < 100000 {
		t.Fatalf("only %d span questions checked", checked)
	}
	t.Logf("GAP-2230 oracle: %d programs, %d span questions", len(programs), checked)
}

// literalCodePositionOracle is literalCodePosition before GAP-2230: the
// reading of the whole prefix per question.
func literalCodePositionOracle(code string, position int, language string) bool {
	var quote byte
	comment := false
	perlHashDelimiters := 0
	for i := 0; i < position; i++ {
		c := code[i]
		if comment {
			if c == '\n' {
				comment = false
			}
			continue
		}
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		} else if c == '#' {
			if language == "perl" && perlHashDelimiters > 0 {
				perlHashDelimiters--
			} else if language == "perl" && perlHashRegexpStart(code, i) > 0 {
				perlHashDelimiters = perlHashRegexpStart(code, i)
			} else if literalCommentStart(code, i, language) {
				comment = true
			}
		}
	}
	return quote == 0 && !comment
}

// TestGAP2230CodeScannerMatchesTheOracle: one scanner asked positions in
// ascending order, with repeats and with steps back, answers what the
// reading of the whole prefix answers for each one.
func TestGAP2230CodeScannerMatchesTheOracle(t *testing.T) {
	alphabet := []byte("'\"\\#\n$smqrty;=~( a")
	languages := []string{"perl", "python", "ruby", "node", "javascript"}
	rng := rand.New(rand.NewSource(2230))
	questions := 0
	for program := range 20000 {
		code := make([]byte, rng.Intn(48))
		for i := range code {
			code[i] = alphabet[rng.Intn(len(alphabet))]
		}
		language := languages[program%len(languages)]
		scan := newLiteralCodeScanner(string(code), language)
		position := 0
		for range 24 {
			switch rng.Intn(6) {
			case 0:
				position = rng.Intn(len(code) + 1) // anywhere, often back
			case 1:
				// the same position again
			default:
				position = min(len(code), position+rng.Intn(4))
			}
			questions++
			if got, want := scan.at(position), literalCodePositionOracle(string(code), position, language); got != want {
				t.Fatalf("%s %q at %d: scanner %v, oracle %v", language, code, position, got, want)
			}
		}
	}
	t.Logf("%d questions", questions)
}
