// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestPerlStageOneLiveCalls(t *testing.T) {
	cases := []struct {
		id, code string
		want     string
	}{
		{"C1 plain", "unlink('/tmp/p');", "unlink"},
		{"C1 CORE", "CORE::unlink('/tmp/p');", "unlink"},
		{"C1 amp CORE", "&CORE::unlink('/tmp/p');", "unlink"},
		{"C1 amp user", "&unlink('/tmp/p');", ""},
		{"C1 sub", "sub unlink { 1 };", ""},
		{"C1 method", "$x->unlink('/tmp/p');", ""},
		{"L1 comment", "# unlink('/tmp/p')\nrename('/tmp/a','/tmp/b');", "rename"},
		{"L2 quote", "q#unlink('/tmp/p')#; truncate('/tmp/p',0);", "truncate"},
		{"L2 substitution", "s{x}{unlink('/tmp/p')}e;", "unlink"},
		{"L7 data", "__END__\nunlink('/tmp/p');", ""},
		{"L7 string", "'__END__'; unlink('/tmp/p');", "unlink"},
		{"L4 regex", "$x =~ /unlink/; rename('/tmp/a','/tmp/b');", "rename"},
		{"L3 key", "$x{unlink}; rename('/tmp/a','/tmp/b');", "rename"},
		{"C1 newline paren", "unlink\n('/tmp/p');", "unlink"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			tokens, ok := perlLex(tc.code)
			if !ok {
				t.Fatal("incomplete")
			}
			calls := perlCalls(tokens)
			if tc.want == "" {
				if len(calls) != 0 {
					t.Fatalf("calls = %+v", calls)
				}
			} else if len(calls) != 1 || calls[0].name != tc.want {
				t.Fatalf("calls = %+v, want %q", calls, tc.want)
			}
		})
	}
}

func TestPerlStageOneFixedPath(t *testing.T) {
	cases := []struct {
		expr, want string
		fixed      bool
	}{
		{"'/tmp/p'", "/tmp/p", true},
		{"'/tmp/' . 'p'", "/tmp/p", true},
		{"q{/tmp/p}", "", false},
		{"$p", "", false},
		{"'/tmp/' . $p", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			tokens, ok := perlLex(tc.expr)
			if !ok {
				t.Fatal("incomplete")
			}
			got, fixed := perlFixedPath(tokens, 0, len(tc.expr))
			if got != tc.want || fixed != tc.fixed {
				t.Fatalf("got %q %v, want %q %v", got, fixed, tc.want, tc.fixed)
			}
		})
	}
}

func TestPerlStageOneInertBodies(t *testing.T) {
	cases := []struct {
		id, code string
		want     int
	}{
		{"heredoc", "print <<END;\nunlink('/tmp/p');\nEND\nrename('/tmp/a','/tmp/b');", 1},
		{"two heredocs", "print <<A, <<B;\nunlink('/tmp/p');\nA\nunlink('/tmp/p');\nB\nrename('/tmp/a','/tmp/b');", 1},
		{"POD", "=pod\nunlink('/tmp/p');\n=cut\nrename('/tmp/a','/tmp/b');", 1},
		{"POD EOF", "=pod\nunlink('/tmp/p');", 0},
		{"DATA", "__DATA__\nunlink('/tmp/p');", 0},
		{"END", "__END__\nunlink('/tmp/p');", 0},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			tokens, complete := perlLex(tc.code)
			if !complete {
				t.Fatal("incomplete")
			}
			calls := perlCalls(tokens)
			if len(calls) != tc.want {
				t.Fatalf("calls = %+v, want %d", calls, tc.want)
			}
		})
	}
}

func TestPerlStageOneQuoteContext(t *testing.T) {
	cases := []struct {
		id, code string
		want     int
	}{
		{"method s", "$x->s('/tmp/p'); unlink('/tmp/q');", 1},
		{"subscript y", "$x{y}; unlink('/tmp/q');", 1},
		{"file test", "-s '/tmp/p'; unlink('/tmp/q');", 1},
		{"fat comma", "q => 'x'; unlink('/tmp/q');", 1},
		{"comment after q", "q # comment\n{a}; unlink('/tmp/q');", 1},
		{"long identifier", "éq{}; unlink('/tmp/q');", 1},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			tokens, complete := perlLex(tc.code)
			if !complete {
				t.Fatal("incomplete")
			}
			calls := perlCalls(tokens)
			if len(calls) != tc.want {
				t.Fatalf("calls = %+v, want %d", calls, tc.want)
			}
		})
	}
}

func TestPerlStageOneBlockKinds(t *testing.T) {
	code := "BEGIN { unlink('/tmp/a') }; sub helper { unlink('/tmp/b') }; while (1) { unlink('/tmp/c') }; eval { unlink('/tmp/d') }; do { unlink('/tmp/e') }"
	tokens, complete := perlLex(code)
	if !complete {
		t.Fatal("lex incomplete")
	}
	blocks, complete := perlBlockContexts(tokens)
	if !complete {
		t.Fatal("blocks incomplete")
	}
	calls := perlCalls(tokens)
	want := []string{"BEGIN", "sub", "loop", "eval", "do"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %+v", calls)
	}
	for i, call := range calls {
		if blocks[call.block].kind != want[i] {
			t.Errorf("call %d block = %s, want %s", i, blocks[call.block].kind, want[i])
		}
	}
}

func TestPerlStageOneSubstitutionReplacement(t *testing.T) {
	cases := []struct {
		id, code string
		want     int
	}{
		{"slash e", "s/x/unlink('p')/e;", 1},
		{"slash inert", "s/x/unlink('p')/;", 0},
		{"bracket e", "s{x}{unlink('/tmp/p')}e;", 1},
		{"bracket comment e", "s{x} # comment\n {unlink('/tmp/p')}e;", 1},
		{"transliteration inert", "y/unlink('p')/x/;", 0},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			tokens, complete := perlLex(tc.code)
			if !complete {
				t.Fatal("incomplete")
			}
			calls := perlCalls(tokens)
			if len(calls) != tc.want {
				t.Fatalf("calls = %+v, want %d", calls, tc.want)
			}
		})
	}
}

func TestPerlStageOneAmbiguousSlash(t *testing.T) {
	cases := []struct {
		code     string
		complete bool
	}{
		{"mystery / unlink('p');", false},
		{"mystery ? unlink('p') : 0;", false},
		{"split /unlink/; unlink('p');", true},
		{"$x =~ /unlink/; unlink('p');", true},
		{"1 / 2; unlink('p');", true},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			_, got := perlLex(tc.code)
			if got != tc.complete {
				t.Fatalf("complete = %v, want %v", got, tc.complete)
			}
		})
	}
}

func TestPerlStageOneBuiltinOperator(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		{"0*unlink('p')", 1},
		{"1&unlink('p')", 1},
		{"1%rename('a','b')", 1},
		{"$h{a}*unlink('p')", 1},
		{"$h{a}&unlink('p')", 1},
		{"&unlink('p')", 0},
		{"*unlink('p')", 0},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			tokens, complete := perlLex(tc.code)
			if !complete {
				t.Fatal("incomplete")
			}
			calls := perlCalls(tokens)
			if len(calls) != tc.want {
				t.Fatalf("calls = %+v, want %d", calls, tc.want)
			}
		})
	}
}

func TestPerlStageOneSpacedQuoteLike(t *testing.T) {
	cases := []string{
		"print q {unlink('p')}; rename('a','b');",
		"print q # comment\n {unlink('p')}; rename('a','b');",
		"print qq {unlink('p')}; rename('a','b');",
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			tokens, complete := perlLex(code)
			if !complete {
				t.Fatal("incomplete")
			}
			calls := perlCalls(tokens)
			if len(calls) != 1 || calls[0].name != "rename" {
				t.Fatalf("calls = %+v", calls)
			}
		})
	}
}

func TestPerlStageOneIncomplete(t *testing.T) {
	cases := []string{
		"format STDOUT =\nunlink('p');",
		"print <<END;\nunterminated",
		"print qq{x@{[unlink('p')]}};",
		"print \"x@{[unlink('p')]}\";",
		"q{unterminated",
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			if _, complete := perlLex(code); complete {
				t.Fatal("expected incomplete")
			}
		})
	}
}

func TestPerlStageOneCallArguments(t *testing.T) {
	cases := []struct {
		id, code string
		want     []int
	}{
		{"three args", "open(my $f, '>', 'p');", []int{3}},
		{"trailing comma", "unlink('p',);", []int{1}},
		{"list", "rename 'a', 'b';", []int{2}},
		{"two calls", "unlink('a'); unlink('b');", []int{1, 1}},
		{"nested", "open(my $f, mode(), 'p'); unlink('q');", []int{3, 1}},
		{"list termination", "unlink 'p' if $x; rename 'a', 'b';", []int{1, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			tokens, complete := perlLex(tc.code)
			if !complete {
				t.Fatal("incomplete")
			}
			calls := perlCalls(tokens)
			if len(calls) != len(tc.want) {
				t.Fatalf("calls = %+v", calls)
			}
			for i, n := range tc.want {
				if calls[i].argc != n {
					t.Errorf("call %d argc = %d, want %d", i, calls[i].argc, n)
				}
			}
		})
	}
}

func TestPerlStageOneStatementModifier(t *testing.T) {
	tokens, complete := perlLex("open(my $f, '>', 'p') while $again;")
	if !complete {
		t.Fatal("incomplete")
	}
	_, complete = perlBlockContexts(tokens)
	if !complete {
		t.Fatal("block incomplete")
	}
	found := false
	for _, tok := range tokens {
		if tok.text == "open" {
			found = true
			if !tok.modifierLoop {
				t.Fatal("open missing modifier loop context")
			}
		}
	}
	if !found {
		t.Fatal("open token missing")
	}
}
