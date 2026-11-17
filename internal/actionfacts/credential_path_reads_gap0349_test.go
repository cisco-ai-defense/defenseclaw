// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCredentialPathReadsSubstrateGapForms: the read forms of
// substrate-1:GAP-0349 (a for-loop variable; perl and ruby -e reading their
// argv files; python -c reading sys.argv; python with a valued option before
// -c; find name globs, which match dotfiles),
// substrate-1:GAP-0344 (a recursive grep or rg with no folder operand
// searches the working folder) and substrate-1:GAP-0233 (yq file operands)
// are credentials-file reads in the chain's record. The rows are the review
// probes' (s7-g341rev2 Q20-Q25, s7-g341rev P04/P05); the benign twins read no
// credentials file. A script's arguments stay no read (rel-1-0-10:GAP-1030),
// so Q27 is not a row.
func TestCredentialPathReadsSubstrateGapForms(t *testing.T) {
	dir := t.TempDir()
	for _, file := range []string{".env", "main.go", "notes.md", "show.py"} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "main.go"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reads := []struct{ id, cwd, command string }{
		{"Q20", dir, `for f in .env; do cat "$f"; done`},
		{"Q20b", dir, `for f in notes.md .env; do head -n 1 "$f"; done`},
		{"Q21", dir, `perl -e 'print while <>' .env`},
		{"Q22", dir, `python3 -c 'import sys; print(open(sys.argv[1]).read())' .env`},
		{"Q23", dir, `find . -name '*.env' -exec cat {} \;`},
		{"Q24", dir, `ruby -e 'puts ARGF.read' .env`},
		{"Q25", dir, `python3 -W ignore -c "print(open('.env').read())"`},
		{"Q25b", dir, `python3 -X utf8 -c "print(open('.env').read())"`},
		{"Q25c", dir, `ruby -r json -e 'puts File.read(".env")'`},
		{"P04", dir, "grep -r KEY"},
		{"P05", dir, "rg KEY"},
		{"YQ1", dir, "yq . .env"},
		{"YQ2", dir, "yq eval '.a' .env"},
		{"YQ3", dir, "yq -o json e '.a' .env"},
	}
	for _, row := range reads {
		facts := Analyze(Input{Tool: "Bash", Command: row.command, CWD: row.cwd, ActiveHome: t.TempDir()})
		if !facts.HasCredentialPathReads() {
			t.Errorf("%s: %q records no credentials-file read (paths %+v)", row.id, row.command, facts.Paths)
		}
	}
	benign := []struct{ id, cwd, command string }{
		{"N-for", dir, `for f in main.go notes.md; do cat "$f"; done`},
		{"N-perl", dir, `perl -e 'print while <>' notes.md`},
		{"N-python", dir, `python3 -c 'import sys; print(sys.argv[1])' notes.md`},
		{"N-module", dir, "python3 -m http.server 8000"},
		{"N-script", dir, "python3 show.py .env"},
		{"N-perl-noargs", dir, `perl -e 'print 1' .env`},
		{"N-python-noargs", dir, `python3 -c 'print(1)' .env`},
		{"N-find", dir, `find . -name '*.go' -exec cat {} \;`},
		{"N-grep-clean", clean, "grep -r KEY"},
		{"N-rg-clean", clean, "rg KEY"},
		{"N-rg-pipe", dir, "cat notes.md | rg KEY"},
		{"N-rg-redirect", dir, "rg KEY < notes.md"},
		{"N-grep-stdin", dir, "grep KEY"},
		{"N-yq", dir, "yq . main.go"},
		{"N-yq-expr", dir, "yq '.env' main.go"},
	}
	for _, row := range benign {
		facts := Analyze(Input{Tool: "Bash", Command: row.command, CWD: row.cwd, ActiveHome: t.TempDir()})
		if facts.HasCredentialPathReads() {
			t.Errorf("%s: %q records a credentials-file read: %+v", row.id, row.command, facts.CredentialPathReads())
		}
	}
}
