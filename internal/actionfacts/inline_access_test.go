// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The tests run with the bound misuse checks on, as every adopter's do.
func init() { bounded.PanicOnMisuse(true) }

// rel-1-0-10:GAP-0657: the access of the code a hand-off reaches.
func TestInlineCodeAccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want InlineAccess
		from bool
	}{
		{"print open read", []string{"python3", "-c", `import sys; print(open(sys.argv[1]).read())`, "/h/c"}, InlineReads, false},
		{"json load", []string{"python3", "-c", `import json, sys; print(json.load(open(sys.argv[1])))`, "/h/c"}, InlineReads, false},
		{"path read_text", []string{"python3", "-c", `from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())`, "/h/c"}, InlineReads, false},
		{"open read mode", []string{"python3", "-c", `import sys; print(open(sys.argv[1], "rb").read())`, "/h/c"}, InlineReads, false},
		{"python option before code", []string{"python3", "-I", "-c", `import sys; print(open(sys.argv[1]).read())`, "/h/c"}, InlineUnknown, true},
		{"open write mode", []string{"python3", "-c", `import sys; open(sys.argv[1], "w").write("")`, "/h/c"}, InlineWrites, true},
		{"open append mode", []string{"python3", "-c", `open(__import__("sys").argv[1], "a")`, "/h/c"}, InlineWrites, true},
		{"os remove", []string{"python3", "-c", `import os, sys; os.remove(sys.argv[1])`, "/h/c"}, InlineWrites, true},
		{"subprocess", []string{"python3", "-c", `import subprocess, sys; subprocess.run(["rm", sys.argv[1]])`, "/h/c"}, InlineWrites, true},
		{"stdout write is no file write", []string{"python3", "-c", `import sys; sys.stdout.write(open(sys.argv[1]).read() + "x" * 2)`, "/h/c"}, InlineUnknown, true},
		{"loop is outside the grammar", []string{"python3", "-c", "import sys\nfor l in open(sys.argv[1]): print(l)", "/h/c"}, InlineUnknown, true},
		{"call outside the table", []string{"python3", "-c", `import os, sys; print(os.stat(sys.argv[1]).st_size)`, "/h/c"}, InlineUnknown, true},
		{"node write", []string{"node", "-e", `require("fs").writeFileSync(process.argv[1], "")`, "/h/c"}, InlineWrites, true},
		{"node read has no grammar", []string{"node", "-e", `console.log(require("fs").readFileSync(process.argv[1], "utf8"))`, "/h/c"}, InlineUnknown, true},
		{"ruby write", []string{"ruby", "-e", `File.write(ARGV[0], "")`, "/h/c"}, InlineWrites, true},
		{"ruby read has no grammar", []string{"ruby", "-e", `puts File.read(ARGV[0])`, "/h/c"}, InlineUnknown, true},
		{"php write", []string{"php", "-r", `file_put_contents($argv[1], "");`, "/h/c"}, InlineWrites, true},
		{"php read has no grammar", []string{"php", "-r", `echo file_get_contents($argv[1]);`, "/h/c"}, InlineUnknown, true},
		{"python stdin code", []string{"python3", "-", "/h/c"}, InlineUnknown, true},
		{"node stdin code", []string{"node", "-", "/h/c"}, InlineUnknown, true},
		{"ruby stdin code", []string{"ruby", "-", "/h/c"}, InlineUnknown, true},
		{"xargs stdin code", []string{"xargs", "python3", "-"}, InlineUnknown, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handoff := InlineCodeHandoff(tc.argv)
			if (handoff.From >= 0) != tc.from {
				t.Fatalf("InlineCodeHandoff(%q).From = %d, want a hand-off: %t", tc.argv, handoff.From, tc.from)
			}
			if tc.from && handoff.Access != tc.want {
				t.Fatalf("InlineCodeHandoff(%q).Access = %d, want %d", tc.argv, handoff.Access, tc.want)
			}
			if !tc.from && tc.want == InlineReads && !handoff.ProvenReads {
				t.Fatalf("InlineCodeHandoff(%q) is no proven read", tc.argv)
			}
		})
	}
}

// rel-1-0-10:GAP-0663: a chain with a wrapper or runner left unread is
// TRUNCATED, whatever its length; a chain within the bound is not.
func TestInlineChainCaps(t *testing.T) {
	call := []string{"python3", "-c", "pass", "/h/c"}
	for _, tc := range []struct {
		name   string
		prefix string
		count  int
		capped bool
	}{
		{"runners at the bound", "xargs", InlineChainRounds, false},
		{"runners past the bound", "xargs", InlineChainRounds + 1, true},
		{"wrappers at the bound", "nohup", InlineChainRounds * 8, false},
		{"wrappers past the bound", "nohup", InlineChainRounds*8 + 1, true},
		{"nine wrappers are read", "nohup", 9, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := append(strings.Fields(strings.Repeat(tc.prefix+" ", tc.count)), call...)
			handoff := InlineCodeHandoff(argv)
			if got := handoff.Caps.Has(bounded.Depth); got != tc.capped {
				t.Fatalf("%d x %s: depth cap = %t, want %t", tc.count, tc.prefix, got, tc.capped)
			}
			if !tc.capped && handoff.From < 0 {
				t.Fatalf("%d x %s: the chain was not read to its child", tc.count, tc.prefix)
			}
		})
	}
}

// A find -exec or xargs child that is a proven read changes no entry.
func TestFindChildProvenRead(t *testing.T) {
	const code = `import sys; print(open(sys.argv[1]).read())`
	if FindEmbeddedCommandMayChange([]string{"find", ".", "-exec", "python3", "-c", code, "{}", ";"}) {
		t.Fatal("a proven read changes an entry")
	}
	if !FindEmbeddedCommandMayChange([]string{"find", ".", "-exec", "python3", "-c", `import os, sys; os.remove(sys.argv[1])`, "{}", ";"}) {
		t.Fatal("a write changes no entry")
	}
}
