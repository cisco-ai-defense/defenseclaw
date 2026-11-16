// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1226, GAP-1227: CG-PATH-001 fired on an ordinary relative import of a
// project module and on Claude Code's own onboarding text in ~/.claude.json
// ("...\n" in a JSON string). Neither builds a path from input. The rule now
// reads what the code does with a path; imports of sibling modules and prose
// ellipses are not traversal, and real traversal forms still fire.
func TestCodeGuardPathTraversalReadsPathOperationsNotImportsOrProse(t *testing.T) {
	s := &CodeGuardScanner{}
	fires := func(filename, line string) bool {
		for _, f := range s.ScanContent(filename, line) {
			if f.RuleID == "CG-PATH-001" {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct{ file, line string }{
		{"test/summary.test.js", "import { summarize } from '../src/summary.js';"},
		{"test/index.test.ts", `import summarize, { type Options } from "../src/index";`},
		{"test/setup.js", "import '../src/polyfills.js';"},
		{"src/index.js", "export * from '../lib/index.js';"},
		{"src/load.js", "const lib = require('../lib/index.js');"},
		{"src/lazy.js", "const mod = await import('../lib/heavy.js');"},
		{"spec/x_spec.rb", "require_relative '../lib/x'"},
		{"src/util.c", `#include "../include/util.h"`},
		{"index.php", "require_once '../vendor/autoload.php';"},
		{".claude.json", `  "guideTemplate": "# Welcome to [Team Name]\n\n## How We Use Claude\n\nBased on [name]'s usage over the last [N] days...\n\n- Start here...\n",`},
		{"src/cli.py", `print("Loading...\n")`},
	} {
		if fires(tc.file, tc.line) {
			t.Errorf("CG-PATH-001 fired on benign %s line %q", tc.file, tc.line)
		}
	}
	for _, tc := range []struct{ file, line string }{
		{"src/read.js", "fs.readFileSync('../../etc/passwd')"},
		{"src/read.js", "import x from '../a.js'; fs.readFileSync('../../etc/shadow')"},
		{"src/serve.js", "res.sendFile(path.join(root, '..', req.query.file))"},
		{"app.py", "open(os.path.join(base, '..', name))"},
		{"main.go", "data, _ := os.ReadFile(filepath.Join(dir, \"..\", name))"},
		{"src/win.js", `const p = "..\\..\\secrets.txt";`},
		{"src/load.js", "const plugin = require(`../plugins/${name}`);"},
		{"index.php", `include "$dir/../" . $_GET["page"];`},
		// GAP-1935: classic payloads and Windows two-dot paths whose next
		// character reads like a string escape.
		{"src/read.js", `fs.readFileSync("....//....//etc/passwd")`},
		{"app.py", `open("..././..././etc/passwd")`},
		{"src/win.js", `const p = "...\\...\\windows\\win.ini";`},
		{"tools/read.ps1", `Get-Content ..\temp\secrets.txt`},
		{"app.py", `open(r"..\notes\" + name)`},
	} {
		if !fires(tc.file, tc.line) {
			t.Errorf("CG-PATH-001 did not fire on %s line %q", tc.file, tc.line)
		}
	}
}

// GAP-2220: CodeGuard read a PowerShell line correctly in ScanContent, but the
// hook path and the folder walk only scan files IsCodeFile accepts, and .ps1
// was not one of them, so a .ps1 Write with a traversal was never scanned.
// Shell and Windows script files are code, in any letter case.
func TestCodeGuardScansShellAndWindowsScriptFiles(t *testing.T) {
	for _, ext := range []string{".ps1", ".psm1", ".bat", ".cmd", ".bash", ".zsh", ".mjs", ".cjs", ".jsx", ".tsx", ".PS1", ".Cmd", ".py", ".sh"} {
		if !IsCodeFile(ext) {
			t.Errorf("IsCodeFile(%q) = false, want true", ext)
		}
	}
	for _, ext := range []string{".md", ".txt", ".png", ""} {
		if IsCodeFile(ext) {
			t.Errorf("IsCodeFile(%q) = true, want false", ext)
		}
	}

	dir := t.TempDir()
	for name, body := range map[string]string{
		"tools/read.ps1":   "Get-Content ..\\temp\\secrets.txt\n",
		"tools/Deploy.PS1": "Get-Content ..\\..\\temp\\secrets.txt\n",
		"tools/read.cmd":   "type ..\\..\\temp\\secrets.txt\n",
		"notes/readme.md":  "see ../docs\n",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := NewCodeGuardScanner("").Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		if f.ID == "CG-PATH-001" {
			got[filepath.ToSlash(strings.SplitN(strings.TrimPrefix(f.Location, dir+string(filepath.Separator)), ":", 2)[0])] = true
		}
	}
	for _, want := range []string{"tools/read.ps1", "tools/Deploy.PS1", "tools/read.cmd"} {
		if !got[want] {
			t.Errorf("CG-PATH-001 not reported for %s; got %v", want, got)
		}
	}
	if got["notes/readme.md"] {
		t.Errorf("a Markdown file was scanned as code: %v", got)
	}
}
