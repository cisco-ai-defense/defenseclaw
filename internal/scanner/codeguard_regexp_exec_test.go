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

// rel-1-0-10:GAP-1152: CG-EXEC-001 read RegExp.prototype.exec on a name the
// file binds to a regular expression as command execution (a Copilot patch
// adding a TypeScript log parser alerted HIGH). Matching a proven regular
// expression is not execution; exec on any receiver the file does not prove
// is a regular expression still fires, in memory and on disk.
func TestCodeGuardExecReadsProvenRegExpExecAsMatching(t *testing.T) {
	s := &CodeGuardScanner{}
	execLines := func(filename, content string) []string {
		var lines []string
		for _, f := range s.ScanContent(filename, content) {
			if f.RuleID == codeGuardExecRuleID {
				lines = append(lines, f.Location)
			}
		}
		return lines
	}
	for _, tc := range []struct{ name, file, content string }{
		{"const literal, later use", "src/parser.ts", strings.Join([]string{
			`const logLinePattern = /^(?:\S+\s+)?(INFO|WARN|ERROR)\s+(.+)$/;`,
			``,
			`export function parseLogLine(line: string): LogEntry | null {`,
			`  const match = logLinePattern.exec(line.trim());`,
			`  return match ? { level: match[1], message: match[2] } : null;`,
			`}`,
		}, "\n")},
		{"use before the const (hoisted function)", "src/a.js", strings.Join([]string{
			`function first(s) { return WORD.exec(s); }`,
			`const WORD = /\w+/g;`,
		}, "\n")},
		{"typed RegExp object", "src/b.ts", strings.Join([]string{
			`const sep: RegExp = new RegExp("[,;]");`,
			`const items = (s: string) => sep.exec(s);`,
		}, "\n")},
		{"optional chain and loop", "src/c.js", strings.Join([]string{
			`const re = /(\d+)/g;`,
			`let m;`,
			`while ((m = re?.exec(text)) !== null) { out.push(m[1]); }`,
		}, "\n")},
	} {
		if got := execLines(tc.file, tc.content); len(got) != 0 {
			t.Errorf("%s: CG-EXEC-001 fired on RegExp matching at %v", tc.name, got)
		}
	}
	for _, tc := range []struct{ name, file, content string }{
		{"child_process member", "src/run.js", `const cp = require("child_process"); cp.exec(cmd);`},
		{"child_process qualified", "src/run.js", `child_process.exec(cmd);`},
		{"bare exec", "src/run.js", `const { exec } = require("child_process");` + "\n" + `exec(cmd);`},
		{"unproven member receiver", "src/run.ts", `const re = /x/;` + "\n" + `this.re.exec(cmd);`},
		{"let is not proven", "src/run.js", `let re = /x/;` + "\n" + `re.exec(cmd);`},
		{"reassigned name", "src/run.js", `const re = /x/;` + "\n" + `re = require("child_process");` + "\n" + `re.exec(cmd);`},
		{"parameter of the same name", "src/run.js", `const re = /x/;` + "\n" + `function go(re) { return re.exec(cmd); }`},
		{"arrow parameter of the same name", "src/run.js", `const re = /x/;` + "\n" + `const go = (re) => re.exec(cmd);`},
		{"destructured name", "src/run.js", `const re = /x/;` + "\n" + `{ const { re } = shell; re.exec(cmd); }`},
		{"imported name", "src/run.ts", `import { re } from "./runner";` + "\n" + `const re = /x/;` + "\n" + `re.exec(cmd);`},
		{"regexp and command on one line", "src/run.js", `const re = /x/;` + "\n" + `re.exec(s) && cp.exec(cmd);`},
		{"comment is not a regexp", "src/run.js", `const re = //x` + "\n" + `re.exec(cmd);`},
		{"python exec builtin", "tool.py", `pattern = 1` + "\n" + `exec(code)`},
	} {
		if got := execLines(tc.file, tc.content); len(got) == 0 {
			t.Errorf("%s: CG-EXEC-001 did not fire", tc.name)
		}
	}

	dir := t.TempDir()
	parser := filepath.Join(dir, "parser.ts")
	if err := os.WriteFile(parser, []byte("const p = /a(b)/;\nexport const f = (s: string) => p.exec(s);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(dir, "runner.js")
	if err := os.WriteFile(runner, []byte("const p = /a/;\nconst cp = require('child_process');\ncp.exec(cmd);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, f := range result.Findings {
		if f.RuleID == codeGuardExecRuleID {
			onDisk = append(onDisk, filepath.Base(f.Location))
		}
	}
	if len(onDisk) != 1 || onDisk[0] != "runner.js:3" {
		t.Fatalf("directory scan CG-EXEC-001 = %v, want only runner.js:3", onDisk)
	}
}

// A custom rule that reuses the builtin ID is not narrowed: the RegExp
// reading belongs to the builtin pattern only.
func TestCodeGuardExecRegExpReadingKeepsCustomRules(t *testing.T) {
	findings := []Finding{{ID: codeGuardExecRuleID, RuleID: codeGuardExecRuleID, Scanner: "codeguard", Description: "re.exec(s)"}}
	receivers := newJSRegExpReceivers(".js")
	receivers.observe("const re = /x/;")
	receivers.observe("re.exec(s)")
	if got := receivers.drop(findings); len(got) != 1 {
		t.Fatalf("custom CG-EXEC-001 finding dropped: %v", got)
	}
}
