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

// rel-1-0-10:GAP-1185: the regular expression proof read the file line by
// line and by keyword, so a binding it did not see (a class or object method
// parameter, a parameter on its own line, a second binding on the const
// line, a const in an inner block, a const whose initializer only starts
// with a literal, a const inside a comment or a string) let exec on the name
// drop CG-EXEC-001. The proof now reads the code of the whole file: one
// const whose whole initializer is the regular expression, every other
// occurrence a member use or a pattern argument, all in the const's block.
func TestCodeGuardExecRegExpProofReadsTheWholeFile(t *testing.T) {
	s := &CodeGuardScanner{}
	fires := func(filename, content string) bool {
		for _, f := range s.ScanContent(filename, content) {
			if f.RuleID == codeGuardExecRuleID {
				return true
			}
		}
		return false
	}
	lines := func(l ...string) string { return strings.Join(l, "\n") }
	for _, tc := range []struct{ name, content string }{
		{"method shorthand parameter", lines(
			`const re = /x/;`,
			`class R { run(re, cmd) { return re.exec(cmd) } }`)},
		{"object method parameter", lines(
			`const re = /x/;`,
			`const o = { run(re, cmd) { return re.exec(cmd) } };`)},
		{"parameter on its own line", lines(
			`const re = /x/;`,
			`function run(`,
			`  re,`,
			`  cmd`,
			`) { return re.exec(cmd) }`)},
		{"second binding on the const line", `const re = /x/; const run = (re) => re.exec(cmd);`},
		{"const in an inner block", lines(
			`Object.assign(globalThis, { re: cp });`,
			`{ const re = /x/; }`,
			`re.exec(id);`)},
		{"const in an inner block on its own lines", lines(
			`function setup() {`,
			`  const re = /x/;`,
			`}`,
			`re.exec(id);`)},
		{"initializer only starts with a literal", lines(
			`const re = /x/.test(s) ? require("child_process") : null;`,
			`re.exec(id);`)},
		{"initializer continues on the next line", lines(
			`const re = /x/`,
			`  .test(s) ? require("child_process") : null;`,
			`re.exec(id);`)},
		{"const in a line comment", lines(
			`// const re = /x/;`,
			`re.exec(cmd);`)},
		{"const in a block comment", lines(
			`/*`,
			`const re = /x/;`,
			`*/`,
			`re.exec(cmd);`)},
		{"const in a string", lines(
			`const doc = "const re = /x/;";`,
			`re.exec(cmd);`)},
		{"const in a template", lines(
			"const doc = `",
			`const re = /x/;`,
			"`;",
			`re.exec(cmd);`)},
		{"destructured parameter", lines(
			`const re = /x/;`,
			`const run = ({ re }) => re.exec(cmd);`)},
		{"rest binding", lines(
			`const re = /x/;`,
			`{ const [...re] = list; re.exec(cmd); }`)},
		{"exec member overwritten", lines(
			`const re = /x/;`,
			`re.exec = require("child_process").exec;`,
			`re.exec(cmd);`)},
		{"prototype patched", lines(
			`const re = /x/;`,
			`RegExp.prototype.exec = require("child_process").exec;`,
			`re.exec(cmd);`)},
		{"RegExp rebound", lines(
			`function RegExp() { return require("child_process"); }`,
			`const re = new RegExp("x");`,
			`re.exec(cmd);`)},
		{"with statement", lines(
			`const re = /x/;`,
			`with (shell) { re.exec(cmd); }`)},
		{"callback parameter", lines(
			`const re = /x/;`,
			`list.map(re => re.exec(cmd));`)},
		{"unterminated string", lines(
			`const re = /x/;`,
			`const s = "open`,
			`re.exec(cmd);`)},
	} {
		if !fires("src/run.js", tc.content) || !fires("src/run.ts", tc.content) {
			t.Errorf("%s: CG-EXEC-001 did not fire", tc.name)
		}
	}
	for _, tc := range []struct{ name, content string }{
		{"const inside the function that uses it", lines(
			`export function parse(line: string) {`,
			`  const entry = /^(\w+)\s+(.+)$/;`,
			`  return entry.exec(line);`,
			`}`)},
		{"matching loop resets lastIndex", lines(
			`const word = /[a-z]+/g;`,
			`word.lastIndex = 0;`,
			`let m;`,
			`while ((m = word.exec(text)) !== null) { out.push(m[0]); }`)},
		{"pattern argument of a string method", lines(
			`const sep = /[,;]/;`,
			`const parts = text.split(sep);`,
			`const first = sep.exec(text);`)},
		{"slash in a class, comment and template around it", lines(
			`// a path matcher: exec here is RegExp matching`,
			"const label = `path ${name}`;",
			`const path = /[/\\]+(\w+)/;`,
			`const half = total / 2;`,
			`const hit = path.exec(label);`)},
	} {
		if fires("src/parse.ts", tc.content) {
			t.Errorf("%s: CG-EXEC-001 fired on RegExp matching", tc.name)
		}
	}
}
