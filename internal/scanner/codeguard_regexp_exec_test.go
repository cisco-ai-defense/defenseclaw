// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// rel-1-0-10:GAP-1185 review r1. R13: a prototype write through bracketed
// keys reached RegExp.prototype.exec from a proven name (re.constructor),
// and the masked string text hid "prototype", so the proof held and exec on
// the name dropped CG-EXEC-001 (rel fired). R14/R15: the name used as a
// value (an object shorthand, a log argument) left it unproven, so plain
// RegExp matching alerted (rel did not). A proven name may now only read
// RegExp members, the text of strings counts for the prototype check, a
// write of an exec member anywhere is a change of meaning, a value use is a
// read, and rel's line reading is the floor of the whole-file reading.
func TestCodeGuardExecRegExpProofReviewRows(t *testing.T) {
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
		{"R13 bracketed prototype write", lines(
			`const re = /x/;`,
			`re.constructor["prototype"]["exec"] = require("child_process").exec;`,
			`re.exec(cmd);`)},
		{"constructor of the name, no require on the line", lines(
			`const cp = require("child_process");`,
			`const re = /x/;`,
			`const proto = re.constructor[name];`,
			`re.exec(cmd);`)},
		{"prototype named in a string", lines(
			`const cp = require("child_process");`,
			`const re = /x/;`,
			`Reflect.set(Reflect.get(RegExp, "prototype"), "exec", cp.exec);`,
			`re.exec(cmd);`)},
		{"exec written through an alias", lines(
			`const cp = require("child_process");`,
			`const re = /x/;`,
			`const alias = re;`,
			`alias.exec = cp.exec;`,
			`re.exec(cmd);`)},
		{"computed member of the name", lines(
			`const re = /x/;`,
			`re[key] = handler;`,
			`re.exec(cmd);`)},
		{"value use on a line rel reads as a binding", lines(
			`const re = /x/;`,
			`register(re, require("./plugins"));`,
			`re.exec(cmd);`)},
		{"value use beside an arrow rel reads as a parameter", lines(
			`const re = /x/;`,
			`register(re, () => setup());`,
			`re.exec(cmd);`)},
	} {
		if !fires("src/run.js", tc.content) || !fires("src/run.ts", tc.content) {
			t.Errorf("%s: CG-EXEC-001 did not fire", tc.name)
		}
	}
	for _, tc := range []struct{ name, content string }{
		{"R14 object shorthand", lines(`const re = /x/;`, `const obj = {re};`, `re.exec(cmd);`)},
		{"R15 log argument", lines(`const re = /x/;`, `console.log(re);`, `re.exec(cmd);`)},
		{"array element", lines(`const re = /x/;`, `const rules = [re, /y/];`, `const m = re.exec(s);`)},
		{"returned in an object", lines(
			`const re = /^v(\d+)/;`,
			`export function version(s) { return { re, hit: re.exec(s) } }`)},
		{"ternary and comparison", lines(
			`const re = /x/;`,
			`const pick = flag ? re : null;`,
			`if (pick === re) { out = re.exec(s); }`)},
		{"exported by name", lines(`const re = /x/;`, `export { other, re };`, `const m = re.exec(s);`)},
	} {
		if fires("src/parse.js", tc.content) || fires("src/parse.ts", tc.content) {
			t.Errorf("%s: CG-EXEC-001 fired on RegExp matching", tc.name)
		}
	}
}

// rel-1-0-10:GAP-1271: the whole-file proof read whether RegExp is the
// builtin once per RegExp(...) initializer, over the whole file, and climbed
// every enclosing bracket for each use of a proven name, so CodeGuard on one
// Write or Edit of a JavaScript file took time quadratic in its size, inline
// on the hook path (4,000 RegExp heads, 107 KB: 25 s; 16,000: 6 min; rel
// 0.1 s). Each fact is now read once per file or once per bracket pair; the
// findings are the same.
func TestCodeGuardExecRegExpProofIsLinear(t *testing.T) {
	if raceDetector {
		t.Skip("timing bounds are for the plain build; -race runs this code about 20 times slower")
	}
	s := &CodeGuardScanner{}
	shapes := []struct {
		name  string
		build func(n int) string
		fires bool
	}{
		{"RegExp heads", func(n int) string {
			var b strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&b, "const r%d = RegExp(\"a%d+\");\n", i, i)
			}
			b.WriteString("r0.exec(s);\n")
			return b.String()
		}, false},
		{"RegExp heads, RegExp assigned at the end", func(n int) string {
			var b strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&b, "const r%d = new RegExp(\"a%d+\", \"g\");\n", i, i)
			}
			b.WriteString("r0.exec(s);\nRegExp = cp.exec;\n")
			return b.String()
		}, true},
		{"nested RegExp heads", func(n int) string {
			var b strings.Builder
			b.WriteString("const re = /x/;\n")
			for i := 0; i < n; i++ {
				fmt.Fprintf(&b, "const r%d = RegExp(f(() => {\n", i)
			}
			b.WriteString(strings.Repeat("}));\n", n))
			b.WriteString("re.exec(s);\n")
			return b.String()
		}, false},
		{"value uses in nested blocks", func(n int) string {
			return "const re = /x/;\n" + strings.Repeat("{\n", n) + strings.Repeat("x = re;\n", n) +
				strings.Repeat("}\n", n) + "re.exec(s);\n"
		}, false},
		{"value uses after closed parens", func(n int) string {
			return "const re = /x/;\nconst v = " + strings.Repeat("f(", n) + "0" + strings.Repeat(")", n) + ";\n" +
				strings.Repeat("x = re;\n", n) + "re.exec(s);\n"
		}, false},
		{"uses in a group after a long comment", func(n int) string {
			return "const re = /x/;\ng(1)/*" + strings.Repeat(" ", 16*n) + "*/(\n" + strings.Repeat("re,\n", n) +
				"0);\nre.exec(s);\n"
		}, false},
	}
	scan := func(build func(int) string, n int) (time.Duration, bool) {
		content := build(n)
		start := time.Now()
		fires := false
		for _, f := range s.ScanContent("src/patterns.js", content) {
			fires = fires || f.RuleID == codeGuardExecRuleID
		}
		return time.Since(start), fires
	}
	for _, shape := range shapes {
		small, fires := scan(shape.build, 4000)
		if fires != shape.fires {
			t.Errorf("%s: CG-EXEC-001 fired=%v, want %v", shape.name, fires, shape.fires)
		}
		large, _ := scan(shape.build, 16000)
		t.Logf("%s: 4,000 %s, 16,000 %s", shape.name, small, large)
		// rel takes 0.1 s on 4,000 RegExp heads and the quadratic proof 25 s:
		// the bounds leave room for a slow or -race run, not for x16 growth.
		if small > 2*time.Second {
			t.Errorf("%s: 4,000 took %s, want under 2 s", shape.name, small)
		}
		if large > 10*small+time.Second {
			t.Errorf("%s: 16,000 took %s, 4,000 %s: not linear", shape.name, large, small)
		}
	}
}

// rel-1-0-10:GAP-1271: innermost and block read the bracket pairs through
// binary searches and the innermost { } of each pair; they give what walking
// up the parents of the pair that opened last gives.
func TestJSGroupsInnermostMatchesTheParentWalk(t *testing.T) {
	walkInnermost := func(g *jsGroups, pos int) int {
		i := -1
		for k := range g.list {
			if g.list[k].open < pos {
				i = k
			}
		}
		for i >= 0 && g.list[i].close < pos {
			i = g.list[i].parent
		}
		return i
	}
	walkBlock := func(g *jsGroups, pos int) (int, int) {
		for i := walkInnermost(g, pos); i >= 0; i = g.list[i].parent {
			if g.kind(i) == '{' {
				return g.list[i].open, g.list[i].close + 1
			}
		}
		return 0, len(g.code)
	}
	r := rand.New(rand.NewSource(1271))
	opens, fillers := "([{", []string{"a", " ", "\n", ";"}
	for iter := 0; iter < 20000; iter++ {
		var b strings.Builder
		var open []byte
		for n := r.Intn(40); n >= 0; n-- {
			switch k := r.Intn(3); {
			case k == 0:
				c := opens[r.Intn(len(opens))]
				open = append(open, c)
				b.WriteByte(c)
			case k == 1 && len(open) > 0:
				b.WriteByte(jsCloses[open[len(open)-1]])
				open = open[:len(open)-1]
			default:
				b.WriteString(fillers[r.Intn(len(fillers))])
			}
		}
		for len(open) > 0 {
			b.WriteByte(jsCloses[open[len(open)-1]])
			open = open[:len(open)-1]
		}
		g, ok := jsGroupsOf(b.String())
		if !ok {
			t.Fatalf("%q: brackets do not pair", b.String())
		}
		for pos := 0; pos <= len(g.code); pos++ {
			if got, want := g.innermost(pos), walkInnermost(g, pos); got != want {
				t.Fatalf("%q at %d: innermost %d, parent walk %d", g.code, pos, got, want)
			}
			gs, ge := g.block(pos)
			ws, we := walkBlock(g, pos)
			if gs != ws || ge != we {
				t.Fatalf("%q at %d: block [%d,%d), parent walk [%d,%d)", g.code, pos, gs, ge, ws, we)
			}
		}
	}
}
