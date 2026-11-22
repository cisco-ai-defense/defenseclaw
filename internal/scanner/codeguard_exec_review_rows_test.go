// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0949: CI #1456 gw17. The benign Copilot apply_patch
// windows-native-project-patch adds src/parser.ts, which matches a log line
// with logLinePattern.exec(line) on a const regex literal. CG-EXEC-001 read
// that as command execution and alerted HIGH. This is the file the patch adds
// (Linux path), scanned in memory the way the hook route scans it.
func TestCodeGuardExecGAP0949CopilotParserPatchIsMatching(t *testing.T) {
	parser := strings.Join([]string{
		`export const LEVELS = ["INFO", "WARN", "ERROR"] as const;`,
		``,
		`export type LogLevel = (typeof LEVELS)[number];`,
		``,
		`export interface LogEntry {`,
		`  level: LogLevel;`,
		`  message: string;`,
		`}`,
		``,
		`const logLinePattern = /^(?:\S+\s+)?(INFO|WARN|ERROR)\s+(.+)$/;`,
		``,
		`export function parseLogLine(line: string): LogEntry | null {`,
		`  const match = logLinePattern.exec(line.trim());`,
		`  if (!match) {`,
		`    return null;`,
		`  }`,
		``,
		`  return {`,
		`    level: match[1] as LogLevel,`,
		`    message: match[2],`,
		`  };`,
		`}`,
	}, "\n")
	for _, f := range (&CodeGuardScanner{}).ScanContent("/home/dev/benign-proj/copilot/src/parser.ts", parser) {
		if f.RuleID == "CG-EXEC-001" {
			t.Errorf("GAP-0949: CG-EXEC-001 fired on RegExp matching at %s", f.Location)
		}
	}
}

// rel-1-0-10:GAP-0955 and GAP-0956: the review rows (S7 cgrev P01-P38) that
// the unshipped s7/wred3 b639e587aa regex view missed. Its literal view blanked
// real calls across statements and ran on .py/.php/.rb (GAP-0955); its
// regex-name table was scope-blind (GAP-0956). Each row is a real command
// call; CG-EXEC-001 must fire on that exact line, as it does at rel. Any
// later RegExp.exec reading must keep every row.
func TestCodeGuardExecWred3ReviewRowsStillAlert(t *testing.T) {
	s := &CodeGuardScanner{}
	for _, tc := range []struct {
		id, file, src string
		line          int
	}{
		{"P01-child_process.exec", "a.js", "child_process.exec(cmd);\n", 1},
		{"P02-require().exec", "a.js", "require('child_process').exec(cmd);\n", 1},
		{"P03-destructured-exec", "a.js", "const {exec} = require('child_process');\nexec(cmd);\n", 2},
		{"P04-import-exec", "a.ts", "import {exec} from 'child_process';\nexec(cmd);\n", 2},
		{"P05-alias-run", "a.js", "const run = child_process.exec;\n", 1},
		{"P06-reassign-next-line", "a.js", "let re = /x/;\nre = require('child_process');\nre.exec(cmd);\n", 3},
		{"P07-reassign-same-line", "a.js", "let re = /x/; re = require('child_process');\nre.exec(cmd);\n", 2},
		{"P08-reassign-second-on-line", "a.js", "let re = /x/;\nn = 1; re = require('child_process');\nre.exec(cmd);\n", 3},
		{"P09-nested-let-shadow", "a.js", "const re = /x/;\nfunction f() { let re = require('child_process');\n re.exec(cmd); }\n", 3},
		{"P10-destructure-shadow", "a.js", "const re = /x/;\nfunction f() {\n  const {re} = {re: require('child_process')};\n  re.exec(cmd);\n}\n", 4},
		{"P11-destructure-exec-shadows-regex-exec", "a.js", "const exec = /x/;\nfunction f() {\n  const {exec} = require('child_process');\n  exec(cmd);\n}\n", 4},
		{"P12-function-param", "a.js", "const re = /x/;\nfunction go(re) {\n  re.exec(cmd);\n}\ngo(require('child_process'));\n", 3},
		{"P13-arrow-param", "a.ts", "const re = /x/;\nconst go = (re: any) => re.exec(cmd);\n", 2},
		{"P14-for-of", "a.js", "const re = /x/;\nfor (const re of [require('child_process')])\n  re.exec(cmd);\n", 3},
		{"P15-member-chain", "a.js", "const re = /x/;\nconst o = {re: require('child_process')};\no.re.exec(cmd);\n", 3},
		{"P16-member-assign", "a.js", "const re = /x/;\nconst o = {};\no.re = require('child_process');\no.re.exec(cmd);\n", 4},
		{"P17-regex-and-module", "a.js", "const re = /x/ && require('child_process');\nre.exec(cmd);\n", 2},
		{"P18-regex-ternary", "a.js", "const re = /x/ ? require('child_process') : null;\nre.exec(cmd);\n", 2},
		{"P19-globalThis.exec", "a.js", "globalThis.exec(cmd);\n", 1},
		{"P20-eval-builds-exec", "a.js", "const re = /x/;\neval('re' + '.exec(cmd)');\n", 2},
		{"P21-ts-as-any", "a.ts", "const re = /x/;\n(re as any).exec(cmd);\n", 2},
		{"P22-ts-angle-cast", "a.ts", "const cp = require('child_process');\n(<RegExp>cp).exec(cmd);\n", 2},
		{"P23-bracket-other-object", "a.js", "const re = /x/;\nobj[re].exec(cmd);\n", 2},
		{"P24-bracket-string-member", "a.js", "const re = /x/;\nobj['re'].exec(cmd);\n", 2},
		{"P25-execFile", "a.js", "child_process.execFile(cmd);\n", 1},
		{"P26-execSync", "a.js", "child_process.execSync(cmd);\n", 1},
		{"P27-spaced-division-flags-name", "a.js", "const g = require('child_process');\nconst q = a / b /g.exec(cmd);\n", 2},
		{"P28-literal-span-js", "a.js", "const half = n / 2; cp.exec(cmd); const s = \"/.exec(\";\n", 1},
		{"P29-literal-span-py", "a.py", "half = n / 2; os.system(cmd); s = \"/.exec(\"\n", 1},
		{"P30-literal-span-php", "a.php", "<?php $h = $n / 2; system($cmd); $s = \"/.exec(\";\n", 1},
		{"P31-literal-span-js-eval", "a.js", "const half = n / 2; eval(code); const s = \"/.exec(\";\n", 1},
		{"P32-shadowed-RegExp", "a.js", "const RegExp = () => require('child_process');\nRegExp().exec(cmd);\n", 2},
		{"P33-python-exec", "a.py", "exec(code)\n", 1},
		{"P34-python-subprocess", "a.py", "subprocess.call(cmd)\n", 1},
		{"P35-php-exec", "a.php", "<?php exec($cmd);\n", 1},
		{"P36-catch-param", "a.js", "const re = /x/;\ntry { f(); } catch (re) {\n  re.exec(cmd);\n}\n", 3},
		{"P37-minified-one-line", "a.js", "let re=/x/;re=require(\"child_process\");re.exec(cmd);\n", 1},
		{"P38-template-member", "a.js", "const re = /x/;\ncp[`exec`](cmd); child_process.exec(cmd);\n", 2},
	} {
		want := fmt.Sprintf("%s:%d", tc.file, tc.line)
		fired := false
		for _, f := range s.ScanContent(tc.file, tc.src) {
			if f.RuleID == "CG-EXEC-001" && f.Location == want {
				fired = true
			}
		}
		if !fired {
			t.Errorf("%s: no CG-EXEC-001 at %s", tc.id, want)
		}
	}
}
