// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func execFires(t *testing.T, filename, content string) bool {
	t.Helper()
	for _, f := range NewCodeGuardScanner("").ScanContent(filename, content) {
		if f.ID == "CG-EXEC-001" {
			return true
		}
	}
	return false
}

// RegExp.prototype.exec is a pattern match: a name the file binds only to a
// regular expression, a literal and a RegExp construction do not make an
// unsafe command execution. Every other exec call keeps the finding
// (CI #1456 gw17: a Copilot apply_patch with pattern.exec(line)).
func TestCodeGuardExecRuleReadsRegExpExecAsAMatch(t *testing.T) {
	for _, tc := range []struct {
		name, file, src string
		fires           bool
	}{
		{"named regex const", "src/parser.ts", "const logLinePattern = /^(INFO|WARN)\\s+(.+)$/;\nconst m = logLinePattern.exec(line.trim());\n", false},
		{"named regex with flags and type", "a.ts", "const re: RegExp = /a[/]b/gi;\nwhile ((m = re.exec(s)) !== null) {}\n", false},
		{"class field regex", "a.ts", "class P {\n  private static readonly TOKEN = /\\d+/g;\n  next(s: string) { return P.TOKEN.exec(s); }\n}\n", false},
		{"member receiver", "a.js", "const pattern = new RegExp(\"a+\", \"g\");\nconst m = this.pattern.exec(x);\n", false},
		{"literal receiver", "a.js", "const m = /ab+c/.exec(line);\n", false},
		{"construction receiver", "a.js", "const m = new RegExp(\"a+\").exec(line);\n", false},
		{"return of literal exec", "a.js", "function f(s) { return /x(\\d)/g.exec(s); }\n", false},
		{"CRLF source", "a.ts", "const re = /x/;\r\nconst m = re.exec(s);\r\n", false},

		{"child_process.exec", "a.js", "const out = child_process.exec(cmd);\n", true},
		{"unbound receiver", "a.js", "cp.exec(userInput);\n", true},
		{"module receiver", "a.js", "const cp = require('child_process');\ncp.exec(userInput);\n", true},
		{"bare exec", "a.ts", "exec(`rm -rf ${dir}`);\n", true},
		{"regex name reused for a module", "a.js", "let sh = /x/;\nsh = require('child_process');\nsh.exec(cmd);\n", true},
		{"regex name shadowed", "a.js", "const re = /x/;\nfunction run(re) { re.exec(cmd); }\nconst re2 = require('child_process');\nre2.exec(cmd);\n", true},
		{"division is not a literal", "a.js", "const q = a/b/g.exec(cmd);\n", true},
		{"unbound receiver beside a regex", "a.js", "const re = /x/;\nre.exec(s); other.exec(cmd);\n", true},
		{"python os.system", "a.py", "import os\nos.system(cmd)\n", true},
		{"python exec", "a.py", "exec(code)\n", true},
		{"php system", "a.php", "<?php system($cmd);\n", true},
		{"eval", "a.js", "const re = /x/;\neval(code);\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := execFires(t, tc.file, tc.src); got != tc.fires {
				t.Fatalf("CG-EXEC-001 fires = %v, want %v for %q", got, tc.fires, tc.src)
			}
		})
	}
}

// The file scan reads a file's names before its lines, as the content scan
// does, and a file without a regular expression is read as before.
func TestCodeGuardExecRuleReadsFilesLikeContent(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"benign.ts": "const pattern = /a+/;\nconst m = pattern.exec(line);\n",
		"unsafe.js": "const cp = require('child_process');\ncp.exec(cmd);\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := NewCodeGuardScanner("").Scan(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var benign, unsafe int
	for _, f := range res.Findings {
		if f.ID != "CG-EXEC-001" {
			continue
		}
		switch {
		case strings.Contains(f.Location, "benign.ts"):
			benign++
		case strings.Contains(f.Location, "unsafe.js"):
			unsafe++
		}
	}
	if benign != 0 || unsafe != 1 {
		t.Fatalf("CG-EXEC-001 benign.ts=%d unsafe.js=%d, want 0 and 1", benign, unsafe)
	}
}
