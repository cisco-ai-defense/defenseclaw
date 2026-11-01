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

package actionfacts

import (
	"strings"
	"testing"
)

// A relative operand of a POSIX shell command run under a native Windows
// working directory (Git Bash) names the file under that directory; it was
// left unresolved, so cd ~ && cp a.txt .defenseclaw/config.yaml hid the
// state write (GAP-2473). A drive path, an MSYS drive mount and ~ under a
// Windows home name the drive file; expanding and quoted-tilde operands
// keep their own readings.
func TestPOSIXRelativeOperandResolvesUnderAWindowsCWD(t *testing.T) {
	t.Parallel()
	slash := func(value string) string { return strings.ToLower(strings.ReplaceAll(value, `\`, "/")) }
	rows := []struct {
		command, cwd, value, want string
	}{
		{"cp a.txt ../.defenseclaw/config.yaml", `C:\Users\u\project`, "../.defenseclaw/config.yaml", "c:/users/u/.defenseclaw/config.yaml"},
		{"cp a.txt .defenseclaw/config.yaml", `C:\Users\u`, ".defenseclaw/config.yaml", "c:/users/u/.defenseclaw/config.yaml"},
		{"cp a.txt ./b/../c.txt", `C:\Users\u\project`, "./b/../c.txt", "c:/users/u/project/c.txt"},
		{"cp a.txt $X/c.txt", `C:\Users\u\project`, "$X/c.txt", ""},
		{"cp a.txt /tmp/c.txt", `C:\Users\u\project`, "/tmp/c.txt", "/tmp/c.txt"},
		{"cp a.txt C:/Users/u/.defenseclaw/config.yaml", `C:\Users\u\project`, "C:/Users/u/.defenseclaw/config.yaml", "c:/users/u/.defenseclaw/config.yaml"},
		{"cp a.txt /c/Users/u/.defenseclaw/config.yaml", `C:\Users\u\project`, "/c/Users/u/.defenseclaw/config.yaml", "c:/users/u/.defenseclaw/config.yaml"},
		{"cp a.txt '~/x.txt'", `C:\Users\u\project`, "~/x.txt", ""},
		{"cp a.txt ../c.txt", "/home/u/project", "../c.txt", "/home/u/c.txt"},
	}
	for _, row := range rows {
		home := `C:\Users\u`
		if strings.HasPrefix(row.cwd, "/") {
			home = "/home/u"
		}
		facts := Analyze(Input{Tool: "Bash", Command: row.command, CWD: row.cwd, ActiveHome: home,
			DialectHint: DialectPOSIX, MovedWindowsShellCWD: true})
		found := false
		for _, fact := range facts.Paths {
			if fact.Value != row.value {
				continue
			}
			found = true
			if slash(fact.Resolved) != row.want {
				t.Errorf("%q in %q: %s resolved %q, want %q", row.command, row.cwd, row.value, fact.Resolved, row.want)
			}
		}
		if !found && row.want != "" {
			t.Errorf("%q in %q: no path fact %q in %#v", row.command, row.cwd, row.value, facts.Paths)
		}
	}
	// The action itself (no moved directory) keeps the train's reading: a
	// relative Git Bash operand under a Windows cwd inside the trusted home
	// resolves there (classifier-ps cd52e3d987 + d6868f00a2, which is what
	// blocks the managed Windows junction rows J01/J02; classifier-c
	// iteration 20 merge note). It is never placed anywhere else.
	facts := Analyze(Input{Tool: "Bash", Command: "cp a.txt ../.defenseclaw/config.yaml", CWD: `C:\Users\u\project`,
		ActiveHome: `C:\Users\u`, DialectHint: DialectPOSIX})
	for _, fact := range facts.Paths {
		if fact.Value != "../.defenseclaw/config.yaml" {
			continue
		}
		if got := slash(fact.Resolved); got != "" && got != "c:/users/u/.defenseclaw/config.yaml" {
			t.Errorf("unmoved %s resolved %q, want unresolved or the home path", fact.Value, fact.Resolved)
		}
	}
}
