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

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2298, GAP-2225 and GAP-2268 (checker it11 RV13-1..3): the shell
// expands a redirect target from HOME and opens it before it runs the
// program, so the target is a write whatever the program is, whatever its
// other words expand to, and on either side of a plain && or || list. The
// class is generated: every home spelling x program form x redirect form
// blocks, and the benign twin (same spelling, form and program, target
// ~/build.log) is allowed.
func TestR105StaticRedirectTargetIsAWriteWhateverTheCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell grammar; the Windows readings have their own rows")
	}
	home, cwd := r104ReviewHome(t)
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	for _, dir := range []string{hooks, filepath.Join(cwd, "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(cwd, "build.sh"),
		filepath.Join(cwd, "Makefile"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	spellings := []string{
		"~",
		"$HOME",
		"${HOME}",
		`"$HOME"`,
		filepath.Dir(home) + "/$USER",
		home,
	}
	programs := []string{
		`echo $X`,
		`printf "$X"`,
		`cat "$F"`,
		`make $FLAGS`,
		`./build.sh "$X"`,
		`./build.sh $(date +%s)`,
		`env ./build.sh`,
		`sudo ./build.sh`,
		`exec ./build.sh`,
		`env make`,
		`cd sub && make`,
		`cd . && ./build.sh`,
		`true && ./build.sh`,
		`false || ./build.sh`,
	}
	redirects := []string{">", ">>", ">&", "&>"}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, spelling := range spellings {
			for _, program := range programs {
				for _, redirect := range redirects {
					for _, row := range []struct {
						target string
						block  bool
					}{
						{spelling + "/.defenseclaw/config.yaml", true},
						{spelling + "/build.log", false},
					} {
						command := program + " " + redirect + " " + row.target
						input := actionfacts.Input{
							Tool: "Bash", Command: command, CWD: cwd,
							ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
						}
						findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
							Input: input, Connector: connectorName, EnforcementCapable: true,
						})
						blocked := buildVerdict(findings, "tool_call").Action == "block"
						if blocked != row.block {
							t.Errorf("%s %q: blocked=%v, want %v (%v)",
								connectorName, command, blocked, row.block, FindingStrings(findings))
						}
					}
				}
			}
		}
	}
}
