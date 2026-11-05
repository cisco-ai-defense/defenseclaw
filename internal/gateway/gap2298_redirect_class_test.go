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

// GAP-0428 regression of the GAP-2298 class (PR #1427 CI, gateway shard 35):
// the shell expands and opens a command's redirects before the command runs,
// so what the command binds (printf %n or -v, an unknown printf format that
// may hold %n, read, export, declare, local) cannot move its own redirect
// target. An assignment-only statement is read both ways: bash assigns
// first, dash opens the redirect first. Nested sh -c and dash -c bodies are
// read the same way.
func TestGAP0428RedirectIsOpenedBeforeTheCommandBinds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell grammar; the Windows readings have their own rows")
	}
	home, cwd := r104ReviewHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		command string
		block   bool
	}{
		{`printf "$X" > "$HOME"/.defenseclaw/config.yaml`, true},
		{`printf "$X" > "$HOME"/build.log`, false},
		{`printf '%n' HOME > "$HOME"/.defenseclaw/config.yaml`, true},
		{`printf 'ab%n' HOME > "$HOME"/build.log`, false},
		{`printf -v HOME x > "$HOME"/.defenseclaw/config.yaml`, true},
		{`printf -v HOME x > "$HOME"/build.log`, false},
		{`read HOME < /dev/null > "$HOME"/.defenseclaw/config.yaml`, true},
		{`printf "$X"; echo > "$HOME"/build.log`, false},
		{`HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml`, true},
		{`A=1 HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml`, true},
		{`HOME=/tmp/elsewhere >> "$HOME"/.defenseclaw/config.yaml`, true},
		{`HOME=/tmp/elsewhere 2> "$HOME"/.defenseclaw/config.yaml`, true},
		{`HOME=/tmp/elsewhere >| "$HOME"/.defenseclaw/config.yaml`, true},
		{`> "$HOME"/.defenseclaw/config.yaml HOME=/tmp/elsewhere`, true},
		{`sh -c 'HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml'`, true},
		{`dash -c 'HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml'`, true},
		{`export HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml`, true},
		{`export HOME=/tmp/elsewhere >> "$HOME"/.defenseclaw/config.yaml`, true},
		{`declare HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml`, true},
		{`declare -x HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml`, true},
		{`typeset HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml`, true},
		{`readonly HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml`, true},
		{`f() { local HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml; }; f`, true},
		{`sh -c 'export HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml'`, true},
		{`dash -c 'export HOME=/tmp/elsewhere > "$HOME"/.defenseclaw/config.yaml'`, true},
		{`FOO=bar > out.log`, false},
		{`X=1 > "$HOME"/build.log`, false},
		{`HOME=/tmp/elsewhere > "$HOME"/build.log`, false},
		{`sh -c 'FOO=bar > out.log'`, false},
		{`dash -c 'X=1 > "$HOME"/build.log'`, false},
		{`export PATH="$PATH:/x" > build.log`, false},
		{`export HOME=/tmp/elsewhere > "$HOME"/build.log`, false},
		{`declare -x FOO=bar > "$HOME"/build.log`, false},
		{`f() { local x=1 > out.log; }; f`, false},
		{`sh -c 'export PATH="$PATH:/x" > build.log'`, false},
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, row := range rows {
			input := actionfacts.Input{
				Tool: "Bash", Command: row.command, CWD: cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connectorName, EnforcementCapable: true,
			})
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
				t.Errorf("%s %q: blocked=%v, want %v (%v)",
					connectorName, row.command, blocked, row.block, FindingStrings(findings))
			}
		}
	}
}
