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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2298, GAP-2225 and GAP-2268 (checker it12 RV14-1..4): the shell opens
// every output redirect target before it runs the command, so a static or
// home-spelled target of active state is a write whatever the program word
// is (it may expand), whatever the other words read (HOME, USER and LOGNAME
// are read, not written), for every output-opening operator (<> included)
// and in Bash-only syntax (here-strings, process substitution, arrays).
// Each row has its benign twin (the same command with the target
// ~/build.log), which stays allowed, and reads of state stay allowed.
func TestR105ShellOpensEveryRedirectTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home; the Windows Git Bash rows are TestR105GitBashRedirectTargetOfWindowsHome")
	}
	home, cwd := r104ReviewHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(cwd, "build.sh"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// @T@ is the target: each row is run with every home spelling.
	rows := []string{
		// RV14-1: arguments that read HOME, USER or LOGNAME.
		`echo $HOME > @T@`,
		`echo "home=$HOME" > @T@`,
		`echo $USER > @T@`,
		`printf '%s\n' "$USER" > @T@`,
		`echo $LOGNAME > @T@`,
		`./build.sh --prefix=$HOME/.local > @T@`,
		`make PREFIX=$HOME/.local > @T@`,
		// RV14-2: the read-write redirect opens the file for writing.
		`printf x 1<> @T@`,
		`printf x <> @T@`,
		`make 1<> @T@`,
		`./build.sh 1<> @T@`,
		`env ./build.sh 1<> @T@`,
		// RV14-3: the program word expands.
		`$CMD > @T@`,
		`${CMD:-make} > @T@`,
		`$(which make) > @T@`,
		`"$PWD/build.sh" > @T@`,
		`"$CMD" "$X" > @T@`,
		// RV14-4: Bash-only words.
		`cat <<< x > @T@`,
		`cat <<< "$X" > @T@`,
		`printf x > @T@ <<< y`,
		`cat <(true) > @T@`,
		`diff <(echo a) <(echo b) > @T@`,
		`echo ${arr[0]} > @T@`,
		`arr=(a b); echo ${arr[0]} > @T@`,
	}
	spellings := []string{"~/", "$HOME/", "${HOME}/", `"$HOME"/`, home + "/"}
	allowed := []string{
		`cat < ~/.defenseclaw/config.yaml > ~/out.txt`,
		`grep x ~/.defenseclaw/config.yaml > ~/out.txt`,
		`cat <<< "$HOME" > ~/home.txt`,
		`echo "$HOME" > ~/home.txt`,
		`printf '%s\n' "$USER" > /tmp/user.txt`,
		`$CMD 2>&1 > ~/build.log`,
		`echo x >&2`,
		`echo x 3>&1 1>&2 2>&3-`,
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		judge := func(command string, block bool) {
			t.Helper()
			input := actionfacts.Input{
				Tool: "Bash", Command: command, CWD: cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connectorName, EnforcementCapable: true,
			})
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != block {
				t.Errorf("%s %q: blocked=%v, want %v (%v)",
					connectorName, command, blocked, block, FindingStrings(findings))
			}
		}
		for _, row := range rows {
			for _, spelling := range spellings {
				judge(strings.ReplaceAll(row, "@T@", spelling+".defenseclaw/config.yaml"), true)
				judge(strings.ReplaceAll(row, "@T@", spelling+"build.log"), false)
			}
		}
		for _, command := range allowed {
			judge(command, false)
		}
	}
}

// RV14-5: the Windows Git Bash leg of the same class. Git Bash expands ~,
// $HOME and the MSYS /c/... spelling to the Windows home and opens the
// target before it runs the program, so each of these is the write the
// control printf x > ~/... is, with and without the POSIX dialect hint.
func TestR105GitBashRedirectTargetOfWindowsHome(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows home")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(cwd, "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(cwd, "build.sh"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	forward := filepath.ToSlash(home)
	msys := "/" + strings.ToLower(forward[:1]) + forward[2:]
	programs := []string{"printf x", "make", "echo $X", "make $FLAGS", `./build.sh "$X"`,
		"env ./build.sh", "./build.sh", "cd sub && make", "true && ./build.sh", "git $SUB", "cat <<< x"}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, program := range programs {
				for _, redirect := range []string{">", ">&", "1<>"} {
					for _, spelling := range []string{"~", "$HOME", forward, msys} {
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
								ActiveHome: home, DialectHint: hint,
							}
							findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
								Input: input, Connector: connectorName, EnforcementCapable: true,
							})
							if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
								t.Errorf("%s hint=%q %q: blocked=%v, want %v (%v)",
									connectorName, hint, command, blocked, row.block, FindingStrings(findings))
							}
						}
					}
				}
			}
		}
	}
}

// GAP-2328 (checker it13 RV15-1): a statement before the redirect that runs
// code from a file, from text or from an expanded program word (source,
// ., eval, $CMD, set -a around a source, a variable setter) may change HOME
// only out of sight. The home-spelled target is still judged as the active
// home: if HOME did change, the shell writes below another home, which is
// no benign project write either. The benign twin (~/build.log) stays
// allowed; only a statement that names HOME, USER or LOGNAME as written
// text keeps the target unresolved.
func TestR105CodeBeforeAHomeRedirectTargetStillJudgesIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home, cwd := r104ReviewHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(cwd, "build.sh"),
		filepath.Join(cwd, "env.sh"),
		filepath.Join(cwd, "in.txt"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	prefixes := []string{
		"source .venv/bin/activate && ",
		". ./env.sh; ",
		"cd sub && source env.sh && ",
		"source ~/.bashrc; ",
		"set -a; . ./env.sh; set +a; ",
		"eval true && ",
		`eval "$(direnv export bash)"; `,
		"$CMD; ",
		"read -r v < in.txt; ",
		"printf -v v %s x; ",
		"mapfile -t a < in.txt; ",
		"export $VARS; ",
		"export USERNAME=dev; ",
		"trap 'echo done' EXIT; ",
	}
	programs := []string{"make", "./build.sh", `python3 -c "print('mode: observe')"`, "npm test",
		"echo $X", "node x.js"}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		judge := func(command string, block bool) {
			t.Helper()
			input := actionfacts.Input{
				Tool: "Bash", Command: command, CWD: cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connectorName, EnforcementCapable: true,
			})
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != block {
				t.Errorf("%s %q: blocked=%v, want %v (%v)",
					connectorName, command, blocked, block, FindingStrings(findings))
			}
		}
		for _, prefix := range prefixes {
			for _, program := range programs {
				for _, spelling := range []string{"~/", "$HOME/", home + "/"} {
					judge(prefix+program+" > "+spelling+".defenseclaw/config.yaml", true)
					judge(prefix+program+" > "+spelling+"build.log", false)
				}
			}
		}
		// Benign work after code that may change HOME stays allowed.
		for _, command := range []string{
			"source .venv/bin/activate && pytest > ~/test.log",
			". ./env.sh; make > ~/build.log",
			`eval "$(direnv export bash)"; npm test > $HOME/npm.log`,
			"source .venv/bin/activate && grep x ~/.defenseclaw/config.yaml > ~/out.txt",
		} {
			judge(command, false)
		}
	}
}
