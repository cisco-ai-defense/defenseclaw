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
