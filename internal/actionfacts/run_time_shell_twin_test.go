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

import "testing"

// TestRunTimeShellTwin: a program word that names its shell at run time is
// written as that shell, behind prefix wrappers and in a static shell
// STRING; a program named at run time that is no shell, and an operator that
// does not name the shell, are not (rel-1-0-10:GAP-0980, GAP-0981).
func TestRunTimeShellTwin(t *testing.T) {
	rows := []struct {
		command, want string
	}{
		{`"$SHELL" -c 'make test'`, `bash -c 'make test'`},
		{`$SHELL -ec 'make test'`, `bash -ec 'make test'`},
		{`${SHELL} -o pipefail -c 'make test'`, `bash -o pipefail -c 'make test'`},
		{`"${SHELL:-sh}" -c -- 'make test'`, `sh -c -- 'make test'`},
		{`"${SHELL:-/bin/zsh}" -c 'make test'`, `zsh -c 'make test'`},
		{`"${SHELL##*/}" -c 'make test'`, `bash -c 'make test'`},
		{`$BASH -lc 'make test'`, `bash -lc 'make test'`},
		{`"$ZSH_NAME" -c 'make test'`, `zsh -c 'make test'`},
		{`$0 -c 'make test'`, `bash -c 'make test'`},
		{`env FOO=1 "$SHELL" -c 'make test'`, `env FOO=1 bash -c 'make test'`},
		{`command "$SHELL" -c 'make test'`, `command bash -c 'make test'`},
		{`exec "$SHELL" -c 'make test'`, `exec bash -c 'make test'`},
		{`nohup "$SHELL" -c 'make test'`, `nohup bash -c 'make test'`},
		{`time "$SHELL" -c 'make test'`, `time bash -c 'make test'`},
		{`FOO=$BAR "$SHELL" -c 'make test'`, `FOO=$BAR bash -c 'make test'`},
		{`"$SHELL" <<< 'make test'`, `bash -c 'make test' <<< 'make test'`},
		// echo ends its line (rel-1-0-10:GAP-1146).
		{`echo 'make test' | "$SHELL" -s`, "echo 'make test' | bash -c 'make test\n'"},
		{`cd web && "$SHELL" -c 'npm test'`, `cd web && bash -c 'npm test'`},
		// A static shell STRING is its own command line.
		{`bash -c '"$SHELL" -c "make test"'`, `bash -c 'bash -c "make test"'`},
		{`"$SHELL" -c "$CMD"`, `bash -c "$CMD"`},
		{`sh -c '$0 -c "make test"'`, `sh -c 'bash -c "make test"'`},
		{`$(which sh) -c 'make test'`, `sh -c 'make test'`},
		{"`which bash` -ec 'make test'", `bash -ec 'make test'`},
		{`"$(command -v bash)" -o pipefail -c 'make test'`, `bash -o pipefail -c 'make test'`},
	}
	for _, row := range rows {
		got, ok, _, _ := RunTimeShellTwin(row.command)
		if !ok || got != row.want {
			t.Errorf("RunTimeShellTwin(%q) = %q, %v; want %q", row.command, got, ok, row.want)
		}
	}
	for _, command := range []string{
		`bash -c 'make test'`,
		`"$GREP" -c TODO notes.txt`,
		`$WC -c notes.txt`,
		`"$TOOL" -c 'make test'`,
		`$T send 'hello'`,
		`"${SHELL:+x}" -c 'make test'`,
		`"${SHELL/bash/python3}" -c 'make test'`,
		`"${#SHELL}" -c 'make test'`,
		`"$SHELL"x -c 'make test'`,
		`echo "$SHELL"`,
		`printf '%s\n' "$SHELL" -c 'make test'`,
		// $0 of a STRING with a name operand is that name.
		`sh -c '$0 -c "make test"' tool`,
		`$(which grep) -c TODO notes.txt`,
		`$(command -V bash) -c 'make test'`,
	} {
		if got, ok, _, _ := RunTimeShellTwin(command); ok {
			t.Errorf("RunTimeShellTwin(%q) = %q; want no reading", command, got)
		}
	}
}
