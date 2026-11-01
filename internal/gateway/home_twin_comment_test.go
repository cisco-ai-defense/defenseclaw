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

// A comment never runs, so a HOME, USER or USERPROFILE word inside one cannot
// change what ~, $HOME or ${HOME} name. The gateway reading (no hook client
// map) declined its home twins on any raw HOME text, so a trailing "# HOME"
// let a home-spelled write to DefenseClaw state or the keys file through with
// no finding while the same command with "# note" blocked (GAP-2473).
func TestHomeSpellingWriteWithACommentThatNamesHomeBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home; the Windows rows are in TestWindowsHomeSpellingWriteWithACommentThatNamesHomeBlocks")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(cwd, "a.txt"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
	}{
		{"cp a.txt $HOME/.defenseclaw/config.yaml # HOME", true},
		{"cp a.txt ~/.defenseclaw/config.yaml # HOME", true},
		{"cp a.txt ${HOME}/.defenseclaw/config.yaml # set HOME later", true},
		{"rm -rf ${HOME}/.defenseclaw/hooks  # clean HOME dir", true},
		{"dd if=a.txt of=$HOME/.defenseclaw/config.yaml # USER LOGNAME HOME", true},
		{"echo k >> ~/.ssh/authorized_keys # HOME", true},
		{"cp a.txt $HOME/.defenseclaw/config.yaml # note", true},
		// The benign twins stay allowed.
		{"cp a.txt $HOME/project/x.txt # HOME", false},
		{"cp a.txt ~/project/y.txt # HOME", false},
		{`echo "# HOME" > notes.txt`, false},
		{"ls ~ # HOME", false},
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, row := range rows {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, Connector: connectorName, EnforcementCapable: true,
				})
				blocked := buildVerdict(findings, "tool_call").Action == "block"
				if blocked != row.block {
					t.Errorf("%s hint=%q %q: block=%v, want %v", connectorName, hint, row.command, blocked, row.block)
				}
			}
		}
	}
}

// The Windows Git Bash rows of GAP-2473: $HOME and $USERPROFILE spellings of
// a DefenseClaw state write with a comment that names HOME or USERPROFILE.
func TestWindowsHomeSpellingWriteWithACommentThatNamesHomeBlocks(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows home")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(cwd, "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct {
		command string
		block   bool
	}{
		{"cp a.txt $HOME/.defenseclaw/config.yaml # HOME", true},
		{"cp a.txt $USERPROFILE/.defenseclaw/config.yaml # HOME", true},
		{"cp a.txt $USERPROFILE/.defenseclaw/config.yaml # USERPROFILE", true},
		{"rm -rf ${USERPROFILE}/.defenseclaw/hooks  # clean HOME dir", true},
		{"cp a.txt $USERPROFILE/.defenseclaw/config.yaml # note", true},
		{"cp a.txt $USERPROFILE/project/x.txt # HOME", false},
		{"cp a.txt $HOME/project/y.txt # USERPROFILE", false},
		{`echo "# USERPROFILE" > notes.txt`, false},
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, row := range rows {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, Connector: connectorName, EnforcementCapable: true,
				})
				blocked := buildVerdict(findings, "tool_call").Action == "block"
				if blocked != row.block {
					t.Errorf("%s hint=%q %q: block=%v, want %v", connectorName, hint, row.command, blocked, row.block)
				}
			}
		}
	}
}
