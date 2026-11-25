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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// g0684Row is one rg call that may move its folder first. up runs the call
// with the hook in the folder above the project. In cmd, @P is the project
// (absolute), @B its name, @U the folder above it.
type g0684Row struct {
	up   bool
	cmd  string
	want []string // what real ripgrep 14.1.0 reads (TestGAP0684RgWorkingFolderLive)
	over string   // why the resolve counts more, "" when exact
}

// g0684Unsure: rg's working folder is not known exactly, so every glob is
// unsure (an include matches every path, a "!" glob none): base and rel
// behaviour, never weaker than real rg.
const g0684Unsure = "count when unsure: rg's working folder is not known exactly"

// g0684Rows is substrate-1:GAP-0684: rg matches its globs from its own
// working folder, the one the call's cd, pushd or popd moved it to, not
// the hook's.
var g0684Rows = []g0684Row{
	// RV6's five rows (weaker than base and rel at 7507c63447).
	{false, "cd @P/sub && rg -g '/.env' KEY @P/sub", []string{"sub/.env"}, ""},
	{true, "cd @P && rg -g '/.env' KEY @P", []string{".env"}, ""},
	{true, "cd @P && rg -g 'deploy/*' KEY @P", []string{"deploy/id_ed25519"}, ""},
	{true, "pushd @P >/dev/null && rg -g 'deploy/*' KEY @P", []string{"deploy/id_ed25519"}, ""},
	{true, "(cd @P && rg -g '/deploy/**' KEY @P)", []string{"deploy/id_ed25519"}, ""},
	// Folders resolved exactly: the globs stay exact (GAP-0683).
	{true, "cd @P && rg -g '*.yml' TODO @P", []string{}, ""},
	{true, "cd @P && rg -g '!deploy/' KEY @P", []string{}, ""},
	{true, "cd ./@B && rg -g '/.env' KEY @P", []string{".env"}, ""},
	{true, "cd @P/sub/.. && rg -g '/.env' KEY @P", []string{".env"}, ""},
	{true, "cd -- @P && rg -g '/.env' KEY @P", []string{".env"}, ""},
	{true, "builtin cd @P && rg -g '/.env' KEY @P", []string{".env"}, ""},
	{true, "if cd @P; then rg -g '/.env' KEY @P; fi", []string{".env"}, ""},
	{true, "sh -c 'cd @P && rg -g /.env KEY @P'", []string{".env"}, ""},
	{true, "cd @P && sh -c 'rg -g /.env KEY @P'", []string{".env"}, ""},
	{true, "cd @P && timeout 5 rg -g '/.env' KEY @P", []string{".env"}, ""},
	{true, "cd @P && echo $(rg -g '/.env' KEY @P)", []string{".env"}, ""},
	{true, "cd @P/.e && rg -g nv KEY @P", []string{".env"}, ""},
	// Folders not known exactly: every glob is unsure.
	{true, "cd @P && cd / && cd - >/dev/null && rg -g '/.env' KEY @P", []string{".env"}, g0684Unsure},
	{true, "pushd @P >/dev/null && pushd / >/dev/null && popd >/dev/null && rg -g '/.env' KEY @P", []string{".env"}, g0684Unsure},
	{true, `D=@P; cd "$D" && rg -g '/.env' KEY @P`, []string{".env"}, g0684Unsure},
	{true, `D=@P; cd "$D" && rg -g '*.yml' TODO @P`, []string{}, g0684Unsure},
	{true, `D=@P/.e; cd "$D" && rg -g nv KEY @P`, []string{".env"}, g0684Unsure},
	{true, "cd $(echo @P) && rg -g 'deploy/*' KEY @P", []string{"deploy/id_ed25519"}, g0684Unsure},
	{true, "CDPATH=@P cd sub >/dev/null && rg -g '/.env' KEY @P/sub", []string{"sub/.env"}, ""},
	{true, "export CDPATH=@P; cd sub >/dev/null && rg -g '/.env' KEY @P/sub", []string{"sub/.env"}, ""},
	{true, "cd @P; rg -g 'deploy/*' KEY @P", []string{"deploy/id_ed25519"}, g0684Unsure},
	{true, "cd(){ builtin cd @P; }; cd @P/sub && rg -g '/.env' KEY @P", []string{".env"}, g0684Unsure},
	{true, "cd @P && HOME=@P/sub; cd ~ && rg -g '/.env' KEY @P/sub", []string{"sub/.env"}, ""},
	{true, "cd @P && cd && rg -g '/.env' KEY @P", []string{}, g0684Unsure},
	// cd -L (the default) takes ".." from the path as written, cd -P from
	// the folder the link names: the folder is unsure.
	{true, "cd @P/lnk/.. && rg -g '/.env' KEY @P", []string{".env"}, g0684Unsure},
	{true, "cd -P @P/lnk/.. && rg -g '/.env' KEY @P", []string{}, g0684Unsure},
	// No move: the hook's folder, as before.
	// A mover body that may return before its cd leaves rg where the
	// return ran too: never one exact folder (substrate-1:GAP-0689, the
	// FU12 merge of rel-1-0-10:GAP-1144 and GAP-0684).
	{false, "f(){ test -e .env && return; cd /; }; f && rg -g '/.env' KEY @P", []string{".env"}, g0684Unsure},
	{false, "f(){ [ -e .env ] && return 0; cd /tmp; }; f && rg -g '/.env' KEY @P", []string{".env"}, g0684Unsure},
	{false, "f(){ return; cd /; }; f && rg -g '/.env' KEY @P", []string{".env"}, g0684Unsure},
	{false, "f(){ test -e .env && builtin return; cd /; }; f && rg -g 'deploy/*' KEY @P", []string{"deploy/id_ed25519"}, g0684Unsure},
	{false, "f(){ if test -e .env; then return; fi; cd /; }; f && rg -g '/.env' KEY @P", []string{".env"}, g0684Unsure},
	// A return that cannot pass the && keeps the folder exact.
	{false, "f(){ test -e .nope && return 1; cd @P/sub; }; f && rg -g '/.env' KEY @P/sub", []string{"sub/.env"}, ""},
	{false, "rg -g 'deploy/*' KEY @P", []string{"deploy/id_ed25519"}, ""},
	{false, "rg -g '/.env' KEY @P", []string{".env"}, ""},
}

// g0684Folder is g0683Folder with a folder .e (a byte prefix of .env) and
// a link lnk to x/y, its physical path, resolved.
func g0684Folder(t *testing.T) string {
	t.Helper()
	dir := g0683Folder(t)
	if physical, err := filepath.EvalSymlinks(dir); err == nil {
		dir = physical
	}
	for _, sub := range []string{".e", "x/y"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(sub)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "x", "y"), filepath.Join(dir, "lnk")); err != nil {
		t.Skipf("no symbolic link here: %v", err)
	}
	return dir
}

// g0684Place is the command of row in dir and the hook's folder.
func g0684Place(dir string, row g0684Row) (cmd, hook string) {
	up := filepath.Dir(dir)
	cmd = strings.NewReplacer("@P", dir, "@B", filepath.Base(dir), "@U", up).Replace(row.cmd)
	if row.up {
		return cmd, up
	}
	return cmd, dir
}

// TestGAP0684RgWorkingFolderLive checks g0684Rows against a real ripgrep
// 14.1.0, run by bash (pushd and popd) in the hook's folder.
func TestGAP0684RgWorkingFolderLive(t *testing.T) {
	rg, _ := g0679LiveRG(t)
	bash, err := exec.LookPath("bash")
	if err != nil {
		if os.Getenv("DEFENSECLAW_RG_REQUIRED") == "1" {
			t.Fatal("no bash for the GAP-0684 ground truth")
		}
		t.Skip("no bash for the GAP-0684 ground truth")
	}
	dir := g0684Folder(t)
	bin := t.TempDir()
	if err := os.Symlink(rg, filepath.Join(bin, "rg")); err != nil {
		t.Fatal(err)
	}
	for _, row := range g0684Rows {
		cmd, hook := g0684Place(dir, row)
		var read []string
		for _, mode := range []string{"-l", "--files-without-match"} {
			run := exec.Command(bash, "-c", strings.ReplaceAll(cmd, "rg ", "rg "+mode+" "))
			run.Dir = hook
			run.Env = []string{"HOME=" + t.TempDir(), "PATH=" + bin + ":/usr/bin:/bin"}
			out, _ := run.Output()
			read = append(read, strings.Split(string(out), "\n")...)
		}
		if got := g0683Rel(dir, read); !slices.Equal(got, row.want) {
			t.Errorf("%s: real rg reads %v, the table says %v", row.cmd, got, row.want)
		}
	}
}

// TestGAP0684EnvChdirNotAuthoritative: env -C and --chdir are not unwrapped
// (posixEnvChangesDirectory), so the call is not an authoritative parse and
// rg's globs are never read against the wrong folder. Such a call starts no
// secret-read chain at this head, at base and at rel alike (P3, 1.0.11).
func TestGAP0684EnvChdirNotAuthoritative(t *testing.T) {
	dir := g0684Folder(t)
	for _, line := range []string{"env -C @P rg -g 'deploy/*' KEY @P", "env --chdir=@P rg -g '/.env' KEY @P"} {
		cmd, hook := g0684Place(dir, g0684Row{up: true, cmd: line})
		facts := Analyze(Input{Tool: "exec", Command: cmd, CWD: hook, ActiveHome: t.TempDir()})
		if facts.Authoritative() || slices.ContainsFunc(facts.Commands, func(c CommandFact) bool { return c.Program == "rg" }) {
			t.Errorf("%s: authoritative %v, commands %v: env -C must stay unread", line, facts.Authoritative(), facts.Commands)
		}
	}
}
