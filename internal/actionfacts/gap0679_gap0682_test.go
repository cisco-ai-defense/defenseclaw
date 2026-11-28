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
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// g0679Credentials is the credentials files of g0679Folder.
var g0679Credentials = []string{".aws/credentials", ".env", ".npmrc", ".ssh/id_rsa", "sub/.env"}

// g0679Folder is g0673Folder with .ssh/id_rsa and cfg.txt, an rg config
// file that turns --hidden on (RIPGREP_CONFIG_PATH=cfg.txt).
func g0679Folder(t *testing.T) string {
	t.Helper()
	dir := g0673Folder(t)
	for name, text := range map[string]string{".ssh/id_rsa": "KEY\n", "cfg.txt": "--hidden\n"} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// g0679Rel is the credentials files among names, relative to dir, sorted.
func g0679Rel(dir string, names []string) []string {
	var out []string
	for _, name := range names {
		if filepath.IsAbs(name) {
			if rel, err := filepath.Rel(dir, name); err == nil {
				name = rel
			}
		}
		name = strings.TrimPrefix(filepath.ToSlash(name), "./")
		if slices.Contains(g0679Credentials, name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// g0679Row is one shell command that runs rg, and the credentials files
// real ripgrep 14.1.0 reads when it runs in g0679Folder (recorded on the
// build box with TestGAP0673RgGroundTruthLive's method: rg -l and rg
// --files-without-match, a clean environment, no stdin). over says why
// the resolve counts more than rg (P3 for 1.0.11, no weaker than rel); an
// empty over means the count must equal rg's.
type g0679Row struct {
	cmd  string
	want []string
	over string
}

const (
	g0679All   = "count when unsure: a hidden read turns every hidden credentials file on"
	g0679Words = "count when unsure: a word known only when it runs may be --hidden"
	// rg reads a -f pattern file; rg -l lists only the files it searches.
	g0679PatternFile = "rg reads the -f pattern file, rg -l does not list it"
)

var g0679Every = []string{".aws/credentials", ".env", ".npmrc", ".ssh/id_rsa", "sub/.env"}

// g0679Rows is substrate-1:GAP-0679: "-" is standard input only where a
// path goes. Where the pattern goes (no -e or -f, first positional word)
// it is the pattern.
var g0679Rows = []g0679Row{
	{"rg --hidden - .", g0679Every, ""},
	{"rg -uu - .", g0679Every, ""},
	{"rg --hidden -", g0679Every, ""},
	{"rg -. - sub", []string{"sub/.env"}, ""},
	{"rg - .aws", []string{".aws/credentials"}, ""},
	{"rg - .env", []string{".env"}, ""},
	{"rg --hidden -- - .", g0679Every, ""},
	{"rg --hidden - -", []string{}, ""},
	{"rg -e KEY --hidden -", []string{}, ""},
	{"rg --hidden -v - .", g0679Every, ""},
	{"rg -uu -v -", g0679Every, ""},
	{"rg -e - --hidden .", g0679Every, ""},
	{"rg --hidden -e KEY - .", g0679Every, ""},
	{"rg -f pat.txt --hidden - .", g0679Every, ""},
	{"rg --hidden KEY -", []string{}, ""},
	{"rg --hidden -- KEY -", []string{}, ""},
}

// g0680Rows is substrate-1:GAP-0680: a folder glob lets rg enter a hidden
// folder, where another include glob matches.
var g0680Rows = []g0679Row{
	{"rg -g '.aws/' -g credentials KEY", []string{".aws/credentials"}, ""},
	{"rg -g '*/' -g credentials KEY", []string{".aws/credentials"}, ""},
	{"rg -g '**/' -g 'id_*' KEY", []string{".ssh/id_rsa"}, ""},
	{"rg --iglob '.AWS/' --iglob CREDENTIALS KEY", []string{".aws/credentials"}, ""},
	{"rg -g '.aws/' -g '.aws/credentials' KEY", []string{".aws/credentials"}, ""},
	{"rg -g '.ssh/' -g id_rsa KEY", []string{".ssh/id_rsa"}, ""},
	{"rg -g '.aws/' -g 'cred*' KEY", []string{".aws/credentials"}, ""},
	{"rg -g '.aws/' KEY", []string{}, ""},
	{"rg -g '.aws/' -g credentials KEY .", []string{".aws/credentials"}, ""},
	{"rg -g '*/' -g 'id_*' KEY .", []string{".ssh/id_rsa"}, ""},
	{"rg -g '/.aws/' -g credentials KEY", []string{".aws/credentials"}, ""},
	{"rg --iglob '*/' --iglob Credentials KEY", []string{".aws/credentials"}, ""},
	{"rg -g '?aws/' -g credentials KEY", []string{".aws/credentials"}, ""},
	{"rg -g 'sub[/].env' KEY", []string{"sub/.env"}, ""},
	{"rg -g 'sub\\/.env' KEY", []string{"sub/.env"}, ""},
	{"rg -g sub KEY", []string{}, ""},
	{"rg -g 'sub/' KEY", []string{}, ""},
	{"rg -g 's*b' -g 'cred*' KEY", []string{}, ""},
	{"rg -g credentials -g id_rsa KEY", []string{}, ""},
	{"rg -g '' KEY", []string{}, ""},
	{"rg -g / KEY", []string{}, ""},
}

// g0681Rows is substrate-1:GAP-0681: a glob segment that starts with a
// class, an escape or a wildcard may match a dot name, and a class may
// match "/".
var g0681Rows = []g0679Row{
	{"rg -g '[!_]env' KEY", []string{".env", "sub/.env"}, ""},
	{"rg -g '[!x]npmrc' KEY", []string{".npmrc"}, ""},
	{"rg -g '.[!x]nv' KEY", []string{".env", "sub/.env"}, ""},
	{"rg --type-add 'e:[!_]env' -te KEY", []string{".env", "sub/.env"}, ""},
	{"rg -g '[^_]env' KEY", []string{".env", "sub/.env"}, ""},
	{"rg -g '\\.env' KEY", []string{".env", "sub/.env"}, ""},
	{"rg -g '[!_]env' KEY .", []string{".env", "sub/.env"}, ""},
	{"rg --type-add 'e:[!_]env' -te KEY .", []string{".env", "sub/.env"}, ""},
	{"rg -g 'sub[!x].env' KEY", []string{"sub/.env"}, ""},
	{"rg -g '[.]env' KEY", []string{".env", "sub/.env"}, ""},
	{"rg -g '[a.]env' KEY", []string{".env", "sub/.env"}, ""},
	{"rg --iglob '[!_]ENV' KEY", []string{".env", "sub/.env"}, ""},
	{"rg --type-add 'e:[^_]npmrc' -te KEY", []string{".npmrc"}, ""},
	{"rg --type-add 'e:*.go,[!_]env' -tall KEY", []string{}, ""},
	{"rg -g '?env' KEY", []string{".env", "sub/.env"}, ""},
	{"rg -g 'cred[!x]ntials' KEY", []string{}, ""},
	{"rg -g 'cred[e]ntials' KEY", []string{}, ""},
	{"rg --type-add 'e:id_[r]sa' -te KEY", []string{}, ""},
}

// g0682Rows is substrate-1:GAP-0682: a word known only when the call runs
// may be an rg option (--hidden), and RIPGREP_CONFIG_PATH set by the call
// may add options from a file.
var g0682Rows = []g0679Row{
	{"F=--hidden; rg $F KEY .", g0679Every, ""},
	{"X=.; rg -$X KEY .", g0679Every, ""},
	{"E=; rg --hidden$E KEY .", g0679Every, ""},
	{`rg "$(printf %s --hidden)" KEY .`, g0679Every, ""},
	{"L=.; rg -l$L KEY .", g0679Every, ""},
	{"RIPGREP_CONFIG_PATH=cfg.txt rg KEY .", g0679Every, ""},
	{"export RIPGREP_CONFIG_PATH=cfg.txt; rg KEY .", g0679Every, ""},
	{`T=e; rg --type-add 'e:*.env' -t "$T" KEY`, []string{".env", "sub/.env"}, ""},
	{`A='e:*.env'; rg --type-add "$A" -te KEY`, []string{".env", "sub/.env"}, g0679All},
	{`P=KEY; rg "$P" .`, []string{}, g0679Words},
	{`P=KEY; rg -e "$P" .`, []string{}, ""},
	{`P=KEY; rg -e"$P" .`, []string{}, ""},
	{`G=x; rg --glob="$G" KEY`, []string{}, g0679All},
	{`D=.; rg KEY "$D"`, []string{}, ""},
}

// g0673RV4Rows is the rest of the RV4 probe rows (jobs/p34brv4/real.out).
var g0673RV4Rows = []g0679Row{
	{"rg -tall KEY", []string{}, ""},
	{"rg -tsh -tconfig -tjson -tyaml KEY", []string{}, ""},
	{"rg --type-add 'e:*.env' -te --type-clear e --type-add 'e:*.go' KEY", []string{}, ""},
	{"rg --type-add 'e:*.go' -te --type-add 'e:*.env' KEY", []string{".env", "sub/.env"}, ""},
	{"rg -g '{.aws,credentials}' KEY", []string{".aws/credentials"}, ""},
	{"rg -L KEY", []string{}, ""},
	{"rg -L KEY lnk", []string{}, ""},
	{"rg --ignore-file .aws/credentials KEY src", []string{}, ""},
	{"rg -f .aws/credentials src", []string{}, g0679PatternFile},
	{"rg -lf .aws/credentials src", []string{}, g0679PatternFile},
	{"rg -f=.aws/credentials src", []string{}, g0679PatternFile},
	{"rg --file .aws/credentials -f pat.txt src", []string{}, g0679PatternFile},
}

// g0679Named is the files a call reads by name: the secret-read record's
// (g0671Named) and the read path facts, which hold a file the command
// names (rg - .env), so the record does not repeat it.
func g0679Named(facts Facts) []string {
	named := g0671Named(facts)
	for _, path := range facts.Paths {
		if path.Access == PathAccessRead && path.Value != "" {
			named = append(named, path.Value)
		}
	}
	return named
}

// g0679Check checks rows against the resolve: never weaker than real rg,
// and exact unless the row says why it counts more.
func g0679Check(t *testing.T, rows []g0679Row) {
	t.Helper()
	dir := g0679Folder(t)
	for _, row := range rows {
		got := g0679Rel(dir, g0679Named(Analyze(Input{Tool: "exec", Command: row.cmd, CWD: dir, ActiveHome: t.TempDir()})))
		for _, file := range row.want {
			if !slices.Contains(got, file) {
				t.Errorf("%s: real rg reads %s, the resolve names %v (weaker than rg)", row.cmd, file, got)
			}
		}
		exact := slices.Equal(got, row.want) || len(got) == 0 && len(row.want) == 0
		switch {
		case row.over == "" && !exact:
			t.Errorf("%s: the resolve names %v, real rg reads %v", row.cmd, got, row.want)
		case row.over != "" && exact:
			t.Errorf("%s: marked over (%s) but now exact: drop the mark", row.cmd, row.over)
		}
	}
}

func TestGAP0679RgDashPattern(t *testing.T)    { g0679Check(t, g0679Rows) }
func TestGAP0680RgFolderGlob(t *testing.T)     { g0679Check(t, g0680Rows) }
func TestGAP0681RgClassGlob(t *testing.T)      { g0679Check(t, g0681Rows) }
func TestGAP0682RgRunTimeOption(t *testing.T)  { g0679Check(t, g0682Rows) }
func TestGAP0673RgGroundTruthRV4(t *testing.T) { g0679Check(t, g0673RV4Rows) }

func TestGAP0679RgOperands(t *testing.T) {
	for _, row := range []struct {
		argv     []string
		operands []int
		stdin    bool
	}{
		{[]string{"rg", "--hidden", "-", "."}, []int{2, 3}, false},
		{[]string{"rg", "--hidden", "-", "-"}, []int{2}, true},
		{[]string{"rg", "-e", "KEY", "-"}, nil, true},
		{[]string{"rg", "KEY", "-", "src"}, []int{1, 3}, true},
		{[]string{"rg", "--", "-", "."}, []int{2, 3}, false},
		{[]string{"rg", "-fpat.txt", "-"}, nil, true},
	} {
		line := parseRgCommandLine(row.argv)
		if !slices.Equal(line.operands, row.operands) || line.stdin != row.stdin {
			t.Errorf("%v: operands %v stdin %v, want %v %v", row.argv, line.operands, line.stdin, row.operands, row.stdin)
		}
	}
}

// g0679LiveRG is the real ripgrep the live checks run (DEFENSECLAW_RG,
// else rg on PATH) and sh; it skips, or with DEFENSECLAW_RG_REQUIRED=1
// fails, when there is none of exactly g0673RgVersion.
func g0679LiveRG(t *testing.T) (string, string) {
	t.Helper()
	rg := os.Getenv("DEFENSECLAW_RG")
	if rg == "" {
		rg, _ = exec.LookPath("rg")
	}
	sh, _ := exec.LookPath("sh")
	var version []byte
	if rg != "" {
		version, _ = exec.Command(rg, "--version").Output()
	}
	first, _, _ := strings.Cut(string(version), "\n")
	if rg == "" || sh == "" || os.PathSeparator == '\\' || strings.TrimSpace(first) != g0673RgVersion {
		msg := "the rg tables were recorded with " + g0673RgVersion + "; this rg is " + strconv.Quote(first) +
			" (set DEFENSECLAW_RG to one; DEFENSECLAW_RG_REQUIRED=1 makes this a failure)"
		if os.Getenv("DEFENSECLAW_RG_REQUIRED") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	return rg, sh
}

// g0679Real is the credentials files real rg reads when sh runs cmd in
// dir: rg -l and rg --files-without-match, rg on PATH, a clean
// environment, no stdin.
func g0679Real(t *testing.T, rg, sh, dir, cmd string) []string {
	t.Helper()
	bin := t.TempDir()
	if err := os.Symlink(rg, filepath.Join(bin, "rg")); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	var read []string
	for _, mode := range []string{"-l", "--files-without-match"} {
		line := strings.Replace(cmd, "rg ", "rg "+mode+" ", 1)
		run := exec.Command(sh, "-c", line)
		run.Dir = dir
		run.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin"}
		out, _ := run.Output() // rg exits 1 or 2 when it reads nothing
		read = append(read, strings.Split(string(out), "\n")...)
	}
	return g0679Rel(dir, read)
}

// TestGAP0679RgGroundTruthLive checks the GAP-0679..0682 and RV4 tables
// against a real ripgrep 14.1.0.
func TestGAP0679RgGroundTruthLive(t *testing.T) {
	rg, sh := g0679LiveRG(t)
	dir := g0679Folder(t)
	for _, rows := range [][]g0679Row{g0679Rows, g0680Rows, g0681Rows, g0682Rows, g0673RV4Rows} {
		for _, row := range rows {
			if got := g0679Real(t, rg, sh, dir, row.cmd); !slices.Equal(got, row.want) {
				t.Errorf("%s: real rg reads %v, the table says %v", row.cmd, got, row.want)
			}
		}
	}
}

// g0681FuzzGlob is one random glob shape: one to three segments, each a
// start and one or two parts, maybe anchored with "/", maybe a folder glob.
func g0681FuzzGlob(r *rand.Rand) string {
	starts := []string{".", "*", "?", "[!_]", "[^x]", "[.]", "[a.]", "[!a-z]", "[e]", "\\.", "{.,}", "{a,.}",
		"e", "s", "c", "a", "id_", "sub", "", "**", "cred", ".a", ".s"}
	parts := []string{"env", "aws", "npmrc", "credentials", "rsa", "ssh", "nv", "*", "?", "[!x]", "[/]",
		"[e]", "{x,y}", ".", "_", "ub", "/", "", "redentials", "/.", "[!/]", "\\/"}
	var segments []string
	for range 1 + r.IntN(3) {
		segment := starts[r.IntN(len(starts))] + parts[r.IntN(len(parts))]
		if r.IntN(2) == 0 {
			segment += parts[r.IntN(len(parts))]
		}
		segments = append(segments, segment)
	}
	glob := strings.Join(segments, "/")
	if r.IntN(5) == 0 {
		glob = "/" + glob
	}
	if r.IntN(5) == 0 {
		glob += "/"
	}
	return glob
}

// g0681FuzzPlain is a random glob of literals, "*", "?", "." and "/".
func g0681FuzzPlain(r *rand.Rand) string {
	const alphabet = "*?./ecnvrdsawi_gotkp"
	var b strings.Builder
	for range 1 + r.IntN(9) {
		b.WriteByte(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

// TestGAP0681GlobFuzzLive is substrate-1:GAP-0680 and GAP-0681 for every
// glob shape, not only the listed ones: random --glob, --iglob, two-glob
// and --type-add shapes (a fixed seed; DEFENSECLAW_RG_FUZZ_SEED picks
// another) run on real ripgrep 14.1.0, and the resolve never names fewer
// credentials files than rg reads.
func TestGAP0681GlobFuzzLive(t *testing.T) {
	rg, _ := g0679LiveRG(t)
	seed := uint64(0x0681)
	if s, err := strconv.ParseUint(os.Getenv("DEFENSECLAW_RG_FUZZ_SEED"), 0, 64); err == nil {
		seed = s
	}
	r := rand.New(rand.NewPCG(seed, 0x0680))
	files := []string{"credentials", "id_*", "*.env", ".env", "cred*", "npmrc", "id_rsa"}
	dir := g0679Folder(t)
	home := t.TempDir()
	const rows = 900
	reads, over, weaker := 0, 0, 0
	for range rows {
		glob := g0681FuzzGlob(r)
		var args []string
		switch r.IntN(6) {
		case 0:
			args = []string{"-g", glob}
		case 1:
			args = []string{"--iglob", strings.ToUpper(glob)}
		case 2:
			args = []string{"-g", glob, "-g", files[r.IntN(len(files))]}
		case 3:
			args = []string{"-g", glob, "-g", g0681FuzzGlob(r)}
		case 4:
			// Only literals, * and ?: the shapes the rule reads with
			// path.Match.
			args = []string{"-g", g0681FuzzPlain(r), "-g", g0681FuzzPlain(r)}
		default:
			args = []string{"--type-add", "e:" + glob, "-te"}
		}
		args = append(args, "KEY")
		var real []string
		for _, mode := range []string{"-l", "--files-without-match"} {
			run := exec.Command(rg, append([]string{mode}, args...)...)
			run.Dir = dir
			run.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			out, _ := run.Output()
			real = append(real, strings.Split(string(out), "\n")...)
		}
		want := g0679Rel(dir, real)
		quoted := make([]string, len(args))
		for i, arg := range args {
			quoted[i] = "'" + arg + "'"
		}
		command := "rg " + strings.Join(quoted, " ")
		got := g0679Rel(dir, g0679Named(Analyze(Input{Tool: "exec", Command: command, CWD: dir, ActiveHome: t.TempDir()})))
		if len(want) > 0 {
			reads++
		}
		if len(got) > len(want) {
			over++
		}
		for _, file := range want {
			if !slices.Contains(got, file) {
				weaker++
				if weaker <= 25 {
					t.Errorf("%s: real rg reads %v, the resolve names %v (weaker than rg)", command, want, got)
				}
				break
			}
		}
	}
	t.Logf("seed %#x: %d shapes, %d where rg reads a credentials file, %d counted more than rg, %d weaker", seed, rows, reads, over, weaker)
}
