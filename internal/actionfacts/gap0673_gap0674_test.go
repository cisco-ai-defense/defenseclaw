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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// g0673Credentials is the credentials files of the ground-truth folder.
var g0673Credentials = []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}

// g0673Folder is the ground-truth folder: the credentials files, a source
// file, a pattern file, an ignore file that whitelists .env (wl.txt), one
// that does not (nowl.txt) and a link to .aws (lnk).
func g0673Folder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{
		".env": "KEY\n", ".npmrc": "KEY\n", ".aws/credentials": "KEY\n", "sub/.env": "KEY\n",
		"src/a.go": "KEY\n", "pat.txt": "KEY\n", "wl.txt": "!.env\n", "nowl.txt": "nothing\n",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A link the walk does not follow; real rg -L reads lnk/credentials,
	// which is no credentials path by its name (P3-2 of RV2, 1.0.11).
	_ = os.Symlink(".aws", filepath.Join(dir, "lnk"))
	return dir
}

// g0673Rel is the credentials files among names, relative to dir, sorted.
func g0673Rel(dir string, names []string) []string {
	var out []string
	for _, name := range names {
		if filepath.IsAbs(name) {
			if rel, err := filepath.Rel(dir, name); err == nil {
				name = rel
			}
		}
		name = strings.TrimPrefix(filepath.ToSlash(name), "./")
		if slices.Contains(g0673Credentials, name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// g0673Rows is the ripgrep ground truth (substrate-1:GAP-0673): for each
// argv after rg, the credentials files real ripgrep 14.1.0 reads in
// g0673Folder (rg -l ARGS and rg --files-without-match ARGS together, run
// on defenseclaw-dev with a clean environment; jobs/p34b5/table2.go.txt).
// TestGAP0673RgGroundTruthLive checks the table against a real rg. over
// says why the resolve counts more than rg; an over-count is no weaker
// than rel. An empty over means the count must equal rg's.
var g0673Rows = []struct {
	args string
	want []string
	over string
}{
	{"KEY", []string{}, ""},
	{"KEY .", []string{}, ""},
	{"--hidden KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-uu KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-u -u KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-uuu KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-u KEY", []string{}, ""},
	{"--unrestricted --unrestricted KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--unrestricted -u KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--hidden --no-hidden KEY", []string{}, ""},
	{"--no-hidden --hidden KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--no-ignore-hidden KEY", []string{}, ""},
	{"--no-ignore KEY", []string{}, ""},
	{"--no-ignore-dot KEY", []string{}, ""},
	{"--no-ignore-vcs KEY", []string{}, ""},
	{"--no-ignore-files KEY", []string{}, ""},
	{"--no-ignore-global KEY", []string{}, ""},
	{"--no-ignore-parent KEY", []string{}, ""},
	{"--no-ignore-exclude KEY", []string{}, ""},
	{"--no-require-git KEY", []string{}, ""},
	{"-g '*.env' KEY", []string{".env", "sub/.env"}, ""},
	{"-g=*.env KEY", []string{".env", "sub/.env"}, ""},
	{"-g*.env KEY", []string{".env", "sub/.env"}, ""},
	{"--glob '*.env' KEY", []string{".env", "sub/.env"}, ""},
	{"--glob=*.env KEY", []string{".env", "sub/.env"}, ""},
	{"--iglob '*.ENV' KEY", []string{".env", "sub/.env"}, ""},
	{"--iglob=*.ENV KEY", []string{".env", "sub/.env"}, ""},
	{"-lg '*.env' KEY", []string{".env", "sub/.env"}, ""},
	{"-lg*.env KEY", []string{".env", "sub/.env"}, ""},
	{"-lg=*.env KEY", []string{".env", "sub/.env"}, ""},
	{"-g '!*.env' KEY", []string{}, ""},
	{"-g '*' KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-g '.aws/*' KEY", []string{}, ""},
	{"-g '.aws/**' KEY", []string{}, ""},
	{"-g '**/.env' KEY", []string{".env", "sub/.env"}, ""},
	{"-g credentials KEY", []string{}, ""},
	{"--type-add 'e:*.env' -te KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -t e KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -t=e KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -lte KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -lt=e KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -lt e KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' --type e KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' --type=e KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add=e:*.env -te KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -tall KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -t all KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -t=all KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' --type all KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' --type=all KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -ltall KEY", []string{".env", "sub/.env"}, ""},
	{"-tall --type-add 'e:*.env' KEY", []string{}, ""},
	{"-tall KEY", []string{}, ""},
	{"--type-add 'e:*.env' -Tall KEY", []string{}, ""},
	{"--type-add 'e:*.env' -T all KEY", []string{}, ""},
	{"--type-add 'e:*.env' -Te KEY", []string{}, ""},
	{"--type-add 'e:*.env' --type-not=e KEY", []string{}, ""},
	{"--type-add 'e:*.env' --type-clear e -te KEY", []string{}, ""},
	{"--type-add 'e:*.env' --type-clear=e -te KEY", []string{}, ""},
	{"--type-add 'f:*.env' --type-add 'e:include:f' -te KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.go' --type-add 'e:*.env' -te KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*' -te KEY", []string{".env", ".npmrc", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -tgo -te KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'g:*.go' -tg KEY", []string{}, ""},
	{"-te --type-add 'e:*.env' KEY", []string{".env", "sub/.env"}, ""},
	{"-tgo KEY", []string{}, ""},
	{"-L KEY", []string{}, ""},
	{"--follow KEY", []string{}, ""},
	{"-L --hidden KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--follow --no-follow KEY", []string{}, ""},
	{"--ignore-file wl.txt KEY", []string{".env", "sub/.env"}, "P3 (1.0.11): an --ignore-file is not read; hidden counts as on"},
	{"--ignore-file=wl.txt KEY", []string{".env", "sub/.env"}, "P3 (1.0.11): an --ignore-file is not read; hidden counts as on"},
	{"--ignore-file nowl.txt KEY", []string{}, "an --ignore-file may whitelist: its lines are not read"},
	{"--pre cat KEY", []string{}, ""},
	{"--pre=cat --pre-glob '*.env' KEY", []string{}, ""},
	{"--pre-glob '*.env' KEY", []string{}, ""},
	{"-e KEY -g '*.env'", []string{".env", "sub/.env"}, ""},
	{"-eKEY -g*.env", []string{".env", "sub/.env"}, ""},
	{"-e=KEY --hidden", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-f pat.txt", []string{}, ""},
	{"-f pat.txt --hidden", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-fpat.txt -.", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--regexp KEY --hidden", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--regexp=KEY -g=*.env", []string{".env", "sub/.env"}, ""},
	{"-j1 -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-j 1 -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-m1 -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-A1 --hidden KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-d 5 -g '*.env' KEY", []string{".env", "sub/.env"}, ""},
	{"-d5 -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--max-depth 1 -. KEY", []string{".env", ".npmrc"}, "--max-depth is not modelled"},
	{"-E utf8 --hidden KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-M 100 --hidden KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-r X --hidden KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-C2 -g '*.env' KEY", []string{".env", "sub/.env"}, ""},
	{"-- --hidden", []string{}, ""},
	{"-e KEY -- --hidden", []string{}, ""},
	{"--hid KEY", []string{}, ""},
	{"--glob-case-insensitive -g '*.ENV' KEY", []string{".env", "sub/.env"}, ""},
	{"-i -g '*.ENV' KEY", []string{}, ""},
	{"-.l KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-l. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-uul KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-ul -u KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-. -g '!.env' KEY", []string{".aws/credentials", ".npmrc"}, ""},
	{"-uuu -g '!*.env' KEY", []string{".aws/credentials", ".npmrc"}, ""},
	{"--no-config --hidden KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--hidden KEY sub", []string{"sub/.env"}, ""},
	{"KEY .aws", []string{".aws/credentials"}, ""},
	{"KEY lnk", []string{}, ""},
	{"-lt e KEY", []string{}, ""},
	{"-lt=e KEY", []string{}, ""},
	{"-lte KEY", []string{}, ""},
	{"--type-add 'e:*.env' -lt e", []string{}, "rg refuses a call with no pattern: not modelled"},
	{"--colors 'match:none' -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--context-separator x -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--sort path -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--max-filesize 1M -g '*.env' KEY", []string{".env", "sub/.env"}, ""},
	{"--hostname-bin x -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--hyperlink-format none -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-uu --no-hidden KEY", []string{}, ""},
	{"--no-hidden -uu KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-u --hidden --no-hidden -u KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"-uu --no-hidden -u KEY", []string{}, ""},
	{"--ignore-file wl.txt --no-ignore-files KEY", []string{}, ""},
	{"--no-ignore-files --ignore-file wl.txt KEY", []string{}, ""},
	{"--no-ignore --ignore-file wl.txt KEY", []string{".env", "sub/.env"}, "P3 (1.0.11): an --ignore-file is not read; hidden counts as on"},
	{"--no-ignore-files --ignore-files --ignore-file wl.txt KEY", []string{".env", "sub/.env"}, "P3 (1.0.11): an --ignore-file is not read; hidden counts as on"},
	{"--type-add 'f:*.env' --type-add 'e:include:f' --type-clear f -te KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:include:f' --type-add 'f:*.env' -te KEY", []string{}, ""},
	{"-t all --type-add 'e:*.env' -te KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -t all -T e KEY", []string{}, ""},
	{"--maxdepth 1 -. KEY", []string{".env", ".npmrc"}, "--max-depth is not modelled"},
	{"--passthrough -. KEY", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--type-add 'go:*.env' -tgo KEY", []string{".env", "sub/.env"}, ""},
	{"--type-add 'e:*.env' -te KEY -", []string{}, ""},
	{"-e -. --hidden", []string{".aws/credentials", ".env", ".npmrc", "sub/.env"}, ""},
	{"--regexp -. KEY", []string{}, ""},
	{"-g -. KEY", []string{}, ""},
	{"--glob --hidden KEY", []string{}, ""},
	{"-t -. KEY", []string{}, ""},
	{"-lt- KEY", []string{}, ""},
}

// TestGAP0673RgGroundTruth is substrate-1:GAP-0673: every rg argv is read
// with one option table (parseRgCommandLine) in every value form rg 14.1
// accepts (--opt=v, --opt v, -xv, -x v, -x=v, bundled -lte), and -t all
// selects the types defined at that point. The credentials files the
// resolve names for each row are never fewer than real rg reads, and the
// same unless the row says why it counts more.
func TestGAP0673RgGroundTruth(t *testing.T) {
	dir := g0673Folder(t)
	for _, row := range g0673Rows {
		facts := Analyze(Input{Tool: "exec", Command: "rg " + row.args, CWD: dir, ActiveHome: t.TempDir()})
		got := g0673Rel(dir, g0671Named(facts))
		for _, file := range row.want {
			if !slices.Contains(got, file) {
				t.Errorf("rg %s: real rg reads %s, the resolve names %v (weaker than rg)", row.args, file, got)
			}
		}
		exact := slices.Equal(got, row.want) || len(got) == 0 && len(row.want) == 0
		switch {
		case row.over == "" && !exact:
			t.Errorf("rg %s: the resolve names %v, real rg reads %v", row.args, got, row.want)
		case row.over != "" && exact:
			t.Errorf("rg %s: marked over (%s) but now exact: drop the mark", row.args, row.over)
		}
	}
	// The operands come from the same table.
	for _, row := range []struct {
		argv     []string
		operands []int
	}{
		{[]string{"rg", "--type-add", "e:*.env", "-lt", "e", "KEY"}, []int{5}},
		{[]string{"rg", "-t=e", "KEY", "."}, []int{2, 3}},
		{[]string{"rg", "--maxdepth", "1", "KEY"}, []int{3}},
		{[]string{"rg", "-e", "-.", "--hidden", "src"}, []int{4}},
		{[]string{"rg", "-fpat.txt", "src"}, []int{2}},
		{[]string{"rg", "--", "-e", "x"}, []int{2, 3}},
	} {
		got := searchOperandIndexes(row.argv, "rg")
		if !slices.Equal(got, row.operands) {
			t.Errorf("%v: operands %v, want %v", row.argv, got, row.operands)
		}
	}
}

// g0673RgVersion is the ripgrep every rg table row was recorded with
// (g0673Rows, g0679Rows ...). The live checks run only that version: with
// another rg, or none (CI installs none), they skip and say so, and with
// DEFENSECLAW_RG_REQUIRED=1 (the local gates) they fail.
const g0673RgVersion = "ripgrep 14.1.0"

// TestGAP0673RgGroundTruthLive checks g0673Rows against a real ripgrep
// 14.1.0 (DEFENSECLAW_RG, else rg on PATH; g0679LiveRG).
func TestGAP0673RgGroundTruthLive(t *testing.T) {
	rg, sh := g0679LiveRG(t)
	dir := g0673Folder(t)
	home := t.TempDir()
	for _, row := range g0673Rows {
		var read []string
		for _, mode := range []string{"-l", "--files-without-match"} {
			cmd := exec.Command(sh, "-c", `"$RG" `+mode+" "+row.args)
			cmd.Dir = dir
			cmd.Env = []string{"RG=" + rg, "HOME=" + home, "PATH=/usr/bin:/bin"}
			out, _ := cmd.Output() // rg exits 1 or 2 when it reads nothing
			read = append(read, strings.Split(string(out), "\n")...)
		}
		if got := g0673Rel(dir, read); !slices.Equal(got, row.want) {
			t.Errorf("rg %s: real rg reads %v, the table says %v", row.args, got, row.want)
		}
	}
}

// TestGAP0674NoWalkKeptPastItsCall is substrate-1:GAP-0674: no walk of a
// recursive search outlives the record that read it, so the memory of the
// walks is bounded by the calls being checked, not by a memo. 40 calls each
// walk a distinct name of one tree whose walk finds 960 credentials files at
// about 600-byte paths (some 0.6 MB a walk); once their facts are dropped,
// the heap they leave stays under 4 MiB. At 02e880d943 the walk memo kept
// them for a second, up to its 16 MiB bound.
func TestGAP0674NoWalkKeptPastItsCall(t *testing.T) {
	long := strings.Repeat("d", 120)
	deep := strings.Join([]string{long + "1", long + "2", long + "3", long + "4"}, "/")
	var files []string
	for i := range 160 {
		for _, name := range []string{".env", ".npmrc", ".pypirc", ".netrc", ".pgpass", ".git-credentials"} {
			files = append(files, "t/"+deep+"/s"+strconv.Itoa(i)+"/"+name)
		}
	}
	dir := g0671Folder(t, files...)
	for i := 1; i <= 40; i++ {
		if err := os.Symlink(filepath.Join(dir, "t"), filepath.Join(dir, "h"+strconv.Itoa(i))); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
	}
	home := t.TempDir()
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	before := heap()
	for i := 1; i <= 40; i++ {
		facts := Analyze(Input{Tool: "exec", Command: "grep -r KEY h" + strconv.Itoa(i), CWD: dir, ActiveHome: home})
		if named := len(g0671Named(facts)); i == 1 && named < 900 {
			t.Fatalf("one walk names %d files: the tree is too small to test the bound", named)
		}
	}
	if after := heap(); after > before && after-before > 4<<20 {
		t.Fatalf("40 checked calls left %d bytes of heap: their walks were kept", after-before)
	}
}
