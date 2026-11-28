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
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// g0683Credentials is the credentials files of g0683Folder.
var g0683Credentials = []string{
	".aws/credentials", ".config/gh/hosts.yml", ".docker/config.json", ".env", ".npmrc", ".ssh/id_rsa",
	"deploy/id_ed25519", "sub/.env",
}

// g0683Folder is a project with credentials files and the ordinary files
// of RV5's GAP-0683 repro (a workflow, package.json, a .tsx, a .toml).
func g0683Folder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := append(slices.Clone(g0683Credentials), "src/a.go", "src/b.ts", "web/app.tsx", "package.json",
		"pyproject.toml", ".github/workflows/ci.yml", "docs/a.md", "pat.txt", "wl.txt")
	for _, name := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		text := "KEY TODO\n"
		if name == "wl.txt" {
			text = "!.env\n"
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// g0683Rel is the credentials files among names, relative to dir, sorted.
func g0683Rel(dir string, names []string) []string {
	var out []string
	for _, name := range names {
		if filepath.IsAbs(name) {
			if rel, err := filepath.Rel(dir, name); err == nil {
				name = rel
			}
		}
		name = strings.TrimPrefix(filepath.ToSlash(name), "./")
		if slices.Contains(g0683Credentials, name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// g0683Rows is substrate-1:GAP-0683: an ordinary search with an include
// glob or a type reads only what rg's globs and types select, in a
// project with credentials files; recorded with real ripgrep 14.1.0 in
// g0683Folder (TestGAP0683RgGroundTruthLive).
var g0683Rows = []g0679Row{
	// RV5's rows: rg reads no credentials file.
	{"rg -g '*.yml' TODO", []string{}, ""},
	{"rg -g '*.toml' TODO", []string{}, ""},
	{"rg -g '*.json' TODO", []string{}, ""},
	{"rg -g '*.{ts,tsx}' TODO", []string{}, ""},
	{"rg -g 'src/**' TODO", []string{}, ""},
	{"rg -g '*.ts' -g '*.json' TODO", []string{}, ""},
	{"rg -g '*.go' TODO", []string{}, ""},
	{"rg -g '*.yml' TODO .", []string{}, ""},
	{"rg -g '*.json' TODO src", []string{}, ""},
	{"rg -tjson TODO", []string{}, ""},
	{"rg -t yaml -t toml TODO", []string{}, ""},
	{"rg -g '!*.md' TODO", []string{"deploy/id_ed25519"}, ""},
	{"rg -g '*.{yml,json}' -g '!*.md' TODO", []string{}, ""},
	{"rg --iglob '*.YML' TODO", []string{}, ""},
	{"rg --type-add 'e:*.env,*.yml' -te TODO", []string{}, ""},
	{"rg --type-add 'e:*.go,*.env' --type=e TODO", []string{}, ""},
	{"rg --type-add 'e:*.{go,env}' --type=e TODO", []string{".env", "sub/.env"}, ""},
	// A non-hidden credentials file a glob matches is read.
	{"rg -g '*.key' TODO", []string{}, ""},
	{"rg -g 'id_*' TODO", []string{"deploy/id_ed25519"}, ""},
	{"rg -g 'deploy/**' TODO", []string{"deploy/id_ed25519"}, ""},
	// What rg does read: the globs reach the hidden file or folder.
	{"rg -g '*.env' TODO", []string{".env", "sub/.env"}, ""},
	{"rg -g '.env' -g '!sub/' TODO", []string{".env"}, ""},
	{"rg -g '{.env,*.go}' TODO", []string{".env", "sub/.env"}, ""},
	{"rg -g '.aws/' -g credentials TODO", []string{".aws/credentials"}, ""},
	{"rg -g '.config/' -g gh -g '*.yml' TODO", []string{".config/gh/hosts.yml"}, ""},
	{"rg -g '*' TODO", g0683Credentials, ""},
	{"rg -g '**' TODO", g0683Credentials, ""},
	{"rg --iglob '.ENV' -g '!.env' TODO", []string{".env", "sub/.env"}, ""},
	{"rg -g '!.env' --iglob '.ENV' TODO", []string{".env", "sub/.env"}, ""},
	{"rg -g .Env --glob-case-insensitive TODO", []string{".env", "sub/.env"}, ""},
	{"rg -g '{,.}env' TODO", []string{".env", "sub/.env"}, ""},
	{"rg -g '.e[n]v' TODO", []string{".env", "sub/.env"}, ""},
	{"rg -g '/.env' TODO", []string{".env"}, ""},
	{"rg -g '.aws/**' TODO", []string{}, ""},
	{"rg -g '!' TODO", []string{}, ""},
	{"rg -g '#.env' TODO", []string{"deploy/id_ed25519"}, ""},
	// --hidden with globs: only what they select.
	{"rg --hidden -g '*.yml' TODO", []string{".config/gh/hosts.yml"}, ""},
	{"rg --hidden -g '*.json' TODO", []string{".docker/config.json"}, ""},
	{"rg --hidden -tjson TODO", []string{".docker/config.json"}, ""},
	{"rg --hidden -g '*.go' TODO", []string{}, ""},
	{"rg --hidden -g '!.aws/' -g '!.docker' -g '!.config' TODO", []string{".env", ".npmrc", ".ssh/id_rsa", "deploy/id_ed25519", "sub/.env"}, ""},
	{"rg -uu -g 'src/**' TODO", []string{}, ""},
	{"rg --hidden -g 'sub/**' TODO", []string{"sub/.env"}, ""},
	// Types.
	{"rg --type-add 'e:*.env' -tall TODO", []string{".env", "sub/.env"}, ""},
	{"rg -te --type-add 'e:*.env' -Te TODO", []string{}, ""},
	{"rg --type-add 'e:*.env' --type-add 'f:include:e,json' -tf --hidden TODO", []string{".docker/config.json", ".env", "sub/.env"}, ""},
	{"rg --type-add 'e:*.env' --type-clear e -te TODO", []string{}, ""},
	// A folder named.
	{"rg -g '*.go' TODO .aws", []string{}, ""},
	{"rg -g credentials TODO .aws", []string{".aws/credentials"}, ""},
	{"rg -g 'sub/.env' TODO ./sub", []string{"sub/.env"}, ""},
	{"rg -g 'sub/**' TODO sub", []string{"sub/.env"}, ""},
	// An --ignore-file whitelists a hidden file past the hidden rule, never
	// past an include glob.
	{"rg --ignore-file wl.txt -g '*.go' TODO", []string{}, ""},
	{"rg --ignore-file wl.txt TODO", []string{".env", "deploy/id_ed25519", "sub/.env"}, g0683IgnoreFile},
}

// g0683IgnoreFile: an --ignore-file's contents are not read (hidden counts
// as on), P3 for 1.0.11, no weaker than rel.
const g0683IgnoreFile = "count when unsure: an --ignore-file may whitelist any hidden file"

// g0683Check is g0679Check in g0683Folder.
func g0683Check(t *testing.T, rows []g0679Row) {
	t.Helper()
	dir := g0683Folder(t)
	for _, row := range rows {
		got := g0683Rel(dir, g0679Named(Analyze(Input{Tool: "exec", Command: row.cmd, CWD: dir, ActiveHome: t.TempDir()})))
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

func TestGAP0683RgIncludeGlobs(t *testing.T) { g0683Check(t, g0683Rows) }

// g0683Real is the credentials files real rg reads when sh runs cmd in
// g0683Folder (g0679Real's method).
func g0683Real(t *testing.T, rg, sh, dir, cmd string) []string {
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
		out, _ := run.Output()
		read = append(read, strings.Split(string(out), "\n")...)
	}
	return g0683Rel(dir, read)
}

// TestGAP0683RgGroundTruthLive checks g0683Rows against a real ripgrep
// 14.1.0.
func TestGAP0683RgGroundTruthLive(t *testing.T) {
	rg, sh := g0679LiveRG(t)
	dir := g0683Folder(t)
	for _, row := range g0683Rows {
		if got := g0683Real(t, rg, sh, dir, row.cmd); !slices.Equal(got, row.want) {
			t.Errorf("%s: real rg reads %v, the table says %v", row.cmd, got, row.want)
		}
	}
}

// g0683ProbeNames is the last segment of every credentials probe: the
// names of the files the walk counts.
func g0683ProbeNames() []string {
	var names []string
	for _, probe := range credentialProbes() {
		name := probe.segments[len(probe.segments)-1]
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// TestGAP0683RgBuiltinTypesLive records rgBuiltinTypeProbeNames with real
// ripgrep 14.1.0: every built-in type (rg --type-list), and the probe names
// rg --files -t TYPE lists in a folder that holds a file of each name.
func TestGAP0683RgBuiltinTypesLive(t *testing.T) {
	rg, _ := g0679LiveRG(t)
	dir := t.TempDir()
	names := g0683ProbeNames()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	list, err := exec.Command(rg, "--type-list").Output()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(list)), "\n") {
		name, _, _ := strings.Cut(line, ":")
		run := exec.Command(rg, "--files", "--hidden", "--no-ignore", "-t", name)
		run.Dir = dir
		out, _ := run.Output()
		var matched []string
		for _, file := range strings.Fields(string(out)) {
			if base := filepath.Base(file); slices.Contains(names, base) {
				matched = append(matched, base)
			}
		}
		if len(matched) > 0 {
			slices.Sort(matched)
			got[name] = matched
		}
	}
	want := map[string][]string{}
	for name, files := range rgBuiltinTypeProbeNames {
		want[name] = slices.Sorted(slices.Values(files))
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		var b strings.Builder
		for _, name := range slices.Sorted(maps.Keys(got)) {
			fmt.Fprintf(&b, "\t%q: {%s},\n", name, strings.Join(g0683Quote(got[name]), ", "))
		}
		t.Errorf("rgBuiltinTypeProbeNames drifted from real rg; it is:\n%s", b.String())
	}
}

func g0683Quote(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = strconv.Quote(name)
	}
	return out
}

// g0683FuzzLiteral is one random literal glob over the names and parts of
// g0683Folder.
func g0683FuzzLiteral(r *rand.Rand) string {
	parts := []string{"*", "**", "?", ".", "/", "env", ".env", "aws", ".aws", "credentials", "cred*", "config",
		".config", "gh", "hosts", ".yml", "*.yml", "*.json", ".json", "docker", ".docker", "id_", "rsa", "*.key",
		"server", "deploy", "sub", "src", "*.go", "{a,.}", "{.,}", "{*.yml,*.json}", "[.]", "[!x]", "[a-z]",
		"npmrc", ".npmrc", "ssh", ".ssh", "!", "#", "\\.", ",", "}", "*/", "/**/", "/**"}
	var b strings.Builder
	for range 1 + r.IntN(4) {
		b.WriteString(parts[r.IntN(len(parts))])
	}
	return b.String()
}

// TestGAP0683GlobFuzzLive is substrate-1:GAP-0683 both ways: random
// literal include and "!" globs, -t types, --hidden and folder operands
// run on real ripgrep 14.1.0 in g0683Folder (a fixed seed;
// DEFENSECLAW_RG_FUZZ_SEED picks another). The resolve names every
// credentials file rg reads (never weaker) and no credentials file rg does
// not read (never over: every glob here is literal, so it is read exactly).
func TestGAP0683GlobFuzzLive(t *testing.T) {
	rg, _ := g0679LiveRG(t)
	seed := uint64(0x0683)
	if s, err := strconv.ParseUint(os.Getenv("DEFENSECLAW_RG_FUZZ_SEED"), 0, 64); err == nil {
		seed = s
	}
	r := rand.New(rand.NewPCG(seed, 0x0683))
	dir := g0683Folder(t)
	home := t.TempDir()
	folders := []string{"", "", "", ".", "sub", ".aws", "./deploy", ".config", dir}
	const rows = 900
	reads, over, weaker := 0, 0, 0
	for range rows {
		var args []string
		for range 1 + r.IntN(3) {
			switch r.IntN(8) {
			case 0:
				args = append(args, "--iglob", strings.ToUpper(g0683FuzzLiteral(r)))
			case 1:
				args = append(args, "-g", "!"+g0683FuzzLiteral(r))
			case 2:
				args = append(args, "-t", []string{"json", "yaml", "toml", "go", "all"}[r.IntN(5)])
			case 3:
				args = append(args, "--type-add", "e:"+g0683FuzzLiteral(r), "-te")
			default:
				args = append(args, "-g", g0683FuzzLiteral(r))
			}
		}
		switch r.IntN(4) {
		case 0:
			args = append(args, "--hidden")
		case 1:
			args = append(args, "--glob-case-insensitive")
		}
		args = append(args, "KEY")
		if folder := folders[r.IntN(len(folders))]; folder != "" {
			args = append(args, folder)
		}
		var real []string
		for _, mode := range []string{"-l", "--files-without-match"} {
			run := exec.Command(rg, append([]string{mode}, args...)...)
			run.Dir = dir
			run.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			out, _ := run.Output()
			real = append(real, strings.Split(string(out), "\n")...)
		}
		want := g0683Rel(dir, real)
		quoted := make([]string, len(args))
		for i, arg := range args {
			quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
		}
		command := "rg " + strings.Join(quoted, " ")
		got := g0683Rel(dir, g0679Named(Analyze(Input{Tool: "exec", Command: command, CWD: dir, ActiveHome: t.TempDir()})))
		if len(want) > 0 {
			reads++
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
		for _, file := range got {
			if !slices.Contains(want, file) {
				over++
				if over <= 25 {
					t.Errorf("%s: real rg reads %v, the resolve names %v (over)", command, want, got)
				}
				break
			}
		}
	}
	t.Logf("seed %#x: %d shapes, %d where rg reads a credentials file, %d over, %d weaker", seed, rows, reads, over, weaker)
}
