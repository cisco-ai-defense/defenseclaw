// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0142: the members an extraction names land below its folder.
func TestArchiveExtractionMembers(t *testing.T) {
	const member = ".defenseclaw/config.yaml"
	for _, tc := range []struct {
		name, program string
		words         string
		want          []string
	}{
		{"tar -C", "tar", "-xf a.tar -C /h " + member, []string{member}},
		{"tar attached -C", "tar", "-xf a.tar -C/h " + member, []string{member}},
		{"tar --directory", "tar", "--extract --file=a.tar --directory /h " + member, []string{member}},
		{"tar old-style", "tar", "xf a.tar -C /h " + member, []string{member}},
		{"tar old-style two values", "tar", "xfC a.tar /h " + member, []string{member}},
		{"tar cluster value", "tar", "-xzf a.tgz -C /h ./" + member, []string{member}},
		{"tar absolute member loses its slash", "tar", "-xf a.tar -C /h /" + member, []string{member}},
		{"tar -P keeps it", "tar", "-xPf a.tar /h/" + member, []string{"/h/" + member, "h/" + member}},
		{"tar strip", "tar", "-xf a.tar --strip-components=1 pkg/" + member, []string{member}},
		{"tar strip separate", "tar", "-xf a.tar --strip-components 2 a/b/" + member, []string{member}},
		{"tar strips it all away", "tar", "-xf a.tar --strip-components=3 a/b", nil},
		{"tar members after --", "tar", "-xf a.tar -- " + member, []string{member}},
		{"tar to stdout", "tar", "-xOf a.tar " + member, nil},
		{"tar to-stdout long", "tar", "--extract --to-stdout -f a.tar " + member, nil},
		{"tar list", "tar", "-tf a.tar " + member, nil},
		{"tar create", "tar", "-cf a.tar " + member, nil},
		{"tar exclude value is no member", "tar", "-xf a.tar --exclude " + member + " proj/notes.txt", []string{"proj/notes.txt"}},
		{"tar no member list", "tar", "-xf a.tar -C /h", nil},
		{"bsdtar", "bsdtar", "-xf a.tar " + member, []string{member}},
		{"unzip -d after", "unzip", "-o a.zip " + member + " -d /h", []string{member}},
		{"unzip -d before", "unzip", "-d /h a.zip " + member, []string{member}},
		{"unzip -d attached", "unzip", "-o a.zip " + member + " -d/tmp/lpt", []string{member}},
		{"unzip cluster", "unzip", "-od /h a.zip " + member, []string{member}},
		{"unzip members and exclusion", "unzip", "a.zip proj/a " + member + " -x skip/me", []string{"proj/a", member}},
		{"unzip junk", "unzip", "-j a.zip " + member, []string{"config.yaml"}},
		{"unzip list", "unzip", "-l a.zip " + member, nil},
		{"unzip pipe", "unzip", "-p a.zip " + member, nil},
		{"unzip no member list", "unzip", "-o a.zip -d /h", nil},
		{"unzip password value is no member", "unzip", "-P secret a.zip " + member, []string{member}},
		{"other program", "cpio", "-id " + member, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			words := strings.Fields(tc.words)
			if got := ArchiveExtractionMembers(tc.program, words); !slices.Equal(got, tc.want) {
				t.Fatalf("ArchiveExtractionMembers(%s %q) = %q; want %q", tc.program, tc.words, got, tc.want)
			}
		})
	}
}

// The extraction paths are the folder and each member joined below it.
func TestArchiveExtractionPathsJoinTheMember(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	want := []string{home, filepath.Join(home, ".defenseclaw", "config.yaml")}
	commands := []string{
		`tar -xf /tmp/a.tar -C ~ .defenseclaw/config.yaml`,
		`sudo unzip -o /tmp/a.zip .defenseclaw/config.yaml -d "$HOME"`,
	}
	if runtime.GOOS != "windows" { // the home is spelled raw in a shell word
		commands = append(commands, `tar -xf /tmp/a.tar --directory=`+home+` ./.defenseclaw/config.yaml`)
	}
	for _, command := range commands {
		if got := ArchiveExtractionPaths(command, cwd, home); !slices.Equal(got, want) {
			t.Errorf("%s: paths %q, want %q", command, got, want)
		}
	}
	// A member that climbs out of the working folder lands where it says.
	if got := ArchiveExtractionPaths(`tar -xf /tmp/a.tar ../.defenseclaw/config.yaml`, cwd, home); !slices.Contains(got, want[1]) {
		t.Errorf("a member below .. : paths %q, want %q among them", got, want[1])
	}
	// No member: the folder alone, as before.
	if got := ArchiveExtractionPaths(`tar -xf /tmp/a.tar -C ~`, cwd, home); !slices.Equal(got, []string{home}) {
		t.Errorf("no member list: paths %q, want the folder alone", got)
	}
}

// rel-1-0-10:GAP-0365: the paths a command hands an inline interpreter child.
func TestInlineHandedPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the state reader judges POSIX homes only")
	}
	const home, cwd = "/home/u", "/home/u/proj"
	const code = `'import sys; open(sys.argv[1], "w").write("")'`
	for _, tc := range []struct {
		name, command string
		paths         []string
		dynamic       bool
	}{
		{"direct", "python3 -c " + code + " ~/.defenseclaw/config.yaml", []string{"/home/u/.defenseclaw/config.yaml"}, false},
		{"relative word", "python3 -c " + code + " notes.txt", []string{"/home/u/proj/notes.txt"}, false},
		{"sudo env", "sudo env A=1 python3 -I -c " + code + " ~/.claude/settings.json", []string{"/home/u/.claude/settings.json"}, false},
		{"variable", "p=~/.defenseclaw/config.yaml; python3 -c " + code + ` "$p"`, []string{"/home/u/.defenseclaw/config.yaml"}, false},
		{"sh -c", `sh -c "python3 -c 'import sys' ~/.codex/config.toml"`, []string{"/home/u/.codex/config.toml"}, false},
		{"bash -c single quotes", `bash -c 'python3 -c "import sys" ~/.codex/config.toml'`, []string{"/home/u/.codex/config.toml"}, false},
		{"xargs", "echo ~/.defenseclaw/config.yaml | xargs python3 -c " + code, nil, true},
		{"while read", "while read f; do python3 -c " + code + ` "$f"; done < list`, nil, true},
		{"xargs sh -c", "xargs -I{} sh -c 'python3 -c \"import sys\" \"$0\"' {}", nil, true},
		{"parallel", "parallel python3 -c " + code + " ::: ~/.defenseclaw/config.yaml", []string{"/home/u/proj/:::", "/home/u/.defenseclaw/config.yaml"}, true},
		{"text after the code", `python3 -c ` + code + ` "two words" 'a;b'`, nil, false},
		{"no handed word", "python3 -c " + code, nil, false},
		{"script", "python3 tool.py ~/.defenseclaw/config.yaml", nil, false},
		{"plain command", "cat ~/.defenseclaw/config.yaml", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, dynamic := InlineHandedPaths(tc.command, cwd, home)
			if !slices.Equal(paths, tc.paths) || dynamic != tc.dynamic {
				t.Fatalf("InlineHandedPaths(%q) = %q, %t; want %q, %t", tc.command, paths, dynamic, tc.paths, tc.dynamic)
			}
		})
	}
}
