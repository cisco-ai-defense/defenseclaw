// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestR104UnprovenProtectedReachDecisions(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "spaced link name")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "aliasdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "payload"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "ordinarydir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "ordinarydir", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "safedir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "payload", "authorized_keys"), []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "writer.py"), []byte("unknown_api('alias')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "writer.sh"), []byte("echo marker >> alias\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "call-f.sh"), []byte("f\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Join(cwd, "sub"), filepath.Join(cwd, "out"), filepath.Join(cwd, "build"), filepath.Join(home, ".ssh", "sub")} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../authorized_keys", filepath.Join(home, ".ssh", "sub", "out.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "sub", "out.txt"), []byte("ordinary"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"EXIT trap function", `f() { echo marker >> alias; }; trap f EXIT`, true},
		{"EXIT trap handler arguments", `f() { echo marker >> alias; }; trap 'f argument' EXIT`, true},
		{"DEBUG trap handler", `f() { echo marker >> alias; }; trap 'f; :' DEBUG`, true},
		{"EXIT trap evaluates function", `f() { echo marker >> alias; }; trap 'eval f' EXIT`, true},
		{"dynamic EXIT trap handler", `f() { echo marker >> alias; }; trap "$HANDLER" EXIT`, true},
		{"inert definition", `f() { echo marker >> alias; }; echo ok`, false},
		{"trap echoes dormant function name", `f() { echo marker >> alias; }; trap 'echo f' EXIT`, false},
		{"eval function with argument", `f() { echo marker >> alias; }; eval 'f argument'`, true},
		{"eval echoes dormant function", `f() { echo marker >> alias; }; eval 'echo f'`, true},
		{"source invokes function", `f() { echo marker >> alias; }; . call-f.sh`, true},
		{"trap signal is not a handler", `f() { :; }; EXIT() { echo marker >> alias; }; trap f EXIT`, false},
		{"dynamic program word", `"$writer" alias`, true},
		{"dynamic copy destination", `cp payload/authorized_keys "$DEST"`, true},
		{"glob redirect to protected link", `echo marker > [a]lias`, true},
		{"assigned variable redirect", `f=alias; echo marker >> "$f"`, true},
		{"glob redirect with read-only link mention", `echo alias > out-*.txt`, true},
		{"unbounded prefixed copy destination", `cp payload/authorized_keys "out/$DEST"`, true},
		{"dynamic copy source ordinary destination", `cp "$SRC" out.txt`, true},
		{"bounded basename copy destination", `name="$(basename docs/guide.md)"; cp docs/guide.md "out/$name"`, false},
		{"bounded function copy destination", `stage_file() { cp "$1" "build/$2"; }; stage_file payload staged.bin`, false},
		{"dynamic eval code", `eval "$CODE"`, true},
		{"dot source script", `. writer.sh`, true},
		{"function keyword writer", `function f { custom_writer alias; }; f`, true},
		{"nested shell eval", `bash -c 'eval "echo marker >> alias"'`, true},
		{"dynamic source program", `source "$SCRIPT"`, true},
		{"Python dynamic trailing argument", `python3 -c 'open("alias","a").write("marker")' "$USER"`, true},
		{"Node dynamic trailing argument", `node -e 'require("fs").writeFileSync("alias","marker")' "$USER"`, true},
		{"Ruby dynamic trailing argument", `ruby -e 'File.write("alias","marker")' "$USER"`, true},
		{"Perl dynamic trailing argument", `perl -e 'open(F, ">>", "alias")' "$USER"`, true},
		{"copy2 directory destination", `python3 -c 'import shutil; shutil.copy2("payload/authorized_keys","aliasdir")'`, true},
		{"copy directory destination", `python3 -c 'import shutil; shutil.copy("payload/authorized_keys","aliasdir")'`, true},
		{"copy directory protected child", `python3 -c 'import shutil; shutil.copy2("payload/authorized_keys","ordinarydir")'`, true},
		{"copy directory ordinary child", `python3 -c 'import shutil; shutil.copy2("payload/authorized_keys","safedir")'`, false},
		{"Ruby regex hash", `ruby -e '/#/.match("x"); File.write("alias","marker")'`, true},
		{"quoted link name with spaces", `ruby -e 'unknown_api("spaced link name")'`, true},
		{"Ruby regex embedded hash", `ruby -e '/a#b/.match("x"); File.write("alias","marker")'`, true},
		{"Ruby regex variable destination", `ruby -e '/#/.match("x"); File.write(target,"marker")'`, true},
		{"Perl regex hash", `perl -e 'm/#/; open(F, ">>", "alias")'`, true},
		{"Perl alternate regex hash", `perl -e 'qr/#/; open(F, ">>", "alias")'`, true},
		{"Perl regex variable destination", `perl -e 'm/#/; open(F, ">>", target)'`, true},
		{"Node async write", `node -e 'require("fs").writeFile("alias","marker",()=>{})'`, true},
		{"Node async variable destination", `node -e 'require("fs").writeFile(target,"marker",()=>{})'`, true},
		{"Node async append", `node -e 'require("fs").appendFile("alias","marker",()=>{})'`, true},
		{"Node promise write", `node -e 'require("fs").promises.writeFile("alias","marker")'`, true},
		{"Nodejs command", `nodejs -e 'require("fs").writeFile("alias","marker",()=>{})'`, true},
		{"Node option code", `node --no-warnings -e 'require("fs").unknownWrite("alias")'`, true},
		{"Python script file", `python3 writer.py`, true},
		{"Python script file with dynamic trailing argument", `python3 writer.py "$USER"`, true},
		{"Node truncate writer class", `node -e 'require("fs").truncate("alias",0,()=>{})'`, true},
		{"Python replace writer class", `python3 -c 'import os; os.replace("payload/authorized_keys","alias")'`, true},
		{"Ruby IO writer class", `ruby -e 'IO.write("alias","marker")'`, true},
		{"Perl sysopen writer class", `perl -e 'sysopen(F,"alias",1)'`, true},
		{"unmodelled Python call", `python3 -c 'unknown_api("alias")'`, true},
		{"home directory reaches unmodelled Ruby code", `cd ~ && ruby -e 'unknown_api()'`, true},
		{"unmodelled Node call", `node -e 'require("fs").unknownWrite("alias")'`, true},
		{"Node read control", `node -e 'require("fs").readFile("alias",()=>{})'`, false},
		{"Python read control", `python3 -c 'open("alias","r").read()'`, false},
		{"Ruby read control", `ruby -e 'File.read("alias")'`, false},
		{"Python copy ordinary destination", `python3 -c 'import shutil; shutil.copy2("payload/authorized_keys","out.txt")'`, false},
		{"CDPATH selected existing link", `cd sub && ln -s ../a b && echo marker > out.txt`, true},
		{"explicit cd ordinary file", `cd ./sub && ln -s ../a b && echo marker > out.txt`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, blocked := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if blocked != tc.block {
					t.Errorf("decision %d = %t, want %t", i, blocked, tc.block)
				}
			}
		})
	}
}

func TestR104UnprovenProtectedReachExplainsBlock(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	input := actionfacts.Input{Tool: "Bash", Command: `f() { echo marker >> alias; }; trap f EXIT`,
		CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
	generation := &compiledRulePackCategories{categories: []ruleCategory{{
		Name: "command", Rules: []PatternRule{{ID: "persistence.ssh_authorized_keys_command",
			Title: "SSH authorized keys mutation", Severity: "CRITICAL", Confidence: 0.98}},
	}}}
	request := trustedActionRequest{Input: input, EnforcementCapable: true}
	findings := appendTrustedHomeResolvedSSHKeyWriteFinding(nil, generation, request, actionfacts.Analyze(input))
	for _, finding := range findings {
		if finding.RuleID == "persistence.ssh_authorized_keys_command" {
			if !strings.Contains(finding.Title, "called function") || !strings.Contains(finding.Title, "literal path") {
				t.Fatalf("unproven block title = %q", finding.Title)
			}
			return
		}
	}
	t.Fatal("unproven write has no enforcement finding")
}
