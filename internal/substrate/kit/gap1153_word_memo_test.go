// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap1153WordHome is a home with a key, a symlink and a hard link to it in
// cwd, and a private backup folder.
func gap1153WordHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home, cwd = t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, "bak")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(key, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(cwd, "ak-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "sshdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, filepath.Join(cwd, "ak-hard")); err != nil {
		t.Fatal(err)
	}
	return home, cwd
}

// TestGAP1153WordFactsMemoKeepsEveryFact: each word fact the call memo
// gives is the one the walk without a memo gives (the kit before it), for
// link, hard link, private and missing words, in every placed folder.
func TestGAP1153WordFactsMemoKeepsEveryFact(t *testing.T) {
	home, cwd := gap1153WordHome(t)
	checked := 0
	for _, command := range []string{
		gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done"),
		"echo k >> ak-link; echo k >> ak-hard; cp -r ~/.ssh ~/bak/sshcopy; " + gap1153Fit("", "true;", "true"),
		"cd sshdir && cat authorized_keys; cd .. && cat ak-link; echo k >> ~/.ssh/authorized_keys",
		"cat sshdir/authorized_keys sshdir/../ak-link ./missing/a ../x /etc/hosts",
	} {
		words := hookpaths.PlacedCommandPathWords(command, cwd, home)
		memo := hookpaths.NewTargetMemo()
		for _, word := range words {
			dirs := word.Dirs
			if len(dirs) == 0 || strings.HasPrefix(word.Value, "/") {
				dirs = []string{cwd}
			}
			for _, dir := range dirs {
				for _, privacy := range []bool{false, true} {
					want, wantListed := commandWordFact(word, dir, home, privacy, false, nil)
					got, gotListed := commandWordFact(word, dir, home, privacy, false, memo)
					if gotListed != wantListed || !reflect.DeepEqual(got, want) {
						t.Fatalf("word %q in %q, privacy %v: memo %+v %v, walk %+v %v", word.Text, dir, privacy, got, gotListed, want, wantListed)
					}
					checked++
				}
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d word facts checked", checked)
	}
}

// TestGAP1153KitWalksTheFolderOnce: the 840 words of an 8 KB script of
// function calls are each placed in the working folder; the kit reads that
// folder once for the call, not once per word and pass (4,200 lstat calls
// before, each a sandbox system call in the actor; substrate-1 GAP-1153).
func TestGAP1153KitWalksTheFolderOnce(t *testing.T) {
	_, cwd := gap1153WordHome(t)
	payload := gap1153Bash(t, gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done"), cwd)
	folder, reads := 0, 0
	restore := fixturefs.ObserveForTest(func(name string) {
		reads++
		if name == cwd {
			folder++
		}
	})
	CollectFacts("claudecode", "PreToolUse", payload, 1<<20)
	restore()
	t.Logf("file system reads: %d, of the working folder: %d", reads, folder)
	if folder > 4 || reads > 1200 {
		t.Errorf("the kit read the working folder %d times in %d reads for one call (substrate-1 GAP-1153)", folder, reads)
	}
}
