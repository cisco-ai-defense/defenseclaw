//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// searchReadsTree is a home with three credentials files and an ordinary
// source file, next to a folder with more subfolders than the walk bound.
func searchReadsTree(t *testing.T) (dir, home string) {
	t.Helper()
	dir = t.TempDir()
	home = filepath.Join(dir, "home")
	for _, f := range []string{".aws/credentials", ".config/gh/hosts.yml", ".config/gcloud/application_default_credentials.json", "src/main.go"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i <= maxCredentialPathWalkFolders; i++ {
		if err := os.Mkdir(filepath.Join(dir, "big"), 0o700); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "big", fmt.Sprintf("d%04d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir, home
}

// searchReads is the credentials reads the resolve records for command, run
// in dir, with the file-unknown read as <unknown>.
func searchReads(t *testing.T, dir, home, command string) []string {
	t.Helper()
	out := parsePOSIX(command, 1, 0)
	classifyOutput(&out)
	rec := resolveCredentialPathReadsWithin(defaultCredentialPathLimits, out.credentialWords, dir, home, out.commands, out.paths)
	var got []string
	if rec == nil {
		return nil
	}
	for _, read := range rec.reads {
		s := read.Resolved
		if s == "" {
			s = read.Value
		}
		if s == "" {
			s = "<unknown>"
		}
		got = append(got, strings.TrimPrefix(s, dir))
	}
	return got
}

// TestGAP0911SearchProbesEachNamedFolder: a walk spent on a huge folder named
// first no longer hides the exact read of a credentials file in a folder
// named after it (substrate-1:GAP-0911): both rels record it.
func TestGAP0911SearchProbesEachNamedFolder(t *testing.T) {
	dir, home := searchReadsTree(t)
	for _, row := range []struct {
		command string
		want    []string
	}{
		{"grep -r aws_secret_access_key big home", []string{"/home/.aws/credentials", "/home/.config/gh/hosts.yml", "<unknown>"}},
		{"grep -r aws_secret_access_key home big", []string{"/home/.aws/credentials", "/home/.config/gh/hosts.yml", "<unknown>"}},
		{"grep -rl aws_secret_access_key big big/d0001 home", []string{"/home/.aws/credentials", "<unknown>"}},
		{"rg --hidden aws_secret_access_key big home", []string{"/home/.aws/credentials", "<unknown>"}},
	} {
		got := searchReads(t, dir, home, row.command)
		for _, want := range row.want {
			if !slices.Contains(got, want) {
				t.Errorf("%q: reads %v, want %s among them", row.command, got, want)
			}
		}
	}
}

// TestGAP0912GrepGlobsReadAsFnmatch: grep's --include and --exclude-dir globs
// match as GNU fnmatch does (substrate-1:GAP-0912).
func TestGAP0912GrepGlobsReadAsFnmatch(t *testing.T) {
	dir, home := searchReadsTree(t)
	for _, row := range []struct {
		command string
		read    bool
	}{
		{"grep -rl --exclude-dir='[!.]*' aws_secret_access_key home", true},
		{"grep -rl --include='[!.]*' aws_secret_access_key home", true},
		{"grep -rl --include='[^.]*' aws_secret_access_key home", true},
		{"grep -rl --include='[]c]*' aws_secret_access_key home", true},
		{"grep -rl --include='[[:alpha:]]*' aws_secret_access_key home", true},
		{"grep -rl --exclude-dir='.[a-z]*' aws_secret_access_key home", false},
		{"grep -rl --include='*.go' aws_secret_access_key home", false},
		{"grep -rl --exclude-dir='[!x]*' aws_secret_access_key home", false},
	} {
		got := searchReads(t, dir, home, row.command)
		if slices.Contains(got, "/home/.aws/credentials") != row.read {
			t.Errorf("%q: reads %v, want the ~/.aws/credentials read %v", row.command, got, row.read)
		}
	}
}

// TestGAP0913SearchInsideAProbeFolder: a search of a folder deep inside a
// credentials probe reads its file (substrate-1:GAP-0913).
func TestGAP0913SearchInsideAProbeFolder(t *testing.T) {
	dir, home := searchReadsTree(t)
	for _, row := range []struct {
		command string
		want    string
	}{
		{"grep -r oauth_token home/.config/gh", "/home/.config/gh/hosts.yml"},
		{"grep -r oauth_token home/.config/gcloud", "/home/.config/gcloud/application_default_credentials.json"},
		{"grep -r oauth_token home/.config", "/home/.config/gh/hosts.yml"},
		{"grep -r aws_secret_access_key home/.aws", "/home/.aws/credentials"},
	} {
		got := searchReads(t, dir, home, row.command)
		if !slices.Contains(got, row.want) {
			t.Errorf("%q: reads %v, want %s among them", row.command, got, row.want)
		}
	}
	for _, command := range []string{"grep -rn TODO home/src", "grep -r oauth_token home/src/gh"} {
		if got := searchReads(t, dir, home, command); len(got) != 0 {
			t.Errorf("%q: reads %v, want none", command, got)
		}
	}
}

// TestGAP0925SearchFolderAfterACd: a recursive search's relative folder
// after a cd is read in the folder the cd reaches, not in the call's start
// folder; a cd the walk cannot follow leaves a file-unknown read
// (substrate-1:GAP-0925: cd ~/.config && grep -r KEY gh read nothing, in
// both rels too).
func TestGAP0925SearchFolderAfterACd(t *testing.T) {
	dir, home := searchReadsTree(t)
	for _, row := range []struct {
		command string
		want    string
	}{
		{"cd home/.config && grep -r oauth_token gh", "gh/hosts.yml"},
		{"cd ~/.config && grep -r oauth_token gh", "gh/hosts.yml"},
		{"cd home/.config && grep -r oauth_token", "gh/hosts.yml"},
		{"cd home && grep -r aws_secret_access_key .aws", ".aws/credentials"},
		{"cd home/src && grep -r aws_secret_access_key ../.aws", ".aws/credentials"},
		{"cd home/src && cd .. && grep -rl aws_secret_access_key .aws", ".aws/credentials"},
		// A failed first cd leaves the second in another folder: both
		// folders are static, so the search reads in each (the GAP-0925
		// file-unknown read is now the exact read, DET111 bar p2hookc).
		{"cd home/src; cd .. && grep -rl aws_secret_access_key .aws", ".aws/credentials"},
		{`cd "$D" && grep -r oauth_token gh`, "<unknown>"},
	} {
		got := searchReads(t, dir, home, row.command)
		if !slices.ContainsFunc(got, func(read string) bool { return strings.HasSuffix(read, row.want) }) {
			t.Errorf("%q: reads %v, want one ending in %s", row.command, got, row.want)
		}
	}
	for _, command := range []string{"cd home/src && grep -rn TODO .", "cd home && grep -r oauth_token src", "cd home/.config && grep -r oauth_token nothere"} {
		if got := searchReads(t, dir, home, command); len(got) != 0 {
			t.Errorf("%q: reads %v, want none", command, got)
		}
	}
}
