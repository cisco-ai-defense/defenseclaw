// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGAP1792AbsoluteRedirectOutsideUnplacedCopyScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scope")
	}
	home := filepath.Join(t.TempDir(), "home")
	cwd := filepath.Join(home, "project")
	dest := filepath.Join(t.TempDir(), "trial")
	outside := filepath.Join(t.TempDir(), "report")
	for _, dir := range []string{cwd, dest} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("ordinary", filepath.Join(cwd, "source-link")); err != nil {
		t.Fatal(err)
	}
	command := "cd " + cwd + " && rsync -a --files-from=/tmp/synthetic-list ./ " + dest +
		"/ && echo $(cd /tmp && pwd) && grep marker > " + outside
	links := CommandLinksWithFacts("Bash", command, cwd, home, nil)
	if !links.OpaqueTargetWithFacts(outside, false, nil) {
		t.Fatal("the unplaced cd no longer creates the conservative global hold")
	}
	if !links.AbsoluteRedirectOutsideCDScopes(outside, nil) {
		t.Fatal("a static absolute redirect outside the fixed copy scope was held")
	}
	if links.AbsoluteRedirectOutsideCDScopes(filepath.Join(dest, "child"), nil) {
		t.Fatal("a child of the copy destination lost its link hold")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Join(dest, "child"), alias); err != nil {
		t.Fatal(err)
	}
	if links.AbsoluteRedirectOutsideCDScopes(alias, nil) {
		t.Fatal("an existing link into the copy scope lost its hold")
	}
	redirects := SafeShellRedirectOccurrencesWithFacts(command, cwd, home, nil)
	marked := false
	for _, redirect := range redirects {
		if redirect.Path == outside && redirect.Absolute {
			marked = true
		}
	}
	if !marked {
		t.Fatal("the static absolute redirect lost its proof")
	}
	relative := SafeShellRedirectOccurrencesWithFacts(command+" && grep marker > report", cwd, home, nil)
	for _, redirect := range relative {
		if redirect.Path == filepath.Join(cwd, "report") && redirect.Absolute {
			t.Fatal("a relative redirect inherited the absolute proof")
		}
	}
	variable := SafeShellRedirectOccurrencesWithFacts(command+" && grep marker > $HOME/report", cwd, home, nil)
	for _, redirect := range variable {
		if redirect.Path == filepath.Join(home, "report") && redirect.Absolute {
			t.Fatal("a home-expanded redirect inherited the literal-root proof")
		}
	}
	descriptor := SafeShellRedirectOccurrencesWithFacts(command+" && cat 1>&"+outside, cwd, home, nil)
	for _, redirect := range descriptor {
		if redirect.Path == outside && redirect.Absolute {
			t.Fatal("a descriptor redirect left an ambiguous absolute proof")
		}
	}
	hidden := CommandLinksWithFacts("Bash", command+"; . ./unknown-script", cwd, home, nil)
	if hidden.AbsoluteRedirectOutsideCDScopes(outside, nil) {
		t.Fatal("an unobserved directory change lost its global hold")
	}
}
