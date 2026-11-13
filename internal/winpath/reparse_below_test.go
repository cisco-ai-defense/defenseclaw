// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// fakeReparseLister answers CheckNoReparseBelow from a table of elements and
// their reparse flags, and records what was asked.
type fakeReparseLister struct {
	reparse map[string]bool
	asked   []string
}

func (f *fakeReparseLister) isReparse(element string) (bool, error) {
	f.asked = append(f.asked, element)
	value, ok := f.reparse[strings.ToLower(element)]
	if !ok {
		return false, fs.ErrNotExist
	}
	return value, nil
}

func TestCheckNoReparseBelowRefusesALinkBelowTheRoot(t *testing.T) {
	home := `C:\Users\alice`
	lister := &fakeReparseLister{reparse: map[string]bool{
		`c:\users\alice`:                       false,
		`c:\users\alice\.claude`:               false,
		`c:\users\alice\.claude\settings.json`: false,
		`c:\users\alice\.codex`:                true,
		`c:\users\alice\.codex\hooks.json`:     false,
	}}
	if err := CheckNoReparseBelow(home, home+`\.claude\settings.json`, lister.isReparse); err != nil {
		t.Fatalf("plain path: %v", err)
	}
	// The folders above the home are never asked (a redirected profile may
	// be a junction).
	for _, asked := range lister.asked {
		if !strings.HasPrefix(strings.ToLower(asked), `c:\users\alice`) {
			t.Fatalf("asked above the home: %s", asked)
		}
	}
	lister.asked = nil
	err := CheckNoReparseBelow(home, home+`\.codex\hooks.json`, lister.isReparse)
	if !errors.Is(err, ErrLinkBelowRoot) || !strings.Contains(err.Error(), `.codex`) {
		t.Fatalf("junction in the middle: %v", err)
	}
	// Nothing below the link is inspected.
	if last := lister.asked[len(lister.asked)-1]; !strings.EqualFold(last, home+`\.codex`) {
		t.Fatalf("inspected below the link: %v", lister.asked)
	}
}

func TestCheckNoReparseBelowRefusesALinkedRoot(t *testing.T) {
	lister := &fakeReparseLister{reparse: map[string]bool{`c:\users\alice`: true, `c:\users\alice\a.json`: false}}
	if err := CheckNoReparseBelow(`C:\Users\alice`, `C:\Users\alice\a.json`, lister.isReparse); !errors.Is(err, ErrLinkBelowRoot) {
		t.Fatalf("linked home: %v", err)
	}
}

func TestCheckNoReparseBelowSpellingsAndMissing(t *testing.T) {
	lister := &fakeReparseLister{reparse: map[string]bool{`c:\users\alice`: false, `c:\users\alice\a`: false}}
	// Forward slashes, another case and the \\?\ prefix are the same path.
	if err := CheckNoReparseBelow(`\\?\C:\USERS\Alice\`, `c:/users/alice/a`, lister.isReparse); err != nil {
		t.Fatalf("spellings: %v", err)
	}
	// A missing element is fs.ErrNotExist (the scan drops a missing file).
	if err := CheckNoReparseBelow(`C:\Users\alice`, `C:\Users\alice\gone\b.json`, lister.isReparse); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	for _, path := range []string{`C:\Users\bob\a.json`, `C:\Users\alice`, `C:\Users\alice\..\bob\a.json`, `C:\Users\alicex\a.json`, `C:\Users\alice\\a.json`} {
		if err := CheckNoReparseBelow(`C:\Users\alice`, path, lister.isReparse); err == nil || errors.Is(err, ErrLinkBelowRoot) {
			t.Fatalf("%s: %v (want not below the root)", path, err)
		}
	}
	if _, err := ElementsBelow(``, `C:\a`); err == nil {
		t.Fatal("empty root accepted")
	}
}

func TestExpectedFinalPathBelowComparesTheOpenedFile(t *testing.T) {
	// The root's final path can differ from its spelling (a redirected
	// profile, an 8.3 name, the \\?\ prefix); the elements below it cannot.
	want, err := ExpectedFinalPathBelow(`\\?\D:\Profiles\alice`, `\\?\C:\Users\alice`, `C:\Users\alice\.claude\settings.json`)
	if err != nil {
		t.Fatal(err)
	}
	if !SameWindowsPath(want, `\\?\d:\profiles\ALICE\.claude\settings.json`) {
		t.Fatalf("plain path: %s", want)
	}
	// A junction at .claude makes the opened file's final path another one.
	if SameWindowsPath(want, `\\?\C:\Windows\System32\config\settings.json`) {
		t.Fatal("a file behind a link compares equal")
	}
	if !SameWindowsPath(`\\?\UNC\server\share\a`, `\\server\share\a\`) {
		t.Fatal("UNC prefix not normalised")
	}
	if _, err := ExpectedFinalPathBelow(`C:\x`, `C:\Users\alice`, `C:\Users\bob\a.json`); err == nil {
		t.Fatal("a path outside the root has an expected final path")
	}
}
