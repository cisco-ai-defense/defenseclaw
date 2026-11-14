// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// fakeBelowStatus is an open error carrying an NTSTATUS code.
type fakeBelowStatus uint32

func (s fakeBelowStatus) Error() string { return fmt.Sprintf("NTSTATUS 0x%08X", uint32(s)) }

type fakeBelowNode struct {
	attributes uint32
	// err is returned by the open of this element (a status the kernel
	// returns inside the open, such as STATUS_REPARSE_POINT_ENCOUNTERED).
	err error
}

// fakeBelowFS answers walkBelow's opens from a table of elements (keyed by
// their lower-case path), as the Windows primitives do: a missing element is
// STATUS_OBJECT_NAME_NOT_FOUND, a file opened as a folder
// STATUS_NOT_A_DIRECTORY, a folder opened as a file STATUS_FILE_IS_A_DIRECTORY.
// It records every open and close.
type fakeBelowFS struct {
	nodes  map[string]fakeBelowNode
	opened []string
	open   int
}

const (
	fakeDir  = fileAttributeDirectory
	fakeFile = uint32(0x20)
	fakeLink = fileAttributeDirectory | fileAttributeReparsePoint
)

func (f *fakeBelowFS) lookup(path string, wantDir, wantFile bool) (string, error) {
	f.opened = append(f.opened, path)
	node, ok := f.nodes[strings.ToLower(path)]
	switch {
	case !ok:
		return "", fakeBelowStatus(statusObjectNameNotFound)
	case node.err != nil:
		return "", node.err
	// FILE_OPEN_REPARSE_POINT: a link opens itself whatever was asked.
	case node.attributes&fileAttributeReparsePoint != 0:
	case wantDir && node.attributes&fileAttributeDirectory == 0:
		return "", fakeBelowStatus(statusNotADirectory)
	case wantFile && node.attributes&fileAttributeDirectory != 0:
		return "", fakeBelowStatus(statusFileIsADirectory)
	}
	f.open++
	return path, nil
}

func (f *fakeBelowFS) ops() belowOps[string] {
	return belowOps[string]{
		openRoot: func(root string) (string, error) { return f.lookup(root, false, false) },
		openChild: func(parent, name string, last bool, kind BelowKind) (string, error) {
			if strings.ContainsAny(name, `\/`) {
				return "", fmt.Errorf("child name %q is not one element", name)
			}
			return f.lookup(parent+`\`+name, !last || kind == BelowDirectory, last && kind == BelowFile)
		},
		attributes: func(handle string) (uint32, error) { return f.nodes[strings.ToLower(handle)].attributes, nil },
		status: func(err error) (uint32, bool) {
			var status fakeBelowStatus
			if errors.As(err, &status) {
				return uint32(status), true
			}
			return 0, false
		},
		close: func(string) { f.open-- },
	}
}

func newFakeBelowFS() *fakeBelowFS {
	return &fakeBelowFS{nodes: map[string]fakeBelowNode{
		`c:\users\alice`:                       {attributes: fakeDir},
		`c:\users\alice\.claude`:               {attributes: fakeDir},
		`c:\users\alice\.claude\settings.json`: {attributes: fakeFile},
		`c:\users\alice\.claude\managed`:       {attributes: fakeDir},
		`c:\users\alice\.codex`:                {attributes: fakeLink},
		`c:\users\alice\.codex\hooks.json`:     {attributes: fakeFile},
		`c:\users\alice\.cursor`:               {err: fakeBelowStatus(statusReparsePointEncountered)},
		`c:\users\alice\pipe`:                  {attributes: fileAttributeDevice},
		`c:\users\alice\file`:                  {attributes: fakeFile},
	}}
}

// GAP-0265 review 5: each element is opened from its parent's handle, so a
// plain path is read and every handle but the returned one is closed; the
// folders above the root are never opened.
func TestWalkBelowOpensEachElementFromItsParent(t *testing.T) {
	fake := newFakeBelowFS()
	handle, attributes, err := walkBelow(`C:\Users\alice`, `C:\Users\alice\.claude\settings.json`, BelowFile, fake.ops())
	if err != nil || attributes != fakeFile || !strings.EqualFold(handle, `C:\Users\alice\.claude\settings.json`) {
		t.Fatalf("plain file: %q %#x %v", handle, attributes, err)
	}
	if fake.open != 1 {
		t.Fatalf("%d handles open after the walk, want only the returned one", fake.open)
	}
	want := []string{`C:\Users\alice`, `C:\Users\alice\.claude`, `C:\Users\alice\.claude\settings.json`}
	if strings.Join(fake.opened, ";") != strings.Join(want, ";") {
		t.Fatalf("opened %v, want %v", fake.opened, want)
	}
	// Spellings: forward slashes, case and the \\?\ prefix.
	fake = newFakeBelowFS()
	if _, _, err := walkBelow(`\\?\C:\USERS\Alice\`, `c:/users/alice/.claude/managed`, BelowDirectory, fake.ops()); err != nil {
		t.Fatalf("spellings: %v", err)
	}
	if _, _, err := walkBelow(`C:\Users\alice`, `C:\Users\alice\.claude\managed`, BelowAny, newFakeBelowFS().ops()); err != nil {
		t.Fatalf("any, folder: %v", err)
	}
	if _, _, err := walkBelow(`C:\Users\alice`, `C:\Users\alice\.claude\settings.json`, BelowAny, newFakeBelowFS().ops()); err != nil {
		t.Fatalf("any, file: %v", err)
	}
}

// A link at or below the root is refused with ErrLinkBelowRoot naming it:
// one the walk opens itself (FILE_OPEN_REPARSE_POINT), one the kernel
// refuses inside the open (OBJ_DONT_REPARSE: STATUS_REPARSE_POINT_ENCOUNTERED),
// and a linked root. Nothing below the link is opened and no handle leaks.
func TestWalkBelowRefusesALinkAtOrBelowTheRoot(t *testing.T) {
	for _, item := range []struct {
		root, path, element string
		kind                BelowKind
	}{
		{`C:\Users\alice`, `C:\Users\alice\.codex\hooks.json`, `C:\Users\alice\.codex`, BelowFile},
		{`C:\Users\alice`, `C:\Users\alice\.codex`, `C:\Users\alice\.codex`, BelowDirectory},
		{`C:\Users\alice`, `C:\Users\alice\.codex`, `C:\Users\alice\.codex`, belowCheck},
		{`C:\Users\alice`, `C:\Users\alice\.cursor\hooks.json`, `C:\Users\alice\.cursor`, BelowFile},
		{`C:\Users\alice\.codex`, `C:\Users\alice\.codex\hooks.json`, `C:\Users\alice\.codex`, BelowFile},
	} {
		fake := newFakeBelowFS()
		_, _, err := walkBelow(item.root, item.path, item.kind, fake.ops())
		if !errors.Is(err, ErrLinkBelowRoot) || !strings.HasSuffix(err.Error(), item.element) {
			t.Fatalf("%s below %s: %v", item.path, item.root, err)
		}
		if fake.open != 0 {
			t.Fatalf("%s: %d handles leaked", item.path, fake.open)
		}
		for _, opened := range fake.opened {
			if len(opened) > len(item.element) {
				t.Fatalf("%s: opened %s below the link", item.path, opened)
			}
		}
	}
	// InspectBelow opens a link at the last element itself and reports it.
	fake := newFakeBelowFS()
	handle, attributes, err := walkBelow(`C:\Users\alice`, `C:\Users\alice\.codex`, belowInspect, fake.ops())
	if err != nil || attributes&fileAttributeReparsePoint == 0 || handle == "" {
		t.Fatalf("inspect a link: %#x %v", attributes, err)
	}
	// ... but not one above it.
	if _, _, err := walkBelow(`C:\Users\alice`, `C:\Users\alice\.codex\hooks.json`, belowInspect, newFakeBelowFS().ops()); !errors.Is(err, ErrLinkBelowRoot) {
		t.Fatalf("inspect below a link: %v", err)
	}
}

// The last element must be what was asked for; a missing element or a path
// through a file is fs.ErrNotExist; a device is never opened as a file; a
// path not below the root, or with a colon (a stream), is refused before any
// open.
func TestWalkBelowKindsAndMissing(t *testing.T) {
	home := `C:\Users\alice`
	for _, item := range []struct {
		path string
		kind BelowKind
		want error
	}{
		{home + `\.claude`, BelowFile, ErrNotRegularBelow},
		{home + `\.claude\settings.json`, BelowDirectory, ErrNotDirectoryBelow},
		{home + `\pipe`, BelowFile, ErrNotRegularBelow},
		{home + `\pipe`, BelowAny, ErrNotRegularBelow},
		{home + `\gone\a.json`, BelowFile, fs.ErrNotExist},
		{home + `\.claude\missing.json`, BelowFile, fs.ErrNotExist},
		{home + `\file\a.json`, BelowFile, fs.ErrNotExist},
	} {
		fake := newFakeBelowFS()
		if _, _, err := walkBelow(home, item.path, item.kind, fake.ops()); !errors.Is(err, item.want) {
			t.Fatalf("%s (kind %d): %v, want %v", item.path, item.kind, err, item.want)
		}
		if fake.open != 0 {
			t.Fatalf("%s: %d handles leaked", item.path, fake.open)
		}
	}
	for _, path := range []string{`C:\Users\bob\a.json`, home, home + `\..\bob\a.json`, `C:\Users\alicex\a.json`, home + `\\a.json`, home + `\a.json:stream`, home + `\.claude\x:y\a.json`} {
		fake := newFakeBelowFS()
		if _, _, err := walkBelow(home, path, BelowFile, fake.ops()); err == nil || errors.Is(err, ErrLinkBelowRoot) || len(fake.opened) != 0 {
			t.Fatalf("%s: %v after %v (want refused before any open)", path, err, fake.opened)
		}
	}
	if _, _, err := walkBelow(``, `C:\a`, BelowFile, newFakeBelowFS().ops()); err == nil {
		t.Fatal("empty root accepted")
	}
	// A root that is a file is not a folder to walk from.
	if _, _, err := walkBelow(home+`\file`, home+`\file\a`, BelowFile, newFakeBelowFS().ops()); !errors.Is(err, ErrNotDirectoryBelow) {
		t.Fatalf("file root: %v", err)
	}
	// Another open error is returned with the element named.
	fake := newFakeBelowFS()
	fake.nodes[`c:\users\alice\.claude\settings.json`] = fakeBelowNode{err: errors.New("Access is denied.")}
	if _, _, err := walkBelow(home, home+`\.claude\settings.json`, BelowFile, fake.ops()); err == nil || !strings.Contains(err.Error(), `settings.json: Access is denied.`) {
		t.Fatalf("access denied: %v", err)
	}
}
