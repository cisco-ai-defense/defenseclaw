// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A fake name table: the name leads to an inode; a rename over the name gives
// it a new inode and leaves the old one to whoever holds it, as POSIX
// semantics replacement does; an editor that writes in place changes the inode
// the name leads to.
type fakeInode struct{ data []byte }

type fakeNames struct {
	current   *fakeInode
	published int
	putBacks  int
	kept      [][]byte
	// atPublish and atPutBack run just before the rename, where an editor saves.
	atPublish func(*fakeNames)
	atPutBack func(*fakeNames)
	failPut   error
}

func (n *fakeNames) saveInPlace(data string) { n.current.data = []byte(data) }
func (n *fakeNames) saveByRename(data string) {
	n.current = &fakeInode{data: []byte(data)}
}

type fakeHold struct {
	names *fakeNames
	inode *fakeInode
}

func (h fakeHold) ReadAll() ([]byte, error)  { return append([]byte(nil), h.inode.data...), nil }
func (h fakeHold) StillNamed() (bool, error) { return h.names.current == h.inode, nil }
func (fakeHold) Close() error                { return nil }

func (n *fakeNames) saves() keptSaves {
	return keptSaves{
		hold: func() (displacedHold, error) {
			if n.current == nil {
				return nil, errManagedTargetMoved
			}
			return fakeHold{names: n, inode: n.current}, nil
		},
		publish: func() error {
			if n.atPublish != nil {
				n.atPublish(n)
			}
			n.published++
			n.current = &fakeInode{data: []byte("converted")}
			return nil
		},
		putBack: func(save []byte) error {
			if n.failPut != nil {
				return n.failPut
			}
			if n.atPutBack != nil {
				n.atPutBack(n)
			}
			n.putBacks++
			n.current = &fakeInode{data: append([]byte(nil), save...)}
			return nil
		},
		keep: func(save []byte) (string, error) {
			n.kept = append(n.kept, append([]byte(nil), save...))
			return "kept-file", nil
		},
	}
}

func replaceFake(n *fakeNames) error {
	found := managedFileSnapshotHash([]byte("read"), true)
	return n.saves().replace("hooks.json", found, []byte("converted"))
}

func fakeFile(content string) *fakeNames {
	return &fakeNames{current: &fakeInode{data: []byte(content)}}
}

func TestKeptSavesReplacesTheFileItRead(t *testing.T) {
	n := fakeFile("read")
	if err := replaceFake(n); err != nil {
		t.Fatal(err)
	}
	if string(n.current.data) != "converted" || n.published != 1 || n.putBacks != 0 {
		t.Fatalf("file=%q published=%d putBacks=%d", n.current.data, n.published, n.putBacks)
	}
}

// A file that is not the bytes the conversion read, or that was replaced
// before the check, is left as it is and nothing is published.
func TestKeptSavesLeavesAFileItDidNotRead(t *testing.T) {
	n := fakeFile("saved")
	if err := replaceFake(n); !errors.Is(err, errManagedTargetMoved) {
		t.Fatalf("error = %v, want errManagedTargetMoved", err)
	}
	if string(n.current.data) != "saved" || n.published != 0 {
		t.Fatalf("file=%q published=%d", n.current.data, n.published)
	}
	gone := &fakeNames{}
	if err := replaceFake(gone); !errors.Is(err, errManagedTargetMoved) || gone.current != nil || gone.published != 0 {
		t.Fatalf("missing file: error=%v current=%v published=%d", err, gone.current, gone.published)
	}
}

// An editor that saves in place after the last check is found in the displaced
// file, put back under the name, and the write is refused.
func TestKeptSavesPutsBackASaveMadeInPlaceBeforeTheRename(t *testing.T) {
	n := fakeFile("read")
	n.atPublish = func(n *fakeNames) {
		n.saveInPlace("read + note")
		n.atPublish = nil
	}
	if err := replaceFake(n); !errors.Is(err, errManagedTargetMoved) {
		t.Fatalf("error = %v, want errManagedTargetMoved", err)
	}
	if string(n.current.data) != "read + note" || n.putBacks != 1 || len(n.kept) != 0 {
		t.Fatalf("file=%q putBacks=%d kept=%q", n.current.data, n.putBacks, n.kept)
	}
}

// An editor that replaces the file by a rename before the check that the held
// file still has the name leaves it alone.
func TestKeptSavesRefusesAFileRenamedOverBeforeTheRename(t *testing.T) {
	n := fakeFile("read")
	hold := n.saves().hold
	saves := n.saves()
	saves.hold = func() (displacedHold, error) {
		h, err := hold()
		n.saveByRename("renamed over")
		return h, err
	}
	found := managedFileSnapshotHash([]byte("read"), true)
	if err := saves.replace("hooks.json", found, []byte("converted")); !errors.Is(err, errManagedTargetMoved) {
		t.Fatalf("error = %v, want errManagedTargetMoved", err)
	}
	if string(n.current.data) != "renamed over" || n.published != 0 {
		t.Fatalf("file=%q published=%d", n.current.data, n.published)
	}
}

// A second save in the instant of the undo is kept in a file of its own, and
// the first save stays under the name: no save is dropped.
func TestKeptSavesKeepsASecondSaveMadeWhileItPutsTheFirstBack(t *testing.T) {
	n := fakeFile("read")
	n.atPublish = func(n *fakeNames) { n.saveInPlace("first save"); n.atPublish = nil }
	n.atPutBack = func(n *fakeNames) { n.saveInPlace("second save"); n.atPutBack = nil }
	err := replaceFake(n)
	if err == nil || errors.Is(err, errManagedTargetMoved) || !strings.Contains(err.Error(), "kept-file") {
		t.Fatalf("error = %v, want one that names the kept file", err)
	}
	if string(n.current.data) != "first save" || len(n.kept) != 1 || !bytes.Equal(n.kept[0], []byte("second save")) {
		t.Fatalf("file=%q kept=%q", n.current.data, n.kept)
	}
}

// A save that cannot be put back is kept in a file of its own.
func TestKeptSavesKeepsASaveItCannotPutBack(t *testing.T) {
	n := fakeFile("read")
	n.atPublish = func(n *fakeNames) { n.saveInPlace("first save"); n.atPublish = nil }
	n.failPut = errors.New("disk full")
	err := replaceFake(n)
	if err == nil || !strings.Contains(err.Error(), "disk full") || !strings.Contains(err.Error(), "kept-file") {
		t.Fatalf("error = %v, want the cause and the kept file", err)
	}
	if len(n.kept) != 1 || !bytes.Equal(n.kept[0], []byte("first save")) {
		t.Fatalf("kept=%q", n.kept)
	}
}
