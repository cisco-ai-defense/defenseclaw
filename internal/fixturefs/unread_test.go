// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fixturefs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Inside Unread, and in a goroutine it starts through Go, no read reaches the
// file system and every one answers "does not exist"; outside it reads go on
// (substrate-1 GAP-0922).
func TestGAP0922UnreadReadsNothing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "present")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var seen []string
	restore := ObserveForTest(func(name string) { seen = append(seen, name) })
	defer restore()
	read := func() error { _, err := os.Lstat(Map(file)); return err }
	var inside, child error
	Unread(func() {
		inside = read()
		done := make(chan struct{})
		Go(func() { child = read(); close(done) })
		<-done
		if !Unreadable() {
			t.Error("Unreadable is false inside Unread")
		}
	})
	if !errors.Is(inside, fs.ErrNotExist) || !errors.Is(child, fs.ErrNotExist) {
		t.Fatalf("reads inside Unread: %v, its goroutine: %v; want not-exist", inside, child)
	}
	if len(seen) != 0 {
		t.Fatalf("Unread reads reached the file system: %v", seen)
	}
	if Unreadable() {
		t.Fatal("Unreadable is still true after Unread")
	}
	if err := read(); err != nil {
		t.Fatalf("read after Unread: %v", err)
	}
	// A goroutine not started through Go reads as before.
	var plain error
	Unread(func() {
		done := make(chan struct{})
		go func() { plain = read(); close(done) }()
		<-done
	})
	if err := plain; err != nil {
		t.Fatalf("plain goroutine read: %v", err)
	}
}
