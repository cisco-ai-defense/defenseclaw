// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func heldConversionFixture(t *testing.T, content string) (path, tmp string) {
	t.Helper()
	root := t.TempDir()
	path = filepath.Join(root, "hooks.json")
	tmp = filepath.Join(root, ".tmp-staged")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, tmp
}

// The file the conversion read is rewritten in place to the new bytes, shorter
// or longer, and the staged file is gone.
func TestHeldConversionRewritesTheFileItRead(t *testing.T) {
	for _, next := range []string{`{"a":1}`, `{"a":1,"b":"a longer document than the one it read"}`, ``} {
		path, tmp := heldConversionFixture(t, `{"a":1,"b":"read by the conversion"}`)
		found := managedFileSnapshotHash([]byte(`{"a":1,"b":"read by the conversion"}`), true)
		if err := publishHeldConversion(tmp, path, found, []byte(next)); err != nil {
			t.Fatalf("publish %q: %v", next, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != next {
			t.Fatalf("file = %q, %v; want %q", got, err, next)
		}
		if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
			t.Fatalf("staged file left behind: %v", err)
		}
	}
}

// A file that is not the bytes the conversion read, or that is gone, is left
// as it is.
func TestHeldConversionLeavesAFileItDidNotRead(t *testing.T) {
	path, tmp := heldConversionFixture(t, `{"saved":"by an editor"}`)
	found := managedFileSnapshotHash([]byte(`{"a":1}`), true)
	if err := publishHeldConversion(tmp, path, found, []byte(`{"a":2}`)); !errors.Is(err, errManagedTargetMoved) {
		t.Fatalf("error = %v, want errManagedTargetMoved", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, []byte(`{"saved":"by an editor"}`)) {
		t.Fatalf("file = %q, want the editor save", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	tmp2 := filepath.Join(filepath.Dir(path), ".tmp-staged-2")
	if err := os.WriteFile(tmp2, []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishHeldConversion(tmp2, path, found, []byte(`{"a":2}`)); !errors.Is(err, errManagedTargetMoved) {
		t.Fatalf("missing file: error = %v, want errManagedTargetMoved", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the missing file was created: %v", err)
	}
}

// While the conversion holds the file, an editor can neither write it nor
// replace it: it gets a sharing violation, and its save is not overwritten.
func TestHeldConversionKeepsEditorsOutWhileItRewrites(t *testing.T) {
	path, tmp := heldConversionFixture(t, `{"a":1}`)
	found := managedFileSnapshotHash([]byte(`{"a":1}`), true)
	ran := false
	atomicFileHeldWriteHook = func(held string) {
		ran = true
		if f, err := os.OpenFile(held, os.O_WRONLY, 0); err == nil {
			f.Close()
			t.Error("an editor could open the held file for writing")
		} else if !atomicFileRenameBusy(err) {
			t.Errorf("write open error = %v, want a sharing violation", err)
		}
		if f, err := os.Open(held); err == nil {
			f.Close()
			t.Error("an editor could open the held file for reading")
		}
		other := filepath.Join(filepath.Dir(held), "editor-save.json")
		if err := os.WriteFile(other, []byte(`{"saved":true}`), 0o600); err != nil {
			t.Error(err)
			return
		}
		if err := os.Rename(other, held); err == nil {
			t.Error("an editor could replace the held file")
		}
	}
	t.Cleanup(func() { atomicFileHeldWriteHook = nil })
	if err := publishHeldConversion(tmp, path, found, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("the hold was never reached")
	}
	if got, _ := os.ReadFile(path); string(got) != `{"a":2}` {
		t.Fatalf("file = %q, want the converted bytes", got)
	}
}

// A process that has the file open for a moment (an indexer, a scan) delays
// the conversion; it does not fail it.
func TestHeldConversionWaitsForABriefReader(t *testing.T) {
	path, tmp := heldConversionFixture(t, `{"a":1}`)
	found := managedFileSnapshotHash([]byte(`{"a":1}`), true)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		reader.Close()
	}()
	if err := publishHeldConversion(tmp, path, found, []byte(`{"a":2}`)); err != nil {
		t.Fatalf("publish while a reader held the file briefly: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != `{"a":2}` {
		t.Fatalf("file = %q, want the converted bytes", got)
	}
}
