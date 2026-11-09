// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const heldRead = `{"a":1,"b":"read by the conversion"}`

func heldConversionFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func stageConversion(t *testing.T, path string, data []byte) (string, conversionPublish) {
	t.Helper()
	staged, info, err := stageAtomicFile(filepath.Dir(path), path, data, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return staged, conversionPublish{stagedInfo: info, perm: 0o600, publish: atomicFilePublish}
}

func convertHeld(t *testing.T, path, read string, next []byte) (os.FileInfo, error) {
	t.Helper()
	staged, pub := stageConversion(t, path, next)
	err := publishHeldConversion(staged, path, managedFileSnapshotHash([]byte(read), true), next, pub)
	if _, statErr := os.Lstat(staged); !os.IsNotExist(statErr) {
		t.Fatalf("staged file left behind: %v", statErr)
	}
	return pub.stagedInfo, err
}

// The file the conversion read is replaced by the staged file itself, shorter
// or longer: the name leads to the complete new file (a rename, not a rewrite
// in place that a stopped process leaves half done), and it is private.
func TestHeldConversionReplacesTheFileItReadByRename(t *testing.T) {
	for _, next := range []string{`{"a":1}`, `{"a":1,"b":"a longer document than the one it read","c":[1,2,3]}`, ``} {
		path := heldConversionFixture(t, heldRead)
		staged, err := convertHeld(t, path, heldRead, []byte(next))
		if err != nil {
			t.Fatalf("publish %q: %v", next, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != next {
			t.Fatalf("file = %q, %v; want %q", got, err, next)
		}
		now, err := os.Stat(path)
		if err != nil || !os.SameFile(staged, now) {
			t.Fatalf("the name does not lead to the staged file: %v", err)
		}
		if !atomicFileAlreadyMatches(path, []byte(next), 0o600) {
			t.Fatalf("the published file is not private with the new bytes")
		}
	}
}

// A file that is not the bytes the conversion read, or that is gone, is left
// as it is.
func TestHeldConversionLeavesAFileItDidNotRead(t *testing.T) {
	path := heldConversionFixture(t, `{"saved":"by an editor"}`)
	if _, err := convertHeld(t, path, heldRead, []byte(`{"a":2}`)); !errors.Is(err, errManagedTargetMoved) {
		t.Fatalf("error = %v, want errManagedTargetMoved", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, []byte(`{"saved":"by an editor"}`)) {
		t.Fatalf("file = %q, want the editor save", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := convertHeld(t, path, heldRead, []byte(`{"a":2}`)); !errors.Is(err, errManagedTargetMoved) {
		t.Fatalf("missing file: error = %v, want errManagedTargetMoved", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the missing file was created: %v", err)
	}
}

// An editor that saves in place in the instant before the rename is found in
// the displaced file and put back; the write is refused.
func TestHeldConversionPutsBackASaveMadeBeforeTheRename(t *testing.T) {
	path := heldConversionFixture(t, heldRead)
	save := []byte("// operator note\n" + heldRead)
	saved := false
	atomicFileBeforePrivatePublish = func(destination string) error {
		if saved {
			return nil
		}
		saved = true
		return os.WriteFile(destination, save, 0o600)
	}
	t.Cleanup(func() { atomicFileBeforePrivatePublish = nil })
	if _, err := convertHeld(t, path, heldRead, []byte(`{"a":2}`)); !errors.Is(err, errManagedTargetMoved) {
		t.Fatalf("error = %v, want errManagedTargetMoved", err)
	}
	if !saved {
		t.Fatal("the save seam was never reached")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, save) {
		t.Fatalf("file = %q, want the save", got)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".tmp-*")); len(leftovers) != 0 {
		t.Fatalf("staging files left behind: %v", leftovers)
	}
}

// A hardlinked copy of the file is another name of the old file: the
// conversion replaces the vendor name only.
func TestHeldConversionLeavesAHardlinkedAliasAlone(t *testing.T) {
	path := heldConversionFixture(t, heldRead)
	alias := filepath.Join(filepath.Dir(path), "alias.json")
	if err := os.Link(path, alias); err != nil {
		t.Skipf("no hardlinks here: %v", err)
	}
	if _, err := convertHeld(t, path, heldRead, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(alias); string(got) != heldRead {
		t.Fatalf("alias = %q, want the bytes it had", got)
	}
	if got, _ := os.ReadFile(path); string(got) != `{"a":2}` {
		t.Fatalf("file = %q, want the converted bytes", got)
	}
}

// A file whose protection was broadened after setup, with its bytes
// unchanged, comes out private.
func TestHeldConversionPublishesWithPrivateProtection(t *testing.T) {
	path := heldConversionFixture(t, heldRead)
	if err := setAtomicFileUnsafeReadDACL(path); err != nil {
		t.Fatal(err)
	}
	if atomicFileAlreadyMatches(path, []byte(heldRead), 0o600) {
		t.Fatal("the fixture is still private")
	}
	if _, err := convertHeld(t, path, heldRead, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	if !atomicFileAlreadyMatches(path, []byte(`{"a":2}`), 0o600) {
		t.Fatal("the published file is not private")
	}
}

// The hold keeps the file it opened when a rename replaces the name, and says
// the name leads elsewhere.
func TestFileHoldKeepsTheDisplacedFile(t *testing.T) {
	path := heldConversionFixture(t, heldRead)
	hold, err := holdFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	if named, err := hold.StillNamed(); err != nil || !named {
		t.Fatalf("StillNamed = %v, %v before the rename", named, err)
	}
	other := filepath.Join(filepath.Dir(path), "other.json")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ReplaceFileAtomically(other, path); err != nil {
		t.Fatalf("a rename over a held file: %v", err)
	}
	got, err := hold.ReadAll()
	if err != nil || string(got) != heldRead {
		t.Fatalf("held bytes = %q, %v; want the displaced file", got, err)
	}
	if named, err := hold.StillNamed(); err != nil || named {
		t.Fatalf("StillNamed = %v, %v after the rename", named, err)
	}
}

// A process that has the file open for a moment (an indexer, a scan) delays
// the conversion; it does not fail it.
func TestHeldConversionWaitsForABriefReader(t *testing.T) {
	path := heldConversionFixture(t, heldRead)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		reader.Close()
	}()
	if _, err := convertHeld(t, path, heldRead, []byte(`{"a":2}`)); err != nil {
		t.Fatalf("publish while a reader held the file briefly: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != `{"a":2}` {
		t.Fatalf("file = %q, want the converted bytes", got)
	}
}
