// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package pathidentity

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// heldTree makes root/above/sub/held, a file or a folder.
func heldTree(t *testing.T, kind string) (root, held string) {
	t.Helper()
	root = t.TempDir()
	held = filepath.Join(root, "above", "sub", "held")
	if err := os.MkdirAll(filepath.Dir(held), 0o700); err != nil {
		t.Fatal(err)
	}
	if kind == "file" {
		if err := os.WriteFile(held, []byte("a"), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Mkdir(held, 0o700); err != nil {
		t.Fatal(err)
	}
	return root, held
}

// rel-1-0-10:GAP-1264: HoldUnlinked holds the last component of a path so
// that no link can take its place while the read runs. The hold opened it
// for its attributes only, which NT does not share-check, so a rename of
// the held component passed it while still() reported that it stayed. A
// hold no rename or delete of the held file or folder can pass is the pin.
// rel-1-0-10:GAP-1263: no folder above it can be renamed either, so none can
// be swapped for a link while the hold is open.
func TestGAP1264HeldComponentCannotBeRenamed(t *testing.T) {
	for _, kind := range []string{"file", "folder"} {
		t.Run(kind, func(t *testing.T) {
			root, held := heldTree(t, kind)
			still, err := HoldUnlinked(held)
			if err != nil {
				t.Fatal(err)
			}
			renamed := os.Rename(held, filepath.Join(filepath.Dir(held), "away"))
			removed := error(nil)
			if renamed != nil {
				removed = os.Remove(held)
			}
			parent := os.Rename(filepath.Dir(held), filepath.Join(root, "above", "sub2"))
			grand := os.Rename(filepath.Join(root, "above"), filepath.Join(root, "above2"))
			stayed := still()
			switch {
			case renamed == nil:
				t.Errorf("the held %s was renamed away while held (still()=%v)", kind, stayed)
			case removed == nil:
				t.Errorf("the held %s was deleted while held (still()=%v)", kind, stayed)
			case parent == nil:
				t.Errorf("the folder above the held %s was renamed while held", kind)
			case grand == nil:
				t.Errorf("the folder two levels above the held %s was renamed while held", kind)
			}
			// The hold is released: the component can be renamed again.
			if err := os.Rename(held, filepath.Join(filepath.Dir(held), "after")); err != nil {
				t.Errorf("the %s cannot be renamed after the hold: %v", kind, err)
			}
		})
	}
}

// rel-1-0-10:GAP-1264: a component another handle keeps from being pinned
// (that handle denies read sharing, or holds delete access so that a hold
// without delete sharing is refused). It keeps its hold (a locked file such
// as a registry hive keeps its answers), and still() reports whether its
// name still opens the file the hold opened. The hold used to look only for
// a link at the name, so a file put in its place passed. The folders above
// stay pinned by the hold's handle.
func TestGAP1264UnpinnableComponentIsLookedAtAgain(t *testing.T) {
	for _, row := range []struct {
		id            string
		access, share uint32
		replace       bool
	}{
		{"exclusive-reader", windows.GENERIC_READ, 0, false},
		{"delete-holder", windows.DELETE | windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE, false},
		{"delete-holder-replaced", windows.DELETE | windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE, true},
	} {
		t.Run(row.id, func(t *testing.T) {
			root, held := heldTree(t, "file")
			name, _ := windows.UTF16PtrFromString(held)
			other, err := windows.CreateFile(name, row.access, row.share, nil, windows.OPEN_EXISTING, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(other) //nolint:errcheck // test handle
			still, err := HoldUnlinked(held)
			if err != nil {
				t.Fatalf("%s: hold error %v, want a hold", row.id, err)
			}
			if os.Rename(filepath.Join(root, "above"), filepath.Join(root, "above2")) == nil {
				still()
				t.Fatalf("%s: a folder above was renamed while held", row.id)
			}
			if row.replace {
				if err := os.Rename(held, held+"-away"); err != nil {
					still()
					t.Fatalf("%s: rename: %v", row.id, err)
				}
				if err := os.WriteFile(held, []byte("b"), 0o600); err != nil {
					still()
					t.Fatal(err)
				}
			}
			if got := still(); got == row.replace {
				t.Fatalf("%s: still() = %v, want %v", row.id, got, !row.replace)
			}
		})
	}
}

// rel-1-0-10:GAP-1263: the hold opened the path by name, so a folder on the
// way that had become a link (a junction swapped in after the check) was
// followed and only the last component was looked at. A link anywhere on
// the way is now refused before anything below it is opened. A plain path
// and a missing name keep their answers.
func TestGAP1263LinkOnTheWayIsRefusedByTheHold(t *testing.T) {
	root, held := heldTree(t, "file")
	junction := filepath.Join(root, "jn")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, filepath.Join(root, "above")).CombinedOutput(); err != nil {
		t.Fatalf("junction: %v %s", err, out)
	}
	for _, row := range []struct{ id, path string }{
		{"junction-above-file", filepath.Join(junction, "sub", "held")},
		{"junction-above-folder", filepath.Join(junction, "sub")},
		{"junction-itself", junction},
	} {
		still, err := HoldUnlinked(row.path)
		if err == nil {
			still()
		}
		if !errors.Is(err, ErrLinked) {
			t.Errorf("%s: hold error %v, want ErrLinked", row.id, err)
		}
	}
	for _, path := range []string{held, filepath.Dir(held), root} {
		still, err := HoldUnlinked(path)
		if err != nil {
			t.Errorf("plain %s: hold error %v", filepath.Base(path), err)
			continue
		}
		if !still() {
			t.Errorf("plain %s: still() false", filepath.Base(path))
		}
	}
	if _, err := HoldUnlinked(filepath.Join(root, "missing", "x")); !os.IsNotExist(err) {
		t.Errorf("missing name: hold error %v, want not-exist", err)
	}
	if _, err := HoldUnlinked(held + `\x`); err == nil || errors.Is(err, ErrUnpinned) {
		t.Errorf("a file used as a folder: hold error %v, want the open's own error", err)
	}
}
