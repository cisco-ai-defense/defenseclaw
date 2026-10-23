// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: review fixes (G-deadcode loop round 3, after head 34b7a39da4)
// for the teardown-only connectors (removed.go). Delete with that file.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

const removedOmnigentEditedModule = removedOmnigent103Module + "\n# my change: allow the build agent\n"

// requireEditedSaved checks that the exact bytes are saved, privately, and
// listed with their step.
func (h *removedHost) requireEditedSaved(t *testing.T, c removedOnlyConnector, body string) {
	t.Helper()
	saved := c.editedCopyPath(h.dataDir, []byte(body))
	data, err := os.ReadFile(saved)
	if err != nil || string(data) != body {
		t.Fatalf("the edited module saved at %s = %q, %v; want its exact bytes %q", saved, data, err, body)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Lstat(saved); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, %v; want 0600", saved, info, err)
		}
	}
	leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
	for _, item := range leftovers {
		if item.Path == saved {
			if !strings.Contains(item.What, "your edited "+c.script) || !strings.Contains(item.Step, "copy back what you need") {
				t.Fatalf("the saved module is listed as %+v", item)
			}
			return
		}
	}
	t.Fatalf("leftovers %+v do not list the saved module %s", leftovers, saved)
}

// recordWritten records the script at the path as the one the older setup
// wrote (its post-setup hash), so the teardown does not save it.
func (h *removedHost) recordWritten(t *testing.T, c removedOnlyConnector) {
	t.Helper()
	if c.editLogical == "" {
		return
	}
	if err := captureManagedFileBackup(h.dataDir, c.name, c.editLogical, h.script(c)); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(h.dataDir, c.name, c.editLogical, h.script(c)); err != nil {
		t.Fatal(err)
	}
}

func (h *removedHost) editedCopies(t *testing.T, c removedOnlyConnector) []string {
	t.Helper()
	return c.editedCopies(h.dataDir)
}

// Review fix (G-deadcode loop round 3), finding 1: an OmniGent policy module
// a user edited after the 1.0.3 setup (its marker kept) was overwritten with
// the stub, under every name, and its bytes were lost: the backup record
// holds only what was there before the setup. The older teardown compared
// the module with the hash its setup recorded and kept an edited one. The
// teardown now saves the exact edited bytes (synced, read back) under
// connector_backups/omnigent before the stub replaces them, so the module
// still denies every request and the edit is not lost. An unedited module
// (its recorded hash) is not saved. A missing record, or one for another
// file, proves nothing, so the module is saved then too. A save that fails
// leaves the module and the tokens as they are; the next run finishes.
func TestRemovedTeardownSavesAnEditedOmnigentModule(t *testing.T) {
	c := removedOmnigent
	cases := map[string]struct {
		prepare   func(t *testing.T, h *removedHost)
		body      string
		wantSaved bool
	}{
		"unedited": {body: removedOmnigent103Module},
		"edited": {
			body: removedOmnigentEditedModule, wantSaved: true,
			prepare: func(t *testing.T, h *removedHost) {
				writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
			},
		},
		"no backup record": {
			body: removedOmnigent103Module, wantSaved: true,
			prepare: func(t *testing.T, h *removedHost) {
				if err := os.Remove(managedFileBackupPath(h.dataDir, c.name, "module")); err != nil {
					t.Fatal(err)
				}
			},
		},
		"a record for another file": {
			body: removedOmnigent103Module, wantSaved: true,
			prepare: func(t *testing.T, h *removedHost) {
				other := filepath.Join(h.home, "elsewhere", c.script)
				if err := os.Remove(managedFileBackupPath(h.dataDir, c.name, "module")); err != nil {
					t.Fatal(err)
				}
				h.recordSetup(t, c.name, "module", other, "", removedOmnigent103Module)
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			if tc.prepare != nil {
				tc.prepare(t, h)
			}
			conn, _ := RetiredConnector(c.name)
			for run := 1; run <= 2; run++ {
				if err := conn.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("Teardown run %d: %v", run, err)
				}
				h.requireStub(t, c)
				h.requireRevoked(t, c)
				copies := h.editedCopies(t, c)
				if !tc.wantSaved {
					if len(copies) != 0 {
						t.Fatalf("the unedited module was saved: %v", copies)
					}
					continue
				}
				if len(copies) != 1 {
					t.Fatalf("run %d: saved copies = %v, want exactly one", run, copies)
				}
				h.requireEditedSaved(t, c, tc.body)
			}
			if err := conn.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean: %v", err)
			}
		})
	}

	// OpenHands never had the record, and its older teardown wrote its stub
	// over the script whatever its bytes: nothing is saved.
	t.Run("openhands", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, removedOpenHands)
		writeRemovedFile(t, h.script(removedOpenHands), removedOpenHands103Script+"# mine\n", 0o700)
		if err := removedOpenHands.Teardown(context.Background(), h.opts); err != nil {
			t.Fatal(err)
		}
		h.requireStub(t, removedOpenHands)
		if matches, _ := filepath.Glob(filepath.Join(h.dataDir, "connector_backups", "openhands", "*"+removedEditedInfix+"*")); len(matches) != 0 {
			t.Fatalf("an OpenHands script was saved: %v", matches)
		}
	})
}

// Finding 1's class: the edit is saved before the rename that replaces it,
// and so is a change made after the first read. A hard-linked module is
// left whole under every name, with its tokens, whatever the save did; once
// its other names are gone the next run saves nothing again and renames the
// stub over it.
func TestRemovedTeardownSavesTheEditBeforeEveryWrite(t *testing.T) {
	c := removedOmnigent
	t.Run("hard links", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, c)
		writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
		links := h.removedHardLinks(t, c)
		first, err := os.Stat(h.script(c))
		if err != nil {
			t.Fatal(err)
		}
		err = c.Teardown(context.Background(), h.opts)
		h.requireLeftStep(t, c, err, c.hardLinkStep(h.script(c)))
		requireRemovedNamesWhole(t, first, removedOmnigentEditedModule, append([]string{h.script(c)}, links...))
		for _, link := range links {
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Teardown(context.Background(), h.opts); err != nil {
			t.Fatal(err)
		}
		h.requireStub(t, c)
		h.requireEditedSaved(t, c, removedOmnigentEditedModule)
		if copies := h.editedCopies(t, c); len(copies) != 1 {
			t.Fatalf("saved copies = %v, want one", copies)
		}
	})
	t.Run("a change after the first read", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, c)
		writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
		later := removedOmnigentEditedModule + "# a later change\n"
		saveWrite := removedKeepEditedWrite
		t.Cleanup(func() { removedKeepEditedWrite = saveWrite })
		changed := false
		removedKeepEditedWrite = func(saved string, data []byte, perm os.FileMode) error {
			if err := saveWrite(saved, data, perm); err != nil {
				return err
			}
			if !changed {
				// Another change lands while the first save is made.
				changed = true
				if err := os.WriteFile(h.script(c), []byte(later), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		}
		if err := c.Teardown(context.Background(), h.opts); err != nil {
			t.Fatalf("Teardown: %v", err)
		}
		h.requireStub(t, c)
		h.requireEditedSaved(t, c, removedOmnigentEditedModule)
		h.requireEditedSaved(t, c, later)
	})
}

// Finding 1: a save that fails leaves the edited module, under every name,
// and the tokens as they are (the module reaches the route that blocks);
// the teardown and VerifyClean fail, and the next run saves it and writes
// the stub.
func TestRemovedTeardownKeepsAnEditedModuleItCannotSave(t *testing.T) {
	c := removedOmnigent
	h := newRemovedHost(t)
	h.stage(t, c)
	writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
	saveWrite := removedKeepEditedWrite
	t.Cleanup(func() { removedKeepEditedWrite = saveWrite })
	removedKeepEditedWrite = func(string, []byte, os.FileMode) error { return syscall.ENOSPC }
	err := c.Teardown(context.Background(), h.opts)
	if err == nil || !strings.Contains(err.Error(), "save the edited") || !strings.Contains(err.Error(), "its tokens were kept") {
		t.Fatalf("Teardown = %v, want the failed save and the tokens kept", err)
	}
	if data, _ := os.ReadFile(h.script(c)); string(data) != removedOmnigentEditedModule {
		t.Fatalf("the module it could not save was changed: %q", data)
	}
	h.requireTokensKept(t, c)
	if err := c.VerifyClean(h.opts); err == nil {
		t.Fatal("VerifyClean passed with the old module at the path")
	}
	if copies := h.editedCopies(t, c); len(copies) != 0 {
		t.Fatalf("a failed save left %v", copies)
	}
	removedKeepEditedWrite = saveWrite
	if err := c.Teardown(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	h.requireStub(t, c)
	h.requireRevoked(t, c)
	h.requireEditedSaved(t, c, removedOmnigentEditedModule)
}

// Review fix (G-deadcode loop round 3), finding 2: the names of the removed
// connectors stay reserved for plugins, under every spelling the teardown
// accepts, and their kept tokens are never loaded as authentication scopes.
func TestRemovedConnectorNamesStayReserved(t *testing.T) {
	r := NewDefaultRegistry()
	for _, name := range []string{"openhands", "OpenHands", "open-hands", "open_hands", " openhands", "omnigent", "OMNIGENT"} {
		err := r.RegisterPlugin(&stubConnector{name: name})
		if err == nil || !strings.Contains(err.Error(), "DefenseClaw 1.0.4 removed") {
			t.Fatalf("RegisterPlugin(%q) = %v, want it refused", name, err)
		}
		if _, ok := r.Get(name); ok {
			t.Fatalf("the refused plugin %q is in the registry", name)
		}
	}
	for _, name := range r.Names() {
		if IsRemovedConnector(name) {
			t.Fatalf("registry names %v hold the removed %q", r.Names(), name)
		}
	}

	h := newRemovedHost(t)
	for _, name := range []string{removedOpenHandsID, removedOmnigentID} {
		if _, err := EnsureHookAPIToken(h.dataDir, name); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := LoadHookAPITokens(h.dataDir, []string{"openhands", "OpenHands", "omnigent", "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded["codex"]; !ok || len(loaded) != 1 {
		t.Fatalf("LoadHookAPITokens loaded scopes %v, want only codex", loaded)
	}
}

// Review fix (G-deadcode loop round 1, after head ce3eda49e8): an edited
// OmniGent module lost its only saved copy when a file already at the saved
// copy's name held the same bytes but was no copy of its own: a hard link to
// the module (the stub written into the module reached it too), a link to
// the module, a hard link to another file, or a file other accounts can
// change. The teardown now counts a copy as saved only when it is a private
// regular file with one name that is not the module; it replaces any other
// file there with a copy of its own, and never writes through a link: the
// save fails, and the module and its tokens stay as they are.
func TestRemovedTeardownSavesTheEditToACopyOfItsOwn(t *testing.T) {
	c := removedOmnigent
	edit := []byte(removedOmnigentEditedModule)
	type prepared struct {
		other     string // a file the teardown must leave as it is
		otherInfo os.FileInfo
	}
	cases := map[string]struct {
		unixOnly bool
		prepare  func(t *testing.T, h *removedHost, saved string) prepared
		// failSave: the save cannot be made (a link at its name); the
		// module, its tokens and the link stay.
		failSave bool
		// leftLinked: the module still has another name after the save,
		// so the teardown leaves it whole with its tokens.
		leftLinked bool
	}{
		"a hard link to the module": {
			prepare: func(t *testing.T, h *removedHost, saved string) prepared {
				removedLinkOrSkip(t, h.script(c), saved)
				return prepared{}
			},
		},
		"a hard link to the module, which has another name too": {
			// The module keeps its other name, so it is left whole with its
			// tokens (TestRemovedTeardownNeverWritesIntoTheOldScript); the
			// name at the copy's name still becomes a copy of its own.
			leftLinked: true,
			prepare: func(t *testing.T, h *removedHost, saved string) prepared {
				removedLinkOrSkip(t, h.script(c), saved)
				removedLinkOrSkip(t, h.script(c), filepath.Join(h.home, "elsewhere", c.script))
				return prepared{}
			},
		},
		"a hard link to another file with the same bytes": {
			prepare: func(t *testing.T, h *removedHost, saved string) prepared {
				other := filepath.Join(h.home, "elsewhere", "mine.py")
				writeRemovedFile(t, other, string(edit), 0o600)
				removedLinkOrSkip(t, other, saved)
				info, err := os.Stat(other)
				if err != nil {
					t.Fatal(err)
				}
				return prepared{other: other, otherInfo: info}
			},
		},
		"a copy other accounts can change": {
			unixOnly: true,
			prepare: func(t *testing.T, h *removedHost, saved string) prepared {
				writeRemovedFile(t, saved, string(edit), 0o666)
				if err := os.Chmod(saved, 0o666); err != nil {
					t.Fatal(err)
				}
				return prepared{}
			},
		},
		"a link to the module": {
			failSave: true,
			prepare: func(t *testing.T, h *removedHost, saved string) prepared {
				if err := os.Symlink(h.script(c), saved); err != nil {
					t.Skipf("symlinks unsupported here: %v", err)
				}
				return prepared{}
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.unixOnly && runtime.GOOS == "windows" {
				t.Skip("Windows keeps the copy private by its folder's DACL, not its mode bits")
			}
			h := newRemovedHost(t)
			h.stage(t, c)
			writeRemovedFile(t, h.script(c), string(edit), 0o600)
			saved := c.editedCopyPath(h.dataDir, edit)
			if err := os.MkdirAll(filepath.Dir(saved), 0o700); err != nil {
				t.Fatal(err)
			}
			got := tc.prepare(t, h, saved)
			module, err := os.Stat(h.script(c))
			if err != nil {
				t.Fatal(err)
			}
			err = c.Teardown(context.Background(), h.opts)
			if tc.leftLinked {
				h.requireLeftStep(t, c, err, c.hardLinkStep(h.script(c)))
				if data, _ := os.ReadFile(h.script(c)); string(data) != string(edit) {
					t.Fatalf("the hard-linked module was changed: %q", data)
				}
				h.requireEditedSaved(t, c, string(edit))
				requireRemovedCopyOfItsOwn(t, saved, module)
				return
			}
			if tc.failSave {
				if err == nil || !strings.Contains(err.Error(), "save the edited") || !strings.Contains(err.Error(), "its tokens were kept") {
					t.Fatalf("Teardown = %v, want the failed save and the tokens kept", err)
				}
				if data, _ := os.ReadFile(h.script(c)); string(data) != string(edit) {
					t.Fatalf("the module it could not save was changed: %q", data)
				}
				if info, err := os.Lstat(saved); err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("the link at %s was changed: %v, %v", saved, info, err)
				}
				h.requireTokensKept(t, c)
				return
			}
			if err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			h.requireStub(t, c)
			h.requireRevoked(t, c)
			h.requireEditedSaved(t, c, string(edit))
			requireRemovedCopyOfItsOwn(t, saved, module)
			if got.other != "" {
				info, err := os.Stat(got.other)
				if err != nil || !os.SameFile(info, got.otherInfo) {
					t.Fatalf("%s is not the same file any more: %v", got.other, err)
				}
				if data, _ := os.ReadFile(got.other); string(data) != string(edit) {
					t.Fatalf("%s was changed: %q", got.other, data)
				}
				requireRemovedCopyOfItsOwn(t, saved, got.otherInfo)
			}
			// A second run keeps the copy it made.
			before, _ := os.Stat(saved)
			if err := c.Teardown(context.Background(), h.opts); err != nil {
				t.Fatalf("second Teardown: %v", err)
			}
			if after, err := os.Stat(saved); err != nil || !os.SameFile(before, after) {
				t.Fatalf("the second run replaced the saved copy: %v", err)
			}
		})
	}

	// The read back after the save checks the same: a save that leaves a
	// name of the module at the copy's name (a write skipped because the
	// bytes match) is no save, so the module and its tokens stay.
	t.Run("a save that leaves a name of the module", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, c)
		writeRemovedFile(t, h.script(c), string(edit), 0o600)
		saveWrite := removedKeepEditedWrite
		t.Cleanup(func() { removedKeepEditedWrite = saveWrite })
		removedKeepEditedWrite = func(saved string, _ []byte, _ os.FileMode) error {
			return os.Link(h.script(c), saved)
		}
		err := c.Teardown(context.Background(), h.opts)
		if err == nil || !strings.Contains(err.Error(), "not a copy of its own") || !strings.Contains(err.Error(), "its tokens were kept") {
			t.Fatalf("Teardown = %v, want the save refused and the tokens kept", err)
		}
		if data, _ := os.ReadFile(h.script(c)); string(data) != string(edit) {
			t.Fatalf("the module it could not save was changed: %q", data)
		}
		h.requireTokensKept(t, c)
	})
}

// removedLinkOrSkip makes link another name of target; it skips the test
// where hard links cannot be made.
func removedLinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, link); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}
}

// requireRemovedCopyOfItsOwn checks saved is a regular file with one name
// that is not the file not.
func requireRemovedCopyOfItsOwn(t *testing.T, saved string, not os.FileInfo) {
	t.Helper()
	info, err := os.Lstat(saved)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("%s = %v, %v; want a regular file", saved, info, err)
	}
	if os.SameFile(info, not) {
		t.Fatalf("%s is still another name of %s", saved, not.Name())
	}
	file, err := os.Open(saved)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if links, err := atomicTransformBoundLinkCountPlatform(file); err != nil || links != 1 {
		t.Fatalf("%s has %d names (%v), want one", saved, links, err)
	}
}
