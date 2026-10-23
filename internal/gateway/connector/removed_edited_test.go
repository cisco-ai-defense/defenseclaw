// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: review fixes (G-deadcode loop round 3, after head 34b7a39da4)
// for the teardown-only connectors (removed.go). Delete with that file.

import (
	"context"
	"errors"
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
	h.requireEditedSavedAt(t, c, c.editedCopyPath(h.dataDir, []byte(body)), body)
}

func (h *removedHost) requireEditedSavedAt(t *testing.T, c removedOnlyConnector, saved, body string) {
	t.Helper()
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
	wantWhat := "your edited " + c.script
	if c.name == removedOpenHandsID {
		wantWhat = "the prior " + c.script + " (including any edits)"
	}
	for _, item := range leftovers {
		if item.Path == saved {
			if !strings.Contains(item.What, wantWhat) || !strings.Contains(item.Step, "copy back what you need") {
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

	// OpenHands never had a post-setup record. Save every marked hook before
	// writing its stub so an edit under another hard-linked name survives.
	t.Run("openhands", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, removedOpenHands)
		body := removedOpenHands103Script + "# mine\n"
		writeRemovedFile(t, h.script(removedOpenHands), body, 0o700)
		if err := removedOpenHands.Teardown(context.Background(), h.opts); err != nil {
			t.Fatal(err)
		}
		h.requireStub(t, removedOpenHands)
		h.requireEditedSaved(t, removedOpenHands, body)
	})
}

// The edit is saved before the publication that replaces it, and so is a
// change made after the first read. A hard-linked module is left whole
// under every name, with its tokens, whatever the save did; once its other
// names are gone the next run saves nothing again and publishes the stub
// over it.
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
		h.requireTokensKept(t, c)
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
// the module (the retired teardown now refuses that hard-linked module), a link to
// the module, a hard link to another file, or a file other accounts can
// change. The teardown now counts a copy as saved only when it is a private
// regular file with one name that is not the module; it leaves occupied
// names in place and saves under a new name. A link at the hash-derived name
// stops the save, leaving the module and its tokens as they are.
func TestRemovedTeardownSavesTheEditToACopyOfItsOwn(t *testing.T) {
	c := removedOmnigent
	edit := []byte(removedOmnigentEditedModule)
	type prepared struct {
		other     string // a file the teardown must leave as it is
		otherInfo os.FileInfo
	}
	cases := map[string]struct {
		unixOnly        bool
		refusesHardLink bool
		linkCount       uint32
		prepare         func(t *testing.T, h *removedHost, saved string) prepared
		// failSave: the save cannot be made (a link at its name); the
		// module, its tokens and the link stay.
		failSave bool
	}{
		"a hard link to the module": {
			// A hard-linked module stays intact with its tokens for manual cleanup.
			refusesHardLink: true,
			linkCount:       2,
			prepare: func(t *testing.T, h *removedHost, saved string) prepared {
				removedLinkOrSkip(t, h.script(c), saved)
				return prepared{}
			},
		},
		"a hard link to the module, which has another name too": {
			refusesHardLink: true,
			linkCount:       3,
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
			if tc.refusesHardLink {
				step := c.hardLinkStep(h.script(c))
				copyAt, deleteAt := strings.Index(step, "copy back what you need"), strings.Index(step, "delete every other name")
				if copyAt < 0 || deleteAt < 0 || copyAt >= deleteAt {
					t.Fatalf("hard-link step %q must tell the operator to copy needed bytes before deleting a backup name", step)
				}
				h.requireLeftStep(t, c, err, step)
				leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
				listed := false
				for _, item := range leftovers {
					if item.Path == saved && strings.Contains(item.Step, "copy back what you need") {
						listed = true
					}
				}
				if !listed {
					t.Fatalf("leftovers %+v do not tell the operator to copy needed bytes from %s", leftovers, saved)
				}
				if data, readErr := os.ReadFile(h.script(c)); readErr != nil || string(data) != string(edit) {
					t.Fatalf("the hard-linked module changed to %q: %v", data, readErr)
				}
				atBase, statErr := os.Stat(saved)
				if statErr != nil || !os.SameFile(module, atBase) {
					t.Fatalf("the hash-name file %s is no longer the module: %v", saved, statErr)
				}
				file, openErr := os.Open(saved)
				if openErr != nil {
					t.Fatal(openErr)
				}
				links, linkErr := atomicTransformBoundLinkCountPlatform(file)
				if closeErr := file.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				if linkErr != nil || links != tc.linkCount {
					t.Fatalf("the module still has %d names (%v), want %d", links, linkErr, tc.linkCount)
				}
				if tc.linkCount == 3 {
					other := filepath.Join(h.home, "elsewhere", c.script)
					otherInfo, statErr := os.Stat(other)
					otherData, readErr := os.ReadFile(other)
					if statErr != nil || readErr != nil || !os.SameFile(module, otherInfo) || string(otherData) != string(edit) {
						t.Fatalf("the third name %s changed: stat %v, read %v", other, statErr, readErr)
					}
				}
				newSaved := saved + "-2"
				h.requireEditedSavedAt(t, c, newSaved, string(edit))
				requireRemovedCopyOfItsOwn(t, newSaved, module)
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
			newSaved := saved + "-2"
			h.requireEditedSavedAt(t, c, newSaved, string(edit))
			requireRemovedCopyOfItsOwn(t, newSaved, module)
			if got.other != "" {
				info, err := os.Stat(got.other)
				if err != nil || !os.SameFile(info, got.otherInfo) {
					t.Fatalf("%s is not the same file any more: %v", got.other, err)
				}
				if data, _ := os.ReadFile(got.other); string(data) != string(edit) {
					t.Fatalf("%s was changed: %q", got.other, data)
				}
				if atBase, err := os.Stat(saved); err != nil || !os.SameFile(atBase, got.otherInfo) {
					t.Fatalf("occupied saved-copy name %s was replaced: %v", saved, err)
				}
				requireRemovedCopyOfItsOwn(t, newSaved, got.otherInfo)
			}
			// A second run keeps the copy it made.
			before, _ := os.Stat(newSaved)
			if err := c.Teardown(context.Background(), h.opts); err != nil {
				t.Fatalf("second Teardown: %v", err)
			}
			if after, err := os.Stat(newSaved); err != nil || !os.SameFile(before, after) {
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

// An OpenHands hook may have another name outside the hooks folder. The
// teardown never writes into its file, so the edit at that other name stays
// as it is, the hook keeps its tokens and the step names the other name.
func TestRemovedOpenHandsHardLinkIsLeftWholeWithItsEdit(t *testing.T) {
	c := removedOpenHands
	for _, failSave := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved", true: "save fails"}[failSave], func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			body := removedOpenHands103Script + "# operator's edit\n"
			writeRemovedFile(t, h.script(c), body, c.mode)
			outside := filepath.Join(h.home, "elsewhere", c.script)
			removedLinkOrSkip(t, h.script(c), outside)
			oldInfo, err := os.Stat(outside)
			if err != nil {
				t.Fatal(err)
			}
			if failSave {
				write := removedKeepEditedWrite
				t.Cleanup(func() { removedKeepEditedWrite = write })
				removedKeepEditedWrite = func(string, []byte, os.FileMode) error { return syscall.ENOSPC }
			}
			err = c.Teardown(context.Background(), h.opts)
			if failSave {
				if err == nil || !strings.Contains(err.Error(), "save the edited") {
					t.Fatalf("Teardown = %v, want a failed save", err)
				}
				for _, name := range []string{h.script(c), outside} {
					if got, readErr := os.ReadFile(name); readErr != nil || string(got) != body {
						t.Fatalf("failed save changed %s to %q: %v", name, got, readErr)
					}
				}
				h.requireTokensKept(t, c)
				return
			}
			h.requireLeftStep(t, c, err, c.hardLinkStep(h.script(c)))
			requireRemovedNamesWhole(t, oldInfo, body, []string{h.script(c), outside})
			h.requireTokensKept(t, c)
			h.requireEditedSaved(t, c, body)
		})
	}
}

// Model an interruption after saving an edited module but before replacing it.
// A retry must retain a later operator edit to the first saved copy.
func TestRemovedOmnigentRetryDoesNotReplaceAnEditedSavedCopy(t *testing.T) {
	c := removedOmnigent
	h := newRemovedHost(t)
	h.stage(t, c)
	body := removedOmnigentEditedModule
	writeRemovedFile(t, h.script(c), body, c.mode)
	if err := c.keepEdited(h.dataDir, h.script(c), nil, []byte(body)); err != nil {
		t.Fatal(err)
	}
	first := c.editedCopyPath(h.dataDir, []byte(body))
	operatorEdit := body + "# operator's later note\n"
	writeRemovedFile(t, first, operatorEdit, 0o600)
	// The destination can be occupied after the teardown's last check.
	// Publication itself must refuse replacement in that case.
	if err := removedKeepEditedWrite(first, []byte(body), 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("publish over the operator's saved copy = %v, want os.ErrExist", err)
	}
	if got, err := os.ReadFile(first); err != nil || string(got) != operatorEdit {
		t.Fatalf("publication changed the operator's saved copy to %q: %v", got, err)
	}

	if err := c.Teardown(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	h.requireStub(t, c)
	h.requireRevoked(t, c)
	if got, err := os.ReadFile(first); err != nil || string(got) != operatorEdit {
		t.Fatalf("retry changed the operator's saved copy to %q: %v", got, err)
	}
	copies := h.editedCopies(t, c)
	if len(copies) != 2 {
		t.Fatalf("saved copies = %v, want the operator's copy and a new private copy", copies)
	}
	var second string
	for _, copy := range copies {
		if copy != first {
			second = copy
		}
	}
	if second == "" {
		t.Fatalf("no new saved copy: %v", copies)
	}
	if got, err := os.ReadFile(second); err != nil || string(got) != body {
		t.Fatalf("new saved copy = %q, %v; want %q", got, err, body)
	}
	leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
	if !removedListsPath(leftovers, first) || !removedListsPath(leftovers, second) {
		t.Fatalf("leftovers %+v omit one of the saved copies", leftovers)
	}
}
