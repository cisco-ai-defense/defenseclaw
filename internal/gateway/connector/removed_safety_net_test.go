// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: the safety net for the teardown-only OpenHands and OmniGent
// connectors (removed.go): the stub is published over the script path in
// one compare-and-swap and never written into the old file, and a script with more
// than one name (a hard link) is left whole, with its tokens. Delete with
// removed.go.

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// removedLongOld is an old script of c that is longer than the stub, with
// DefenseClaw's marker: the 1.0.3 scripts are several KiB.
func removedLongOld(c removedOnlyConnector) string {
	if c.name == removedOmnigentID {
		return removedOmnigent103Module + strings.Repeat("# the 1.0.3 module goes on\n", 120)
	}
	return removedOpenHands103Script + strings.Repeat("# the 1.0.3 hook goes on\n", 120)
}

// removedOldScripts are the old scripts of c the teardown replaces: the
// 1.0.3 one, a longer one, a shorter one than the stub, and (OpenHands) the
// stub an older teardown left that exits 0.
func removedOldScripts(c removedOnlyConnector) []struct{ name, body string } {
	olds := []struct{ name, body string }{
		{"the 1.0.3 script", map[string]string{removedOpenHandsID: removedOpenHands103Script, removedOmnigentID: removedOmnigent103Module}[c.name]},
		{"a 1.0.3 script longer than the stub", removedLongOld(c)},
		{"a script shorter than the stub", c.marker + "6\n" + "exit 0\n"},
	}
	if c.name == removedOpenHandsID {
		olds = append(olds, struct{ name, body string }{"a stub that exits 0", disabledHookTombstone(c.label)})
	}
	return olds
}

// requireRemovedHookBlocks runs an OpenHands hook script and requires the
// block: exit 2 and the deny reason.
func requireRemovedHookBlocks(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command(path)
	cmd.Stdin = strings.NewReader(`{"event":"pre_tool_use","tool_name":"bash"}`)
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), removedOpenHandsDenyReason) {
		t.Fatalf("%s ran with %v, stdout %q; want exit 2 with the deny reason", path, err, out)
	}
}

// removedHardLinks gives the script two more names, one outside the hooks
// folder; it skips the test where hard links cannot be made.
func (h *removedHost) removedHardLinks(t *testing.T, c removedOnlyConnector) []string {
	t.Helper()
	links := []string{
		filepath.Join(h.home, "elsewhere", c.script),
		filepath.Join(h.dataDir, "hooks", "copy-"+c.script),
	}
	for _, link := range links {
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(h.script(c), link); err != nil {
			t.Skipf("hard links unsupported here: %v", err)
		}
	}
	return links
}

// removedHoldOld opens the old script file, so its bytes can be read after
// the teardown whatever names it has left; an open handle adds no name. On
// Windows it returns nil: a handle there may keep the rename from
// replacing the file.
func removedHoldOld(t *testing.T, path string) *os.File {
	t.Helper()
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

// requireRemovedOldWhole checks that the old file still holds exactly old:
// nothing ever wrote into it.
func requireRemovedOldWhole(t *testing.T, file *os.File, old string) {
	t.Helper()
	if file == nil {
		return
	}
	got := make([]byte, len(old)+len(removedOpenHandsTombstone)+1)
	n, err := file.ReadAt(got, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if string(got[:n]) != old {
		t.Fatalf("the old script file was written into: it holds %q, want its old bytes %q", got[:n], old)
	}
}

// requireRemovedNamesWhole checks that every name still names the old file
// and holds its old bytes.
func requireRemovedNamesWhole(t *testing.T, first os.FileInfo, old string, names []string) {
	t.Helper()
	for _, name := range names {
		info, err := os.Stat(name)
		if err != nil || !os.SameFile(first, info) {
			t.Fatalf("%s is not the old file any more (%v)", name, err)
		}
		if data, err := os.ReadFile(name); err != nil || string(data) != old {
			t.Fatalf("%s = %q, %v; want the old bytes, whole", name, data, err)
		}
	}
}

// Review fix (Q-windows loop round 2): the teardown wrote the stub into
// the live old script before it renamed a copy over the path. A short
// write whose old bytes could not be put back left part of the stub over
// the old script under every name: with a short old script, only the
// stub's first comment lines, a script that exits 0 (an allow) without
// reaching the gateway, while a hard-linked file kept its tokens. Now the
// old file is never written. A script with one name gets the stub renamed
// over its path and its old file keeps its bytes. A script with more names
// is left whole under every name with its tokens; the teardown, VerifyClean
// and the leftovers give the step, a second run changes nothing, and once
// the other names are gone the next run renames the stub and revokes the
// tokens. The same holds on Windows, which never wrote into the file.
func TestRemovedTeardownNeverWritesIntoTheOldScript(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		for _, old := range removedOldScripts(c) {
			t.Run(c.name+"/one name/"+old.name, func(t *testing.T) {
				h := newRemovedHost(t)
				h.stage(t, c)
				writeRemovedFile(t, h.script(c), old.body, c.mode)
				h.recordWritten(t, c)
				first, err := os.Stat(h.script(c))
				if err != nil {
					t.Fatal(err)
				}
				held := removedHoldOld(t, h.script(c))
				if err := c.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("Teardown: %v", err)
				}
				requireRemovedOldWhole(t, held, old.body)
				h.requireStub(t, c)
				h.requireRevoked(t, c)
				if err := c.VerifyClean(h.opts); err != nil {
					t.Fatalf("VerifyClean: %v", err)
				}
				if info, err := os.Stat(h.script(c)); err != nil || os.SameFile(first, info) {
					t.Fatalf("the path still names the old file (%v); want the stub renamed over it", err)
				}
				if c.name == removedOpenHandsID && runtime.GOOS != "windows" {
					requireRemovedHookBlocks(t, h.script(c))
				}
			})
			t.Run(c.name+"/hard links/"+old.name, func(t *testing.T) {
				h := newRemovedHost(t)
				h.stage(t, c)
				writeRemovedFile(t, h.script(c), old.body, c.mode)
				h.recordWritten(t, c)
				links := h.removedHardLinks(t, c)
				first, err := os.Stat(h.script(c))
				if err != nil {
					t.Fatal(err)
				}
				held := removedHoldOld(t, h.script(c))
				names := append([]string{h.script(c)}, links...)
				// OpenHands has no post-setup hash, so its marked hook is
				// saved before anything else; that copy is the only change.
				var saved []string
				if c.name == removedOpenHandsID {
					saved = append(saved, c.editedCopyPath(h.dataDir, []byte(old.body)))
				}
				before := h.snapshot(t, saved...)
				err = c.Teardown(context.Background(), h.opts)
				h.requireLeftStep(t, c, err, c.hardLinkStep(h.script(c)))
				requireRemovedOldWhole(t, held, old.body)
				requireRemovedNamesWhole(t, first, old.body, names)
				requireRemovedSame(t, "teardown of a hard-linked script", h.snapshot(t, saved...), before)
				if c.name == removedOpenHandsID {
					h.requireEditedSaved(t, c, old.body)
				}
				again := h.snapshot(t)
				if err := c.Teardown(context.Background(), h.opts); err == nil {
					t.Fatal("a second teardown of the hard-linked script passed")
				}
				requireRemovedSame(t, "a second teardown of a hard-linked script", h.snapshot(t), again)
				// The step: delete the other names, then run the teardown.
				for _, link := range links {
					if err := os.Remove(link); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("the teardown after the step: %v", err)
				}
				requireRemovedOldWhole(t, held, old.body)
				h.requireStub(t, c)
				h.requireRevoked(t, c)
			})
		}
		t.Run(c.name+"/a hard-linked file without the marker", func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			writeRemovedFile(t, h.script(c), "#!/bin/sh\necho my own hook\n", c.mode)
			h.removedHardLinks(t, c)
			before := h.snapshot(t)
			err := c.Teardown(context.Background(), h.opts)
			h.requireLeftStep(t, c, err, c.foreignStep())
			requireRemovedSame(t, "teardown of a hard-linked file DefenseClaw did not write", h.snapshot(t), before)
		})
		t.Run(c.name+"/a hard-linked stub", func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			writeRemovedFile(t, h.script(c), c.tombstone, c.mode)
			links := h.removedHardLinks(t, c)
			if err := c.Teardown(context.Background(), h.opts); err != nil {
				t.Fatalf("Teardown of a hard-linked stub: %v", err)
			}
			h.requireRevoked(t, c)
			for _, path := range append(links, h.script(c)) {
				if data, err := os.ReadFile(path); err != nil || string(data) != c.tombstone {
					t.Fatalf("%s = %q, %v; want the stub", path, data, err)
				}
			}
		})
	}
}

// Review fix (Q-windows loop round 2), the failure half: a rename of the
// stub that fails (a full disk, an I/O error) leaves the old script whole
// at the path, under the same file, with its tokens; the teardown and
// VerifyClean fail, and the next run renames the stub and revokes them.
func TestRemovedStubRenameThatFailsLeavesTheOldScriptWhole(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		for _, old := range removedOldScripts(c) {
			for _, cause := range []error{syscall.ENOSPC, syscall.EIO} {
				t.Run(c.name+"/"+old.name+"/"+cause.Error(), func(t *testing.T) {
					h := newRemovedHost(t)
					h.stage(t, c)
					writeRemovedFile(t, h.script(c), old.body, c.mode)
					h.recordWritten(t, c)
					first, err := os.Stat(h.script(c))
					if err != nil {
						t.Fatal(err)
					}
					held := removedHoldOld(t, h.script(c))
					save := removedStubPublish
					t.Cleanup(func() { removedStubPublish = save })
					removedStubPublish = func(string, string, os.FileMode, func([]byte, bool) (atomicTransformResult, error)) error {
						return cause
					}
					err = c.Teardown(context.Background(), h.opts)
					if err == nil || !errors.Is(err, cause) || !strings.Contains(err.Error(), "its tokens were kept") {
						t.Fatalf("Teardown = %v, want %v and the tokens kept", err, cause)
					}
					requireRemovedOldWhole(t, held, old.body)
					requireRemovedNamesWhole(t, first, old.body, []string{h.script(c)})
					h.requireTokensKept(t, c)
					if err := c.VerifyClean(h.opts); err == nil {
						t.Fatal("VerifyClean passed with the old script at the path")
					}
					removedStubPublish = save
					if err := c.Teardown(context.Background(), h.opts); err != nil {
						t.Fatalf("the next run: %v", err)
					}
					requireRemovedOldWhole(t, held, old.body)
					h.requireStub(t, c)
					h.requireRevoked(t, c)
				})
			}
		}
	}
}

// A Python import can run a definition left beyond the deny stub when a
// longer module is overwritten before its old suffix is truncated. Publishing
// a complete staged file avoids that intermediate state; a stopped publish
// keeps a recovery intent and the tokens for the next teardown. The same
// holds for the OpenHands script, which is never written in place either.
func TestRemovedTeardownPublishesACompleteStub(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name+"/interrupted publication", func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			old := removedLongOld(c)
			if c.name == removedOmnigentID {
				old += "\ndef defenseclaw_policy(event):\n    return {\"result\": \"ALLOW\"}\n"
			}
			writeRemovedFile(t, h.script(c), old, c.mode)
			if len(old) <= len(c.tombstone) {
				t.Fatal("the old script must be longer than the deny stub")
			}
			var phase atomicTransformPhaseState
			restore := setAtomicTransformPhaseHookForTest(h.script(c), func(at atomicTransformPhase, state atomicTransformPhaseState) error {
				if at == atomicTransformPhaseDetached {
					phase = state
					return errAtomicTransformSimulatedCrash
				}
				return nil
			})
			t.Cleanup(restore)
			err := c.Teardown(context.Background(), h.opts)
			if !errors.Is(err, errAtomicTransformSimulatedCrash) || phase.IntentPath == "" {
				body, _ := os.ReadFile(h.script(c))
				t.Fatalf("Teardown = %v, receipt = %q, script = %q; want a recoverable CAS interruption", err, phase.IntentPath, body)
			}
			h.requireTokensKept(t, c)
			if err := c.VerifyClean(h.opts); err == nil {
				t.Fatal("VerifyClean accepted an interrupted publication")
			}
			restore()
			if err := c.Teardown(context.Background(), h.opts); err != nil {
				t.Fatalf("recover interrupted publication: %v", err)
			}
			if body, err := os.ReadFile(h.script(c)); err != nil || string(body) != c.tombstone {
				t.Fatalf("published script = %q, %v; want only the complete deny stub", body, err)
			}
			h.requireRevoked(t, c)
		})
	}
}
