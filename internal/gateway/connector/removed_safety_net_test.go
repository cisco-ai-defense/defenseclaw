// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: the safety net for the teardown-only OpenHands and OmniGent
// connectors (removed.go): a hard-linked script is left unchanged for safe
// manual recovery, with tokens that still reach the retired deny route.

import (
	"context"
	"errors"
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

// Both removed connectors refuse hard-linked marked scripts on every OS.
func TestRemovedTeardownRefusesHardLinkedScripts(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		olds := []struct{ name, body string }{
			{"the 1.0.3 script", map[string]string{removedOpenHandsID: removedOpenHands103Script, removedOmnigentID: removedOmnigent103Module}[c.name]},
			{"a 1.0.3 script longer than the stub", removedLongOld(c)},
		}
		if c.name == removedOpenHandsID {
			olds = append(olds, struct{ name, body string }{"a stub that exits 0", disabledHookTombstone(c.label)})
		}
		for _, old := range olds {
			t.Run(c.name+"/"+old.name, func(t *testing.T) {
				h := newRemovedHost(t)
				h.stage(t, c)
				writeRemovedFile(t, h.script(c), old.body, c.mode)
				h.recordWritten(t, c)
				links := h.removedHardLinks(t, c)
				first, err := os.Stat(h.script(c))
				if err != nil {
					t.Fatal(err)
				}
				skip := append(append([]string{h.script(c)}, links...), h.tokens(c)...)
				if c.name == removedOpenHandsID {
					skip = append(skip, c.editedCopyPath(h.dataDir, []byte(old.body)))
				}
				before := h.snapshot(t, skip...)
				err = c.Teardown(context.Background(), h.opts)
				h.requireLeftStep(t, c, err, c.hardLinkStep(h.script(c)))
				for _, name := range append([]string{h.script(c)}, links...) {
					if got, readErr := os.ReadFile(name); readErr != nil || string(got) != old.body {
						t.Fatalf("linked script %s = %q, %v; want original bytes", name, got, readErr)
					}
					if info, statErr := os.Stat(name); statErr != nil || !os.SameFile(first, info) {
						t.Fatalf("linked script %s changed identity: %v", name, statErr)
					}
				}
				h.requireTokensKept(t, c)
				if c.name == removedOpenHandsID {
					h.requireEditedSaved(t, c, old.body)
				}
				requireRemovedSame(t, "refused hard-linked script", h.snapshot(t, skip...), before)
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

// removedInPlaceSeams replaces the in-place writes until the returned func
// (or the end of the test) puts them back. writeAt gets the call's number.
func removedInPlaceSeams(t *testing.T, writeAt func(file *os.File, data []byte, offset int64, call int) (int, error), truncate func(*os.File, int64) error) func() {
	t.Helper()
	saveWrite, saveTruncate := removedInPlaceWriteAt, removedInPlaceTruncate
	restore := func() { removedInPlaceWriteAt, removedInPlaceTruncate = saveWrite, saveTruncate }
	t.Cleanup(restore)
	calls := 0
	if writeAt != nil {
		removedInPlaceWriteAt = func(file *os.File, data []byte, offset int64) (int, error) {
			calls++
			return writeAt(file, data, offset, calls)
		}
	}
	if truncate != nil {
		removedInPlaceTruncate = truncate
	}
	return restore
}

// removedWritePart writes the first half of data, then fails (a full disk).
func removedWritePart(file *os.File, data []byte, offset int64) (int, error) {
	n, err := file.WriteAt(data[:len(data)/2], offset)
	if err != nil {
		return n, err
	}
	return n, syscall.ENOSPC
}

// A failed partial in-place write of a single-name hook rolls forward to a
// complete stub without losing the saved old bytes.
func TestRemovedInPlaceWriteFailureWithOneNameRollsForward(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows never writes the old OpenHands shell hook in place")
	}
	c := removedOpenHands
	h := newRemovedHost(t)
	h.stage(t, c)
	old := removedOpenHands103Script
	removedInPlaceSeams(t, func(f *os.File, data []byte, offset int64, call int) (int, error) {
		if call == 1 {
			return removedWritePart(f, data, offset)
		}
		return 0, syscall.EIO
	}, nil)
	if err := c.Teardown(context.Background(), h.opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	h.requireStub(t, c)
	h.requireRevoked(t, c)
	h.requireEditedSaved(t, c, old)
}

// A Python import can run a definition left beyond the deny stub when a
// longer module is overwritten before its old suffix is truncated. Publishing
// a complete staged file avoids that intermediate state; a stopped publish
// keeps a recovery intent and the tokens for the next teardown.
func TestRemovedOmnigentPublishesACompleteStub(t *testing.T) {
	c := removedOmnigent
	t.Run("interrupted publication", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, c)
		old := removedLongOld(c) + "\ndef defenseclaw_policy(event):\n    return {\"result\": \"ALLOW\"}\n"
		writeRemovedFile(t, h.script(c), old, c.mode)
		if len(old) <= len(c.tombstone) {
			t.Fatal("the old module must be longer than the deny stub")
		}
		// Before the fix this was the interruption after the first WriteAt
		// and before Truncate. A CAS publication never reaches this seam.
		removedInPlaceSeams(t, nil, func(*os.File, int64) error {
			panic("interrupted before cutting the old Python suffix")
		})
		var phase atomicTransformPhaseState
		restore := setAtomicTransformPhaseHookForTest(h.script(c), func(at atomicTransformPhase, state atomicTransformPhaseState) error {
			if at == atomicTransformPhaseDetached {
				phase = state
				return errAtomicTransformSimulatedCrash
			}
			return nil
		})
		t.Cleanup(restore)
		var err error
		func() {
			defer func() { _ = recover() }()
			err = c.Teardown(context.Background(), h.opts)
		}()
		if !errors.Is(err, errAtomicTransformSimulatedCrash) || phase.IntentPath == "" {
			body, _ := os.ReadFile(h.script(c))
			t.Fatalf("Teardown = %v, receipt = %q, module has old allow suffix = %v; want recoverable CAS interruption",
				err, phase.IntentPath, strings.Contains(string(body), "return {\"result\": \"ALLOW\"}"))
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
			t.Fatalf("published module = %q, %v; want only the complete deny stub", body, err)
		}
		h.requireRevoked(t, c)
	})
	t.Run("hard-linked module", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, c)
		old := removedLongOld(c)
		writeRemovedFile(t, h.script(c), old, c.mode)
		other := filepath.Join(h.home, "elsewhere", c.script)
		removedLinkOrSkip(t, h.script(c), other)
		err := c.Teardown(context.Background(), h.opts)
		h.requireLeftStep(t, c, err, c.hardLinkStep(h.script(c)))
		for _, name := range []string{h.script(c), other} {
			if body, readErr := os.ReadFile(name); readErr != nil || string(body) != old {
				t.Fatalf("linked module %s = %q, %v; want original bytes", name, body, readErr)
			}
		}
		h.requireTokensKept(t, c)
		if err := c.VerifyClean(h.opts); err == nil {
			t.Fatal("VerifyClean accepted a hard-linked old module")
		}
	})
}
