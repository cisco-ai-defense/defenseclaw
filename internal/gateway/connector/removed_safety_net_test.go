// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: the safety net for the teardown-only OpenHands and OmniGent
// connectors (removed.go, G-deadcode review loop round 1): the stub is
// written into the script file itself, so every name of it (a hard link)
// blocks, and a copy is renamed over the path. Delete with removed.go.

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

// requireStubUnderEveryName checks the hard links still name the old file
// and hold the stub (with the tail for a longer old script), which blocks.
func (h *removedHost) requireStubUnderEveryName(t *testing.T, c removedOnlyConnector, first os.FileInfo, links []string) {
	t.Helper()
	for _, link := range links {
		info, err := os.Stat(link)
		if err != nil || !os.SameFile(first, info) {
			t.Fatalf("%s is not the old file any more (%v)", link, err)
		}
		if info.Mode().Perm() != c.mode {
			t.Fatalf("%s mode %v, want %v", link, info.Mode(), c.mode)
		}
		data, err := os.ReadFile(link)
		if err != nil || c.classifyScript(data) != removedScriptStub {
			t.Fatalf("%s = %q, %v; want the stub", link, data, err)
		}
		if c.name == removedOpenHandsID {
			requireRemovedHookBlocks(t, link)
		}
	}
}

// Safety net, finding 2's class: a marked script with more names (a hard
// link) gets the stub written into the file itself, so every name blocks,
// and the path gets a copy renamed over it. The tokens go, VerifyClean
// passes, nothing else changes, and a second run changes nothing. On
// Windows the stub is only renamed: a hard-linked file keeps its bytes and
// its tokens (so an old module still reaches the route that blocks), with
// the step.
func TestRemovedTeardownWritesTheStubUnderEveryNameOfTheScript(t *testing.T) {
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
				before := h.snapshot(t, skip...)
				err = c.Teardown(context.Background(), h.opts)
				if runtime.GOOS == "windows" {
					h.requireLeftStep(t, c, err, c.hardLinkStep(h.script(c)))
					return
				}
				if err != nil {
					t.Fatalf("Teardown: %v", err)
				}
				h.requireStub(t, c)
				h.requireRevoked(t, c)
				if err := c.VerifyClean(h.opts); err != nil {
					t.Fatalf("VerifyClean: %v", err)
				}
				if info, err := os.Stat(h.script(c)); err != nil || os.SameFile(first, info) {
					t.Fatalf("the path still names the old file (%v); want the copy renamed over it", err)
				}
				h.requireStubUnderEveryName(t, c, first, links)
				if c.name == removedOpenHandsID {
					requireRemovedHookBlocks(t, h.script(c))
				}
				requireRemovedSame(t, "teardown of a hard-linked script", h.snapshot(t, skip...), before)
				again := h.snapshot(t)
				if err := c.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("second Teardown: %v", err)
				}
				requireRemovedSame(t, "a second teardown", h.snapshot(t), again)
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

// Safety net, finding 2: a write of the stub into a hard-linked file that
// fails part way never leaves a name with part of the stub before the old
// script. The old bytes are put back, or every name already begins with the
// whole stub, which blocks. The tokens stay (an old hook reaches the route
// that blocks), the teardown and VerifyClean fail with the step, nothing is
// renamed (so the next start still sees the other names), and the next run
// writes the stub under every name and revokes the tokens.
func TestRemovedInPlaceWriteThatFailsLeavesNoPartScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows the stub is only renamed over the path")
	}
	pass := func(file *os.File, data []byte, offset int64) (int, error) { return file.WriteAt(data, offset) }
	type failure struct {
		name      string
		only      string // a connector name, "" for both
		long      bool
		writeAt   func(file *os.File, data []byte, offset int64, call int) (int, error)
		truncate  func(*os.File, int64) error
		want      string
		keepsOld  bool // every name keeps the old bytes
		stubFirst bool // every name begins with the whole stub
	}
	failures := []failure{
		{name: "the stub's write fails part way", writeAt: func(f *os.File, d []byte, o int64, call int) (int, error) {
			if call == 1 {
				return removedWritePart(f, d, o)
			}
			return pass(f, d, o)
		}, want: "were put back", keepsOld: true},
		{name: "the stub's write fails part way over a longer script", long: true, writeAt: func(f *os.File, d []byte, o int64, call int) (int, error) {
			if call == 1 {
				return removedWritePart(f, d, o)
			}
			return pass(f, d, o)
		}, want: "were put back", keepsOld: true},
		{name: "the stub's write writes nothing", writeAt: func(f *os.File, d []byte, o int64, call int) (int, error) {
			if call == 1 {
				return 0, syscall.ENOSPC
			}
			return pass(f, d, o)
		}, want: "nothing was changed", keepsOld: true},
		{name: "the bytes cannot be put back either", writeAt: func(f *os.File, d []byte, o int64, call int) (int, error) {
			switch call {
			case 1:
				return removedWritePart(f, d, o)
			case 2:
				return 0, syscall.EIO
			}
			return pass(f, d, o)
		}, want: "may hold part of the stub"},
		{name: "the tail after the stub fails", only: removedOpenHandsID, long: true, writeAt: func(f *os.File, d []byte, o int64, call int) (int, error) {
			if call == 2 {
				return removedWritePart(f, d, o)
			}
			return pass(f, d, o)
		}, want: "begins with the whole stub", stubFirst: true},
		{name: "the old tail cannot be cut", long: true, truncate: func(*os.File, int64) error { return syscall.EIO },
			want: "old tail could not be cut", stubFirst: true},
	}
	for _, c := range removedConnectorsUnderTest() {
		for _, f := range failures {
			if f.only != "" && f.only != c.name {
				continue
			}
			t.Run(c.name+"/"+f.name, func(t *testing.T) {
				h := newRemovedHost(t)
				h.stage(t, c)
				old := map[string]string{removedOpenHandsID: removedOpenHands103Script, removedOmnigentID: removedOmnigent103Module}[c.name]
				if f.long {
					old = removedLongOld(c)
				}
				writeRemovedFile(t, h.script(c), old, c.mode)
				h.recordWritten(t, c)
				links := h.removedHardLinks(t, c)
				first, err := os.Stat(h.script(c))
				if err != nil {
					t.Fatal(err)
				}
				names := append([]string{h.script(c)}, links...)
				before := h.snapshot(t, names...)
				restore := removedInPlaceSeams(t, f.writeAt, f.truncate)
				err = c.Teardown(context.Background(), h.opts)
				if err == nil || !strings.Contains(err.Error(), f.want) || !strings.Contains(err.Error(), "To finish: "+c.hardLinkStep(h.script(c))) ||
					!strings.Contains(err.Error(), "its tokens were kept") {
					t.Fatalf("Teardown = %v, want %q, the step and the tokens kept", err, f.want)
				}
				h.requireTokensKept(t, c)
				if err := c.VerifyClean(h.opts); err == nil {
					t.Fatal("VerifyClean passed while the old file may still run")
				}
				requireRemovedSame(t, "a failed write into the file", h.snapshot(t, names...), before)
				for _, name := range names {
					info, err := os.Stat(name)
					if err != nil || !os.SameFile(first, info) {
						t.Fatalf("%s is not the old file any more (%v): nothing may be renamed", name, err)
					}
					data, err := os.ReadFile(name)
					if err != nil {
						t.Fatal(err)
					}
					if f.keepsOld && string(data) != old {
						t.Fatalf("%s = %q; want the old bytes put back", name, data)
					}
					if f.stubFirst {
						if !strings.HasPrefix(string(data), c.tombstone) {
							t.Fatalf("%s = %q; want the whole stub first", name, data)
						}
						if c.name == removedOpenHandsID {
							requireRemovedHookBlocks(t, name)
						}
					}
				}
				restore()
				if err := c.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("the next run: %v", err)
				}
				// The path holds the stub: the renamed copy, or (when only the
				// cut failed) the whole stub with its tail already written.
				if data, err := os.ReadFile(h.script(c)); err != nil || c.classifyScript(data) != removedScriptStub {
					t.Fatalf("%s = %q, %v; want the stub", h.script(c), data, err)
				}
				h.requireRevoked(t, c)
				h.requireStubUnderEveryName(t, c, first, links)
			})
		}
		// A file with one name gets the rename whatever the write into it did.
		t.Run(c.name+"/one name, the bytes cannot be put back", func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			removedInPlaceSeams(t, func(f *os.File, d []byte, o int64, call int) (int, error) {
				if call == 1 {
					return removedWritePart(f, d, o)
				}
				return 0, syscall.EIO
			}, nil)
			if err := c.Teardown(context.Background(), h.opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			h.requireStub(t, c)
			h.requireRevoked(t, c)
		})
	}
}
