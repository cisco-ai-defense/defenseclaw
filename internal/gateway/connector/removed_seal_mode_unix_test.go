//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: T8 smoke review loop round 3. A stub the agent cannot run or
// load was taken as done because only its bytes were checked. Delete with
// removed.go.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The stub's mode drifted: an OpenHands hook that is not executable fails to
// start, and OpenHands lets the call through; a stub other accounts may
// change can be made to allow. VerifyClean fails and the leftovers say so,
// and the teardown puts the mode right: a stub with one name is replaced,
// one with more names gets the mode through the file, so every name has it.
// A mode that still runs and loads it, and that only its owner may change,
// is left as it is. A stub that cannot be read at all fails the teardown.
func TestRemovedTeardownPutsRightAStubTheAgentCannotRunOrLoad(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		modes := []os.FileMode{0o620, 0o602, 0o666, 0o777}
		fine := os.FileMode(0o644)
		if c.name == removedOpenHandsID {
			modes = append(modes, 0o400, 0o600, 0o644, 0o720)
			fine = 0o755
		}
		for _, mode := range modes {
			for _, linked := range []bool{false, true} {
				name := c.name + "/" + mode.String()
				if linked {
					name += "/hard-linked"
				}
				t.Run(name, func(t *testing.T) {
					h := newRemovedHost(t)
					h.stage(t, c)
					conn, _ := RetiredConnector(c.name)
					if err := conn.Teardown(context.Background(), h.opts); err != nil {
						t.Fatal(err)
					}
					other := filepath.Join(h.dataDir, "hooks", "copy-of-"+c.script)
					if linked {
						if err := os.Link(h.script(c), other); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Chmod(h.script(c), mode); err != nil {
						t.Fatal(err)
					}
					err := conn.VerifyClean(h.opts)
					if err == nil || !strings.Contains(err.Error(), "holds the stub, but its mode is") {
						t.Fatalf("VerifyClean with the stub at mode %v = %v, want it incomplete", mode, err)
					}
					found := false
					for _, left := range c.leftovers(h.opts) {
						found = found || (left.Path == h.script(c) && left.What == RemovedStubUnusableWhat)
					}
					if !found {
						t.Fatalf("leftovers do not name the unusable stub: %+v", c.leftovers(h.opts))
					}
					if err := conn.Teardown(context.Background(), h.opts); err != nil {
						t.Fatal(err)
					}
					h.requireStub(t, c)
					if linked {
						info, err := os.Lstat(other)
						if err != nil || info.Mode().Perm() != c.mode {
							t.Fatalf("the other name of the stub = %v, %v; want mode %v", info, err, c.mode)
						}
					}
					if err := conn.VerifyClean(h.opts); err != nil {
						t.Fatalf("VerifyClean after the teardown: %v", err)
					}
				})
			}
		}
		t.Run(c.name+"/a mode that still works", func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			conn, _ := RetiredConnector(c.name)
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.script(c), fine); err != nil {
				t.Fatal(err)
			}
			if err := conn.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean with the stub at mode %v: %v", fine, err)
			}
		})
		t.Run(c.name+"/unreadable", func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a file of mode 0")
			}
			h := newRemovedHost(t)
			h.stage(t, c)
			conn, _ := RetiredConnector(c.name)
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.script(c), 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(h.script(c), 0o600) })
			if err := conn.Teardown(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), h.script(c)) {
				t.Fatalf("Teardown with an unreadable stub = %v, want it to fail naming it", err)
			}
			if err := conn.VerifyClean(h.opts); err == nil {
				t.Fatal("VerifyClean with an unreadable stub passed")
			}
		})
	}
}
