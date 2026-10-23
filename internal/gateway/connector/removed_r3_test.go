// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: review fixes (G-deadcode loop round 3) for the teardown-only
// OpenHands and OmniGent connectors (removed.go). Delete with that file.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// removedOldHookByToken is the part of a 1.0.3 OpenHands hook the finding is
// about: with its token missing it exits 0 (fail mode open) before it reaches
// the gateway; with it, the retired route blocks the call (exit 2 here).
func removedOldHookByToken(token string) string {
	return "#!/bin/sh\n# defenseclaw-managed-hook v6\n" +
		"[ -f '" + token + "' ] || exit 0\n" +
		"exit 2\n"
}

func (h *removedHost) requireTokensKept(t *testing.T, c removedOnlyConnector) {
	t.Helper()
	for _, token := range h.tokens(c) {
		if _, err := os.Lstat(token); err != nil {
			t.Fatalf("token %s was revoked while an old hook may still run: %v", token, err)
		}
	}
}

// requireLeftStep checks the teardown error, VerifyClean and the leftovers
// for a script path teardown has to leave: the step that finishes it by
// hand, the tokens kept and listed behind that step.
func (h *removedHost) requireLeftStep(t *testing.T, c removedOnlyConnector, err error, step string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "To finish: "+step) || !strings.Contains(err.Error(), "its tokens were kept") {
		t.Fatalf("Teardown = %v, want the step %q and the tokens kept", err, step)
	}
	h.requireTokensKept(t, c)
	if err := c.VerifyClean(h.opts); err == nil || !strings.Contains(err.Error(), "To finish: "+step) {
		t.Fatalf("VerifyClean = %v, want it to fail with the step %q", err, step)
	}
	leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
	listed := false
	for _, item := range leftovers {
		if item.Path == h.script(c) && item.Step == step && strings.Contains(item.What, "tokens") {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("leftovers %+v do not list %s with the step %q", leftovers, h.script(c), step)
	}
	for _, token := range h.tokens(c) {
		found := false
		for _, item := range leftovers {
			if item.Path == token && item.Step == "follow the step for "+h.script(c)+" first" {
				found = true
			}
		}
		if !found {
			t.Fatalf("leftovers %+v do not list the kept token %s behind the script's step", leftovers, token)
		}
	}
}

// Finding 1 (P1): teardown left a script it could not prove it wrote (a
// link, a marker below the head, a file too large, a folder, no marker) and
// still revoked the tokens, so an old hook there exited 0 (fail mode open)
// before it reached the retired route that blocks. Now the tokens stay while
// anything but the stub is at the path, the teardown and VerifyClean fail
// with the manual step on every run, and once the path is cleared the
// teardown revokes them.
func TestRemovedTeardownKeepsTheTokensWhileAnOldHookMayRun(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		variants := []struct {
			name  string
			plant func(t *testing.T, h *removedHost) string // returns the old hook to run, "" for none
		}{
			{"a symlink in the hooks folder to an old hook", func(t *testing.T, h *removedHost) string {
				target := filepath.Join(h.dataDir, "hooks", "old-"+c.script)
				writeRemovedFile(t, target, removedOldHookByToken(h.tokens(c)[0]), 0o700)
				if err := os.Remove(h.script(c)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, h.script(c)); err != nil {
					t.Skipf("symlink: %v", err)
				}
				return h.script(c)
			}},
			{"an old hook with its marker below line three", func(t *testing.T, h *removedHost) string {
				writeRemovedFile(t, h.script(c), "#!/bin/sh\n#\n#\n"+strings.TrimPrefix(removedOldHookByToken(h.tokens(c)[0]), "#!/bin/sh\n"), 0o700)
				return h.script(c)
			}},
			{"a file too large to check", func(t *testing.T, h *removedHost) string {
				writeRemovedFile(t, h.script(c), c.marker+"6\n"+strings.Repeat("#\n", removedScriptReadLimit), 0o700)
				return ""
			}},
			{"a file without the marker", func(t *testing.T, h *removedHost) string {
				writeRemovedFile(t, h.script(c), "#!/bin/sh\nexit 0\n", 0o700)
				return ""
			}},
			{"a folder", func(t *testing.T, h *removedHost) string {
				if err := os.Remove(h.script(c)); err != nil {
					t.Fatal(err)
				}
				writeRemovedFile(t, filepath.Join(h.script(c), "keep"), "x", 0o600)
				return ""
			}},
		}
		for _, v := range variants {
			t.Run(c.name+"/"+v.name, func(t *testing.T) {
				h := newRemovedHost(t)
				h.stage(t, c)
				hook := v.plant(t, h)
				before := h.snapshot(t)
				for run := 1; run <= 2; run++ {
					err := c.Teardown(context.Background(), h.opts)
					h.requireLeftStep(t, c, err, c.foreignStep())
					requireRemovedSame(t, "teardown that has to leave the script", h.snapshot(t), before)
				}
				if hook != "" && c.name == removedOpenHandsID && runtime.GOOS != "windows" {
					err := exec.Command(hook).Run()
					if exit, _ := err.(*exec.ExitError); exit == nil || exit.ExitCode() != 2 {
						t.Fatalf("the old hook ran with %v; want exit 2 (its token is kept, so it reaches the route that blocks)", err)
					}
				}
				// The manual step done, the teardown finishes.
				if err := os.RemoveAll(h.script(c)); err != nil {
					t.Fatal(err)
				}
				if err := c.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("Teardown after the manual step: %v", err)
				}
				h.requireRevoked(t, c)
				if err := c.VerifyClean(h.opts); err != nil {
					t.Fatalf("VerifyClean after the manual step: %v", err)
				}
			})
		}
	}
}
