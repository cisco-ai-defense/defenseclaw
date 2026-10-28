// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A replacement after the old module was read belongs to the operator. The
// fallback publication must neither consume it nor revoke tokens while it
// could still be the module the agent loads.
func TestRemovedTeardownKeepsAReplacementInstalledDuringTeardown(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		for _, phase := range []string{"before second read", "before publication"} {
			for _, replacementKind := range []string{"foreign", "marked"} {
				t.Run(c.name+"/"+phase+"/"+replacementKind, func(t *testing.T) {
					h := newRemovedHost(t)
					h.stage(t, c)
					old := removedOmnigentEditedModule
					if c.name == removedOpenHandsID {
						old = removedOpenHands103Script + "# operator edit\n"
					}
					writeRemovedFile(t, h.script(c), old, c.mode)
					foreign := "# operator-owned replacement, no DefenseClaw marker\nkeep these bytes\n"
					if replacementKind == "marked" {
						foreign = old + "# a later operator replacement\n"
					}
					replacement := filepath.Join(h.dataDir, "hooks", "operator-replacement")
					writeRemovedFile(t, replacement, foreign, c.mode)
					installed := false
					install := func() {
						if installed {
							return
						}
						if err := os.Rename(replacement, h.script(c)); err != nil {
							t.Fatal(err)
						}
						installed = true
					}
					if phase == "before second read" {
						// The replacement lands while the first bytes are saved.
						write := removedKeepEditedWrite
						t.Cleanup(func() { removedKeepEditedWrite = write })
						removedKeepEditedWrite = func(path string, data []byte, mode os.FileMode) error {
							if err := write(path, data, mode); err != nil {
								return err
							}
							install()
							return nil
						}
					} else {
						restore := setAtomicTransformBeforeCommitHookForTest(h.script(c), func(int) { install() })
						t.Cleanup(restore)
					}
					err := c.Teardown(context.Background(), h.opts)
					if !installed {
						t.Fatal("the replacement was never installed")
					}
					if err == nil || !strings.Contains(err.Error(), "its tokens were kept") {
						t.Fatalf("Teardown = %v, want a refusal with tokens kept", err)
					}
					if strings.Contains(err.Error(), "old hook reaches") || strings.Contains(err.Error(), "stub that blocks every call, but its copy") {
						t.Fatalf("Teardown falsely describes the replaced path: %v", err)
					}
					if got, readErr := os.ReadFile(h.script(c)); readErr != nil || string(got) != foreign {
						t.Fatalf("operator replacement = %q, %v; want exact bytes", got, readErr)
					}
					h.requireTokensKept(t, c)
					h.requireEditedSaved(t, c, old)
					if verifyErr := c.VerifyClean(h.opts); verifyErr == nil {
						t.Fatal("VerifyClean accepted the replacement module")
					}
				})
			}
		}
	}
}

// The script goes away while its first bytes are saved: nothing is put at
// the path and the tokens stay until a later run reads it afresh.
func TestRemovedTeardownKeepsAnAbsentPathAfterTheFirstRead(t *testing.T) {
	h := newRemovedHost(t)
	c := removedOpenHands
	h.stage(t, c)
	old := removedOpenHands103Script + "# operator edit\n"
	writeRemovedFile(t, h.script(c), old, c.mode)
	write := removedKeepEditedWrite
	t.Cleanup(func() { removedKeepEditedWrite = write })
	removedKeepEditedWrite = func(path string, data []byte, mode os.FileMode) error {
		if err := write(path, data, mode); err != nil {
			return err
		}
		if err := os.Remove(h.script(c)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return nil
	}
	err := c.Teardown(context.Background(), h.opts)
	if err == nil || !strings.Contains(err.Error(), "its tokens were kept") {
		t.Fatalf("Teardown = %v, want a refusal with tokens kept", err)
	}
	if _, statErr := os.Lstat(h.script(c)); !os.IsNotExist(statErr) {
		t.Fatalf("the absent module was recreated: %v", statErr)
	}
	h.requireTokensKept(t, c)
	h.requireEditedSaved(t, c, old)
}

// Saving the first marked hook comes before the second read. A second
// marked file can arrive at that path meanwhile; it and its other names must
// not be replaced by this teardown.
func TestRemovedTeardownRefusesAnEarlyMarkedReplacement(t *testing.T) {
	for _, linked := range []bool{false, true} {
		name := "one name"
		if linked {
			name = "hard-linked replacement"
		}
		t.Run(name, func(t *testing.T) {
			c := removedOpenHands
			h := newRemovedHost(t)
			h.stage(t, c)
			old := removedOpenHands103Script + "# prior edit\n"
			writeRemovedFile(t, h.script(c), old, c.mode)
			replacementBody := removedOpenHands103Script + "# newer operator edit\n"
			replacement := filepath.Join(h.dataDir, "hooks", "newer-hook")
			writeRemovedFile(t, replacement, replacementBody, c.mode)
			var other string
			if linked {
				other = filepath.Join(h.home, "elsewhere", c.script)
				removedLinkOrSkip(t, replacement, other)
			}
			write := removedKeepEditedWrite
			t.Cleanup(func() { removedKeepEditedWrite = write })
			installed := false
			removedKeepEditedWrite = func(path string, data []byte, mode os.FileMode) error {
				if err := write(path, data, mode); err != nil {
					return err
				}
				if !installed {
					if err := os.Rename(replacement, h.script(c)); err != nil {
						t.Fatal(err)
					}
					installed = true
				}
				return nil
			}
			err := c.Teardown(context.Background(), h.opts)
			if !installed || err == nil || !strings.Contains(err.Error(), "its tokens were kept") {
				t.Fatalf("Teardown = %v, installed = %v; want refusal after the swap", err, installed)
			}
			for _, name := range []string{h.script(c), other} {
				if name == "" {
					continue
				}
				if got, readErr := os.ReadFile(name); readErr != nil || string(got) != replacementBody {
					t.Fatalf("replacement %s = %q, %v; want exact later bytes", name, got, readErr)
				}
			}
			h.requireTokensKept(t, c)
			h.requireEditedSaved(t, c, old)
			if err := c.VerifyClean(h.opts); err == nil {
				t.Fatal("VerifyClean accepted the newer marked hook")
			}
		})
	}
}
