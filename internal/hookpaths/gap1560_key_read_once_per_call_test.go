// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The private-key reader reads each reading once per hook call
// (rel-1-0-10:GAP-1560). The gateway judges head -n1 $(pwd)/w/*/* twice, as
// the call and as its statement (pwd is the other one), and each judgment
// expanded the same capped pattern: twice the walk of $PWD/w/*/*. Within one
// call a repeat is answered as the first read answered (the file system of
// one decision is one file system), with the same caps added to the call; a
// new call, or a call whose budgets or causes changed since, reads again.
func TestGAP1560PrivateKeyReadOncePerHookCall(t *testing.T) {
	home := t.TempDir()
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "w")
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "a", "k")
	// A call with no folder reads $(pwd)/ as /, so the head spells dir.
	command := "head -n1 $(pwd)" + dir + "/*/*"
	read := func() (bool, bounded.CapSet) {
		return ActionPrivateKeyReadBounded(command, "", home, actionfacts.DialectPOSIX)
	}

	t.Run("a repeat in the call is the first answer", func(t *testing.T) {
		end := HookCall()
		first, _ := read()
		if first {
			t.Fatalf("%q: a key read before the link exists", command)
		}
		if err := os.Symlink(key, link); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(link) })
		if again, _ := read(); again != first {
			t.Errorf("%q: the repeat in the call read %v, want the first answer %v (read once per call)", command, again, first)
		}
		end()
		end = HookCall()
		defer end()
		if got, _ := read(); !got {
			t.Errorf("%q: a new call does not read the link %s to the key", command, link)
		}
	})

	t.Run("a call that spent its budget since reads again", func(t *testing.T) {
		_ = os.Remove(link)
		end := HookCall()
		defer end()
		if got, _ := read(); got {
			t.Fatalf("%q: a key read with no link", command)
		}
		if err := os.Symlink(key, link); err != nil {
			t.Fatal(err)
		}
		call := currentHookCall()
		call.bodyUnread = true
		if got, _ := read(); !got {
			t.Errorf("%q: the call's causes changed after the first read; want a fresh read that finds the link", command)
		}
	})

	t.Run("a repeat adds the first read's caps to the call", func(t *testing.T) {
		wide := filepath.Join(t.TempDir(), "wide")
		for folder := range 2 {
			sub := filepath.Join(wide, fmt.Sprintf("d%d", folder))
			if err := os.MkdirAll(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			for file := range 2100 {
				if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%04d", file)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		wideCommand := "grep -l k $(pwd)" + wide + "/*/*"
		end := HookCall()
		defer end()
		var firstCut, againCut bounded.CapSet
		cut := globCutOf(func() {
			_, firstCut = ActionPrivateKeyReadBounded(wideCommand, "", home, actionfacts.DialectPOSIX)
		})
		if !firstCut.Has(bounded.Paths) || cut != firstCut {
			t.Fatalf("%q: first read cut %v (call %v), want the path cap", wideCommand, firstCut, cut)
		}
		cut = globCutOf(func() {
			_, againCut = ActionPrivateKeyReadBounded(wideCommand, "", home, actionfacts.DialectPOSIX)
		})
		if againCut != firstCut || cut != firstCut {
			t.Errorf("%q: the repeat cut %v and added %v to the call, want %v as the first read", wideCommand, againCut, cut, firstCut)
		}
	})
}
