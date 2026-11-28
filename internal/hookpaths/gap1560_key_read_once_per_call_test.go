// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
//
// The review rows (RV-1560 P3-1, P3-2): a first read that changed the call's
// budgets or causes itself is not kept, a share wait the budget cut short
// among them (GAP-1606 budgetCuts), and a repeat after a cut elsewhere in the
// call reads again; each field of a reading (cwd, home, dialect) keeps its
// own answer; and a call keeps at most maxCallKeyReads answers, past which a
// reading is read every time.
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
		return ActionPrivateKeyReadBoundedIn(Call{}, command, "", home, actionfacts.DialectPOSIX)
	}

	t.Run("a repeat in the call is the first answer", func(t *testing.T) {
		end := HookCall()
		first, _ := read()
		if first {
			t.Fatalf("%q: a key read before the link exists", command)
		}
		testSymlink(t, key, link)
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
		testSymlink(t, key, link)
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
			_, firstCut = ActionPrivateKeyReadBoundedIn(Call{}, wideCommand, "", home, actionfacts.DialectPOSIX)
		})
		if !firstCut.Has(bounded.Paths) || cut != firstCut {
			t.Fatalf("%q: first read cut %v (call %v), want the path cap", wideCommand, firstCut, cut)
		}
		cut = globCutOf(func() {
			_, againCut = ActionPrivateKeyReadBoundedIn(Call{}, wideCommand, "", home, actionfacts.DialectPOSIX)
		})
		if againCut != firstCut || cut != firstCut {
			t.Errorf("%q: the repeat cut %v and added %v to the call, want %v as the first read", wideCommand, againCut, cut, firstCut)
		}
	})

	// shares makes the folders of fixtures network shares of this machine
	// whose probe runs probe, and forgets the folders the walk knows.
	shares := func(t *testing.T, probe func(root string), roots ...string) {
		t.Helper()
		resetPlainFolders(t)
		restore := OverrideNetworkSharesForTest(func(path string) string {
			for _, root := range roots {
				if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
					return root
				}
			}
			return ""
		}, probe)
		t.Cleanup(restore)
	}
	// shareTree is a share folder s with one folder s/a and the link s/a/k
	// to the key when linked, and the command that reads s/*/*.
	shareTree := func(t *testing.T, linked bool) (share, command string) {
		t.Helper()
		share = filepath.Join(linkFreeTempDir(t), "share")
		if err := os.MkdirAll(filepath.Join(share, "a"), 0o700); err != nil {
			t.Fatal(err)
		}
		if linked {
			testSymlink(t, key, filepath.Join(share, "a", "k"))
		}
		return share, "head -n1 " + share + "/*/*"
	}
	kept := func(call *hookCall, command, cwd, home string, dialect actionfacts.Dialect) bool {
		_, ok := call.keyReads[keyReadKey{command: command, cwd: cwd, home: home, dialect: dialect}]
		return ok
	}

	t.Run("a first read that spent the call's share wait is not kept", func(t *testing.T) {
		share, shareCommand := shareTree(t, false)
		// The share answers, after a wait the call pays from its budget.
		shares(t, func(string) { time.Sleep(20 * time.Millisecond) }, share)
		end := HookCall()
		defer end()
		call := currentHookCall()
		before := call.spent()
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, shareCommand, "", home, actionfacts.DialectPOSIX); got {
			t.Fatalf("%q: a key read with no link", shareCommand)
		}
		if call.spent() == before {
			t.Fatalf("%q: the first read left the call's state as it was; the row needs a read that spends the share wait", shareCommand)
		}
		if kept(call, shareCommand, "", home, actionfacts.DialectPOSIX) {
			t.Errorf("%q: the call kept the answer of a first read that changed its state", shareCommand)
		}
		testSymlink(t, key, filepath.Join(share, "a", "k"))
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, shareCommand, "", home, actionfacts.DialectPOSIX); !got {
			t.Errorf("%q: the repeat after a first read that changed the call's state gave its answer; want a fresh read that finds the link", shareCommand)
		}
	})

	t.Run("a first read the budget cut is not kept", func(t *testing.T) {
		share, shareCommand := shareTree(t, true)
		release := make(chan struct{})
		var once sync.Once
		answer := func() { once.Do(func() { close(release) }) }
		t.Cleanup(answer)
		shares(t, func(string) { <-release }, share)
		end := HookCall()
		defer end()
		call := currentHookCall()
		// The shares before it spent the call's budget: the wait for this
		// share is cut short at once, while the share would still answer.
		call.waitLeft = 0
		mark := call.cutMark()
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, shareCommand, "", home, actionfacts.DialectPOSIX); got {
			t.Fatalf("%q: a key read below a share the budget cut off", shareCommand)
		}
		if call.cutMark() == mark {
			t.Fatalf("%q: the first read counted no budget cut; the row needs a read the budget cuts", shareCommand)
		}
		if kept(call, shareCommand, "", home, actionfacts.DialectPOSIX) {
			t.Errorf("%q: the call kept the answer of a first read the budget cut", shareCommand)
		}
		answer()
		shareAnswered(t, share)
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, shareCommand, "", home, actionfacts.DialectPOSIX); !got {
			t.Errorf("%q: the repeat once the share answered gave the cut answer; want a fresh read that finds the link", shareCommand)
		}
	})

	t.Run("a repeat after a budget cut in the call reads again", func(t *testing.T) {
		_ = os.Remove(link)
		share, _ := shareTree(t, false)
		release := make(chan struct{})
		var once sync.Once
		answer := func() { once.Do(func() { close(release) }) }
		t.Cleanup(answer)
		shares(t, func(string) { <-release }, share)
		end := HookCall()
		defer end()
		call := currentHookCall()
		call.waitLeft = 0
		if got, _ := read(); got {
			t.Fatalf("%q: a key read with no link", command)
		}
		if !kept(call, command, "", home, actionfacts.DialectPOSIX) {
			t.Fatalf("%q: the call kept no answer of a first read that changed nothing; the row needs a kept answer", command)
		}
		// Another reading of the call meets the share the budget cuts off.
		mark := call.cutMark()
		if _, err := pathStat(filepath.Join(share, "a")); err == nil {
			t.Fatal("a stat below a share the budget cut off answered")
		}
		if call.cutMark() == mark {
			t.Fatal("the stat below the share counted no budget cut")
		}
		testSymlink(t, key, link)
		t.Cleanup(func() { _ = os.Remove(link) })
		if got, _ := read(); !got {
			t.Errorf("%q: the repeat after a budget cut in the call gave the first answer; want a fresh read that finds the link", command)
		}
	})

	t.Run("each field of a reading keeps its own answer", func(t *testing.T) {
		_ = os.Remove(link)
		testSymlink(t, key, link)
		t.Cleanup(func() { _ = os.Remove(link) })
		end := HookCall()
		defer end()
		// cwd: $PWD/*/* below a folder with no key link, then below dir.
		folder := "head -n1 $PWD/*/*"
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, folder, t.TempDir(), home, actionfacts.DialectPOSIX); got {
			t.Fatalf("%q in a folder with no link: a key read", folder)
		}
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, folder, dir, home, actionfacts.DialectPOSIX); !got {
			t.Errorf("%q in %s: no key read; the answer of another folder was given", folder, dir)
		}
		// home: the same link, in a home with no key, then in the key's.
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, command, "", t.TempDir(), actionfacts.DialectPOSIX); got {
			t.Fatalf("%q in a home with no key: a key read", command)
		}
		if got, _ := read(); !got {
			t.Errorf("%q: no key read; the answer of another home was given", command)
		}
		// dialect: POSIX reads the backslashes as escapes, PowerShell as
		// separators of the key's path.
		backslashed := "cat " + strings.ReplaceAll(key, "/", `\`) + " | head"
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, backslashed, "", home, actionfacts.DialectPOSIX); got {
			t.Fatalf("%q in POSIX: a key read", backslashed)
		}
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, backslashed, "", home, actionfacts.DialectPowerShell); !got {
			t.Errorf("%q in PowerShell: no key read; the POSIX answer was given", backslashed)
		}
	})

	t.Run("a call keeps at most maxCallKeyReads answers", func(t *testing.T) {
		_ = os.Remove(link)
		testSymlink(t, key, link)
		t.Cleanup(func() { _ = os.Remove(link) })
		absolute := "head -n1 " + dir + "/*/*"
		folder := func(i int) string { return fmt.Sprintf("/fx1560/%d", i) }
		const readings = maxCallKeyReads + 44
		end := HookCall()
		defer end()
		call := currentHookCall()
		for i := range readings {
			if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, absolute, folder(i), home, actionfacts.DialectPOSIX); !got {
				t.Fatalf("%q in %s (reading %d): no key read", absolute, folder(i), i+1)
			}
		}
		if len(call.keyReads) != maxCallKeyReads {
			t.Errorf("after %d readings the call keeps %d answers, want %d", readings, len(call.keyReads), maxCallKeyReads)
		}
		_ = os.Remove(link)
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, absolute, folder(readings-1), home, actionfacts.DialectPOSIX); got {
			t.Errorf("%q in %s: a reading past the cap gave its first answer; want a fresh read (the link is gone)", absolute, folder(readings-1))
		}
		if got, _ := ActionPrivateKeyReadBoundedIn(Call{}, absolute, folder(0), home, actionfacts.DialectPOSIX); !got {
			t.Errorf("%q in %s: a kept reading was read again", absolute, folder(0))
		}
		if len(call.keyReads) != maxCallKeyReads {
			t.Errorf("the call keeps %d answers after the readings past the cap, want %d", len(call.keyReads), maxCallKeyReads)
		}
	})
}
