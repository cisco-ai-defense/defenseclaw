// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// withHookSessionTestKeys accepts key files the test account made, where
// the gateway and the hook accept only root's.
func withHookSessionTestKeys(t *testing.T) {
	t.Helper()
	restore := enterprisepolicy.OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	t.Cleanup(restore)
}

// hookSessionTestAccount is the account whose key the tests follow.
const hookSessionTestAccount = "1001"

// hookSessionTestKeyID names the test account's one key, or "".
func hookSessionTestKeyID(root string) string {
	key, err := enterprisepolicy.ReadPublishedSessionKey(root, hookSessionTestAccount)
	if err != nil {
		return ""
	}
	return key.ID()
}

// Kill switch (GAP-0352, 1.0.4 guard loop round 1): every lifecycle run
// that changes anything removes the key of the protected session records
// once it holds its lock and before it sets an owner, and the package
// upgrade's ensure too; only a run that finished without an error makes new
// keys, as its last step, while it still holds the lock. Status and verify
// touch neither. A run that fails leaves no key, so every outage allow
// written before it, and since, proves nothing; uninstall leaves none
// either. A key that cannot be shown dead stops every run but uninstall
// before it changes anything; one that is shadowed or marked revoked is a
// warning.
func TestTheLifecycleKillsTheHookSessionKeyFirstAndMakesANewOneLast(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			withHookSessionTestKeys(t)
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			root := h.env.P(h.env.Layout.HookSessionDir)
			// The gateway makes an account's folder when it first answers
			// for it; the lifecycle makes a key for every account folder.
			account, _ := enterprisepolicy.PublishedSessionIdentityDir(root, hookSessionTestAccount)
			if err := os.Mkdir(account, 0o700); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			if hookSessionTestKeyID(root) == "" {
				t.Fatal("a run must make a key for every account folder")
			}
			if dir, _ := enterprisepolicy.PublishedSessionKeyDir(root); dir != h.env.P(h.env.Layout.HookSocketDir) {
				t.Fatalf("the key must be in the hook socket folder, which only root and the gateway can change: %s", dir)
			}
			var events []string
			// locked reports whether a lifecycle run holds the lock.
			locked := func() bool {
				lock, err := h.env.acquireLock(context.Background())
				if err != nil {
					return true
				}
				lock.release()
				return false
			}
			previousRetire, previousCreate, previousLchown := hookSessionKillKeys, hookSessionRotateKeys, h.env.Lchown
			t.Cleanup(func() {
				hookSessionKillKeys, hookSessionRotateKeys, h.env.Lchown = previousRetire, previousCreate, previousLchown
			})
			hookSessionKillKeys = func(path string) error {
				if !locked() {
					t.Error("the key must go only once the run holds its lock")
				}
				events = append(events, "kill")
				return previousRetire(path)
			}
			hookSessionRotateKeys = func(path string, trust enterprisepolicy.PublishedSessionTrust) error {
				if !locked() {
					t.Error("the new key must be made while the run still holds the lock")
				}
				events = append(events, "create")
				return previousCreate(path, trust)
			}
			h.env.Lchown = func(path string, uid, gid int) error {
				// The lifecycle folder, which holds the lock, is made before
				// the lock is taken; it is root's alone.
				if path != h.env.P(h.env.Layout.LifecycleDir) {
					events = append(events, "chown")
				}
				return previousLchown(path, uid, gid)
			}
			for _, opts := range []Options{{Action: ActionEnsure, PayloadDir: h.payload("1.0.1")}, {Action: ActionRepair}, {Action: ActionEnsure}} {
				events = nil
				old := hookSessionTestKeyID(root)
				requireOK(t, h.run(opts))
				if len(events) < 2 || events[0] != "kill" || events[len(events)-1] != "create" {
					t.Fatalf("%s: the key must go first and a new one come last: %v", opts.Action, events)
				}
				if now := hookSessionTestKeyID(root); now == "" || now == old {
					t.Fatalf("%s: the run must end with a new key: %q (was %q)", opts.Action, now, old)
				}
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				events = nil
				old := hookSessionTestKeyID(root)
				h.run(Options{Action: action})
				if len(events) != 0 || hookSessionTestKeyID(root) != old {
					t.Fatalf("%s must touch no key: %v", action, events)
				}
			}
			// A run that fails makes no new key.
			h.healthy = false
			events = nil
			if result := h.run(Options{Action: ActionRepair}); len(result.Errors) == 0 {
				t.Fatal("a repair of an unhealthy gateway must fail")
			}
			if len(events) == 0 || events[0] != "kill" {
				t.Fatalf("a failing run removes the key first too: %v", events)
			}
			for _, event := range events {
				if event == "create" {
					t.Fatalf("a failed run must make no new key: %v", events)
				}
			}
			if hookSessionTestKeyID(root) != "" {
				t.Fatal("a failed run must leave no key")
			}
			h.healthy = true
			requireOK(t, h.run(Options{Action: ActionRepair}))
			if hookSessionTestKeyID(root) == "" {
				t.Fatal("the next repair must make a key")
			}
			// A key that could not be removed but is shadowed or marked
			// revoked is reported, and the run goes on.
			hookSessionKillKeys = func(string) error {
				return errors.New("read-only file system; a revocation mark ends the key")
			}
			result := h.run(Options{Action: ActionRepair})
			found := false
			for _, warning := range result.Warnings {
				found = found || warning.Code == codeHookSessionKey
			}
			if len(result.Errors) != 0 || !found {
				t.Fatalf("a key that is shadowed or marked revoked must be a warning: %+v", result)
			}
			hookSessionKillKeys = previousRetire
			// Uninstall removes the key and makes none.
			events = nil
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			for _, event := range events {
				if event == "create" {
					t.Fatalf("an uninstall must make no key: %v", events)
				}
			}
			if keys, _ := filepath.Glob(filepath.Join(h.env.P(h.env.Layout.HookSocketDir), filepath.Base(root)+".*"+enterprisepolicy.PublishedSessionKeyInfix+"*")); len(keys) != 0 {
				t.Fatalf("an uninstall must leave no key: %v", keys)
			}
		})
	}
}

// Review P1 (1.0.4 guard loop round 1, finding 4): a key the run cannot
// show dead (it can be neither removed, nor shadowed, nor marked revoked,
// or the key folder cannot be listed) stops install, upgrade, repair and
// ensure before they change anything: no owner or mode is put back, nothing
// is deployed, and no key is made. An uninstall goes on with a warning: it
// removes the record folder.
func TestTheLifecycleStopsWhenAKeyCannotBeShownDead(t *testing.T) {
	withHookSessionTestKeys(t)
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	previousKill, previousRotate, previousLchown := hookSessionKillKeys, hookSessionRotateKeys, h.env.Lchown
	t.Cleanup(func() {
		hookSessionKillKeys, hookSessionRotateKeys, h.env.Lchown = previousKill, previousRotate, previousLchown
	})
	hookSessionKillKeys = func(string) error {
		return fmt.Errorf("%w: input/output error", enterprisepolicy.ErrPublishedSessionKeyAlive)
	}
	rotated, chowned := 0, 0
	hookSessionRotateKeys = func(string, enterprisepolicy.PublishedSessionTrust) error { rotated++; return nil }
	h.env.Lchown = func(path string, uid, gid int) error {
		if path != h.env.P(h.env.Layout.LifecycleDir) {
			chowned++
		}
		return previousLchown(path, uid, gid)
	}
	for _, opts := range []Options{{Action: ActionRepair}, {Action: ActionEnsure}, {Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}, {Action: ActionInstall, PayloadDir: h.payload("1.0.0")}} {
		rotated, chowned = 0, 0
		result := h.run(opts)
		found := false
		for _, message := range result.Errors {
			found = found || message.Code == codeHookSessionKey
		}
		if !found || rotated != 0 || chowned != 0 {
			t.Fatalf("%s must stop before it changes anything when a key cannot be shown dead: %+v (rotated %d, chowned %d)", opts.Action, result, rotated, chowned)
		}
	}
	result := h.run(Options{Action: ActionUninstall})
	found := false
	for _, warning := range result.Warnings {
		found = found || warning.Code == codeHookSessionKey
	}
	if len(result.Errors) != 0 || !found {
		t.Fatalf("an uninstall goes on with a warning: %+v", result)
	}
}

// Review P1 (1.0.4 guard loop round 1, finding 6): a run removes the keys
// only once it holds the lifecycle lock, which is also the key lock, and
// holds it until it made new keys: the hook guardian makes no key
// meanwhile. A key
// another process made after the kill (a run this one waited for, or a
// guardian that does not know the key lock), and an allow made under it,
// do not outlive the run: its last step gives every account a new key.
func TestTheLifecycleRunOwnsTheKeysFromItsKillToItsNewKeys(t *testing.T) {
	withHookSessionTestKeys(t)
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	root := h.env.P(h.env.Layout.HookSessionDir)
	account, _ := enterprisepolicy.PublishedSessionIdentityDir(root, hookSessionTestAccount)
	if err := os.Mkdir(account, 0o700); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	keyLock := enterprisepolicy.PublishedSessionKeysLockPath(h.env.P(h.env.Layout.LifecycleDir))
	if filepath.Base(keyLock) != lockFileName {
		t.Fatalf("the key lock must be the lifecycle lock: %s", keyLock)
	}
	key := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: "linux:b:1:100"}
	proves := func() bool {
		_, err := enterprisepolicy.CheckPublishedForeignHookSession(root, hookSessionTestAccount, key, enterprisepolicy.GuardDecision{}, func(string) error { return nil })
		return err == nil
	}
	guardianMakesKeys := func() bool {
		ran, err := enterprisepolicy.WithPublishedSessionKeyCreation(keyLock, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		return ran
	}
	previousKill, previousRotate := hookSessionKillKeys, hookSessionRotateKeys
	t.Cleanup(func() { hookSessionKillKeys, hookSessionRotateKeys = previousKill, previousRotate })
	keyMadeMeanwhile := ""
	hookSessionKillKeys = func(path string) error {
		if guardianMakesKeys() {
			t.Error("the guardian may make keys while the run removes them")
		}
		err := previousKill(path)
		// Another process makes a key after the kill, and the gateway
		// publishes an allow under it.
		if ensureErr := enterprisepolicy.EnsurePublishedSessionKey(path, hookSessionTestAccount, enterprisepolicy.PublishedSessionTrust{}); ensureErr != nil {
			t.Error(ensureErr)
		}
		keyMadeMeanwhile = hookSessionTestKeyID(path)
		if writeErr := enterprisepolicy.WritePublishedSessionRecordsForTest(path, hookSessionTestAccount, key, enterprisepolicy.GuardDecision{}, time.Now()); writeErr != nil {
			t.Error(writeErr)
		}
		if !proves() {
			t.Error("the allow made after the kill must prove the process until the run ends")
		}
		return err
	}
	hookSessionRotateKeys = func(path string, trust enterprisepolicy.PublishedSessionTrust) error {
		if guardianMakesKeys() {
			t.Error("the guardian may make keys before the run made its own")
		}
		return previousRotate(path, trust)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	if keyMadeMeanwhile == "" || hookSessionTestKeyID(root) == keyMadeMeanwhile || hookSessionTestKeyID(root) == "" {
		t.Fatalf("the run must end with a new key, not the one made after its kill: %q (made %q)", hookSessionTestKeyID(root), keyMadeMeanwhile)
	}
	if proves() {
		t.Fatal("an allow made under a key made during the run must not outlive the run")
	}
	if !guardianMakesKeys() {
		t.Fatal("the guardian makes keys again once the run ended")
	}
}
