// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The 1.0.4 guard review loop round 1: any doubt blocks. A key the
// operating system refuses to remove, a key folder that cannot be listed,
// or a failed second key must never leave an earlier allow that passes an
// outage, and no key made while a lifecycle run holds the key lock may
// outlive the run.

// withPublishedSessionFaults restores the key and mark seams after the test.
func withPublishedSessionFaults(t *testing.T) {
	t.Helper()
	remove, rename, create, mark, list := publishedSessionRemoveKey, publishedSessionRenameKey, publishedSessionCreateKeyFile, publishedSessionCreateMarkFile, publishedSessionList
	t.Cleanup(func() {
		publishedSessionRemoveKey, publishedSessionRenameKey, publishedSessionCreateKeyFile, publishedSessionCreateMarkFile, publishedSessionList = remove, rename, create, mark, list
	})
}

func refuseRemovalOf(names ...string) func(string) error {
	return func(path string) error {
		for _, name := range names {
			if path == name {
				return &os.PathError{Op: "remove", Path: path, Err: errors.New("the operating system refused the unlink")}
			}
		}
		return os.Remove(path)
	}
}

// Findings 1 and 2: the gateway's revocation of a key the operating system
// refuses to remove marks that key revoked, so the earlier allow made with
// it proves nothing, and the gateway reads no key to make a new allow with;
// another account keeps its allow. Only when no mark can be added either is
// the key reported alive. The guardian's next pass replaces a marked key and
// removes the marks, and the next allow proves the process again.
func TestRevokePublishedSessionKeyMarksAKeyItCannotRemove(t *testing.T) {
	withPublishedSessionFaults(t)
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	other := publishedSessionOtherIdentity(identity)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	for _, account := range []string{identity, other} {
		if err := publishCurrent(root, account, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	stuck := publishedSessionTestKey(t, root, identity).ID()
	publishedSessionRemoveKey = refuseRemovalOf(stuck)

	publishedSessionCreateMarkFile = func(string) error { return errors.New("no space left on device") }
	if err := RevokePublishedSessionKey(root, identity); !errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a key that can be neither removed nor marked must be reported alive: %v", err)
	}
	publishedSessionCreateMarkFile = createPublishedSessionMarkFile
	err := RevokePublishedSessionKey(root, identity)
	if err == nil || errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a key that cannot be removed must be marked revoked: %v", err)
	}
	if _, err := os.Lstat(stuck); err != nil {
		t.Fatalf("the refused unlink keeps the key file: %v", err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("an allow made with a key marked revoked must prove nothing")
	}
	if _, err := ReadPublishedSessionKey(root, identity); err == nil {
		t.Fatal("a key marked revoked is no key: the gateway must make no allow with it")
	}
	if !publishedSessionTestAllows(root, other, key) {
		t.Fatal("another account's allow must not be touched")
	}
	// Every later denial marks the same key again: one mark per key.
	if err := RevokePublishedSessionKey(root, identity); err == nil || errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a second revocation: %v", err)
	}
	digest, _ := publishedSessionIdentityDigest(identity)
	marks, err := publishedSessionMarksOf(root, digest)
	if err != nil || len(marks.names) != 1 {
		t.Fatalf("one key has one mark: %+v %v", marks, err)
	}

	publishedSessionRemoveKey = os.Remove
	if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if got := publishedSessionTestKey(t, root, identity).ID(); got == stuck {
		t.Fatal("the guardian's pass must replace a key marked revoked")
	}
	if marks, err := publishedSessionMarksOf(root, digest); err != nil || len(marks.names) != 0 {
		t.Fatalf("the pass must remove the marks of the key it replaced: %+v %v", marks, err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the new key must not bring the earlier allow back")
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the next allow under the new key proves the process")
	}
}

// Finding 2, every way a key is ended: an account whose old key cannot be
// removed and that already has a second key (an earlier kill shadowed it)
// is never left with that old key alone, whatever else fails: the guardian's
// pass, a rotation, the lifecycle's kill and its last step make a new key
// before they remove old ones, keep the keys they have when they cannot,
// and mark the old key revoked when nothing else is left.
func TestPublishedSessionKeyFailuresNeverLeaveAnOldKeyAlone(t *testing.T) {
	for _, step := range []struct {
		name string
		run  func(root, identity string) error
	}{
		{"the guardian's pass", func(root, _ string) error { return EnsurePublishedSessionKeys(root, publishedSessionTestTrust) }},
		{"a rotation", func(root, identity string) error {
			return RotatePublishedSessionKey(root, identity, publishedSessionTestTrust)
		}},
		{"the lifecycle's kill", func(root, _ string) error { return KillAllPublishedSessionKeys(root) }},
		{"the lifecycle's last step", func(root, _ string) error { return RotateAllPublishedSessionKeys(root, publishedSessionTestTrust) }},
	} {
		for _, faults := range []struct {
			name           string
			create, marked bool
		}{
			{"no new key can be made", true, false},
			{"no new key and no mark can be made", true, true},
			{"a new key can be made", false, false},
		} {
			t.Run(step.name+", "+faults.name, func(t *testing.T) {
				withPublishedSessionFaults(t)
				root := publishedSessionTestRoot(t)
				identity := publishedSessionTestIdentity(t)
				key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
				if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
					t.Fatal(err)
				}
				stuck := publishedSessionTestKey(t, root, identity).ID()
				if _, err := createAccountTestKey(root, identity, publishedSessionTestTrust); err != nil {
					t.Fatal(err)
				}
				publishedSessionRemoveKey = refuseRemovalOf(stuck)
				if faults.create {
					publishedSessionCreateKeyFile = func(string, PublishedSessionTrust) error { return errors.New("no space left on device") }
				}
				if faults.marked {
					publishedSessionCreateMarkFile = func(string) error { return errors.New("no space left on device") }
				}
				_ = step.run(root, identity)
				publishedSessionRemoveKey, publishedSessionCreateKeyFile, publishedSessionCreateMarkFile = os.Remove, createPublishedSessionKeyFile, createPublishedSessionMarkFile
				if publishedSessionTestAllows(root, identity, key) {
					t.Fatal("the key the earlier allow was made with must not be left alone")
				}
				// The guardian's next pass, once the unlink works again.
				if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
					t.Fatal(err)
				}
				if publishedSessionTestKey(t, root, identity).ID() == stuck || publishedSessionTestAllows(root, identity, key) {
					t.Fatal("the next pass must give the account a new key that proves no earlier allow")
				}
			})
		}
	}
}

// A mark a revocation adds while a rotation runs is not removed by that
// rotation, which removes only the marks it listed before it changed
// anything: a mark that ends whatever key the account has (its keys could
// not be listed) keeps blocking until the next pass replaces the key again.
func TestPublishedSessionMarkAddedDuringARotationStays(t *testing.T) {
	withPublishedSessionFaults(t)
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	digest, _ := publishedSessionIdentityDigest(identity)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	publishedSessionRenameKey = func(from, to string) error {
		if err := markPublishedSessionKeysRevoked(root, digest, nil); err != nil {
			t.Fatal(err)
		}
		return os.Rename(from, to)
	}
	if err := RotatePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	publishedSessionRenameKey = os.Rename
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a mark added during the rotation must keep blocking")
	}
	if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the next pass replaces the key and removes the mark")
	}
}

// Finding 6: while a lifecycle run holds the key lock, the guardian makes no
// key (WithPublishedSessionKeyCreation does not run and returns at once);
// once the run let it go, it does. The run's own lock waits for a guardian
// that holds the lock shared, and gives up within its context. A host
// without a lifecycle folder has nothing to hold, and a guardian that finds
// no lock makes no key on Linux and macOS, where the lock is the
// lifecycle's own.
func TestPublishedSessionKeyLockKeepsTheGuardianFromMakingKeys(t *testing.T) {
	path := PublishedSessionKeysLockPath(t.TempDir())
	ran := false
	if runtime.GOOS != "windows" {
		if got, err := WithPublishedSessionKeyCreation(path, func() error { ran = true; return nil }); err != nil || got || ran {
			t.Fatalf("a guardian that finds no lifecycle lock must make no key: %v %v", got, err)
		}
	}
	release, err := LockPublishedSessionKeysForLifecycle(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	got, err := WithPublishedSessionKeyCreation(path, func() error { ran = true; return nil })
	if err != nil || got || ran {
		t.Fatalf("the guardian made keys while a lifecycle run held the key lock: ran %v, %v", got, err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("the guardian must not wait for a lifecycle run: %s", waited)
	}
	release()
	if got, err := WithPublishedSessionKeyCreation(path, func() error { ran = true; return nil }); err != nil || !got || !ran {
		t.Fatalf("with no run the guardian makes keys: %v %v", got, err)
	}

	held := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_, _ = WithPublishedSessionKeyCreation(path, func() error {
			close(held)
			<-done
			return nil
		})
	}()
	<-held
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = LockPublishedSessionKeysForLifecycle(ctx, path)
	cancel()
	if err == nil {
		t.Fatal("a lifecycle run must wait for a guardian that makes a key")
	}
	close(done)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	release, err = LockPublishedSessionKeysForLifecycle(ctx, path)
	cancel()
	if err != nil {
		t.Fatalf("the run takes the lock once the guardian let it go: %v", err)
	}
	release()

	missing := PublishedSessionKeysLockPath(filepath.Join(t.TempDir(), "not-installed"))
	release, err = LockPublishedSessionKeysForLifecycle(context.Background(), missing)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Lstat(filepath.Dir(missing)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a host where nothing is installed gets no lifecycle folder from the key lock")
	}
	if got, err := WithPublishedSessionKeyCreation(missing, func() error { return nil }); err != nil || got {
		t.Fatalf("a guardian without a lifecycle folder makes no key: %v %v", got, err)
	}
}

// Finding 6: the lifecycle's last step gives every account a new key,
// whatever key it had: an allow made under a key another process made
// while the run changed the deployment proves nothing after the run.
func TestRotateAllPublishedSessionKeysReplacesEveryKey(t *testing.T) {
	root := publishedSessionTestRoot(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	identity := publishedSessionTestIdentity(t)
	accounts := []string{identity, publishedSessionOtherIdentity(identity)}
	before := map[string]string{}
	for _, account := range accounts {
		if err := publishCurrent(root, account, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		before[account] = publishedSessionTestKey(t, root, account).ID()
	}
	if err := RotateAllPublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	for _, account := range accounts {
		if got := publishedSessionTestKey(t, root, account).ID(); got == before[account] || strings.TrimSpace(got) == "" {
			t.Fatalf("%s kept its key", account)
		}
		if publishedSessionTestAllows(root, account, key) {
			t.Fatalf("an allow of %s from before the last step must prove nothing", account)
		}
	}
}
