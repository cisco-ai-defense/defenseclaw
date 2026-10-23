// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The 1.0.4 guard review loop round 4: an allow lives only as long as its
// proof. It passes an outage for at most PublishedSessionProofLifetime
// after its last renewal, with no 15-minute window, and a renewal brings it
// back to life only with the account's current key generation.
func TestPublishedSessionProofLivesOnlyAsLongAsItsRenewal(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	written := time.Now()
	if err := publishCurrent(root, identity, key, GuardDecision{}, written); err != nil {
		t.Fatal(err)
	}
	at := func(after time.Duration) error {
		t.Helper()
		restore := OverridePublishedSessionNowForTest(func() time.Time { return written.Add(after) })
		defer restore()
		_, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err
	}
	for _, after := range []time.Duration{0, PublishedSessionRenewEvery, PublishedSessionProofLifetime - time.Second} {
		if err := at(after); err != nil {
			t.Fatalf("%s after its renewal the proof passes: %v", after, err)
		}
	}
	for _, after := range []time.Duration{PublishedSessionProofLifetime + time.Second, 5 * time.Minute, 14 * time.Minute} {
		if err := at(after); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%s after its renewal the proof is gone: %v", after, err)
		}
	}
	// Renewed: the same allow, written again with the current key.
	if err := publishCurrent(root, identity, key, GuardDecision{}, written.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := at(time.Minute + PublishedSessionProofLifetime - time.Second); err != nil {
		t.Fatalf("a renewal extends the proof: %v", err)
	}
	// A new key generation: the old proof is dead until it is renewed with
	// it.
	if err := RotatePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if err := at(time.Minute); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a proof of an earlier key generation: %v", err)
	}
}

// A clock that goes back while the hook checks the records is doubt.
func TestPublishedSessionClockGoingBackDuringTheCheckBlocks(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	written := time.Now()
	if err := publishCurrent(root, identity, key, GuardDecision{}, written); err != nil {
		t.Fatal(err)
	}
	reads := 0
	restore := OverridePublishedSessionNowForTest(func() time.Time {
		reads++
		if reads == 1 {
			return written.Add(10 * time.Second)
		}
		return written.Add(5 * time.Second)
	})
	defer restore()
	if _, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); err == nil || !strings.Contains(err.Error(), "clock went back") {
		t.Fatalf("a clock that went back during the check: %v", err)
	}
}

// publishedSessionTestClosedPath is the closed mark of identity under root.
func publishedSessionTestClosedPath(t *testing.T, root, identity string) string {
	t.Helper()
	digest, _ := publishedSessionIdentityDigest(identity)
	path, ok := publishedSessionClosedPath(root, digest)
	if !ok {
		t.Fatal("no closed mark path")
	}
	return path
}

// A closed account's allows pass no outage, whatever their proof, and so
// does one whose closed mark cannot be read; another account is not
// touched. A mark that is there already is kept, a folder that takes no new
// file is an error, and a folder that holds no record has nothing to close.
// Clearing the mark opens the account again.
func TestPublishedSessionClosedAccountPassesNoOutage(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	other := publishedSessionOtherIdentity(identity)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	for _, account := range []string{identity, other} {
		if err := publishCurrent(root, account, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("an open account's fresh allow passes an outage")
	}
	if err := MarkPublishedSessionAccountClosed(root, identity); err != nil {
		t.Fatal(err)
	}
	if err := MarkPublishedSessionAccountClosed(root, identity); err != nil {
		t.Fatalf("closing a closed account again: %v", err)
	}
	if _, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) || !strings.Contains(err.Error(), "closed the account") {
		t.Fatalf("a closed account's fresh allow: %v", err)
	}
	if err := PublishedSessionAccountClosed(root, identity); err == nil {
		t.Fatal("the gateway sees the account closed")
	}
	if !publishedSessionTestAllows(root, other, key) {
		t.Fatal("another account stays open")
	}
	if err := ClearPublishedSessionAccountClosed(root, identity); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) || PublishedSessionAccountClosed(root, identity) != nil {
		t.Fatal("a cleared account is open again")
	}

	closedPath := publishedSessionTestClosedPath(t, root, identity)
	previousStat := publishedSessionClosedStat
	publishedSessionClosedStat = func(path string) (fs.FileInfo, error) {
		if path == closedPath {
			return nil, fs.ErrPermission
		}
		return previousStat(path)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a closed mark that cannot be read is doubt")
	}
	if err := MarkPublishedSessionAccountClosed(root, identity); err == nil {
		t.Fatal("a closed mark that cannot be read back did not close the account")
	}
	publishedSessionClosedStat = previousStat

	previousCreate := publishedSessionCreateClosedFile
	publishedSessionCreateClosedFile = func(string) error { return fs.ErrPermission }
	if err := MarkPublishedSessionAccountClosed(root, identity); err == nil {
		t.Fatal("a folder that takes no new file must not close the account silently")
	}
	publishedSessionCreateClosedFile = previousCreate

	empty := filepath.Join(t.TempDir(), "sessions")
	if err := MarkPublishedSessionAccountClosed(filepath.Join(empty, "missing"), identity); err != nil {
		t.Fatalf("a record folder that does not exist holds nothing to close: %v", err)
	}
}

// The hook guardian rotates the key of a closed account and then opens it:
// no allow of the old key verifies. When the key cannot be ended the
// account stays closed.
func TestPublishedSessionGuardianOpensAClosedAccountOnlyAfterTheKeyEnds(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := MarkPublishedSessionAccountClosed(root, identity); err != nil {
		t.Fatal(err)
	}
	closedPath := publishedSessionTestClosedPath(t, root, identity)
	before := publishedSessionTestKey(t, root, identity).ID()

	previousRename, previousRemove, previousCreate, previousMark := publishedSessionRenameKey, publishedSessionRemoveKey, publishedSessionCreateKeyFile, publishedSessionCreateMarkFile
	publishedSessionRenameKey = func(string, string) error { return fs.ErrPermission }
	publishedSessionRemoveKey = func(string) error { return fs.ErrPermission }
	publishedSessionCreateKeyFile = func(string, PublishedSessionTrust) error { return fs.ErrPermission }
	publishedSessionCreateMarkFile = func(string) error { return fs.ErrPermission }
	err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust)
	publishedSessionRenameKey, publishedSessionRemoveKey, publishedSessionCreateKeyFile, publishedSessionCreateMarkFile = previousRename, previousRemove, previousCreate, previousMark
	if !errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a key that cannot be ended: %v", err)
	}
	if _, err := os.Lstat(closedPath); err != nil {
		t.Fatalf("the account stays closed while its key lives: %v", err)
	}

	if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(closedPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the guardian opens the account once its key is ended: %v", err)
	}
	if publishedSessionTestKey(t, root, identity).ID() == before {
		t.Fatal("the closed account gets a new key")
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("an allow of the old key proves nothing")
	}
}

// The end of an account's last allow is the latest renewal of an allow
// with a MAC plus the proof lifetime; a block or an allow without a key
// adds nothing, an account with none has none, and a record that cannot be
// read is an error.
func TestPublishedSessionAllowWindowEndIsTheLastRenewalPlusTheLifetime(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	if end, err := PublishedSessionAllowWindowEnd(root, identity); err != nil || !end.IsZero() {
		t.Fatalf("an account with no record: %v %v", end, err)
	}
	first := time.Now().Add(-time.Minute).Truncate(time.Second)
	last := first.Add(30 * time.Second)
	for i, at := range []time.Time{first, last} {
		if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Session: fmt.Sprintf("s-%d", i), Process: fmt.Sprintf("p-%d", i)}, GuardDecision{}, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Session: "s-b", Process: "p-b"}, GuardDecision{Deny: true, Reason: "x"}, last.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := PublishForeignHookSessionDecision(root, identity, SessionKey{Connector: "copilot", Session: "s-n", Process: "p-n"}, GuardDecision{}, SessionRecordKey{}, last.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	end, err := PublishedSessionAllowWindowEnd(root, identity)
	if err != nil || !end.Equal(last.Add(PublishedSessionProofLifetime)) {
		t.Fatalf("the window ends at %v (%v), want %v", end, err, last.Add(PublishedSessionProofLifetime))
	}
	dir, _ := PublishedSessionIdentityDir(root, identity)
	if err := os.WriteFile(filepath.Join(dir, "copilot-p-corrupt.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishedSessionAllowWindowEnd(root, identity); err == nil {
		t.Fatal("a record that cannot be read leaves the window unknown")
	}
}
