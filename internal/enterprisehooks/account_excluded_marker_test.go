// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	excludedSIDOne   = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	excludedSIDTwo   = "S-1-5-21-1111111111-2222222222-3333333333-1002"
	enrolledSIDOther = "S-1-5-21-1111111111-2222222222-3333333333-1003"
)

func plainMarkerIO() accountExcludedMarkerIO {
	return accountExcludedMarkerIO{
		ensure: func(dir string) error { return os.MkdirAll(dir, 0o755) },
		write:  func(path string, body []byte) error { return os.WriteFile(path, body, 0o600) },
		remove: os.Remove,
		read: func(path string) ([]byte, bool, error) {
			data, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				return nil, false, nil
			}
			return data, err == nil, err
		},
		checkDir: func(string) error { return nil },
	}
}

func markerNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// The excluded account reads as excluded; an enrolled account of the same
// machine, and an account with no marker, do not (GAP-0979: the machine-wide
// hook refused every call of the excluded account as a pending enrollment).
func TestAccountExcludedMarkerCoversOnlyTheExcludedAccounts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hookruntime")
	files := plainMarkerIO()
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne, strings.ToLower(excludedSIDTwo)}, files); err != nil {
		t.Fatal(err)
	}
	for sid, want := range map[string]bool{excludedSIDOne: true, excludedSIDTwo: true, enrolledSIDOther: false} {
		got, err := accountExcludedMarkerPresent(dir, sid, files)
		if err != nil || got != want {
			t.Fatalf("%s: excluded=%t err=%v, want %t", sid, got, err, want)
		}
	}
	// A second pass with the same set changes nothing.
	before := markerNames(t, dir)
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne, excludedSIDTwo}, files); err != nil {
		t.Fatal(err)
	}
	if after := markerNames(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("markers changed from %v to %v", before, after)
	}
}

// An account taken off exclude_users loses its marker in the next cycle, and
// the markers of the accounts still excluded stay; an empty set removes all and
// creates nothing; files that are not markers are never touched.
func TestAccountExcludedMarkerEndsWithTheExclusion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hookruntime")
	files := plainMarkerIO()
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne, excludedSIDTwo}, files); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, ".defenseclaw-hot-config-undo-closed")
	if err := os.WriteFile(other, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDTwo}, files); err != nil {
		t.Fatal(err)
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, files); err != nil || got {
		t.Fatalf("the marker of the account taken off the list survived: excluded=%t err=%v", got, err)
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDTwo, files); err != nil || !got {
		t.Fatalf("the marker of the account still excluded was removed: excluded=%t err=%v", got, err)
	}
	if err := publishAccountExcludedMarkers(dir, nil, files); err != nil {
		t.Fatal(err)
	}
	if names := markerNames(t, dir); len(names) != 1 || names[0] != filepath.Base(other) {
		t.Fatalf("directory after the last exclusion ended = %v, want only the closure marker", names)
	}
	// No directory and no exclusions: nothing is created.
	missing := filepath.Join(t.TempDir(), "never")
	if err := publishAccountExcludedMarkers(missing, nil, files); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an empty set created the directory: %v", err)
	}
}

// A damaged marker, an untrusted directory, a marker written for another SID
// and a caller without a SID are never "excluded"; a bad SID never reaches a
// file name.
func TestAccountExcludedMarkerRefusesAnythingButAValidMarker(t *testing.T) {
	dir := t.TempDir()
	files := plainMarkerIO()
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne}, files); err != nil {
		t.Fatal(err)
	}
	path := accountExcludedMarkerPath(dir, excludedSIDOne)
	for name, body := range map[string]string{
		"damaged":        "other\n",
		"other account":  string(accountExcludedMarkerBody(excludedSIDTwo)),
		"empty":          "",
		"extra trailing": string(accountExcludedMarkerBody(excludedSIDOne)) + "x",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, files); err == nil || got {
			t.Fatalf("%s marker: excluded=%t err=%v", name, got, err)
		}
	}
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne}, files); err != nil {
		t.Fatalf("a damaged marker was not replaced: %v", err)
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, files); err != nil || !got {
		t.Fatalf("replaced marker: excluded=%t err=%v", got, err)
	}
	untrusted := files
	untrusted.checkDir = func(string) error { return errors.New("untrusted directory") }
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, untrusted); err == nil || got {
		t.Fatalf("untrusted directory: excluded=%t err=%v", got, err)
	}
	for _, bad := range []string{"", "alice", `..\..\x`, "S-1-5-21-1/../2", "S-1-", "S-1-5-21-1 -2"} {
		if got, err := accountExcludedMarkerPresent(dir, bad, files); err == nil || got {
			t.Fatalf("SID %q: excluded=%t err=%v", bad, got, err)
		}
		err := publishAccountExcludedMarkers(filepath.Join(dir, "sub"), []string{bad}, files)
		if err == nil {
			t.Fatalf("a marker was published for %q", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); err == nil {
		t.Fatal("a bad SID created the directory")
	}
}

// A marker that cannot be written fails only that account; the others are still
// published, and the failure is returned.
func TestAccountExcludedMarkerWriteFailureKeepsTheOtherAccounts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hookruntime")
	files := plainMarkerIO()
	realWrite := files.write
	files.write = func(path string, body []byte) error {
		if strings.HasSuffix(path, excludedSIDOne) {
			return errors.New("access is denied")
		}
		return realWrite(path, body)
	}
	err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne, excludedSIDTwo}, files)
	if err == nil || !strings.Contains(err.Error(), excludedSIDOne) {
		t.Fatalf("err = %v, want the failed account named", err)
	}
	if got, readErr := accountExcludedMarkerPresent(dir, excludedSIDTwo, plainMarkerIO()); readErr != nil || !got {
		t.Fatalf("the other account was not published: excluded=%t err=%v", got, readErr)
	}
	if got, _ := accountExcludedMarkerPresent(dir, excludedSIDOne, plainMarkerIO()); got {
		t.Fatal("the account whose write failed reads as excluded")
	}
}

// holdsOpen is a store whose files named by held cannot be removed or
// replaced, as when a reader holds them open without delete sharing; a file
// that does not exist yet can still be created.
func holdsOpen(files accountExcludedMarkerIO, held ...string) accountExcludedMarkerIO {
	isHeld := func(path string) bool {
		for _, name := range held {
			if filepath.Base(path) == name {
				return true
			}
		}
		return false
	}
	realRemove, realWrite := files.remove, files.write
	files.remove = func(path string) error {
		if isHeld(path) {
			return errors.New("the process cannot access the file because it is being used by another process")
		}
		return realRemove(path)
	}
	files.write = func(path string, body []byte) error {
		if _, err := os.Stat(path); err == nil && isHeld(path) {
			return errors.New("the process cannot access the file because it is being used by another process")
		}
		return realWrite(path, body)
	}
	return files
}

// A marker that cannot be removed does not keep authorizing the account: the
// revocation record, a new file nothing holds, ends the pass; and when the
// held file also cannot be replaced, which a reader holding it open causes
// (GAP-0979: a failed delete plus a failed replacement left the old pass
// valid). The record is cleared when the marker is gone or published again.
func TestAccountExcludedMarkerCannotOutliveTheExclusionWhenRemovalFails(t *testing.T) {
	previousWait := accountExcludedRemoveWait
	accountExcludedRemoveWait = 0
	t.Cleanup(func() { accountExcludedRemoveWait = previousWait })
	dir := filepath.Join(t.TempDir(), "hookruntime")
	files := plainMarkerIO()
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne, excludedSIDTwo}, files); err != nil {
		t.Fatal(err)
	}
	heldName := filepath.Base(accountExcludedMarkerPath(dir, excludedSIDOne))
	held := holdsOpen(files, heldName)
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDTwo}, held); err != nil {
		t.Fatalf("the revocation was not written: %v", err)
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, files); got || err == nil {
		t.Fatalf("the held marker of the account taken off the list is still valid: excluded=%t err=%v", got, err)
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDTwo, files); err != nil || !got {
		t.Fatalf("the account still excluded lost its pass: excluded=%t err=%v", got, err)
	}
	// Every later cycle keeps the revocation while the marker is held.
	if err := publishAccountExcludedMarkers(dir, nil, held); err != nil {
		t.Fatal(err)
	}
	if got, _ := accountExcludedMarkerPresent(dir, excludedSIDOne, files); got {
		t.Fatal("the held marker became valid again in a later cycle")
	}
	// The account excluded again while the old marker is still held: its
	// revocation cannot be cleared by a failing remove, so no pass.
	revokedName := filepath.Base(accountExcludedRevokedPath(dir, excludedSIDOne))
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne}, holdsOpen(files, heldName, revokedName)); err == nil {
		t.Fatal("a revocation that could not be cleared was not reported")
	}
	if got, _ := accountExcludedMarkerPresent(dir, excludedSIDOne, files); got {
		t.Fatal("an account whose revocation could not be cleared got its pass back")
	}
	// Once the reader lets go, the next cycle removes the marker and its record.
	if err := publishAccountExcludedMarkers(dir, nil, files); err != nil {
		t.Fatal(err)
	}
	if names := markerNames(t, dir); len(names) != 0 {
		t.Fatalf("directory after the reader let go = %v, want it empty", names)
	}
	// An account excluded again after a revocation gets its pass back.
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne}, held); err != nil {
		t.Fatal(err)
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, files); err != nil || !got {
		t.Fatalf("an account excluded again has no pass: excluded=%t err=%v", got, err)
	}
}

// When even the revocation record cannot be written the marker stays valid
// and the error says so; the benign twin, a removal that works, leaves
// nothing behind.
func TestAccountExcludedMarkerReportsAnUnrevokableMarker(t *testing.T) {
	previousWait := accountExcludedRemoveWait
	accountExcludedRemoveWait = 0
	t.Cleanup(func() { accountExcludedRemoveWait = previousWait })
	dir := filepath.Join(t.TempDir(), "hookruntime")
	files := plainMarkerIO()
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne}, files); err != nil {
		t.Fatal(err)
	}
	denied := files
	denied.remove = func(string) error { return errors.New("access is denied") }
	denied.write = func(string, []byte) error { return errors.New("access is denied") }
	err := publishAccountExcludedMarkers(dir, nil, denied)
	if err == nil || !strings.Contains(err.Error(), "neither removed") {
		t.Fatalf("err = %v, want the unrevoked marker reported", err)
	}
	if err := publishAccountExcludedMarkers(dir, nil, files); err != nil {
		t.Fatal(err)
	}
	if names := markerNames(t, dir); len(names) != 0 {
		t.Fatalf("directory after a working removal = %v, want it empty", names)
	}
}

// A revocation record that cannot be read is a revocation too.
func TestAccountExcludedMarkerUnreadableRevocationIsARevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hookruntime")
	files := plainMarkerIO()
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne}, files); err != nil {
		t.Fatal(err)
	}
	readRecord := files.read
	files.read = func(path string) ([]byte, bool, error) {
		if strings.HasPrefix(filepath.Base(path), accountExcludedRevokedPrefix) {
			return nil, false, errors.New("the file is not trusted")
		}
		return readRecord(path)
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, files); got || err == nil {
		t.Fatalf("excluded=%t err=%v with an unreadable revocation record", got, err)
	}
}

// A directory that cannot be prepared for new markers still has its stale
// markers removed: revocation does not wait for publication.
func TestAccountExcludedMarkerRevocationDoesNotWaitForPublication(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hookruntime")
	files := plainMarkerIO()
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne}, files); err != nil {
		t.Fatal(err)
	}
	files.ensure = func(string) error { return errors.New("the directory is not trusted") }
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDTwo}, files); err == nil {
		t.Fatal("a failed ensure was not reported")
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, plainMarkerIO()); err != nil || got {
		t.Fatalf("the stale marker survived a failed ensure: excluded=%t err=%v", got, err)
	}
}
