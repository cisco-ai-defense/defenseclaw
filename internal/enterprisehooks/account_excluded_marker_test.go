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
