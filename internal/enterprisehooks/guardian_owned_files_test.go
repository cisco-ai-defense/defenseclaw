// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOwnedFileFingerprintTellsContentModeAndAbsenceApart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".hook-hermes.token")
	if got := OwnedFileFingerprint(path); got != "absent" {
		t.Fatalf("missing file = %q, want absent", got)
	}
	if err := os.WriteFile(path, []byte("issued\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	issued := OwnedFileFingerprint(path)
	if runtime.GOOS == "windows" {
		// Windows reads metadata only; an overwrite changes it.
		if err := os.WriteFile(path, []byte("lane-made-longer\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if OwnedFileFingerprint(path) == issued {
			t.Fatal("an overwritten file kept its fingerprint")
		}
		return
	}
	if !strings.HasPrefix(issued, "sha256:") || strings.Contains(issued, "issued") {
		t.Fatalf("fingerprint = %q, want a digest without the content", issued)
	}
	if again := OwnedFileFingerprint(path); again != issued {
		t.Fatalf("unchanged file changed fingerprint: %q then %q", issued, again)
	}
	// An in-place overwrite that keeps the mode (GAP-0044).
	if err := os.WriteFile(path, []byte("lane-made\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if OwnedFileFingerprint(path) == issued {
		t.Fatal("an overwritten file kept its fingerprint")
	}
	if err := os.WriteFile(path, []byte("issued\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if OwnedFileFingerprint(path) != issued {
		t.Fatal("the same bytes and mode did not give the same fingerprint")
	}
	{
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if OwnedFileFingerprint(path) == issued {
			t.Fatal("a mode change kept the fingerprint")
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if got := OwnedFileFingerprint(link); !strings.HasPrefix(got, "irregular:") {
			t.Fatalf("link = %q, want irregular (never followed)", got)
		}
	}
}

func TestGuardianOwnedFilesRecordRoundTripAndChangedFiles(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, ".hook-hermes.token")
	record := filepath.Join(dir, ".hookcfg.hermes")
	for _, path := range []string{token, record} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := GuardianOwnedTarget{User: "dcm-std1", UID: 502, Connector: "hermes"}
	for _, path := range []string{token, record} {
		target.Files = append(target.Files, GuardianOwnedFile{Path: path, Fingerprint: OwnedFileFingerprint(path)})
	}
	data, dropped, err := MarshalGuardianOwnedFilesRecord(GuardianOwnedFilesRecord{UpdatedAt: "2026-10-17T00:00:00Z", Targets: []GuardianOwnedTarget{target}})
	if err != nil || dropped != 0 {
		t.Fatalf("marshal: dropped=%d err=%v", dropped, err)
	}
	path := filepath.Join(dir, GuardianOwnedFilesFile)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := ReadGuardianOwnedFilesRecord(path)
	if err != nil || len(read.Targets) != 1 || read.Version != 1 {
		t.Fatalf("read = %+v, %v", read, err)
	}
	if changed := read.Targets[0].ChangedFiles(OwnedFileFingerprint); len(changed) != 0 {
		t.Fatalf("untouched files reported changed: %v", changed)
	}
	if err := os.WriteFile(token, []byte("lane-made-longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	changed := read.Targets[0].ChangedFiles(OwnedFileFingerprint)
	if len(changed) != 2 || changed[0] != token || changed[1] != record {
		t.Fatalf("changed = %v, want the overwritten token and the removed record", changed)
	}

	if _, err := ReadGuardianOwnedFilesRecord(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing record err = %v, want not exist", err)
	}
	for name, body := range map[string]string{
		"invalid.json":     "{not json",
		"version.json":     `{"version":2,"targets":[]}`,
		"noconnector.json": `{"version":1,"targets":[{"user":"a","files":[]}]}`,
	} {
		bad := filepath.Join(dir, name)
		if err := os.WriteFile(bad, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadGuardianOwnedFilesRecord(bad); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: err = %v, want an invalid-record error", name, err)
		}
	}
}
