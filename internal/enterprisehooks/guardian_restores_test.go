// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The one reader of the guardian's restore record that the Windows and the
// Linux and macOS lifecycles share (GAP-0624): a missing record, a read
// failure and invalid content stay apart, so a caller can report the
// restart status unknown instead of "no restore".
func TestReadGuardianRestoreRecordClassifiesFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, GuardianRestoresFile)
	if _, err := ReadGuardianRestoreRecord(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing record: %v, want not exist", err)
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":1,"targets":[{"uid":1001,"user":"u","connector":"hermes","restored_at":"2026-10-13T20:00:00Z"}]}`)
	record, err := ReadGuardianRestoreRecord(path)
	if err != nil || len(record.Targets) != 1 || record.Targets[0].UID == nil || *record.Targets[0].UID != 1001 ||
		!record.Targets[0].RestoredAtTime().Equal(time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC)) {
		t.Fatalf("valid record: %+v, %v", record, err)
	}
	for name, body := range map[string]string{
		"not JSON":       "{",
		"version 2":      `{"version":2,"targets":[]}`,
		"over the bound": `{"version":1,"targets":[],"pad":"` + strings.Repeat("x", GuardianRestoresMaxBytes) + `"}`,
	} {
		write(body)
		if _, err := ReadGuardianRestoreRecord(path); !errors.Is(err, ErrGuardianRestoreRecordInvalid) {
			t.Fatalf("%s: %v, want an invalid record", name, err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGuardianRestoreRecord(path); err == nil || errors.Is(err, ErrGuardianRestoreRecordInvalid) || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory in place of the record: %v, want a read failure", err)
	}
}

func TestReadGuardianRestoreRecordRetryingRetriesOnlyReadFailures(t *testing.T) {
	failure := errors.New("sharing violation")
	for name, want := range map[string]struct {
		err   error
		calls int
	}{
		"read failure":   {failure, 4},
		"missing record": {os.ErrNotExist, 1},
		"invalid record": {ErrGuardianRestoreRecordInvalid, 1},
	} {
		calls := 0
		_, err := ReadGuardianRestoreRecordRetrying("record", func(string) (GuardianRestoreRecord, error) {
			calls++
			return GuardianRestoreRecord{}, want.err
		}, []time.Duration{0, 0, 0})
		if !errors.Is(err, want.err) || calls != want.calls {
			t.Fatalf("%s: %d reads, error %v; want %d reads", name, calls, err, want.calls)
		}
	}
	calls := 0
	if _, err := ReadGuardianRestoreRecordRetrying("record", func(string) (GuardianRestoreRecord, error) {
		calls++
		if calls < 3 {
			return GuardianRestoreRecord{}, failure
		}
		return GuardianRestoreRecord{Version: 1}, nil
	}, []time.Duration{0, 0, 0}); err != nil || calls != 3 {
		t.Fatalf("recovering read: %d reads, error %v", calls, err)
	}
}
