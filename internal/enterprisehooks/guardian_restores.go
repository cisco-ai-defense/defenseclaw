// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// GuardianRestoresFile records, in the standalone guardian's data
// directory, when the hook guardian (Windows, Linux, macOS) last put back
// each target's hooks because they no longer verified. Status, verify and
// ensure name the sessions of that account and connector that started
// before the restore: an agent keeps the hooks it loaded when it started.
// The guardian writes it (internal/cli); the Windows lifecycle
// (internal/cli) and the Linux and macOS lifecycle (internal/enterpriseunix)
// read it through ReadGuardianRestoreRecord, so both readers apply the same
// bounds and the same notion of an invalid record.
const GuardianRestoresFile = "hook_guardian_restores.json"

// GuardianRestoresMaxBytes bounds the record, which holds one entry per
// enrolled target at most. The writer keeps it under the bound.
const GuardianRestoresMaxBytes = 1 << 20

// ErrGuardianRestoreRecordInvalid wraps a record whose bytes were read but
// are not a version 1 record within GuardianRestoresMaxBytes. Any other
// error is a read failure, which may still hide earlier entries.
var ErrGuardianRestoreRecordInvalid = errors.New("invalid hook guardian restore record")

// GuardianRestoreReadBackoff spaces the retries of a failed read: on
// Windows a reader can meet a sharing violation while the guardian replaces
// the record.
var GuardianRestoreReadBackoff = []time.Duration{10 * time.Millisecond, 40 * time.Millisecond, 150 * time.Millisecond}

// GuardianRestore is one target's last restore. A Windows target is keyed
// by its SID, a Linux or macOS one by its uid.
type GuardianRestore struct {
	SID        string `json:"sid,omitempty"`
	UID        *int   `json:"uid,omitempty"`
	User       string `json:"user,omitempty"`
	Connector  string `json:"connector"`
	RestoredAt string `json:"restored_at"`
}

// GuardianRestoreRecord is the version 1 record.
type GuardianRestoreRecord struct {
	Version int               `json:"version"`
	Targets []GuardianRestore `json:"targets"`
}

// RestoredAtTime is the entry's restore time, or the zero time when it does
// not parse.
func (entry GuardianRestore) RestoredAtTime() time.Time {
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(entry.RestoredAt))
	if err != nil {
		return time.Time{}
	}
	return at
}

// ReadGuardianRestoreRecord reads and checks the record at path once,
// without following a link at its name. A missing record returns an
// os.ErrNotExist error.
func ReadGuardianRestoreRecord(path string) (GuardianRestoreRecord, error) {
	info, err := pathidentity.LstatPinned(path)
	if err != nil {
		return GuardianRestoreRecord{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return GuardianRestoreRecord{}, fmt.Errorf("hook guardian restore record %s is not a regular non-link file", path)
	}
	if info.Size() > GuardianRestoresMaxBytes {
		return GuardianRestoreRecord{}, fmt.Errorf("%w: hook guardian restore record exceeds %d-byte limit", ErrGuardianRestoreRecordInvalid, GuardianRestoresMaxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return GuardianRestoreRecord{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return GuardianRestoreRecord{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return GuardianRestoreRecord{}, fmt.Errorf("hook guardian restore record %s changed identity before open", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, GuardianRestoresMaxBytes+1))
	if err != nil {
		return GuardianRestoreRecord{}, err
	}
	if len(data) > GuardianRestoresMaxBytes {
		return GuardianRestoreRecord{}, fmt.Errorf("%w: hook guardian restore record exceeds %d-byte limit", ErrGuardianRestoreRecordInvalid, GuardianRestoresMaxBytes)
	}
	var record GuardianRestoreRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return GuardianRestoreRecord{}, fmt.Errorf("%w: %v", ErrGuardianRestoreRecordInvalid, err)
	}
	if record.Version != 1 {
		return GuardianRestoreRecord{}, fmt.Errorf("%w: hook guardian restore record has version %d", ErrGuardianRestoreRecordInvalid, record.Version)
	}
	return record, nil
}

// ReadGuardianRestoreRecordRetrying reads the record with read, retrying a
// failed read after each wait of backoff; a missing or invalid record is not
// retried.
func ReadGuardianRestoreRecordRetrying(path string, read func(string) (GuardianRestoreRecord, error), backoff []time.Duration) (GuardianRestoreRecord, error) {
	record, err := read(path)
	for _, wait := range backoff {
		if err == nil || errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrGuardianRestoreRecordInvalid) {
			break
		}
		time.Sleep(wait)
		record, err = read(path)
	}
	return record, err
}
