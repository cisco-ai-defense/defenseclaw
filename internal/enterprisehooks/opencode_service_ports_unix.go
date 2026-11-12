// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// UnixOpenCodeServicePortsFileName is the guardian's root-only record of the
// OpenCode background-server port each eligible account has (gas-ux-r1
// GAP-0053). It is the only authority: a binding, once made, never changes
// because of any user's file (REVIEW-gx053-9), and no entry is dropped.
const UnixOpenCodeServicePortsFileName = "opencode-service-ports.json"

const unixOpenCodeServicePortsMaxBytes = 1 << 20

type unixOpenCodeServicePortsFile struct {
	Version int                       `json:"version"`
	Ports   []UnixOpenCodeServicePort `json:"ports"`
	// Unknown are the eligible accounts whose OpenCode file the last pass
	// could not read or write as the account (a failed or timed-out worker,
	// a linked or read-only folder): their record entry did not change.
	// Additive to version 1, as are the fields below: an earlier loader
	// ignores them.
	Unknown []UnixOpenCodeServicePortUnknown `json:"unknown,omitempty"`
	// Contested are ports the files of two or more accounts named in the
	// pass that built the record (REVIEW-gx053-11): no account is given such
	// a port until an administrator clears the mark.
	Contested []UnixOpenCodeContestedPort `json:"contested,omitempty"`
	// Cleared logs every administrator clear of a contested mark.
	Cleared []UnixOpenCodeContestCleared `json:"contested_cleared,omitempty"`
	// ImportDone records that the import pass committed this record
	// (REVIEW-gx053-12): the record, bindings and marks are committed before
	// any user file is rewritten. The load reads it (REVIEW-gx053-13 S2): a
	// record written with false is not past its import pass, so the next pass
	// is the import pass; a record without the key (an earlier round's) counts
	// as done.
	ImportDone *bool `json:"import_done,omitempty"`
}

// unixOpenCodeServicePortsTempPattern is the temp file the record writer
// creates beside the record before the atomic rename.
const unixOpenCodeServicePortsTempPattern = ".defenseclaw-opencode-ports-*.new"

// UnixOpenCodeServicePortUnknown is one account the last pass could not read
// or write.
type UnixOpenCodeServicePortUnknown struct {
	UID    int    `json:"uid"`
	User   string `json:"user"`
	Reason string `json:"reason"`
	// Path is the account's service.json; Fix is the administrator's step
	// that clears the warning.
	Path string `json:"path,omitempty"`
	Fix  string `json:"fix,omitempty"`
}

// UnixOpenCodeContestedPort is a port the files of several accounts named.
type UnixOpenCodeContestedPort struct {
	Port int   `json:"port"`
	UIDs []int `json:"uids"`
}

// UnixOpenCodeContestCleared is one administrator clear of a contested mark.
type UnixOpenCodeContestCleared struct {
	Port int    `json:"port"`
	UIDs []int  `json:"uids"`
	At   string `json:"at"`
	By   string `json:"by,omitempty"`
}

// UnixOpenCodeServicePort is one account's entry.
type UnixOpenCodeServicePort struct {
	UID  int    `json:"uid"`
	User string `json:"user"`
	Port int    `json:"port"`
}

// UnixOpenCodeServicePortsState is the whole record. Exists is false when no
// record file is there (the first pass after an install, an upgrade from a
// build without one, or an administrator's rebuild): only that pass imports
// ports from users' files.
type UnixOpenCodeServicePortsState struct {
	Exists bool
	// ImportDone: the record is past its import pass. Read from the record's
	// import_done key; a record without the key (an earlier build's) is done.
	// False only for a record committed with import_done false.
	ImportDone bool
	Ports      map[int]int
	Users      map[int]string
	Unknown    []UnixOpenCodeServicePortUnknown
	Contested  []UnixOpenCodeContestedPort
	Cleared    []UnixOpenCodeContestCleared
}

// LoadUnixOpenCodeServicePortsFull reads the whole record at path.
func LoadUnixOpenCodeServicePortsFull(path string) (UnixOpenCodeServicePortsState, error) {
	state := UnixOpenCodeServicePortsState{Ports: map[int]int{}, Users: map[int]string{}}
	path = filepath.Clean(strings.TrimSpace(path))
	if err := validateRootOwnedDirChain(filepath.Dir(path)); err != nil {
		return state, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	state.Exists = true
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return state, fmt.Errorf("enterprise hooks: OpenCode service ports record %s must be a 0600 regular file", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || (st.Uid != 0 && !unixManifestTestOwnerAllowed(st.Uid)) || st.Nlink != 1 {
		return state, fmt.Errorf("enterprise hooks: OpenCode service ports record %s is not a root-owned single-link file", path)
	}
	data, err := readBoundedFile(path, unixOpenCodeServicePortsMaxBytes)
	if err != nil {
		return state, err
	}
	var record unixOpenCodeServicePortsFile
	if err := json.Unmarshal(data, &record); err != nil {
		return state, fmt.Errorf("enterprise hooks: parse OpenCode service ports record: %w", err)
	}
	if record.Version != 1 {
		return state, fmt.Errorf("enterprise hooks: OpenCode service ports record version %d is not supported", record.Version)
	}
	for _, entry := range record.Ports {
		if entry.UID > 0 && entry.Port > 0 && entry.Port <= 65535 {
			state.Ports[entry.UID] = entry.Port
			if entry.User != "" {
				state.Users[entry.UID] = entry.User
			}
		}
	}
	state.Unknown, state.Cleared = record.Unknown, record.Cleared
	state.ImportDone = record.ImportDone == nil || *record.ImportDone
	for _, entry := range record.Contested {
		if entry.Port > 0 && entry.Port <= 65535 {
			state.Contested = append(state.Contested, entry)
		}
	}
	return state, nil
}

// WriteUnixOpenCodeServicePortsFull publishes the whole record at path,
// root-only.
func WriteUnixOpenCodeServicePortsFull(path string, state UnixOpenCodeServicePortsState) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return fmt.Errorf("enterprise hooks: OpenCode service ports path must be absolute: %s", path)
	}
	importDone := state.ImportDone
	record := unixOpenCodeServicePortsFile{Version: 1, Ports: []UnixOpenCodeServicePort{}, ImportDone: &importDone}
	for uid, port := range state.Ports {
		record.Ports = append(record.Ports, UnixOpenCodeServicePort{UID: uid, User: state.Users[uid], Port: port})
	}
	sort.Slice(record.Ports, func(i, j int) bool { return record.Ports[i].UID < record.Ports[j].UID })
	record.Unknown = append(record.Unknown, state.Unknown...)
	sort.Slice(record.Unknown, func(i, j int) bool { return record.Unknown[i].UID < record.Unknown[j].UID })
	record.Contested = append(record.Contested, state.Contested...)
	sort.Slice(record.Contested, func(i, j int) bool { return record.Contested[i].Port < record.Contested[j].Port })
	record.Cleared = append(record.Cleared, state.Cleared...)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	// Atomic commit: a temp file in the same folder, fsync, rename
	// (writeUnixRootOnlyRecord), then fsync the folder so the rename is on
	// disk before any user file is rewritten.
	if err := writeUnixRootOnlyRecord(path, append(data, '\n'), unixOpenCodeServicePortsTempPattern, unixOpenCodeServicePortsMaxBytes); err != nil {
		return err
	}
	return syncUnixDir(filepath.Dir(path))
}

// SweepUnixOpenCodeServicePortsTemp removes the temp files a killed record
// write left beside the record at path (REVIEW-gx053-13 S2): regular files in
// the record's own folder whose name matches the writer's temp pattern and
// whose modification time is before passStart.
//
// The caller MUST hold the guardian reconcile lock of that folder
// (LockUnixGuardianReconcile). The lock is what keeps a live writer's temp file
// safe: every writer of the record (the guardian pass, opencode-port-clear)
// takes it, so none is mid-write while the sweep runs. The modification-time
// check does not protect a writer that does not hold the lock; it only spares
// a file created after the pass began. The sweep follows no link and never
// descends into a folder. It returns the number of files removed.
func SweepUnixOpenCodeServicePortsTemp(path string, passStart time.Time) (int, error) {
	dir := filepath.Dir(filepath.Clean(strings.TrimSpace(path)))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	var firstErr error
	for _, entry := range entries {
		if ok, _ := filepath.Match(unixOpenCodeServicePortsTempPattern, entry.Name()); !ok {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() || !info.ModTime().Before(passStart) {
			continue
		}
		if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		removed++
	}
	return removed, firstErr
}

func syncUnixDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// LockUnixGuardianReconcile takes the hook guardian's reconcile lock
// (managed.HookGuardianReconcileLockFile in dir, the folder of the record), an
// exclusive flock, waiting up to wait. A guardian pass holds it for its whole
// read, plan, commit and rewrite; an administrator's change to the record
// takes the same lock, so the two never interleave (REVIEW-gx053-12 MF2).
func LockUnixGuardianReconcile(ctx context.Context, dir string, wait time.Duration) (func(), error) {
	path := filepath.Join(dir, managed.HookGuardianReconcileLockFile)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the hook guardian reconcile lock %s: %w", path, err)
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("another reconcile holds %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

// ClearUnixOpenCodeContestedPortLocked is ClearUnixOpenCodeContestedPort
// under the guardian's reconcile lock: the read, the change, the atomic
// commit and the log entry happen while no guardian pass runs, so a pass
// never undoes the clear (REVIEW-gx053-12 MF2).
func ClearUnixOpenCodeContestedPortLocked(path string, port int, by string, now time.Time, wait time.Duration) ([]int, error) {
	unlock, err := LockUnixGuardianReconcile(context.Background(), filepath.Dir(filepath.Clean(path)), wait)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return ClearUnixOpenCodeContestedPort(path, port, by, now)
}

// ClearUnixOpenCodeContestedPort removes the contested mark of port from the
// record at path and logs the clear in it (an administrator's operation:
// `enterprise linux|macos opencode-port-clear`). It returns the uids that had
// claimed the port; an unmarked port is an error and changes nothing.
func ClearUnixOpenCodeContestedPort(path string, port int, by string, now time.Time) ([]int, error) {
	state, err := LoadUnixOpenCodeServicePortsFull(path)
	if err != nil {
		return nil, err
	}
	if !state.Exists {
		return nil, fmt.Errorf("no OpenCode service ports record at %s", path)
	}
	var claimants []int
	kept := state.Contested[:0]
	for _, entry := range state.Contested {
		if entry.Port == port {
			claimants = entry.UIDs
			continue
		}
		kept = append(kept, entry)
	}
	if claimants == nil {
		return nil, fmt.Errorf("port %d is not marked contested in %s", port, path)
	}
	state.Contested = kept
	state.Cleared = append(state.Cleared, UnixOpenCodeContestCleared{Port: port, UIDs: claimants, At: now.UTC().Format(time.RFC3339), By: by})
	return claimants, WriteUnixOpenCodeServicePortsFull(path, state)
}

// ClearUnixOpenCodeUnknownLocked removes the unknown entry of uid from the
// record at path under the guardian reconcile lock (an administrator
// operation: `enterprise linux|macos opencode-port-unknown-clear`). The
// entry is the guardian snapshot of an account whose service.json it could not
// read or write; one whose account is gone has nothing left to repair. The
// account check runs under the lock, after the entry is found: hasAccount
// reports whether any account of the host holds uid, and an error from it, like
// a true answer, refuses and changes nothing. Bindings, contested marks and the
// clear log stay as they are. It returns the removed entry.
func ClearUnixOpenCodeUnknownLocked(path string, uid int, wait time.Duration, hasAccount func(uid int) (bool, error)) (UnixOpenCodeServicePortUnknown, error) {
	unlock, err := LockUnixGuardianReconcile(context.Background(), filepath.Dir(filepath.Clean(path)), wait)
	if err != nil {
		return UnixOpenCodeServicePortUnknown{}, err
	}
	defer unlock()
	state, err := LoadUnixOpenCodeServicePortsFull(path)
	if err != nil {
		return UnixOpenCodeServicePortUnknown{}, err
	}
	if !state.Exists {
		return UnixOpenCodeServicePortUnknown{}, fmt.Errorf("no OpenCode service ports record at %s", path)
	}
	var removed UnixOpenCodeServicePortUnknown
	found := false
	kept := make([]UnixOpenCodeServicePortUnknown, 0, len(state.Unknown))
	for _, entry := range state.Unknown {
		if entry.UID == uid {
			removed, found = entry, true
			continue
		}
		kept = append(kept, entry)
	}
	if !found {
		return UnixOpenCodeServicePortUnknown{}, fmt.Errorf("uid %d is not in the unknown list of %s", uid, path)
	}
	has, err := hasAccount(uid)
	if err != nil {
		return UnixOpenCodeServicePortUnknown{}, fmt.Errorf("cannot confirm that uid %d has no account, so its entry stays: %w", uid, err)
	}
	if has {
		return UnixOpenCodeServicePortUnknown{}, fmt.Errorf("uid %d still resolves to an account on this host, so its entry is not stale and stays; repair the account service.json as the warning says", uid)
	}
	state.Unknown = kept
	return removed, WriteUnixOpenCodeServicePortsFull(path, state)
}
