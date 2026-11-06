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
	// any user file is rewritten, so a record that exists never reopens the
	// import window. A record an earlier round wrote has no flag and counts
	// as done.
	ImportDone bool `json:"import_done,omitempty"`
}

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
	// ImportDone: the record was committed by an import pass (or an earlier
	// build: a record that exists is done).
	ImportDone bool
	Ports      map[int]int
	Users      map[int]string
	Unknown    []UnixOpenCodeServicePortUnknown
	Contested  []UnixOpenCodeContestedPort
	Cleared    []UnixOpenCodeContestCleared
}

// LoadUnixOpenCodeServicePorts reads the record at path (none: empty).
func LoadUnixOpenCodeServicePorts(path string) (map[int]int, error) {
	state, err := LoadUnixOpenCodeServicePortsFull(path)
	return state.Ports, err
}

// LoadUnixOpenCodeServicePortsState is LoadUnixOpenCodeServicePorts with the
// accounts the last pass could not read or write.
func LoadUnixOpenCodeServicePortsState(path string) (map[int]int, []UnixOpenCodeServicePortUnknown, error) {
	state, err := LoadUnixOpenCodeServicePortsFull(path)
	return state.Ports, state.Unknown, err
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
	state.ImportDone = true // the flag, or a record an earlier round wrote
	for _, entry := range record.Contested {
		if entry.Port > 0 && entry.Port <= 65535 {
			state.Contested = append(state.Contested, entry)
		}
	}
	return state, nil
}

// WriteUnixOpenCodeServicePorts publishes a record of ports and unknown
// accounts at path, root-only.
func WriteUnixOpenCodeServicePorts(path string, ports map[int]int, users map[int]string, unknown []UnixOpenCodeServicePortUnknown) error {
	return WriteUnixOpenCodeServicePortsFull(path, UnixOpenCodeServicePortsState{Ports: ports, Users: users, Unknown: unknown})
}

// WriteUnixOpenCodeServicePortsFull publishes the whole record at path,
// root-only.
func WriteUnixOpenCodeServicePortsFull(path string, state UnixOpenCodeServicePortsState) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return fmt.Errorf("enterprise hooks: OpenCode service ports path must be absolute: %s", path)
	}
	record := unixOpenCodeServicePortsFile{Version: 1, Ports: []UnixOpenCodeServicePort{}, ImportDone: true}
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
	if err := writeUnixRootOnlyRecord(path, append(data, '\n'), ".defenseclaw-opencode-ports-*.new", unixOpenCodeServicePortsMaxBytes); err != nil {
		return err
	}
	return syncUnixDir(filepath.Dir(path))
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
