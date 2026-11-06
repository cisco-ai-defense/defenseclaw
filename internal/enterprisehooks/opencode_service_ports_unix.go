// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
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
	Exists    bool
	Ports     map[int]int
	Users     map[int]string
	Unknown   []UnixOpenCodeServicePortUnknown
	Contested []UnixOpenCodeContestedPort
	Cleared   []UnixOpenCodeContestCleared
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
	record := unixOpenCodeServicePortsFile{Version: 1, Ports: []UnixOpenCodeServicePort{}}
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
	return writeUnixRootOnlyRecord(path, append(data, '\n'), ".defenseclaw-opencode-ports-*.new", unixOpenCodeServicePortsMaxBytes)
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
