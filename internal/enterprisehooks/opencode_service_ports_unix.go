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
	// could not read as the account (its worker failed or timed out): no
	// port was given that pass. Status and verify name them. Additive to
	// version 1: an earlier loader ignores it.
	Unknown []UnixOpenCodeServicePortUnknown `json:"unknown,omitempty"`
}

// UnixOpenCodeServicePortUnknown is one account the last pass could not read.
type UnixOpenCodeServicePortUnknown struct {
	UID    int    `json:"uid"`
	User   string `json:"user"`
	Reason string `json:"reason"`
	// Path is the account's service.json; Fix is the administrator's step
	// that clears the warning.
	Path string `json:"path,omitempty"`
	Fix  string `json:"fix,omitempty"`
}

// UnixOpenCodeServicePort is one account's entry.
type UnixOpenCodeServicePort struct {
	UID  int    `json:"uid"`
	User string `json:"user"`
	Port int    `json:"port"`
}

// LoadUnixOpenCodeServicePorts reads the record at path (none: empty).
func LoadUnixOpenCodeServicePorts(path string) (map[int]int, error) {
	ports, _, err := LoadUnixOpenCodeServicePortsState(path)
	return ports, err
}

// LoadUnixOpenCodeServicePortsState is LoadUnixOpenCodeServicePorts with the
// accounts the last pass could not read or write.
func LoadUnixOpenCodeServicePortsState(path string) (map[int]int, []UnixOpenCodeServicePortUnknown, error) {
	ports := map[int]int{}
	path = filepath.Clean(strings.TrimSpace(path))
	if err := validateRootOwnedDirChain(filepath.Dir(path)); err != nil {
		return ports, nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ports, nil, nil
	}
	if err != nil {
		return ports, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return ports, nil, fmt.Errorf("enterprise hooks: OpenCode service ports record %s must be a 0600 regular file", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || (st.Uid != 0 && !unixManifestTestOwnerAllowed(st.Uid)) || st.Nlink != 1 {
		return ports, nil, fmt.Errorf("enterprise hooks: OpenCode service ports record %s is not a root-owned single-link file", path)
	}
	data, err := readBoundedFile(path, unixOpenCodeServicePortsMaxBytes)
	if err != nil {
		return ports, nil, err
	}
	var record unixOpenCodeServicePortsFile
	if err := json.Unmarshal(data, &record); err != nil {
		return ports, nil, fmt.Errorf("enterprise hooks: parse OpenCode service ports record: %w", err)
	}
	if record.Version != 1 {
		return ports, nil, fmt.Errorf("enterprise hooks: OpenCode service ports record version %d is not supported", record.Version)
	}
	for _, entry := range record.Ports {
		if entry.UID > 0 && entry.Port > 0 && entry.Port <= 65535 {
			ports[entry.UID] = entry.Port
		}
	}
	return ports, record.Unknown, nil
}

// WriteUnixOpenCodeServicePorts publishes the record at path, root-only.
func WriteUnixOpenCodeServicePorts(path string, ports map[int]int, users map[int]string, unknown []UnixOpenCodeServicePortUnknown) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return fmt.Errorf("enterprise hooks: OpenCode service ports path must be absolute: %s", path)
	}
	record := unixOpenCodeServicePortsFile{Version: 1, Ports: []UnixOpenCodeServicePort{}}
	for uid, port := range ports {
		record.Ports = append(record.Ports, UnixOpenCodeServicePort{UID: uid, User: users[uid], Port: port})
	}
	sort.Slice(record.Ports, func(i, j int) bool { return record.Ports[i].UID < record.Ports[j].UID })
	record.Unknown = append(record.Unknown, unknown...)
	sort.Slice(record.Unknown, func(i, j int) bool { return record.Unknown[i].UID < record.Unknown[j].UID })
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeUnixRootOnlyRecord(path, append(data, '\n'), ".defenseclaw-opencode-ports-*.new", unixOpenCodeServicePortsMaxBytes)
}
