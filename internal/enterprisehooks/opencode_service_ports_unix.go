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
// GAP-0053): the one its service.json named, or the one the guardian wrote.
// Assignment keeps these, so an account's port never moves and a new
// account never takes another's.
const UnixOpenCodeServicePortsFileName = "opencode-service-ports.json"

const unixOpenCodeServicePortsMaxBytes = 1 << 20

type unixOpenCodeServicePortsFile struct {
	Version int                       `json:"version"`
	Ports   []UnixOpenCodeServicePort `json:"ports"`
}

// UnixOpenCodeServicePort is one account's entry.
type UnixOpenCodeServicePort struct {
	UID  int    `json:"uid"`
	User string `json:"user"`
	Port int    `json:"port"`
}

// LoadUnixOpenCodeServicePorts reads the record at path (none: empty).
func LoadUnixOpenCodeServicePorts(path string) (map[int]int, error) {
	ports := map[int]int{}
	path = filepath.Clean(strings.TrimSpace(path))
	if err := validateRootOwnedDirChain(filepath.Dir(path)); err != nil {
		return ports, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ports, nil
	}
	if err != nil {
		return ports, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return ports, fmt.Errorf("enterprise hooks: OpenCode service ports record %s must be a 0600 regular file", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || (st.Uid != 0 && !unixManifestTestOwnerAllowed(st.Uid)) || st.Nlink != 1 {
		return ports, fmt.Errorf("enterprise hooks: OpenCode service ports record %s is not a root-owned single-link file", path)
	}
	data, err := readBoundedFile(path, unixOpenCodeServicePortsMaxBytes)
	if err != nil {
		return ports, err
	}
	var record unixOpenCodeServicePortsFile
	if err := json.Unmarshal(data, &record); err != nil {
		return ports, fmt.Errorf("enterprise hooks: parse OpenCode service ports record: %w", err)
	}
	if record.Version != 1 {
		return ports, fmt.Errorf("enterprise hooks: OpenCode service ports record version %d is not supported", record.Version)
	}
	for _, entry := range record.Ports {
		if entry.UID > 0 && entry.Port > 0 && entry.Port <= 65535 {
			ports[entry.UID] = entry.Port
		}
	}
	return ports, nil
}

// WriteUnixOpenCodeServicePorts publishes the record at path, root-only.
func WriteUnixOpenCodeServicePorts(path string, ports map[int]int, users map[int]string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return fmt.Errorf("enterprise hooks: OpenCode service ports path must be absolute: %s", path)
	}
	record := unixOpenCodeServicePortsFile{Version: 1, Ports: []UnixOpenCodeServicePort{}}
	for uid, port := range ports {
		record.Ports = append(record.Ports, UnixOpenCodeServicePort{UID: uid, User: users[uid], Port: port})
	}
	sort.Slice(record.Ports, func(i, j int) bool { return record.Ports[i].UID < record.Ports[j].UID })
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeUnixRootOnlyRecord(path, append(data, '\n'), ".defenseclaw-opencode-ports-*.new", unixOpenCodeServicePortsMaxBytes)
}
