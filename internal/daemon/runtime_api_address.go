// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"encoding/json"
	"net"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// RuntimeAPIAddress is the loopback listener the gateway with PID pid
// published in dataDir (gateway-api.json, recordRuntimeAPIAddress), or nil:
// the record must be a private regular file (0600 on POSIX, an owner-only
// protected DACL on Windows, no link) that names pid and a loopback address.
func RuntimeAPIAddress(dataDir string, pid int) *net.TCPAddr {
	if pid <= 0 || !filepath.IsAbs(dataDir) {
		return nil
	}
	record := filepath.Join(filepath.Clean(dataDir), "gateway-api.json")
	if err := safefile.ValidatePrivateFile(record); err != nil {
		return nil
	}
	raw, err := safefile.ReadRegularFileBounded(record, 4<<10)
	if err != nil {
		return nil
	}
	var published struct {
		PID  int    `json:"pid"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if json.Unmarshal(raw, &published) != nil || published.PID != pid || published.Port < 1 || published.Port > 65535 {
		return nil
	}
	ip := net.ParseIP(published.Host)
	if ip == nil || !ip.IsLoopback() {
		return nil
	}
	return &net.TCPAddr{IP: ip, Port: published.Port}
}

// ProcessSignalable reports whether this account may signal pid: false only
// for a live process of another account, such as the gateway an
// administrator started for this home.
func ProcessSignalable(pid int) bool { return processSignalable(pid) }
