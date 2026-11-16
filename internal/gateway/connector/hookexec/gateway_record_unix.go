// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package hookexec

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// gatewayRecord is the gateway.pid record of this account's gateway.
type gatewayRecord struct {
	PID           int    `json:"pid"`
	Executable    string `json:"executable"`
	DataDir       string `json:"data_dir"`
	StartTime     int64  `json:"start_time"`
	StartIdentity string `json:"start_identity"`
}

// readGatewayRecord reads dataDir/gateway.pid when it is a regular file of
// this account that holds one complete record for dataDir.
func readGatewayRecord(dataDir string) (gatewayRecord, bool) {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return gatewayRecord{}, false
	}
	f, err := os.OpenFile(filepath.Join(dataDir, "gateway.pid"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return gatewayRecord{}, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<10 {
		return gatewayRecord{}, false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return gatewayRecord{}, false
	}
	var record gatewayRecord
	decoder := json.NewDecoder(io.LimitReader(f, 16<<10+1))
	var trailing any
	if decoder.Decode(&record) != nil || decoder.Decode(&trailing) != io.EOF ||
		record.PID <= 0 || record.StartIdentity == "" || record.DataDir != dataDir ||
		record.Executable == "" || record.StartTime <= 0 {
		return gatewayRecord{}, false
	}
	return record, true
}

// recordedGatewayPID is the process the record in dataDir names, when that
// process is alive and is the one the record describes: its kernel start
// identity matches, in the text the gateway writes it in (procidentity.Recorded,
// shared with the gateway), so a reused PID is no match. A stopped process is
// alive.
func recordedGatewayPID(dataDir string) (int, bool) {
	record, ok := readGatewayRecord(dataDir)
	if !ok {
		return 0, false
	}
	if !procidentity.IsRecorded(record.PID, record.StartIdentity) {
		return 0, false
	}
	return record.PID, true
}
