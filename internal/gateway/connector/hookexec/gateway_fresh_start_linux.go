// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// perUserFreshGatewayWindow covers the short interval after a gateway start
// when its listener has returned but the first hook answer is still pending.
const perUserFreshGatewayWindow = 12 * time.Second

// PerUserGatewayFreshStartNoAnswer recognizes a no-status call sent to a
// recently started gateway recorded for this account. The connected peer,
// record, executable and kernel start identity must all name one process.
func PerUserGatewayFreshStartNoAnswer(dataDir string, peer *PerUserPeerRecord) bool {
	if dataDir == "" || !filepath.IsAbs(dataDir) || peer == nil {
		return false
	}
	before, ok := peer.wait(50 * time.Millisecond)
	if !ok || before.pid <= 0 || before.identity == "" {
		return false
	}
	start, ok := procidentity.StartTime(before.pid)
	if !ok {
		return false
	}
	age := time.Since(start)
	if age < 0 || age > perUserFreshGatewayWindow {
		return false
	}
	f, err := os.OpenFile(filepath.Join(dataDir, "gateway.pid"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<10 {
		return false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return false
	}
	var record struct {
		PID           int    `json:"pid"`
		Executable    string `json:"executable"`
		DataDir       string `json:"data_dir"`
		StartTime     int64  `json:"start_time"`
		StartIdentity string `json:"start_identity"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, 16<<10+1))
	var trailing any
	if decoder.Decode(&record) != nil || decoder.Decode(&trailing) != io.EOF ||
		record.PID != before.pid || record.StartIdentity != before.identity ||
		record.DataDir != dataDir || record.Executable == "" || record.StartTime <= 0 {
		return false
	}
	// The daemon captures this lower bound before spawning the child. A stale
	// record with a refreshed timestamp cannot make an old peer look fresh.
	recordedStart := time.Unix(record.StartTime, 0)
	if recordedStart.After(start.Add(2*time.Second)) || start.Sub(recordedStart) > 30*time.Second {
		return false
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(before.pid) + "/exe")
	if err != nil || strings.TrimSuffix(executable, " (deleted)") != record.Executable {
		return false
	}
	identity, ok := procidentity.Of(before.pid)
	return ok && identity == before.identity
}
