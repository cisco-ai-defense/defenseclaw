// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	current, ok := verifiedFreshGatewayPeer(dataDir, peer)
	if !ok {
		return false
	}
	answered, valid := perUserGatewayAnswerSeen(dataDir, current)
	return valid && !answered
}

func verifiedFreshGatewayPeer(dataDir string, peer *PerUserPeerRecord) (perUserPeerProcess, bool) {
	if dataDir == "" || !filepath.IsAbs(dataDir) || peer == nil {
		return perUserPeerProcess{}, false
	}
	before, ok := peer.wait(50 * time.Millisecond)
	if !ok || before.pid <= 0 || before.identity == "" {
		return perUserPeerProcess{}, false
	}
	start, ok := procidentity.StartTime(before.pid)
	if !ok {
		return perUserPeerProcess{}, false
	}
	age := time.Since(start)
	if age < 0 || age > perUserFreshGatewayWindow {
		return perUserPeerProcess{}, false
	}
	f, err := os.OpenFile(filepath.Join(dataDir, "gateway.pid"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return perUserPeerProcess{}, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<10 {
		return perUserPeerProcess{}, false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return perUserPeerProcess{}, false
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
		return perUserPeerProcess{}, false
	}
	// The daemon captures this lower bound before spawning the child. A stale
	// record with a refreshed timestamp cannot make an old peer look fresh.
	recordedStart := time.Unix(record.StartTime, 0)
	if recordedStart.After(start.Add(2*time.Second)) || start.Sub(recordedStart) > 30*time.Second {
		return perUserPeerProcess{}, false
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(before.pid) + "/exe")
	if err != nil || strings.TrimSuffix(executable, " (deleted)") != record.Executable {
		return perUserPeerProcess{}, false
	}
	identity, ok := procidentity.Of(before.pid)
	return before, ok && identity == before.identity
}

func perUserGatewayAnswerPath(dataDir string, peer perUserPeerProcess) string {
	sum := sha256.Sum256([]byte(strconv.Itoa(peer.pid) + ":" + peer.identity))
	return filepath.Join(dataDir, "gateway.answer."+fmt.Sprintf("%x", sum[:16]))
}

func perUserGatewayAnswerSeen(dataDir string, peer perUserPeerProcess) (answered, valid bool) {
	f, err := os.OpenFile(perUserGatewayAnswerPath(dataDir, peer), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, true
	}
	if err != nil {
		return false, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256 {
		return false, false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return false, false
	}
	var record struct {
		PID      int    `json:"pid"`
		Identity string `json:"identity"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, 257))
	var trailing any
	if decoder.Decode(&record) != nil || decoder.Decode(&trailing) != io.EOF {
		return false, false
	}
	if record.PID != peer.pid || record.Identity != peer.identity {
		return false, false
	}
	return true, true
}

// PerUserGatewayRecordLocalAnswer records the process's first completed hook
// answer before sending it to a client. The marker is scoped to the kernel
// process identity, so a restart begins with an unanswered window of its own.
func PerUserGatewayRecordLocalAnswer(dataDir string) error {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return nil
	}
	identity, ok := procidentity.Of(os.Getpid())
	if !ok || identity == "" {
		return errors.New("gateway answer identity unavailable")
	}
	current := perUserPeerProcess{pid: os.Getpid(), identity: identity}
	if answered, valid := perUserGatewayAnswerSeen(dataDir, current); answered && valid {
		return nil
	} else if !valid {
		return errors.New("gateway answer record unavailable")
	}
	f, err := os.OpenFile(perUserGatewayAnswerPath(dataDir, current), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, os.ErrExist) {
		if answered, valid := perUserGatewayAnswerSeen(dataDir, current); answered && valid {
			return nil
		}
		return errors.New("gateway answer record incomplete")
	}
	if err != nil {
		return err
	}
	defer f.Close()
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(perUserGatewayAnswerPath(dataDir, current))
		}
	}()
	if err := json.NewEncoder(f).Encode(struct {
		PID      int    `json:"pid"`
		Identity string `json:"identity"`
	}{current.pid, current.identity}); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	complete = true
	return nil
}
