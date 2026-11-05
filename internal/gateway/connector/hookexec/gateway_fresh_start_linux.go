// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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

// perUserGatewayRecentlyStarted is the cheap first look of the native hook
// (one lstat per call): this account's gateway record was written within
// the fresh-start window, so a gateway may have started moments ago.
func perUserGatewayRecentlyStarted(dataDir string) bool {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return false
	}
	info, err := os.Lstat(filepath.Join(dataDir, "gateway.pid"))
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	age := time.Since(info.ModTime())
	return age > -2*time.Second && age <= perUserFreshGatewayWindow+2*time.Second
}

// perUserFreshGatewayHoldsCall is the native hook's restart-window proof
// (rel-1-0-6 GAP-0295): the server end of the call's proven connection
// (check) is held by the gateway this account's record names, that process
// started within perUserFreshGatewayWindow (kernel start time, executable and
// start identity all match the record), and it has completed no hook answer
// yet. A gateway that answered any call, an old gateway, an unknown holder
// and an unreadable record are no proof.
func perUserFreshGatewayHoldsCall(dataDir string, check *perUserPeerCheck) bool {
	return perUserFreshGatewayProof(dataDir, check).ok
}

func perUserFreshGatewayProof(dataDir string, check *perUserPeerCheck) restartProofResult {
	if check == nil {
		return restartProofResult{reason: "no_verified_connection"}
	}
	ends := check.ends.Load()
	if ends == nil {
		return restartProofResult{reason: "no_verified_connection"}
	}
	client, okc := ends.local.(*net.TCPAddr)
	server, oks := ends.remote.(*net.TCPAddr)
	if !okc || !oks {
		return restartProofResult{reason: "no_verified_connection"}
	}
	current, ok := freshGatewayFromRecord(dataDir)
	if !ok {
		return restartProofResult{reason: "not_fresh"}
	}
	if !perUserProcessHoldsConnection(current.pid, client, server) {
		return restartProofResult{reason: "no_holder"}
	}
	// The pid was not reused while its files were read.
	if identity, ok := procidentity.Of(current.pid); !ok || identity != current.identity {
		return restartProofResult{reason: "not_fresh"}
	}
	// Calls that reach a restarted gateway together are answered in no
	// set order: a sibling answered first does not make this one a call
	// the serving gateway took and withheld. What counts is whether the
	// gateway had completed any answer before this connection reached it
	// (rel-1-0-6 GAP-0295, v108k).
	before, valid := perUserGatewayAnsweredBefore(dataDir, current, ends.at)
	if !valid {
		return restartProofResult{reason: "answer_record_unavailable"}
	}
	if before {
		return restartProofResult{reason: "answered_before"}
	}
	return restartProofResult{ok: true}
}

func verifiedFreshGatewayPeer(dataDir string, peer *PerUserPeerRecord) (perUserPeerProcess, bool) {
	if dataDir == "" || !filepath.IsAbs(dataDir) || peer == nil {
		return perUserPeerProcess{}, false
	}
	before, ok := peer.wait(50 * time.Millisecond)
	if !ok || before.pid <= 0 || before.identity == "" {
		return perUserPeerProcess{}, false
	}
	current, ok := freshGatewayFromRecord(dataDir)
	return current, ok && current.pid == before.pid && current.identity == before.identity
}

func freshGatewayFromRecord(dataDir string) (perUserPeerProcess, bool) {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
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
		record.PID <= 0 || record.StartIdentity == "" || record.DataDir != dataDir ||
		record.Executable == "" || record.StartTime <= 0 {
		return perUserPeerProcess{}, false
	}
	start, ok := procidentity.StartTime(record.PID)
	if !ok {
		return perUserPeerProcess{}, false
	}
	age := time.Since(start)
	if age < 0 || age > perUserFreshGatewayWindow {
		return perUserPeerProcess{}, false
	}
	// The daemon captures this lower bound before spawning the child. A stale
	// record with a refreshed timestamp cannot make an old peer look fresh.
	recordedStart := time.Unix(record.StartTime, 0)
	if recordedStart.After(start.Add(2*time.Second)) || start.Sub(recordedStart) > 30*time.Second {
		return perUserPeerProcess{}, false
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(record.PID) + "/exe")
	if err != nil || strings.TrimSuffix(executable, " (deleted)") != record.Executable {
		return perUserPeerProcess{}, false
	}
	identity, ok := procidentity.Of(record.PID)
	return perUserPeerProcess{pid: record.PID, identity: identity}, ok && identity == record.StartIdentity
}

func perUserGatewayAnswerPath(dataDir string, peer perUserPeerProcess) string {
	sum := sha256.Sum256([]byte(strconv.Itoa(peer.pid) + ":" + peer.identity))
	return filepath.Join(dataDir, "gateway.answer."+fmt.Sprintf("%x", sum[:16]))
}

// perUserGatewayAnsweredBefore reports whether peer recorded its first
// completed hook answer at or before at (the marker's modification time,
// written once before that answer was sent). The kernel stamps it with a
// coarse clock that can only lag, so an error makes an answer look earlier:
// the call then stays closed. A zero at, or a marker that cannot be read, is
// treated as answered before.
func perUserGatewayAnsweredBefore(dataDir string, peer perUserPeerProcess, at time.Time) (before, valid bool) {
	answered, valid := perUserGatewayAnswerSeen(dataDir, peer)
	if !valid || !answered {
		return answered, valid
	}
	if at.IsZero() {
		return true, true
	}
	info, err := os.Lstat(perUserGatewayAnswerPath(dataDir, peer))
	if err != nil || !info.Mode().IsRegular() {
		return true, false
	}
	return !info.ModTime().After(at), true
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
	return recordPerUserGatewayAnswer(dataDir, current)
}

// PerUserGatewayRecordObservedAnswer preserves a completed response even if
// the start record has not yet been published. A known connected peer is
// identified by the kernel; a completed reply may also use the sole owner
// of the verified listener when the accepted socket has already closed.
func PerUserGatewayRecordObservedAnswer(dataDir string, peer *PerUserPeerRecord) {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return
	}
	if observed, known := peer.wait(0); known {
		_ = recordPerUserGatewayAnswer(dataDir, observed)
		return
	}
	current, ok := freshGatewayFromRecord(dataDir)
	if ok {
		_ = recordPerUserGatewayAnswer(dataDir, current)
		return
	}
	server, connected := peer.connectedServer()
	if !connected {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	owners, found := perUserListenerOwners(ctx, server)
	if found && ctx.Err() == nil && len(owners) == 1 && owners[0].identity != "" {
		_ = recordPerUserGatewayAnswer(dataDir, owners[0])
	}
}

func recordPerUserGatewayAnswer(dataDir string, current perUserPeerProcess) error {
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
