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
	"github.com/defenseclaw/defenseclaw/internal/proofclock"
)

// perUserFreshGatewayWindow covers the short interval after a gateway start
// when its listener has returned but the first hook answer is still pending.
const perUserFreshGatewayWindow = 12 * time.Second

// freshOwnerCaptureWait bounds the background read of the sole holder of a
// verified connection (perUserCaptureFreshGatewayOwner); a read past it
// leaves the owner unknown and the call closed.
const freshOwnerCaptureWait = time.Second

// PerUserGatewayFreshStartNoAnswer recognizes a no-status call sent to a
// recently started gateway recorded for this account. The connected peer,
// record, executable and kernel start identity must all name one process.
// An answer counts only if it finished before this connection was proven.
// The second result names the bounded reason when the proof is unavailable.
func PerUserGatewayFreshStartNoAnswer(dataDir string, peer *PerUserPeerRecord) (bool, string) {
	if dataDir == "" || !filepath.IsAbs(dataDir) || peer == nil {
		return false, "no_verified_connection"
	}
	connected, ok := peer.wait(50 * time.Millisecond)
	if !ok || connected.pid <= 0 || connected.identity == "" {
		return false, "no_holder"
	}
	current, ok := freshGatewayFromRecord(dataDir)
	if !ok {
		return false, "not_fresh"
	}
	if current.pid != connected.pid || current.identity != connected.identity {
		return false, "no_holder"
	}
	before, valid := perUserGatewayAnsweredBefore(dataDir, current, peer.at)
	if !valid {
		return false, "answer_record_unavailable"
	}
	if before {
		return false, "answered_before"
	}
	return true, ""
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
	age := proofclock.Since(info.ModTime())
	return age > -2*time.Second && age <= perUserFreshGatewayWindow+2*time.Second
}

// perUserFreshGatewayProof is the native hook's restart-window proof
// (rel-1-0-6 GAP-0295): the server end of the call's proven connection
// (check) was held by the gateway this account's record names when the
// connection was open, or is still held at the deadline. That process
// started within perUserFreshGatewayWindow (kernel start time, executable and
// start identity all match the record), and it had completed no hook answer
// before the connection. An old gateway, an unknown holder and an unreadable
// record are no proof.
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
	if owner := check.owner.Load(); owner != nil {
		if owner.pid != current.pid || owner.identity != current.identity {
			return restartProofResult{reason: "no_holder"}
		}
	} else {
		// The accepted socket must have exactly one holder, as on the
		// shell helper's connection proof. A capture taken earlier also
		// preserves this fact if the socket closed at the deadline.
		holder, unique := perUserConnectedPeerPID(client, server)
		if !unique || holder != current.pid {
			return restartProofResult{reason: "no_holder"}
		}
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

// perUserCaptureFreshGatewayOwner records the sole holder while the call's
// verified connection is open. A canceled request can close that socket at
// the answer deadline before the proof runs. Capture runs only for a recent
// gateway record and never delays the request.
func perUserCaptureFreshGatewayOwner(check *perUserPeerCheck) {
	if check == nil {
		return
	}
	ends := check.ends.Load()
	if ends == nil {
		return
	}
	client, okc := ends.local.(*net.TCPAddr)
	server, oks := ends.remote.(*net.TCPAddr)
	if !okc || !oks {
		return
	}
	go captureFreshGatewayOwner(check, client, server, perUserConnectedPeerPIDWithin)
}

// captureFreshGatewayOwner reads the sole holder of the connection with scan
// and records it when the read ends inside freshOwnerCaptureWait on the proof
// clock. A read that ends after that wait names no owner, whatever it found.
// scan is the process-table read; a test replaces it to end the read at a
// moment it chooses.
func captureFreshGatewayOwner(check *perUserPeerCheck, client, server *net.TCPAddr, scan func(context.Context, *net.TCPAddr, *net.TCPAddr) (int, bool)) {
	ctx, cancel := proofclock.WithTimeout(context.Background(), freshOwnerCaptureWait)
	defer cancel()
	pid, ok := scan(ctx, client, server)
	if !ok {
		return
	}
	identity, ok := procidentity.Of(pid)
	if ok && identity != "" && ctx.Err() == nil {
		check.owner.Store(&perUserPeerProcess{pid: pid, identity: identity})
	}
}

func freshGatewayFromRecord(dataDir string) (perUserPeerProcess, bool) {
	record, ok := readGatewayRecord(dataDir)
	if !ok {
		return perUserPeerProcess{}, false
	}
	start, ok := procidentity.StartTime(record.PID)
	if !ok {
		return perUserPeerProcess{}, false
	}
	age := proofclock.Since(start)
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
	if !procidentity.IsRecorded(record.PID, record.StartIdentity) {
		return perUserPeerProcess{}, false
	}
	identity, ok := procidentity.Of(record.PID)
	return perUserPeerProcess{pid: record.PID, identity: identity}, ok
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
	ctx, cancel := proofclock.WithTimeout(context.Background(), 50*time.Millisecond)
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
