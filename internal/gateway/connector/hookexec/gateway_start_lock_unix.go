// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// perUserGatewayStartLockName is the per-data-directory lock that a
// `defenseclaw-gateway start`, `restart` and a hook cold start hold while they
// bring this account's gateway down and up (internal/cli gatewayStartLockName,
// acquireGatewayStartLock): `restart` holds it from before the stop until the
// new gateway is ready.
const perUserGatewayStartLockName = "gateway.start.lock"

// PerUserGatewayStartInProgress reports whether a start, restart or hook
// cold start of the per-user gateway whose data directory is dataDir holds
// its start lock now. Only a regular file this account owns counts; any
// other state, or a lock nobody holds, is no start.
func PerUserGatewayStartInProgress(dataDir string) bool {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return false
	}
	f, err := os.OpenFile(filepath.Join(dataDir, perUserGatewayStartLockName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return false
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return false
	}
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}

// PerUserGatewayRestartProven reports a no-answer of a per-user call that a
// restart of this account's gateway explains (rel-1-0-6 GAP-0295, lead
// ruling): a start, restart or hook cold start holds the start lock now
// (PerUserGatewayStartInProgress), and the process that owned the server
// end of the connection this call was sent on (peer, read from the kernel
// when the call connected) is gone, was replaced (its pid now names another
// process), or no longer owns the gateway port because another process
// listens there. Nothing an agent can write decides it: an unknown peer, a
// peer that cannot be read again, and a port nobody listens on are no proof,
// and a held lock while the same gateway stays up and slow is a gateway that
// is up and slow: the call stays closed (GAP-2279).
func PerUserGatewayRestartProven(dataDir string, peer *PerUserPeerRecord) bool {
	if !PerUserGatewayStartInProgress(dataDir) {
		return false
	}
	before, ok := peer.wait(perUserPeerReadWait)
	if !ok {
		return false
	}
	if perUserPeerGone(before) {
		return true
	}
	owner, ok := perUserListenerOwner(before.server)
	if !ok || owner.pid == before.pid {
		return false
	}
	return owner.identity != "" && owner.identity != before.identity
}

// perUserPeerGone reports a peer process that has exited (no such process,
// or ended and not reaped) or whose pid now names another process (another
// start identity). A process the system cannot name is no proof.
func perUserPeerGone(peer perUserPeerProcess) bool {
	if err := syscall.Kill(peer.pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	} else if err != nil {
		return false
	}
	if procidentity.Ended(peer.pid) {
		return true
	}
	identity, ok := procidentity.Of(peer.pid)
	return ok && identity != peer.identity
}
