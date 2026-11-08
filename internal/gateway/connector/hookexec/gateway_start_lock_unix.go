// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
	"github.com/defenseclaw/defenseclaw/internal/proofclock"
)

// perUserGatewayStartLockName is the per-data-directory lock that a
// `defenseclaw-gateway start`, `restart` and a hook cold start hold while they
// bring this account's gateway down and up (internal/cli gatewayStartLockName,
// acquireGatewayStartLock): `restart` holds it from before the stop until the
// new gateway is ready.
const perUserGatewayStartLockName = "gateway.start.lock"

// perUserStartLockOpen opens the start lock for the look: no link is
// followed, and the open never waits (O_NONBLOCK), so a FIFO or another
// file that blocks its open in the lock's place cannot hang the call; the
// regular-file check below refuses it (review r4). A test seam.
var perUserStartLockOpen = func(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// PerUserGatewayStartInProgress reports whether a start, restart or hook
// cold start of the per-user gateway whose data directory is dataDir holds
// its start lock now. Only a regular file this account owns counts; any
// other state, or a lock nobody holds, is no start.
func PerUserGatewayStartInProgress(dataDir string) bool {
	return perUserGatewayStartInProgressWith(perUserStartLockOpen, dataDir)
}

// perUserGatewayStartInProgressWith is PerUserGatewayStartInProgress with
// the lock opened by open.
func perUserGatewayStartInProgressWith(open func(string) (*os.File, error), dataDir string) bool {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return false
	}
	f, err := open(filepath.Join(dataDir, perUserGatewayStartLockName))
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
// ruling): a start, restart or hook cold start holds the start lock at the
// deadline, and the process that owned the server
// end of the connection this call was sent on (peer, read from the kernel
// when the call connected) is gone, was replaced (its pid now names another
// process), or no longer owns the gateway port because another process
// listens there. Nothing an agent can write decides it: an unknown peer, a
// peer that cannot be read again, and a port nobody listens on are no proof,
// and a held lock while the same gateway stays up and slow is a gateway that
// is up and slow: the call stays closed (GAP-2279).
//
// The whole proof runs within perUserRestartProofBudget after the call's
// deadline (review r3 finding 3): a proof that is not done by then is no
// proof, and hook-post exits 9.
func PerUserGatewayRestartProven(dataDir string, peer *PerUserPeerRecord) bool {
	return PerUserGatewayRestartProvenDuringCall(dataDir, peer, false)
}

// PerUserGatewayRestartProvenDuringCall also accepts a start lock observed
// after this request reached its verified socket. The lock may have been
// released by the time the unanswered request reaches its deadline. A changed
// peer is still required; a gateway that remains up and slow stays closed.
func PerUserGatewayRestartProvenDuringCall(dataDir string, peer *PerUserPeerRecord, startObserved bool) bool {
	ctx, cancel := proofclock.WithTimeout(context.Background(), perUserRestartProofBudget)
	defer cancel()
	proven := make(chan bool, 1)
	// Read now: a proof past its budget leaves the goroutine running
	// (GAP-0680).
	open := perUserStartLockOpen
	go func() { proven <- perUserGatewayRestartProof(ctx, open, dataDir, peer, startObserved) }()
	select {
	case ok := <-proven:
		return ok && ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

// perUserRestartProofBudget bounds PerUserGatewayRestartProven.
var perUserRestartProofBudget = 300 * time.Millisecond

func perUserGatewayRestartProof(ctx context.Context, open func(string) (*os.File, error), dataDir string, peer *PerUserPeerRecord, startObserved bool) bool {
	if !startObserved && !perUserGatewayStartInProgressWith(open, dataDir) {
		return false
	}
	wait := perUserPeerReadWait
	if deadline, ok := ctx.Deadline(); ok && proofclock.Until(deadline) < wait {
		wait = proofclock.Until(deadline)
	}
	before, ok := peer.wait(wait)
	if !ok {
		return false
	}
	if perUserPeerGone(before) {
		return true
	}
	// Every process of this account that holds a listener on the exact
	// gateway address now (review r3 findings 1 and 2): the old peer among
	// them is no change, whatever else holds one.
	owners, ok := perUserListenerOwners(ctx, before.server)
	if !ok || ctx.Err() != nil {
		return false
	}
	other := false
	for _, owner := range owners {
		if owner.pid == before.pid {
			return false
		}
		if owner.identity != "" && owner.identity != before.identity {
			other = true
		}
	}
	return other
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
