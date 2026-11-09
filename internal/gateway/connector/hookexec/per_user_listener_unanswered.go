// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// errPerUserNotAccepted ends the wait for a connection that sat in the accept
// queue of its listener and was never accepted, so no process has shown that
// it holds the socket. It proves nothing about who listens: the transport
// reads the listener's owner next (classifyUnaccepted).
var errPerUserNotAccepted = errors.New("connected gateway server socket was not accepted in time")

// unansweredMargin is how long before the connect deadline of a try the
// transport decides a still-queued connection, so the decision is made
// before connectBy ends the try; queueDwell is the least time a connection
// sat in the queue before it is decided, so a gateway that is about to accept
// is never read as stopped. A gateway that accepts up to the decision still
// gets the call and answers it, so the margin stays short: it is not the time
// the owner scan may take. The scan of a decided connection is not cut by the
// connect deadline (ownerScanGrace in connectBy): a busy host reads every
// process of the account for hundreds of milliseconds (560 ms measured at
// load 130), and a scan cut at the deadline ends the try as an unverified
// peer, a false block of an ordinary call to the own frozen gateway of the
// account.
const (
	unansweredMargin = 250 * time.Millisecond
	queueDwell       = 500 * time.Millisecond
)

type perUserGatewayHomesKey struct{}

// withPerUserGatewayHomes names, for the connections made under ctx, the
// folders that may hold this account's gateway.pid record. homes is read only
// when a connection waits unaccepted.
func withPerUserGatewayHomes(ctx context.Context, homes func() []string) context.Context {
	return context.WithValue(ctx, perUserGatewayHomesKey{}, homes)
}

// WithPerUserGatewayDataDir names the folder that holds this account's
// gateway.pid for the per-user connections made under ctx.
func WithPerUserGatewayDataDir(ctx context.Context, dataDir string) context.Context {
	if dataDir == "" {
		return ctx
	}
	return withPerUserGatewayHomes(ctx, func() []string { return []string{dataDir} })
}

// classifyUnaccepted turns the end of a wait for an accept into the one thing
// it can prove. A connection that stayed in the accept queue of a listener
// that is the recorded gateway of this account, and of no other process, is
// this account's gateway stopped or frozen (errPerUserListenerUnanswered). A
// listener of another account, another process of this account, a gateway
// the record does not name, or a table that cannot be read is no proof, and
// the error is returned as it is.
func classifyUnaccepted(ctx context.Context, err error, server *net.TCPAddr) error {
	if err != nil && server != nil && errors.Is(err, errPerUserNotAccepted) && ownGatewayHoldsQueue(ctx, server) {
		return fmt.Errorf("%w: %w", errPerUserListenerUnanswered, err)
	}
	return err
}

// verifyConnected runs verify on conn. A connection still unaccepted shortly
// before check.by (the connect deadline of the try) is decided there, so the
// answer is the transport's and not connectBy's cancel; without a deadline it
// is decided when verify gives up.
func verifyConnected(ctx context.Context, check *perUserPeerCheck, conn net.Conn, verify func(net.Conn) error) error {
	server, _ := conn.RemoteAddr().(*net.TCPAddr)
	if check == nil || check.by.IsZero() || server == nil {
		return classifyUnaccepted(ctx, verify(conn), server)
	}
	done := make(chan error, 1)
	// settled is set once the wait ended in anything but "not accepted": the
	// connection was accepted (its answer is the result) or failed on its own.
	var settled atomic.Bool
	go func() {
		err := verify(conn)
		if !errors.Is(err, errPerUserNotAccepted) {
			settled.Store(true)
		}
		done <- err
	}()
	at := check.by.Add(-unansweredMargin)
	if least := time.Now().Add(queueDwell); at.Before(least) {
		at = least
	}
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case err := <-done:
		return classifyUnaccepted(ctx, err, server)
	case <-timer.C:
	}
	select {
	case err := <-done:
		return classifyUnaccepted(ctx, err, server)
	default:
	}
	// While the owner is read the connect deadline waits for the read
	// (connectBy). A read that says no ends that wait, so a proof that comes
	// after the deadline from anywhere else stays void.
	check.deciding.Store(ownerScanSupported)
	holds := ownGatewayHoldsQueueRetried(ctx, check, conn, &settled)
	// A connection that was accepted while the owner was read has its answer
	// (or its own error): a listener owned by the own gateway does not show
	// that the connection was never accepted. Only a wait that ended as not
	// accepted leaves the finding of the scan to decide.
	select {
	case err := <-done:
		if !holds || !errors.Is(err, errPerUserNotAccepted) {
			check.deciding.Store(false)
			return err
		}
	default:
	}
	if holds {
		if check.abandoned.Load() {
			// The scan outlasted ownerScanGrace and connectBy ended the try:
			// a proof that came after the end of the try is no proof.
			return errPerUserPeerCheckUnfinished
		}
		// deciding stays set until the dial returns this answer
		// (ownerScanEnded sees the check no longer pending).
		return fmt.Errorf("%w: %w", errPerUserListenerUnanswered, errPerUserNotAccepted)
	}
	check.deciding.Store(false)
	// The owner was read and read again (ownGatewayHoldsQueueRetried): the
	// error of the wait stands without a third read.
	return <-done
}

// ownerScanRetry is how long a read of the owner of a queued connection that
// says no is repeated before the no stands. A read on a busy host can fail for
// a moment (a process of the account in the middle of exec, a table read cut
// short), and a refusal blocks an ordinary call to the own frozen gateway of
// the account in every fail mode. A holder that is not the gateway answers no
// at every read, so the wait only delays that block.
const (
	ownerScanRetry = 500 * time.Millisecond
	ownerScanPoll  = 50 * time.Millisecond
)

// ownGatewayHoldsQueueRetried is ownGatewayHoldsQueue repeated, while it says
// no, for ownerScanRetry, and not after the try was abandoned (connectBy) or
// once the wait settled (the connection was accepted or failed on its own;
// the caller reads that result first). Its yes also needs conn itself to be
// seen unaccepted in the socket table after the owner was read: the owner of
// the listener does not show that this connection was never accepted, and a
// gateway that accepted it has an answer that the peer check, which may still
// be running, is about to release (a connection that cannot be seen queued
// is left to that result, which is closed when the peer is not proved).
func ownGatewayHoldsQueueRetried(ctx context.Context, check *perUserPeerCheck, conn net.Conn, settled *atomic.Bool) bool {
	server, _ := conn.RemoteAddr().(*net.TCPAddr)
	end := time.Now().Add(ownerScanRetry)
	for {
		if settled.Load() {
			return false
		}
		if ownGatewayHoldsQueue(ctx, server) {
			return connectionStillQueued(conn)
		}
		if !ownerScanSupported || check.abandoned.Load() || !time.Now().Add(ownerScanPoll).Before(end) {
			return false
		}
		time.Sleep(ownerScanPoll)
	}
}

// errPerUserListenerUnanswered ends a per-user try whose connection sat in
// the accept queue of a listener that is this account's recorded gateway (the
// process its gateway.pid record names, the only holder of the port) and took
// no accept: that gateway is stopped, frozen or wedged. Nothing was sent. It
// is not a listener the OS cannot tie to the record
// (errPerUserPeerUnverified, closed in every fail mode) and not a gateway
// that took the call (errGatewayTookCallNoAnswer); the call follows the
// account's outage mode (failPerUserListenerUnanswered).
var errPerUserListenerUnanswered = errors.New("this account's gateway listener accepted no connection")

// PerUserPostListenerUnanswered reports whether err, from PostPerUserHook, is
// a connection that waited in the accept queue of this account's recorded
// gateway and was never accepted. The call was not sent.
func PerUserPostListenerUnanswered(err error) bool {
	return errors.Is(err, errPerUserListenerUnanswered) && !errors.Is(err, errPerUserPeerUnverified)
}

// failPerUserListenerUnanswered ends a call whose gateway listener is this
// account's recorded gateway and accepts nothing. It is an outage, so the account's outage
// mode decides: open with the visible warning in the default tiers, closed in
// strict and managed ones. A tool call that does not plainly name nothing a
// protected file could be reached through stays closed in every tier, as a
// gateway that is up and late does (GAP-0518, failNoAnswer).
func failPerUserListenerUnanswered(opts Options, sp spec, failMode string) int {
	if opts.lateOrdinary != nil && !opts.lateOrdinary() {
		return failNoAnswer(opts, sp, failMode)
	}
	return failUnreachable(withPerUserOutage(opts), sp, failMode, perUserGatewayNoAnswerReason)
}
