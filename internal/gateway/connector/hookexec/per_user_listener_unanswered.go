// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
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
// is never read as stopped. The margin is the time the owner scan of the
// listener (every process of the account, and on Linux a short re-read of a
// thread that cannot be read for a moment, unreadableThreadWindow) has before
// the deadline cuts the try: a scan still running at the deadline is lost and
// the try ends as an unverified peer, a false block of an ordinary call, so
// the margin holds the scan of a busy host (170 ms measured with tests running
// on the same account) with room for the re-read window on top.
const (
	unansweredMargin = time.Second
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
	go func() { done <- verify(conn) }()
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
	if ownGatewayHoldsQueue(ctx, server) {
		return fmt.Errorf("%w: %w", errPerUserListenerUnanswered, errPerUserNotAccepted)
	}
	return classifyUnaccepted(ctx, <-done, server)
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
