// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"syscall"
	"time"
)

// errGatewayStartFailing ends a hook request early when the managed gateway
// service keeps failing to start. Its socket stays open (systemd holds it
// and restarts the service without a limit), so without this a hook waits
// its whole budget, about 30 seconds per prompt, before failing closed.
var errGatewayStartFailing = errors.New("the managed gateway service keeps failing to start")

// errGatewayRestarting ends a managed hook request whose gateway is still
// stopping or starting when the restart budget ends. The call fails closed:
// it is blocked, never allowed.
var errGatewayRestarting = errors.New("the managed gateway service is restarting")

// managedGatewayRestartingReason is the hook-failure reason of a managed
// hook that failed closed because its gateway was restarting (a package
// upgrade, a rollback, a configuration change that needs a restart) for
// longer than gatewayRestartBudget.
const managedGatewayRestartingReason = "enterprise_managed_gateway_restarting"

// gatewayRestartBudget is how long, from the start of the hook, a hook keeps
// trying a gateway that is restarting: it sends the call again when the
// gateway refused the connection or dropped it unanswered, and a managed
// hook stops waiting on a call queued in a socket while the service is not
// running. After it the call fails (closed for a managed hook; a per-user
// hook applies its fail mode, closed unless the account chose open). A
// restart that is over by then is invisible to the agent, which is answered
// from the policy the gateway loads at start, the last one applied; a longer
// one blocks each call within about 3 seconds instead of holding it for the
// hook's whole budget (#1278, GAP-0094, GAP-0102, GAP-0107). A gateway that
// is up and evaluating keeps the full budget.
const gatewayRestartBudget = 3 * time.Second

// gatewayRestartRetryDelay is the pause between two tries.
var gatewayRestartRetryDelay = 200 * time.Millisecond

// gatewayRestartDeadline is when a hook started at startedAt stops waiting
// for a restarting gateway; zero (no restart handling) for a Secure Client
// hook, which keeps its behavior.
func gatewayRestartDeadline(opts Options, startedAt time.Time) time.Time {
	if opts.SecureClient || startedAt.IsZero() {
		return time.Time{}
	}
	return startedAt.Add(gatewayRestartBudget)
}

// ManagedGatewayRestartingReason is the reason code of a managed hook that
// failed closed because its gateway was still restarting at the end of the
// restart budget.
const ManagedGatewayRestartingReason = managedGatewayRestartingReason

// ErrManagedGatewayRestarting is wrapped by a managed hook transport error
// that a gateway still restarting at the end of the restart budget ended.
var ErrManagedGatewayRestarting = errGatewayRestarting

// ManagedGatewayRestarting reports an error from a managed hook transport
// (ExchangeForeignHookSession) that a gateway still stopping or starting at
// the end of the restart budget ended.
func ManagedGatewayRestarting(err error) bool {
	return errors.Is(err, errGatewayRestarting)
}

// newManagedHookHTTPClient builds the verified transport of a managed hook.
// A gateway that binds its own hook socket (macOS) has none for a moment
// while it restarts, so the standalone transport is built again, the socket
// checked again each time, until restartDeadline instead of failing closed
// at once. The error left at the end is the caller's fail-closed result.
func newManagedHookHTTPClient(ctx context.Context, opts Options, timeout time.Duration, restartDeadline time.Time) (*http.Client, error) {
	if !opts.ManagedStandalone {
		return managedEnterpriseHTTPClientFor(timeout, opts.APIAddr, opts.ManagedGatewayServiceName, opts.SecureClient)
	}
	client, err := managedStandaloneHTTPClient(timeout, opts.ManagedUnixSocket, opts.ManagedServiceUID)
	for err != nil && awaitGatewayRestart(ctx, restartDeadline, err) {
		client, err = managedStandaloneHTTPClient(timeout, opts.ManagedUnixSocket, opts.ManagedServiceUID)
	}
	return client, err
}

// gatewayRestartShaped reports a transport error that a gateway restart
// causes: the service is not running, nothing accepts the connection, or
// the connection closed before any answer. Any other peer-verification
// failure is final: a listener that is not the gateway gets no second try.
// A per-user listener the transport refused is final whatever the check
// error wraps (one that closed or unbound during its owner check reads
// ENOENT, EOF, a reset, a refusal or the connect deadline).
func gatewayRestartShaped(err error) bool {
	if err == nil || errors.Is(err, errPerUserPeerUnverified) {
		return false
	}
	if errors.Is(err, errManagedGatewayNotRunning) || errors.Is(err, errGatewayNotConnected) {
		return true
	}
	if errors.Is(err, errManagedGatewayPeerUnverified) || errors.Is(err, errInvalidHookRequest) {
		return false
	}
	return connectionRefused(err) || connectionReset(err) || errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// awaitGatewayRestart waits before the next try of a call that failed
// because its gateway is restarting, and reports whether to try again: only
// for a restart-shaped error, and only while the next try still starts
// before deadline.
func awaitGatewayRestart(ctx context.Context, deadline time.Time, err error) bool {
	if deadline.IsZero() || ctx.Err() != nil || !gatewayRestartShaped(err) {
		return false
	}
	delay := gatewayRestartRetryDelay
	if !time.Now().Add(delay).Before(deadline) {
		return false
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// gatewayServiceState is the service manager's view of the managed gateway.
type gatewayServiceState struct {
	Active   string // ActiveState: active, activating, failed, ...
	Sub      string // SubState: running, start, auto-restart, ...
	Restarts int    // NRestarts
}

// gatewayStartWatchInterval is how often a waiting hook asks the service
// manager about the gateway; gatewayRunningWatchInterval once it runs.
var (
	gatewayStartWatchInterval   = time.Second
	gatewayRunningWatchInterval = 2 * time.Second
)

// watchManagedGatewayStarts returns ctx, ended with errGatewayStartFailing
// once the standalone gateway service is seen failing a start that began
// while this hook waited, or with errGatewayRestarting when the service is
// still not running at deadline (the call sits in the socket systemd holds
// across the restart). stop ends the watch (call it once the response
// arrives); release frees ctx. Off Linux, or outside the standalone
// profile, ctx is returned unchanged.
func watchManagedGatewayStarts(ctx context.Context, opts Options, deadline time.Time) (watched context.Context, stop, release func()) {
	probe := standaloneGatewayServiceProbe
	if !opts.ManagedEnterprise || !opts.ManagedStandalone || probe == nil {
		return ctx, func() {}, func() {}
	}
	watched, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(done) }) }
	go watchGatewayStarts(watched, done, cancel, probe, gatewayStartWatchInterval, deadline)
	return watched, stop, func() { stop(); cancel(nil) }
}

// watchGatewayStarts polls probe until the watch stops, the service manager
// cannot answer, or the request is ended: by a restart counted after the
// first poll that ends in another failure, or by a service that is still
// stopping or starting at deadline (zero: never). A single crash followed
// by a good start, or a running gateway whose answer is just slow, keeps
// the request waiting; a running gateway is still watched, since it can
// stop under a call it accepted.
func watchGatewayStarts(
	ctx context.Context,
	done <-chan struct{},
	cancel context.CancelCauseFunc,
	probe func(context.Context) (gatewayServiceState, error),
	interval time.Duration,
	deadline time.Time,
) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	baseline := -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-timer.C:
		}
		state, err := probe(ctx)
		if err != nil {
			// No answer from the service manager: keep waiting as before.
			return
		}
		if baseline < 0 {
			baseline = state.Restarts
		}
		next := interval
		switch {
		case state.Active == "failed":
			cancel(errGatewayStartFailing)
			return
		case state.Restarts > baseline && state.Sub == "auto-restart":
			cancel(errGatewayStartFailing)
			return
		case state.Active == "active":
			next = max(interval, gatewayRunningWatchInterval)
		case !deadline.IsZero():
			// Stopping, starting or stopped: the call waits in the socket.
			left := time.Until(deadline)
			if left <= 0 {
				cancel(errGatewayRestarting)
				return
			}
			next = min(interval, left)
		}
		timer.Reset(next)
	}
}

// perUserGatewayRestartingReason is the hook-failure reason of a per-user
// hook whose own gateway still refused or dropped the call at the end of
// gatewayRestartBudget: it is restarting (defenseclaw-gateway restart, an
// upgrade) or not running.
const perUserGatewayRestartingReason = "gateway restarting or not running"

// perUserGatewayWait is the outcome of awaitPerUserGateway.
type perUserGatewayWait struct {
	resp *http.Response
	err  error
	// recoveryErr is the cause of a cold start that failed; the call fails
	// with it, as before the restart budget.
	recoveryErr error
	// outlasted reports a call still refused or dropped at the end of the
	// restart budget.
	outlasted bool
}

// awaitPerUserGateway sends a per-user hook call again, every
// gatewayRestartRetryDelay until deadline, while this account's gateway
// refuses or drops it: a restart, an upgrade or a start is answered by the
// gateway that comes up, and a longer outage ends the call within the
// budget instead of holding it until the old gateway's stop and the new
// one's start are over (GAP-0094, GAP-0102, GAP-0107). The first refused
// connection starts the gateway (opts.GatewayRecovery) beside the tries,
// not before them: the start outlives the hook when it takes longer than
// the budget (bounded by the hook's own deadline, not by the call's end),
// so the next call finds the gateway running. A start that
// fails at once (the gateway was stopped with defenseclaw-gateway stop, a
// recent start failed) ends the wait with its cause.
func awaitPerUserGateway(
	ctx context.Context,
	opts Options,
	deadline time.Time,
	resp *http.Response,
	err error,
	send func() (*http.Response, error),
) perUserGatewayWait {
	var recovered chan error
	recoveryStarted := false
	for err != nil && !deadline.IsZero() && gatewayRestartShaped(err) {
		if !recoveryStarted && opts.GatewayRecovery != nil && connectionRefused(err) {
			recoveryStarted = true
			recovered = make(chan error, 1)
			start := opts.GatewayRecovery
			// The start must not end with this call: a gateway that takes
			// longer than the budget to start still serves the next one.
			// It keeps the hook's own deadline as its bound.
			startCtx, cancelStart := context.WithoutCancel(ctx), context.CancelFunc(func() {})
			if hookDeadline, ok := ctx.Deadline(); ok {
				startCtx, cancelStart = context.WithDeadline(startCtx, hookDeadline)
			}
			go func(cause error) {
				defer cancelStart()
				recovered <- start(startCtx, cause)
			}(err)
		}
		delay := gatewayRestartRetryDelay
		if !time.Now().Add(delay).Before(deadline) {
			return perUserGatewayWait{resp: resp, err: err, outlasted: true}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return perUserGatewayWait{resp: resp, err: err}
		case recoveryErr := <-recovered:
			timer.Stop()
			// A nil channel never fires again: one start per call.
			recovered = nil
			if recoveryErr != nil {
				return perUserGatewayWait{resp: resp, err: err, recoveryErr: recoveryErr}
			}
		case <-timer.C:
		}
		resp, err = send()
	}
	return perUserGatewayWait{resp: resp, err: err}
}

// errGatewayNotConnected ends a per-user hook try that has no connection to
// the gateway at the end of the restart budget. A connect to a port nobody
// listens on can take about 2 seconds on Windows, so one late try could
// otherwise hold the call well past the budget.
var errGatewayNotConnected = errors.New("no connection to the gateway within the restart budget")

// connectBy returns ctx for one per-user hook try: it is ended with
// errGatewayNotConnected at deadline unless the try has its connection by
// then. A try that is connected keeps ctx until release (call it once the
// response is read): a gateway that accepted the call evaluates it within
// the hook's whole budget.
func connectBy(ctx context.Context, deadline time.Time) (tryCtx context.Context, release func()) {
	if deadline.IsZero() {
		return ctx, func() {}
	}
	connected := make(chan struct{})
	var once sync.Once
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { once.Do(func() { close(connected) }) }}
	ctx, peerCheck := withPerUserPeerCheck(ctx)
	tryCtx, cancel := context.WithCancelCause(httptrace.WithClientTrace(ctx, trace))
	go func() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-timer.C:
			select {
			case <-connected:
			default:
				if peerCheck.pending.Load() {
					// A listener took the connection and its owner is not
					// proven yet (the Windows tuple wait of one that
					// closed at once): never an outage.
					cancel(errPerUserPeerCheckUnfinished)
				} else {
					cancel(errGatewayNotConnected)
				}
			}
		case <-connected:
		case <-tryCtx.Done():
		}
	}()
	return tryCtx, func() { cancel(nil) }
}

// firstTryConnectWindow is the least time the first try of a per-user hook
// has to connect to its gateway.
const firstTryConnectWindow = time.Second

// firstTryConnectDeadline is the connect deadline of a per-user hook's first
// try at now. The restart budget counts from the start of the call, the
// PowerShell adapter or bridge in front of a Windows hook included, so a
// hook that started slowly could reach its first try with the budget spent
// and fail without asking its running gateway: a Cursor sessionStart behind
// a slow adapter answered locally and the gateway never saw it. A spent
// budget ends the retries, not the first try. A tool call stays bounded by
// its answer deadline.
func firstTryConnectDeadline(restartDeadline, now time.Time) time.Time {
	if restartDeadline.IsZero() {
		return restartDeadline
	}
	if floor := now.Add(firstTryConnectWindow); restartDeadline.Before(floor) {
		return floor
	}
	return restartDeadline
}

// notConnectedError keeps errGatewayNotConnected on the error of a try that
// connectBy ended.
func notConnectedError(tryCtx context.Context, err error) error {
	if err != nil && errors.Is(context.Cause(tryCtx), errGatewayNotConnected) && !errors.Is(err, errGatewayNotConnected) {
		return fmt.Errorf("%w: %w", errGatewayNotConnected, err)
	}
	return err
}
