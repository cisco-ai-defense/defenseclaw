// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// errPerUserGatewayFrozen ends a per-user call whose gateway took the
// connection and then answered nothing, while a probe of the same verified
// listener got no HTTP status either: the gateway is frozen (suspended or
// wedged), not busy. It is the outage of an unanswered listener
// (failPerUserListenerUnanswered), as on Linux and macOS, where a frozen
// gateway leaves the call in its accept queue (errPerUserListenerUnanswered).
//
// On Windows the Go runtime keeps an AcceptEx posted on the listener, so the
// kernel accepts the next connection even while the gateway process is
// suspended, and the accept-queue proof never applies there: every call to a
// frozen gateway was "taken and not answered". A prompt, a tool result or a
// stop event then waited its whole registered hook timeout (29 s, 89 s for
// Stop and PostToolBatch) and was blocked with "fail mode closed" in the open
// tier too (rel-1-0-10 GAP-1107).
var errPerUserGatewayFrozen = errors.New("this account's gateway took the call and answers nothing, not even a health probe")

// The probe starts once the call has waited the tool-gate answer budget
// (hookAnswerBudget from hook start), gets perUserFrozenProbeWindow for a
// status, and repeats every perUserFrozenProbeEvery while the call waits. A
// gateway that is up answers /health within milliseconds while it evaluates
// the call; the LLM judge of a prompt can take longer than the budget.
var (
	perUserFrozenProbeWindow = 2 * time.Second
	perUserFrozenProbeEvery  = 5 * time.Second
)

// perUserFrozenProbeOn reports whether the transport of this call needs the
// probe: the per-user Windows loopback client this hook built itself. Tests
// replace it.
var perUserFrozenProbeOn = func(opts Options) bool {
	return runtime.GOOS == "windows" && opts.perUserLoopbackDial
}

// perUserFrozenProbeCall reports a per-user Claude Code or Codex call that
// has no answer deadline of its own: every event but a tool gate (a prompt,
// a tool result, a stop or session event). A tool gate keeps its answer
// budget and the ordinary-call rule (noAnswerFailMode).
func perUserFrozenProbeCall(opts Options) bool {
	return !opts.ManagedEnterprise && opts.ManagedUnixSocket == "" && !opts.SecureClient &&
		opts.HTTPClient != nil && opts.answerBy.IsZero() && !opts.StartedAt.IsZero() &&
		lateOrdinaryConnector(opts.Connector) && !toolGateEvent(opts.Connector, opts.Event) &&
		perUserFrozenProbeOn(opts)
}

// watchPerUserFrozenGateway returns ctx for the request of the call, ended
// with errPerUserGatewayFrozen when a probe proves the gateway frozen; stop,
// which ends the watch once the call has a response or an error; and
// release, which the call runs when it is done.
func watchPerUserFrozenGateway(ctx context.Context, opts Options) (watched context.Context, stop, release func()) {
	noop := func() {}
	if !perUserFrozenProbeCall(opts) {
		return ctx, noop, noop
	}
	watched, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(done) }) }
	go func() {
		timer := time.NewTimer(time.Until(opts.StartedAt.Add(hookAnswerBudget)))
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-watched.Done():
				return
			case <-timer.C:
			}
			if perUserGatewayAnswersNothing(watched, opts) {
				select {
				case <-done:
				default:
					cancel(errPerUserGatewayFrozen)
				}
				return
			}
			timer.Reset(perUserFrozenProbeEvery)
		}
	}()
	return watched, stop, func() { stop(); cancel(nil) }
}

// perUserGatewayAnswersNothing probes /health of the gateway through the
// verified client of the call, which proves the owner of the listener again;
// no token is sent. Only a probe whose connection was made and verified and
// that then got no status within the window is a frozen gateway. A refused
// connection, an unverified listener or a dial that did not finish proves
// nothing here, and any status, an error status included, is a gateway that
// is up.
func perUserGatewayAnswersNothing(ctx context.Context, opts Options) bool {
	probeCtx, cancel := context.WithTimeout(ctx, perUserFrozenProbeWindow)
	defer cancel()
	var connected atomic.Bool
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(probeCtx, trace), http.MethodGet,
		"http://"+opts.APIAddr+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := opts.HTTPClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		return false
	}
	return connected.Load() && ctx.Err() == nil && errors.Is(probeCtx.Err(), context.DeadlineExceeded)
}

// perUserGatewayFrozen reports a call that watchPerUserFrozenGateway ended.
func perUserGatewayFrozen(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errPerUserGatewayFrozen)
}
