// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const foreignHookSessionPathPrefix = "/api/v1/foreign-hook-session/"

// The hook asks the gateway to apply a clean scan again when its session
// store could not apply it, until foreignHookSessionRetryReserve before the
// call's answer deadline (or the context's deadline): that much is left for
// the hook request after the exchange. When neither deadline is set it asks
// for foreignHookSessionRetryWindow.
var (
	foreignHookSessionRetryReserve = 1500 * time.Millisecond
	foreignHookSessionRetryWindow  = 2 * time.Second
)

// ExchangeForeignHookSession asks the standalone gateway to apply one scan to
// its protected session record. An unavailable or malformed answer is an
// error; the caller must deny the hook invocation in that case.
//
// The exchange carries retry_until: a gateway that could not read, write or
// fence the record for a scan that found no unapproved hook (five agents
// starting at once, a busy disk) applies it again until then, and audits
// only its final answer (GAP-1711, GAP-1812). The hook sends the exchange
// once.
func ExchangeForeignHookSession(ctx context.Context, opts Options, connector string, payload []byte) ([]byte, error) {
	started := opts.StartedAt
	if started.IsZero() {
		started = time.Now()
	}
	return exchangeForeignHookSessionOnce(ctx, opts, connector,
		withForeignHookSessionRetryUntil(payload, foreignHookSessionRetryUntil(ctx, answerDeadline(opts, started))))
}

// foreignHookSessionRetryUntil is the exchange's retry_until: the earlier of
// answerBy and the context's deadline, less foreignHookSessionRetryReserve.
func foreignHookSessionRetryUntil(ctx context.Context, answerBy time.Time) time.Time {
	limit := answerBy
	if deadline, ok := ctx.Deadline(); ok && (limit.IsZero() || deadline.Before(limit)) {
		limit = deadline
	}
	if limit.IsZero() {
		return time.Now().Add(foreignHookSessionRetryWindow)
	}
	return limit.Add(-foreignHookSessionRetryReserve)
}

// withForeignHookSessionRetryUntil sets retry_until in the exchange payload,
// or returns the payload unchanged when it is not a JSON object.
func withForeignHookSessionRetryUntil(payload []byte, until time.Time) []byte {
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil || fields == nil {
		return payload
	}
	value, err := json.Marshal(until.UTC())
	if err != nil {
		return payload
	}
	fields["retry_until"] = value
	out, err := json.Marshal(fields)
	if err != nil {
		return payload
	}
	return out
}

func exchangeForeignHookSessionOnce(ctx context.Context, opts Options, connector string, payload []byte) ([]byte, error) {
	if !opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "" {
		return nil, errors.New("managed hook runtime unavailable")
	}
	remaining, ok := ctx.Deadline()
	timeout := defaultHookRequestTimeout
	if ok {
		timeout = time.Until(remaining)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	token := ""
	if !opts.ManagedStandalone {
		if opts.AuthenticatedManagedToken == nil {
			return nil, errors.New("authenticated managed hook token unavailable")
		}
		token = strings.TrimSpace(*opts.AuthenticatedManagedToken)
		if token == "" {
			return nil, errors.New("authenticated managed hook token empty")
		}
	}
	// The exchange is the first gateway call of a guarded hook, so the
	// restart budget counts from the hook invocation (StartedAt), as for
	// the hook request after it (#1278).
	started := opts.StartedAt
	if started.IsZero() {
		started = time.Now()
	}
	// Only a managed hook exchanges a session; the guard leaves a per-user
	// hook without one.
	var restartDeadline time.Time
	if opts.ManagedEnterprise {
		restartDeadline = gatewayRestartDeadline(opts, started)
	}
	client := opts.HTTPClient
	if client == nil {
		var err error
		client, err = newManagedHookHTTPClient(ctx, opts, timeout, restartDeadline)
		if err != nil {
			return nil, err
		}
	}
	addr := opts.APIAddr
	if opts.ManagedStandalone && addr == "" {
		addr = "127.0.0.1:1" // the Unix transport dials the socket
	}
	// The exchange of a tool call is held to the hook's answer budget,
	// counted from the invocation like the hook request after it: a gateway
	// that accepted the exchange but gives no answer (it is stopping, starting
	// or too busy) ends it in time, and the guard denies the call.
	answerBy := answerDeadline(opts, started)
	// A scan that ran close to its own budget may have left the exchange
	// almost none of the answer budget: a missing answer then is the hook's
	// own delay, not a gateway outage, and stays closed in fail mode open
	// (final review, P2).
	spentLocally := gatewayAnswerWindowShort(opts, answerBy)
	noAnswer := func(cause, err error) error {
		if spentLocally {
			return fmt.Errorf("%w: %w: %v", errAnswerBudgetSpentLocally, cause, err)
		}
		return fmt.Errorf("%w: %v", cause, err)
	}
	ctx, stopAnswer, _, releaseAnswer := awaitAnswerBy(ctx, answerBy, progressCeiling(opts, started), nil)
	defer releaseAnswer()
	// A call queued in the socket systemd holds across a restart is ended
	// at the restart budget, like the hook request (Linux).
	ctx, stopWatch, releaseWatch := watchManagedGatewayStarts(ctx, opts, restartDeadline)
	defer releaseWatch()
	send := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"http://"+addr+foreignHookSessionPathPrefix+url.PathEscape(connector), bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidHookRequest, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "foreign-hook-guard/1.0")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		setUserIdentityHeaders(req, opts)
		return client.Do(req)
	}
	// The session exchange meets a restarting gateway like the hook call
	// after it does: it is sent again within the restart budget, the peer
	// verified on every try.
	response, err := send()
	for err != nil && awaitGatewayRestart(ctx, restartDeadline, err) {
		response, err = send()
	}
	stopWatch()
	if err != nil {
		// Keep why the watch or the answer budget ended the call: the caller
		// denies with the cause named.
		cause := context.Cause(ctx)
		if errors.Is(cause, errGatewayNoAnswer) {
			return nil, noAnswer(cause, err)
		}
		if errors.Is(cause, errGatewayRestarting) || errors.Is(cause, errGatewayStartFailing) {
			return nil, fmt.Errorf("%w: %v", cause, err)
		}
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session gateway returned HTTP %d", response.StatusCode)
	}
	// The answer budget holds until the whole answer is read: a gateway that
	// stalls in the body is cut off at the budget, like one that sends no
	// headers.
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	stopAnswer()
	if err != nil {
		if cause := context.Cause(ctx); errors.Is(cause, errGatewayNoAnswer) {
			return nil, noAnswer(cause, err)
		}
		return nil, err
	}
	return body, nil
}
