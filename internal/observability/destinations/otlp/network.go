// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type attemptContextKey struct{}

// bundledLocalStackDestination reports the destination names the bundled
// local observability stack's setup writes (the CLI's
// is_local_observability_stack_destination).
func bundledLocalStackDestination(name string) bool {
	return name == "local-observability" || name == "local-otlp-logs"
}

// verifyBundledCollector proves a connection reaches a listener of this
// account or of the system account (hookexec.VerifyLocalPeer). Replaceable
// in tests.
var verifyBundledCollector = hookexec.VerifyLocalPeer

// errBundledCollectorUnverified is a bundled-stack connection whose listener
// another account holds, or whose account could not be read: nothing was
// written to it.
var errBundledCollectorUnverified = errors.New("OTLP collector listener is not proven to be this account's local stack")

// checkBundledCollector wraps dial for the bundled stack's destination: a
// loopback connection is closed before any byte unless verifyBundledCollector
// proves its listener. When the stack is stopped, another account can bind
// its collector port and would otherwise receive every trace, metric and log
// (GAP-1087). Other destinations dial as before: an operator's own local
// agent may run as its own service account.
func checkBundledCollector(
	config signalConfig,
	dial func(context.Context, string, string) (net.Conn, error),
) func(context.Context, string, string) (net.Conn, error) {
	if !config.bundledStack {
		return dial
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if remote, ok := connection.RemoteAddr().(*net.TCPAddr); ok && remote.IP.IsLoopback() {
			if verifyErr := verifyBundledCollector(connection); verifyErr != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("%w: %v", errBundledCollectorUnverified, verifyErr)
			}
		}
		return connection, nil
	}
}

func countAttempt(ctx context.Context) {
	if counter, ok := ctx.Value(attemptContextKey{}).(*atomic.Uint64); ok && counter != nil {
		counter.Add(1)
	}
}

func withAttemptCounter(ctx context.Context) (context.Context, *atomic.Uint64) {
	counter := &atomic.Uint64{}
	return context.WithValue(ctx, attemptContextKey{}, counter), counter
}

type observedRoundTripper struct {
	inner   http.RoundTripper
	tracker *dialOutcomeTracker
}

func (transport observedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	countAttempt(request.Context())
	var wroteRequest atomic.Bool
	traced := request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest.Store(true) },
	}))
	response, err := transport.inner.RoundTrip(traced)
	if err == nil {
		captureRejection(request.Context(), response)
	}
	if response != nil &&
		(response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
		transport.tracker.recordAuthentication()
	}
	if err != nil && wroteRequest.Load() &&
		!errors.Is(err, netguard.ErrV8AddressProhibited) && !errors.Is(err, netguard.ErrV8EndpointInvalid) {
		return response, retryableTransportError{cause: err}
	}
	return response, err
}

type retryableTransportError struct{ cause error }

func (err retryableTransportError) Error() string { return "OTLP acknowledgement was not received" }
func (err retryableTransportError) Unwrap() error { return err.cause }
func (retryableTransportError) Temporary() bool   { return true }
func (retryableTransportError) Timeout() bool     { return false }

type dialOutcomeTracker struct {
	mu                   sync.Mutex
	sequence             uint64
	latestUnsafe         uint64
	latestAuthentication uint64
}

func (tracker *dialOutcomeTracker) snapshot() uint64 {
	if tracker == nil {
		return 0
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.sequence
}

func (tracker *dialOutcomeTracker) record(err error) {
	if tracker == nil {
		return
	}
	tracker.mu.Lock()
	tracker.sequence++
	if errors.Is(err, netguard.ErrV8AddressProhibited) || errors.Is(err, netguard.ErrV8EndpointInvalid) {
		tracker.latestUnsafe = tracker.sequence
	}
	tracker.mu.Unlock()
}

func (tracker *dialOutcomeTracker) unsafeSince(sequence uint64) bool {
	if tracker == nil {
		return false
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.latestUnsafe > sequence
}

func (tracker *dialOutcomeTracker) recordAuthentication() {
	if tracker == nil {
		return
	}
	tracker.mu.Lock()
	tracker.sequence++
	tracker.latestAuthentication = tracker.sequence
	tracker.mu.Unlock()
}

func (tracker *dialOutcomeTracker) authenticationSince(sequence uint64) bool {
	if tracker == nil {
		return false
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.latestAuthentication > sequence
}

func newGRPCConnection(config signalConfig) (*grpc.ClientConn, error) {
	authority := config.url.Host
	if config.url.Port() == "" {
		port := "443"
		if config.url.Scheme == "http" {
			port = "80"
		}
		authority = net.JoinHostPort(config.url.Hostname(), port)
	}
	var transportCredentials credentials.TransportCredentials
	if config.url.Scheme == "http" {
		transportCredentials = insecure.NewCredentials()
	} else {
		transportCredentials = credentials.NewTLS(cloneTLS(config.tls))
	}
	connection, err := grpc.NewClient(
		"passthrough:///"+authority,
		grpc.WithAuthority(config.url.Host),
		grpc.WithTransportCredentials(transportCredentials),
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			connection, err := checkBundledCollector(config,
				netguard.V8SafeDialContext(config.policy, config.dialer, config.resolver))(ctx, "tcp", address)
			config.tracker.record(err)
			return connection, err
		}),
		grpc.WithUnaryInterceptor(func(
			ctx context.Context,
			method string,
			request, response any,
			connection *grpc.ClientConn,
			invoker grpc.UnaryInvoker,
			options ...grpc.CallOption,
		) error {
			baseline := config.tracker.snapshot()
			countAttempt(ctx)
			err := invoker(ctx, method, request, response, connection, options...)
			if config.tracker.unsafeSince(baseline) {
				// The SDK retry classifier treats Unavailable as transient. Rewrite
				// only the in-memory RPC status so a prohibited dial is terminal;
				// the outer exporter uses the tracker to retain unsafe classification.
				return status.Error(codes.PermissionDenied, "OTLP endpoint is prohibited")
			}
			switch status.Code(err) {
			case codes.Unauthenticated, codes.PermissionDenied:
				config.tracker.recordAuthentication()
			}
			return err
		}),
		grpc.WithDisableRetry(),
	)
	if err != nil {
		return nil, newError(ErrorInitialization, err)
	}
	return connection, nil
}

func closeHTTPTransport(transport *http.Transport) {
	if transport != nil {
		transport.CloseIdleConnections()
	}
}

// grpcRedialWait bounds how long an export waits for the channel to leave
// TRANSIENT_FAILURE after redialGRPC reset its backoff.
const grpcRedialWait = time.Second

// redialGRPC makes an export dial again at once when its channel is waiting
// out the reconnect backoff of an earlier failed connect. The delivery circuit
// already spaces the attempts (a cooldown, then one probe), so the channel's
// own exponential backoff (up to two minutes) on top only kept a destination
// failing after its collector was reachable again (GAP-0532).
func redialGRPC(ctx context.Context, connection *grpc.ClientConn) {
	if connection == nil || connection.GetState() != connectivity.TransientFailure {
		return
	}
	connection.ResetConnectBackoff()
	waitContext, cancel := context.WithTimeout(ctx, grpcRedialWait)
	defer cancel()
	connection.WaitForStateChange(waitContext, connectivity.TransientFailure)
}
