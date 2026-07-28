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
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type attemptContextKey struct{}

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
	inner http.RoundTripper
}

func (transport observedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	countAttempt(request.Context())
	var wroteRequest atomic.Bool
	traced := request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest.Store(true) },
	}))
	response, err := transport.inner.RoundTrip(traced)
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
	mu           sync.Mutex
	sequence     uint64
	latestUnsafe uint64
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
			connection, err := netguard.V8SafeDialContext(config.policy, config.dialer, config.resolver)(ctx, "tcp", address)
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
