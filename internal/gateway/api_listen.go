// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/systemd"
)

// inheritedAPIListener is replaceable by tests.
var inheritedAPIListener = func() (net.Listener, bool, error) { return systemd.Listener("api") }

// apiListenRetryBudget bounds the first bind's address-in-use retry;
// apiListenHeldRetryInterval paces the standalone retry that follows while
// the hook socket keeps serving. Both are replaceable by tests.
var (
	apiListenRetryBudget       = 30 * time.Second
	apiListenHeldRetryInterval = 2 * time.Second
)

// apiListenTCP binds the API address. Replaceable by tests, which use it to
// return bind failures a single test process cannot produce, such as the one
// Windows returns under another account's wildcard listener.
var apiListenTCP = func(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", addr)
}

// acquireAPIListener returns the API listener: the socket-activated "api"
// descriptor when systemd or launchd passed one, otherwise a bound listener.
// An inherited socket must be exactly the configured api_bind:api_port — on
// Linux a mismatch fails closed rather than silently serving the API
// somewhere the managed config did not name. The macOS plist declares the
// default address only. A standalone managed gateway must adopt that socket;
// only other profiles may bind a configured address in its place.
func (a *APIServer) acquireAPIListener(ctx context.Context) (net.Listener, error) {
	listener, inherited, err := inheritedAPIListener()
	if err != nil {
		return nil, err
	}
	if inherited {
		if err := inheritedAddrMatches(listener.Addr(), a.addr); err != nil {
			_ = listener.Close()
			if !apiInheritedMismatchBinds || a.scannerCfg != nil && a.scannerCfg.StandaloneEnterprise() {
				return nil, err
			}
			fmt.Fprintf(os.Stderr, "[sidecar-api] %v; binding the configured address instead\n", err)
			return listenWithRetry(ctx, a.addr, apiListenRetryBudget)
		}
		return listener, nil
	}
	return listenWithRetry(ctx, a.addr, apiListenRetryBudget)
}

// apiInheritedMismatchBinds is true where the inherited API socket's address
// is fixed by the installed service definition rather than the config
// (launchd). Replaceable in tests.
var apiInheritedMismatchBinds = runtime.GOOS == "darwin"

// retryAPIListenerBind keeps trying to bind the API address after the first
// bind found it held, and hands the listener to Run through bound. It stops
// when ctx ends, closing a listener Run did not take, and logs a held port
// once a minute rather than on every attempt.
func (a *APIServer) retryAPIListenerBind(ctx context.Context, bound chan<- net.Listener) {
	ticker := time.NewTicker(apiListenHeldRetryInterval)
	defer ticker.Stop()
	lastLogged := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		ln, err := apiListenTCP(ctx, a.addr)
		if err != nil {
			if time.Since(lastLogged) >= time.Minute {
				fmt.Fprintf(os.Stderr, "[sidecar-api] %s still unavailable; retrying the API bind: %v\n", a.addr, err)
				lastLogged = time.Now()
			}
			continue
		}
		select {
		case bound <- ln:
		case <-ctx.Done():
			_ = ln.Close()
		}
		return
	}
}

func inheritedAddrMatches(actual net.Addr, configured string) error {
	host, rawPort, err := net.SplitHostPort(configured)
	if err != nil {
		return fmt.Errorf("api: configured address %q: %w", configured, err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return fmt.Errorf("api: configured port %q: %w", rawPort, err)
	}
	tcp, ok := actual.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("api: socket-activated listener %s is not TCP", actual)
	}
	want := net.ParseIP(host)
	if host == "localhost" {
		want = net.IPv4(127, 0, 0, 1)
	}
	if want == nil || !tcp.IP.Equal(want) || tcp.Port != port {
		return fmt.Errorf("api: socket-activated listener %s does not match configured %s", actual, configured)
	}
	return nil
}
