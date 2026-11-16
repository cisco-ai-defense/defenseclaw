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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	if apiInheritedMismatchBinds && a.scannerCfg != nil && a.scannerCfg.StandaloneEnterprise() {
		// A rolled-back package upgrade (GAP-2144): the lifecycle put the
		// previous release's job definition back, which declares no API
		// socket, while the package left this build's binaries in place.
		// The job is then the one its definition describes, and the
		// gateway binds the port itself as that release did, until the next
		// ensure installs this build's definition.
		if declares, known := apiLaunchdDefinitionDeclaresSocket(); known && !declares {
			fmt.Fprintln(os.Stderr, "[sidecar-api] the installed launchd job definition declares no API socket "+
				"(a rolled-back upgrade); binding the API port until the next ensure installs this build's definition")
			return listenWithRetry(ctx, a.addr, apiListenRetryBudget)
		}
		// GAP-1086: launchd holds the managed API port across restarts only
		// while its job declares the socket. Under an older job the gateway
		// would bind the port itself, and every restart would free it for
		// another account while native exporters keep sending to it.
		return nil, errors.New("api: the managed gateway's launchd job holds no API socket, so the port " +
			"would be free while the gateway restarts; reload the job: launchctl bootout " +
			"system/com.cisco.defenseclaw.gateway, then launchctl bootstrap system " +
			"/Library/LaunchDaemons/com.cisco.defenseclaw.gateway.plist")
	}
	return listenWithRetry(ctx, a.addr, apiListenRetryBudget)
}

// apiLaunchdGatewayDefinition is the managed gateway's launchd job
// definition. Replaceable in tests.
var apiLaunchdGatewayDefinition = "/Library/LaunchDaemons/com.cisco.defenseclaw.gateway.plist"

// apiLaunchdDefinitionMaxBytes bounds the read of that definition.
const apiLaunchdDefinitionMaxBytes = 1 << 20

// apiLaunchdDefinitionDeclaresSocket reports whether the installed gateway
// job definition declares launchd sockets. known is false unless the file is
// a root-owned regular XML plist that only root can write, so any other
// state keeps the GAP-1086 refusal. Replaceable in tests.
var apiLaunchdDefinitionDeclaresSocket = func() (declares, known bool) {
	return launchdDefinitionDeclaresSocket(apiLaunchdGatewayDefinition)
}

func launchdDefinitionDeclaresSocket(path string) (declares, known bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !fileOwnedByRoot(info) {
		return false, false
	}
	f, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, apiLaunchdDefinitionMaxBytes+1))
	if err != nil || len(data) > apiLaunchdDefinitionMaxBytes {
		return false, false
	}
	text := bytes.TrimSpace(data)
	if !bytes.HasPrefix(text, []byte("<?xml")) || !bytes.Contains(text, []byte("<plist")) {
		return false, false
	}
	return bytes.Contains(text, []byte("<key>Sockets</key>")), true
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
