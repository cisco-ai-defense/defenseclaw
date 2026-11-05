// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
)

// unmanagedHelperSocket is the root sensor helper an unmanaged gateway was
// started to broker through, or "" when its environment names none it can
// trust. The variable only names the path; the trust comes from the path
// (CheckRootSocket: a root-owned socket in root-owned folders nobody else can
// write) and from the serving process (uid 0, checked here once and again on
// every connect by NewRootHelper). Anything else keeps the gateway reading
// directly, with the per-user process filter.
func unmanagedHelperSocket(ctx context.Context) string {
	socket := strings.TrimSpace(os.Getenv(acquire.SocketEnvVar))
	if socket == "" {
		return ""
	}
	if !filepath.IsAbs(socket) {
		log.Printf("[ai_runtime] %s=%q is not an absolute path; reading directly", acquire.SocketEnvVar, socket)
		return ""
	}
	socket = filepath.Clean(socket)
	// A gateway started together with its helper (one systemctl restart of
	// both units) can look before the helper has bound the socket. The
	// socket is waited for, with backoff, for at most helperSocketWait of
	// wall-clock time, only when it is absent from folders only root can
	// write (acquire.RootSocketAwaitable); anything else reads directly at
	// once, and so does a cancelled ctx (cowork-1-0-8 GAP-0049).
	deadline := helperSocketNow().Add(helperSocketWait)
	logged := false
	for delay := 250 * time.Millisecond; ; delay = min(2*delay, 4*time.Second) {
		err := checkHelperSocket(socket)
		if err == nil {
			probe, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = probeHelperSocket(probe, socket)
			cancel()
		}
		if err == nil {
			return socket
		}
		if !awaitHelperSocket(socket) || helperSocketNow().Add(delay).After(deadline) {
			log.Printf("[ai_runtime] not brokering through %s: %v; reading directly", socket, err)
			return ""
		}
		if !logged {
			log.Printf("[ai_runtime] helper socket %s is not up yet; waiting up to %s", socket, helperSocketWait)
			logged = true
		}
		if !sleepHelperSocket(ctx, delay) {
			log.Printf("[ai_runtime] stopped waiting for helper socket %s; reading directly", socket)
			return ""
		}
	}
}

// helperSocketWait bounds the wait for a helper that starts with the gateway.
const helperSocketWait = 30 * time.Second

// sleepUnlessCancelled sleeps for d and reports whether ctx is still live.
func sleepUnlessCancelled(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Seams for tests: a test process cannot create root-owned folders.
var (
	checkHelperSocket = acquire.CheckRootSocket
	probeHelperSocket = acquire.ProbeRootHelper
	awaitHelperSocket = acquire.RootSocketAwaitable
	sleepHelperSocket = sleepUnlessCancelled
	helperSocketNow   = time.Now
)
