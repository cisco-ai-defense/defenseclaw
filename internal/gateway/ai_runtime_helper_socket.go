// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// brokeredHomeReader is AI Discovery's read of the user homes through the
// root sensor helper of an unmanaged, de-privileged gateway: the Claude Cowork
// VM package's gateway runs as defenseclaw-cowork and cannot read the session
// users' homes (cowork-1-0-8 GAP-0008). It applies exactly where
// chooseAcquirer brokers through an unmanaged helper, and each read trusts the
// socket as that does (unmanagedHelperSocket, then the root peer check of
// NewRootHelper on connect). nil everywhere else, so managed, standalone,
// Secure Client and per-user gateways read homes as before.
func brokeredHomeReader(cfg *config.Config) func(context.Context) (inventory.BrokeredHomeReport, error) {
	if cfg == nil || runtime.GOOS != "linux" || managed.IsManagedEnterprise(cfg.DeploymentMode) ||
		cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() ||
		strings.TrimSpace(os.Getenv(acquire.SocketEnvVar)) == "" || acquire.NewLocal().WideCoverage() {
		return nil
	}
	return func(ctx context.Context) (inventory.BrokeredHomeReport, error) {
		var report inventory.BrokeredHomeReport
		socket := unmanagedHelperSocket(ctx)
		if socket == "" {
			return report, errors.New("the sensor helper socket is not up or not trusted")
		}
		if err := newBrokeredHomeHelper(socket).Discovery(ctx, &report); err != nil {
			if errors.Is(err, acquire.ErrDiscoveryUnsupported) {
				return report, inventory.ErrBrokeredHomesUnsupported
			}
			return report, err
		}
		return report, nil
	}
}

// newBrokeredHomeHelper is a seam for tests, which cannot serve a socket as
// root.
var newBrokeredHomeHelper = acquire.NewRootHelper
