//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/peerbroker"
)

// windowsServiceNameEnvForBroker is the service name the SCM host exports
// (cmd/defenseclaw service_windows.go): the broker starts only in the
// guardian service process, never in the enumerator or a CLI run.
const windowsServiceNameEnvForBroker = "DEFENSECLAW_WINDOWS_SERVICE_NAME"

// startEnterpriseHookPeerBroker serves the managed Windows route-only peer
// SID broker (S1 Q7 lead ruling) from the standalone guardian: LocalSystem,
// one pipe only the gateway service SID may open, one question (who owns
// the client end of a loopback connection the gateway accepted). When it
// stops it is restarted with a backoff; the gateway refuses every
// route-only caller while it is down.
func startEnterpriseHookPeerBroker(ctx context.Context, errOut io.Writer) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	gatewayService := strings.TrimSpace(os.Getenv(peerbroker.GatewayServiceEnv))
	if gatewayService == "" {
		return
	}
	names, err := peerbroker.NamesFor(gatewayService)
	if err != nil || !strings.EqualFold(strings.TrimSpace(os.Getenv(windowsServiceNameEnvForBroker)), names.Guardian) {
		return
	}
	server, err := peerbroker.NewServer(gatewayService, func(event peerbroker.Event) {
		if event.Outcome == "verified" {
			return
		}
		fmt.Fprintf(errOut, "[hook-guardian] peer broker %s: %s (gateway pid %d)\n", event.Stage, event.Outcome, event.ClientPID)
	})
	if err != nil {
		fmt.Fprintf(errOut, "[hook-guardian] peer broker not started (managed Windows route-only callers are refused): %v\n", err)
		return
	}
	go func() {
		backoff := 2 * time.Second
		for {
			err := server.Serve(ctx, nil)
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintf(errOut, "[hook-guardian] peer broker stopped (managed Windows route-only callers are refused until it serves again): %v\n", err)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}()
}
