// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1342: a gateway process that is alive but does not answer /health is
// reported as not answering, with restart as the fix, not as "NOT RUNNING
// ... start" (start only says it is already running).
func TestStatusNamesRestartForALiveGatewayThatDoesNotAnswer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	previousConfig, previousState := cfg, gatewayManagedState
	t.Cleanup(func() { cfg, gatewayManagedState = previousConfig, previousState })
	cfg = &config.Config{DataDir: t.TempDir()}
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = port

	gatewayManagedState = func() (bool, int) { return true, 4242 }
	var runErr error
	out := captureStdout(t, func() { runErr = runSidecarStatus(nil, nil) })
	if runErr == nil || !strings.Contains(out, "NOT ANSWERING") || !strings.Contains(out, "PID 4242") ||
		!strings.Contains(out, "defenseclaw-gateway restart") {
		t.Fatalf("hung gateway status: err=%v\n%s", runErr, out)
	}

	gatewayManagedState = func() (bool, int) { return false, 0 }
	out = captureStdout(t, func() { runErr = runSidecarStatus(nil, nil) })
	if runErr == nil || !strings.Contains(out, "NOT RUNNING") || !strings.Contains(out, "defenseclaw-gateway start") {
		t.Fatalf("stopped gateway status: err=%v\n%s", runErr, out)
	}
}
