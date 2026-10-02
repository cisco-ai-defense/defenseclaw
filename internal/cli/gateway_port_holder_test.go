// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A listener this home did not start (a gateway leaked by another home or
// test run) is named by PID instead of being reported as this gateway.
func TestForeignGatewayListenerNamesHolderPID(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c := config.DefaultConfig()
	c.Gateway.APIBind = "127.0.0.1"
	c.Gateway.APIPort = listener.Addr().(*net.TCPAddr).Port

	problem := foreignGatewayListener(c)
	if want := fmt.Sprintf("held by PID %d", os.Getpid()); !strings.Contains(problem, want) ||
		!strings.Contains(problem, "not by this account's gateway") {
		t.Fatalf("foreign listener = %q, want it to contain %q", problem, want)
	}
	// The fix names the command that moves this account's gateway.
	if fix := foreignGatewayListenerFix(c); !strings.Contains(fix, "defenseclaw setup gateway --api-port ") {
		t.Fatalf("fix = %q, want the setup gateway --api-port command", fix)
	}
	listener.Close()
	if problem := foreignGatewayListener(c); problem != "" {
		t.Fatalf("free port reported as held: %q", problem)
	}
}

// GAP-1059: the suggested port must not be the holder's sandbox ingress or
// egress port (api_port+1, +2), and it must leave room for this account's.
func TestFreeGatewayAPIPortSkipsSandboxPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	from := listener.Addr().(*net.TCPAddr).Port
	if from+40 > 65535 {
		t.Skip("ephemeral port too close to the top of the range")
	}
	// The next candidate's sandbox egress port is taken, so it is skipped.
	blocker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", from+gatewayAPIPortStep+2))
	if err != nil {
		t.Skipf("candidate port busy: %v", err)
	}
	defer blocker.Close()
	got := freeGatewayAPIPort("127.0.0.1", from)
	if got == 0 {
		t.Skip("no free candidate ports on this host")
	}
	if got <= from+2 || (got-from)%gatewayAPIPortStep != 0 || got == from+gatewayAPIPortStep {
		t.Fatalf("freeGatewayAPIPort(%d) = %d, want a later multiple of %d clear of busy sandbox ports", from, got, gatewayAPIPortStep)
	}
}
