// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
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
	// GAP-1706: one command form everywhere, and another account's process
	// is not this account's to stop.
	previous := gatewayPortHeldByOtherAccount
	t.Cleanup(func() { gatewayPortHeldByOtherAccount = previous })
	for _, other := range []bool{true, false} {
		gatewayPortHeldByOtherAccount = func(string, int) bool { return other }
		fix := foreignGatewayListenerFix(c)
		if !strings.Contains(fix, " --non-interactive, then run: defenseclaw-gateway start") ||
			strings.HasPrefix(fix, "Stop that process") == other ||
			strings.Contains(fix, "belongs to another account") != other {
			t.Fatalf("other account %v: fix = %q", other, fix)
		}
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

// GAP-1344: Windows names a holder by PID only (no uid). Another account's
// gateway on this account's port is not this account's gateway, so status
// must not show its status as ours; a managed install keeps its own checks.
func TestForeignGatewayListenerHolderWithoutUID(t *testing.T) {
	oldHolder, oldAnswers, oldState := gatewayPortHolder, gatewayPortAnswers, gatewayManagedState
	t.Cleanup(func() { gatewayPortHolder, gatewayPortAnswers, gatewayManagedState = oldHolder, oldAnswers, oldState })
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{PID: 13496, UID: -1}, nil }
	gatewayPortAnswers = func(string) bool { return true }
	c := config.DefaultConfig()
	c.Gateway.APIBind = "127.0.0.1"
	c.Gateway.APIPort = 18970

	for _, own := range []struct {
		running bool
		pid     int
	}{{true, 4242}, {false, 0}} {
		gatewayManagedState = func() (bool, int) { return own.running, own.pid }
		if problem := foreignGatewayListener(c); !strings.Contains(problem, "held by PID 13496") ||
			!strings.Contains(problem, "not by this account's gateway") {
			t.Fatalf("own gateway running=%v: foreign listener = %q", own.running, problem)
		}
	}
	gatewayManagedState = func() (bool, int) { return true, 13496 }
	if problem := foreignGatewayListener(c); problem != "" {
		t.Fatalf("this account's own gateway reported as foreign: %q", problem)
	}
	gatewayManagedState = func() (bool, int) { return false, 0 }
	c.DeploymentMode = "managed_enterprise"
	if problem := foreignGatewayListener(c); problem != "" {
		t.Fatalf("managed install reported a foreign listener: %q", problem)
	}
}
