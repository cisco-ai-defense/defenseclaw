// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// GAP-1762: setup gateway refuses a port another account claimed, so the
// suggestion skips it too and names the next free one.
func TestFreeGatewayAPIPortSkipsOtherAccountsClaims(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	from := listener.Addr().(*net.TCPAddr).Port
	if from+gatewayAPIPortTries*gatewayAPIPortStep+2 > 65535 {
		t.Skip("ephemeral port too close to the top of the range")
	}
	free := freeGatewayAPIPort("127.0.0.1", from)
	if free == 0 {
		t.Skip("no free candidate ports on this host")
	}
	previous := gatewayPortClaimedByOtherAccount
	t.Cleanup(func() { gatewayPortClaimedByOtherAccount = previous })
	gatewayPortClaimedByOtherAccount = func(port int) bool { return port == free }
	got := freeGatewayAPIPort("127.0.0.1", from)
	if got == free || (got != 0 && (got-from)%gatewayAPIPortStep != 0) {
		t.Fatalf("freeGatewayAPIPort(%d) = %d, want a port other than the claimed %d", from, got, free)
	}
	if fix := foreignGatewayListenerFixAt("127.0.0.1", from); strings.Contains(fix, fmt.Sprintf("--api-port %d ", free)) {
		t.Fatalf("fix = %q, names the claimed port %d", fix, free)
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

// GAP-1285: another account's gateway took the port between the start check
// and readiness; the readiness error names the holder and the next step.
func TestReadinessIdentityMismatchNamesForeignHolder(t *testing.T) {
	oldHolder, oldAnswers, oldState := gatewayPortHolder, gatewayPortAnswers, gatewayManagedState
	oldOther := gatewayPortHeldByOtherAccount
	t.Cleanup(func() {
		gatewayPortHolder, gatewayPortAnswers, gatewayManagedState = oldHolder, oldAnswers, oldState
		gatewayPortHeldByOtherAccount = oldOther
	})
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{PID: 13496, UID: -1}, nil }
	gatewayPortAnswers = func(string) bool { return true }
	gatewayManagedState = func() (bool, int) { return false, 0 }
	gatewayPortHeldByOtherAccount = func(string, int) bool { return true }
	c := config.DefaultConfig()
	c.Gateway.APIBind = "127.0.0.1"
	c.Gateway.APIPort = 18970

	mismatch := fmt.Errorf("%w: authenticated status returned 401 Unauthorized", errGatewayIdentityMismatch)
	got := explainForeignListenerAtReadiness(c, mismatch)
	if !errors.Is(got, errGatewayIdentityMismatch) || !strings.Contains(got.Error(), "held by PID 13496") ||
		!strings.Contains(got.Error(), "defenseclaw setup gateway --api-port ") {
		t.Fatalf("readiness error = %v, want the holder and the setup gateway command", got)
	}
	other := errors.New("gateway did not become ready before timeout")
	if got := explainForeignListenerAtReadiness(c, other); got != other {
		t.Fatalf("unrelated readiness error changed: %v", got)
	}
}

// GAP-0130: the installer's pre-flight refuses an API port another account's
// process holds before it builds or swaps anything, but never calls this
// account's own older gateway foreign.
func TestCheckAPIPortRefusesOnlyAnotherAccountsListener(t *testing.T) {
	oldHolder, oldAnswers := gatewayPortHolder, gatewayPortAnswers
	t.Cleanup(func() { gatewayPortHolder, gatewayPortAnswers = oldHolder, oldAnswers })
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("gateway:\n  api_port: 19321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	holder := func(h daemon.PortHolder, err error) {
		gatewayPortHolder = func(string, int) (daemon.PortHolder, error) { return h, err }
	}
	gatewayPortAnswers = func(string) bool { return true }

	holder(daemon.PortHolder{PID: 77, UID: os.Getuid()}, nil)
	if err := checkAPIPort(path); err != nil {
		t.Fatalf("this account's own gateway refused: %v", err)
	}
	holder(daemon.PortHolder{UID: os.Getuid() + 1}, nil)
	err := checkAPIPort(path)
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:19321 is held by a process of another account") ||
		!strings.Contains(err.Error(), "defenseclaw setup gateway --api-port ") ||
		!strings.Contains(err.Error(), "upgrade again") {
		t.Fatalf("another account's listener: %v", err)
	}
	// macOS lsof does not list another account's sockets: an answering port nobody lists is theirs.
	holder(daemon.PortHolder{UID: -1}, daemon.ErrNoListener)
	if err := checkAPIPort(path); err == nil {
		t.Fatal("an unlisted listener that answers was not refused")
	}
	gatewayPortAnswers = func(string) bool { return false }
	if err := checkAPIPort(path); err != nil {
		t.Fatalf("a free port refused: %v", err)
	}
	if err := checkAPIPort(filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatalf("a missing config refused: %v", err)
	}
}
