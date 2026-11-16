// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
)

// TestChooseAcquirerKeysOnDeploymentMode pins the rule left after the retired
// ai_discovery.runtime.acquisition and helper_socket keys: a gateway with wide
// coverage reads directly, a de-privileged managed gateway asks the helper at
// the installer-owned path whatever its environment says, and a de-privileged
// unmanaged gateway asks a helper only when its environment names a socket it
// can trust as root's (the Claude Cowork VM split).
func TestChooseAcquirerKeysOnDeploymentMode(t *testing.T) {
	previousSleep := sleepHelperSocket
	t.Cleanup(func() { sleepHelperSocket = previousSleep })
	waits := 0
	sleepHelperSocket = func(context.Context, time.Duration) bool { waits++; return true }
	t.Setenv(acquire.SocketEnvVar, "")
	if chooseAcquirer(context.Background(), &config.Config{DataDir: t.TempDir()}).Brokered() {
		t.Fatal("an unmanaged gateway asked a helper, but no helper is installed for it")
	}
	t.Setenv(acquire.SocketEnvVar, "relative/helper.sock")
	if chooseAcquirer(context.Background(), &config.Config{DataDir: t.TempDir()}).Brokered() {
		t.Fatal("an unmanaged gateway brokered through a relative socket path")
	}
	// A path in a folder this account owns is never trusted.
	t.Setenv(acquire.SocketEnvVar, filepath.Join(t.TempDir(), "elsewhere.sock"))
	if chooseAcquirer(context.Background(), &config.Config{DataDir: t.TempDir()}).Brokered() {
		t.Fatal("an unmanaged gateway brokered through a socket in a folder its own account can write")
	}
	if waits != 0 {
		t.Fatalf("waited %d times for a socket in a folder its own account can write", waits)
	}

	dataDir := t.TempDir()
	managedAcquirer := chooseAcquirer(context.Background(), &config.Config{DeploymentMode: "managed_enterprise", DataDir: dataDir})
	if acquire.NewLocal().WideCoverage() {
		// Running as root: the managed gateway can read everything itself.
		if managedAcquirer.Brokered() {
			t.Fatal("a managed gateway with wide coverage added a broker")
		}
		return
	}
	if !managedAcquirer.Brokered() {
		t.Fatal("a de-privileged managed gateway read directly and sees only its own account")
	}
	if got, want := managedAcquirer.Describe(), "brokered via "+acquire.DefaultSocketPath(dataDir, true); got != want {
		t.Fatalf("Describe() = %q, want %q (the environment must not move the managed socket)", got, want)
	}
}

// cowork-1-0-8 GAP-0049: a gateway restarted together with its helper may
// look before the socket exists. It waits, for at most helperSocketWait of
// wall-clock time, only for a socket absent from folders only root can write,
// and brokers once it is up; a socket that never appears, an untrusted
// folder, or a cancelled start reads directly.
func TestUnmanagedGatewayWaitsBoundedForTheHelperSocket(t *testing.T) {
	previousCheck, previousProbe, previousAwait, previousSleep, previousNow :=
		checkHelperSocket, probeHelperSocket, awaitHelperSocket, sleepHelperSocket, helperSocketNow
	t.Cleanup(func() {
		checkHelperSocket, probeHelperSocket, awaitHelperSocket, sleepHelperSocket, helperSocketNow =
			previousCheck, previousProbe, previousAwait, previousSleep, previousNow
	})
	if runtime.GOOS == "windows" {
		// Windows has no unmanaged helper broker by design: the Cowork VM
		// sensor and its root helper are Linux-only, and
		// acquire/root_socket_windows.go refuses every socket (CheckRootSocket)
		// and never waits (RootSocketAwaitable is false). So the expected
		// Windows result is no wait and no broker, through the real checks,
		// for any absolute path the environment names. The bounded wait below
		// is the Linux and macOS path.
		var slept time.Duration
		sleepHelperSocket = func(_ context.Context, d time.Duration) bool { slept += d; return true }
		checks := 0
		checkHelperSocket = func(socket string) error { checks++; return previousCheck(socket) }
		for _, socket := range []string{filepath.Join(t.TempDir(), "sensor-helper.sock"), `C:\ProgramData\DefenseClaw\sensor-helper.sock`} {
			t.Setenv(acquire.SocketEnvVar, socket)
			if got := unmanagedHelperSocket(context.Background()); got != "" || slept != 0 {
				t.Fatalf("unmanaged Windows gateway with %s=%q: brokered via %q, slept %v; want no broker and no wait", acquire.SocketEnvVar, socket, got, slept)
			}
		}
		if checks != 2 {
			t.Fatalf("the Windows socket check ran %d times, want 2 (once per absolute path, no retries)", checks)
		}
		return
	}
	t.Setenv(acquire.SocketEnvVar, "/run/defenseclaw-cowork-sensor/sensor-helper.sock")
	clock := time.Unix(1_800_000_000, 0)
	helperSocketNow = func() time.Time { return clock }
	var slept time.Duration
	sleepHelperSocket = func(_ context.Context, d time.Duration) bool { slept += d; clock = clock.Add(d); return true }
	awaitHelperSocket = func(string) bool { return true }
	absent := fmt.Errorf("helper socket: %w", fs.ErrNotExist)
	checks := 0
	checkHelperSocket = func(string) error {
		if checks++; checks <= 3 {
			return absent
		}
		return nil
	}
	probeHelperSocket = func(context.Context, string) error { return nil }
	if unmanagedHelperSocket(context.Background()) == "" || checks != 4 || slept == 0 {
		t.Fatalf("helper that came up after %d checks: brokered=false or slept=%v", checks, slept)
	}
	slept, checks = 0, -1000
	if unmanagedHelperSocket(context.Background()) != "" || slept > helperSocketWait {
		t.Fatalf("a socket that never appears brokered, or waited %v (cap %v)", slept, helperSocketWait)
	}
	// A socket missing from a folder its account could write is not waited for.
	slept, checks = 0, 0
	awaitHelperSocket = func(string) bool { return false }
	if unmanagedHelperSocket(context.Background()) != "" || slept != 0 {
		t.Fatalf("an untrusted socket was waited for (%v) or brokered", slept)
	}
	// A cancelled start returns promptly from the wait.
	awaitHelperSocket = func(string) bool { return true }
	sleepHelperSocket, helperSocketNow = previousSleep, previousNow
	checks = -1000
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	started := time.Now()
	if unmanagedHelperSocket(ctx) != "" {
		t.Fatal("a cancelled start brokered")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("a cancelled start returned after %v", elapsed)
	}
}

// The trusted unmanaged branch: a root-owned socket served by root brokers,
// one served by another account does not, and the per-user process filter
// stays on whenever the gateway reads directly.
func TestUnmanagedGatewayBrokersOnlyThroughATrustedRootSocket(t *testing.T) {
	if acquire.NewLocal().WideCoverage() {
		t.Skip("a gateway with wide coverage never brokers")
	}
	previousCheck, previousProbe, previousAwait, previousSleep :=
		checkHelperSocket, probeHelperSocket, awaitHelperSocket, sleepHelperSocket
	t.Cleanup(func() {
		checkHelperSocket, probeHelperSocket, awaitHelperSocket, sleepHelperSocket =
			previousCheck, previousProbe, previousAwait, previousSleep
	})
	socket := "/run/defenseclaw-cowork-sensor/sensor-helper.sock"
	t.Setenv(acquire.SocketEnvVar, socket)
	cfg := &config.Config{DataDir: t.TempDir()}
	// Every case here is a socket that exists or a folder that is not
	// root's: none is waited for (REVIEW-5); the fallback is immediate.
	awaitHelperSocket = func(string) bool { return false }
	sleeps := 0
	sleepHelperSocket = func(context.Context, time.Duration) bool { sleeps++; return true }
	t.Cleanup(func() {
		if sleeps != 0 {
			t.Errorf("waited %d times for a socket that is there or untrusted", sleeps)
		}
	})

	checkHelperSocket = func(string) error { return nil }
	probeHelperSocket = func(context.Context, string) error { return nil }
	trusted := chooseAcquirer(context.Background(), cfg)
	if !trusted.Brokered() || trusted.Describe() != "brokered via "+socket {
		t.Fatalf("root-owned socket served by root: Brokered=%v Describe=%q", trusted.Brokered(), trusted.Describe())
	}
	if _, wrapped := ownAccountProcesses(cfg, trusted).(ownerProcessAcquirer); wrapped {
		t.Fatal("the root helper's machine-wide view was filtered to the gateway account")
	}

	probeHelperSocket = func(context.Context, string) error { return acquire.ErrHelperNotRoot }
	if chooseAcquirer(context.Background(), cfg).Brokered() {
		t.Fatal("brokered through a socket another account serves")
	}
	// The broker chooseAcquirer returns checks the serving uid on every
	// connect: a socket this (non-root) test process serves answers nothing,
	// even when the selection-time checks were passed.
	if os.Geteuid() != 0 && runtime.GOOS != "windows" {
		served := filepath.Join(shortTempDir(t), "s.sock")
		listener, err := net.Listen("unix", served)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		t.Setenv(acquire.SocketEnvVar, served)
		probeHelperSocket = func(context.Context, string) error { return nil }
		broker := chooseAcquirer(context.Background(), cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, err := broker.Processes(ctx); !errors.Is(err, acquire.ErrHelperNotRoot) {
			t.Fatalf("Processes through a non-root server = %v, want ErrHelperNotRoot", err)
		}
		t.Setenv(acquire.SocketEnvVar, socket)
	}
	checkHelperSocket = func(string) error { return errors.New("folder writable by group or others") }
	probeHelperSocket = func(context.Context, string) error { return nil }
	direct := chooseAcquirer(context.Background(), cfg)
	if direct.Brokered() {
		t.Fatal("brokered through a socket in a writable folder")
	}
	if name, _ := inventory.CurrentProcessOwner(); name != "" {
		if _, wrapped := ownAccountProcesses(cfg, direct).(ownerProcessAcquirer); !wrapped {
			t.Fatal("a gateway reading directly lost the per-user process filter")
		}
	}
}

// shortTempDir keeps unix socket paths under the 108-byte sun_path limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dcgw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// cowork-1-0-8 GAP-0008: only an unmanaged, de-privileged Linux gateway
// whose environment names a root helper reads homes through it; managed
// gateways keep their own paths. An old helper is "unsupported", not down.
func TestBrokeredHomeReaderOnlyForTheUnmanagedHelper(t *testing.T) {
	if runtime.GOOS != "linux" || acquire.NewLocal().WideCoverage() {
		t.Skip("the Cowork VM broker is a de-privileged Linux gateway's")
	}
	previousCheck, previousProbe, previousHelper := checkHelperSocket, probeHelperSocket, newBrokeredHomeHelper
	t.Cleanup(func() {
		checkHelperSocket, probeHelperSocket, newBrokeredHomeHelper = previousCheck, previousProbe, previousHelper
	})
	t.Setenv(acquire.SocketEnvVar, "")
	if brokeredHomeReader(&config.Config{}) != nil {
		t.Fatal("a gateway with no helper socket brokers discovery")
	}
	t.Setenv(acquire.SocketEnvVar, "/run/defenseclaw-cowork-sensor/sensor-helper.sock")
	if brokeredHomeReader(&config.Config{DeploymentMode: "managed_enterprise"}) != nil {
		t.Fatal("a managed gateway brokers discovery")
	}
	reader := brokeredHomeReader(&config.Config{})
	if reader == nil {
		t.Fatal("the Cowork VM gateway does not broker discovery")
	}

	dir, err := os.MkdirTemp("", "bhr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	checkHelperSocket = func(string) error { return nil }
	probeHelperSocket = func(context.Context, string) error { return nil }
	serve := func(name string, discovery func(context.Context) (any, error)) {
		socket := filepath.Join(dir, name)
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Skipf("unix sockets unavailable: %v", err)
		}
		server := acquire.NewServer(acquire.ServerConfig{Discovery: discovery})
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = server.Serve(ctx, listener) }()
		t.Cleanup(cancel)
		newBrokeredHomeHelper = func(string) *acquire.Helper { return acquire.NewHelper(socket) }
	}
	serve("old", nil)
	if _, err := reader(context.Background()); !errors.Is(err, inventory.ErrBrokeredHomesUnsupported) {
		t.Fatalf("a helper without discovery: %v", err)
	}
	serve("new", func(context.Context) (any, error) {
		return inventory.BrokeredHomeReport{Version: inventory.BrokeredHomeReportVersion,
			Homes: []inventory.BrokeredHome{{Home: "/sessions/cwk-v1", UID: 1005, User: "cwk-v1"}}}, nil
	})
	report, err := reader(context.Background())
	if err != nil || len(report.Homes) != 1 || report.Homes[0].User != "cwk-v1" {
		t.Fatalf("report %+v err %v", report, err)
	}
}
