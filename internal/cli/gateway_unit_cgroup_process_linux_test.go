// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// GAP-0205, black box: a real systemd user unit runs `stop` or `start` the
// way the documented Type=forking unit runs ExecStop and ExecStart, against a
// probe gateway (a real process with its PID record) that runs outside the
// unit, as the gateway a `defenseclaw setup remove` restart from a shell
// leaves behind. Skipped where no systemd user manager runs.

const gap0205UnitChildEnv = "DC_TEST_GAP0205_UNIT_CHILD"

// TestGAP0205UnitProcessChild is the process systemd runs; it does nothing
// in an ordinary test run.
func TestGAP0205UnitProcessChild(t *testing.T) {
	switch os.Getenv(gap0205UnitChildEnv) {
	case "stop":
		err := runStop(stopCmd, nil)
		fmt.Printf("\nGAP0205-CHILD stop err=%v\n", err)
	case "start":
		// Ends the start where it would launch the gateway; the error names
		// the marker, so the parent knows the start got that far.
		stubRootRuntimeLeftovers(t, "gap0205-start-reached-launch")
		err := runStart(startCmd, nil)
		fmt.Printf("\nGAP0205-CHILD start err=%v\n", err)
	case "stop-own":
		d := daemon.New(config.DefaultDataPath())
		if _, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"}); err != nil {
			fmt.Printf("\nGAP0205-CHILD stop-own start err=%v\n", err)
			return
		}
		waitForCLIProbe(t, d, os.Getenv(cliRestartProbeEnv))
		err := runStop(stopCmd, nil)
		running, _ := d.IsRunning()
		fmt.Printf("\nGAP0205-CHILD stop-own err=%v running=%v\n", err, running)
	}
}

func gap0205RequireSystemdUserManager(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "systemd-run", "--user", "--wait", "--quiet", "--collect", "true").CombinedOutput(); err != nil {
		t.Skipf("no systemd user manager: %v %s", err, strings.TrimSpace(string(out)))
	}
}

// gap0205RunAsUnit runs the child as a transient systemd user service.
// viaShell puts a shell between systemd and the child: an SSM-, Salt- or
// CI-agent-like caller that inherits INVOCATION_ID and the unit's cgroup but
// whose parent is not systemd.
func gap0205RunAsUnit(t *testing.T, mode, home string, viaShell bool) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--user", "--wait", "--pipe", "--quiet", "--collect", "--same-dir"}
	for _, env := range []string{
		gap0205UnitChildEnv + "=" + mode,
		"DEFENSECLAW_HOME=" + home,
		testProcessGuardChildEnv + "=" + strconv.Itoa(os.Getpid()),
		cliRestartProbeEnv + "=" + os.Getenv(cliRestartProbeEnv),
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	} {
		args = append(args, "--setenv="+env)
	}
	command := []string{exe, "-test.run=^TestGAP0205UnitProcessChild$", "-test.count=1"}
	if viaShell {
		command = append([]string{"/bin/sh", "-c", `"$0" "$@"; exit $?`}, command...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemd-run", append(args, command...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("systemd-run %s: %v\n%s", mode, err, out)
	}
	return string(out)
}

// gap0205ProbeGatewayOutsideTheUnit starts the probe gateway from the test
// process (a login session or a CI job, never the transient unit).
func gap0205ProbeGatewayOutsideTheUnit(t *testing.T, configYAML string) (string, *daemon.Daemon, int) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "probe-running")
	t.Setenv(cliRestartProbeEnv, marker)
	d := daemon.New(config.DefaultDataPath())
	pid, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"})
	if err != nil {
		t.Fatalf("start probe gateway: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop(3 * time.Second) })
	waitForCLIProbe(t, d, marker)
	return home, d, pid
}

func TestGAP0205UnitExecStopLeavesAGatewayOutsideTheUnitRunning(t *testing.T) {
	gap0205RequireSystemdUserManager(t)
	for _, tc := range []struct {
		name     string
		viaShell bool
		stops    bool
	}{
		{name: "systemd runs stop, gateway outside the unit", viaShell: false, stops: false},
		{name: "an agent in the unit runs stop", viaShell: true, stops: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An unloadable config: stop signals the verified PID and sends
			// no request to a port.
			home, d, pid := gap0205ProbeGatewayOutsideTheUnit(t, "gateway: [unterminated\n")
			out := gap0205RunAsUnit(t, "stop", home, tc.viaShell)
			if !strings.Contains(out, "GAP0205-CHILD stop err=<nil>") {
				t.Fatalf("stop did not exit 0:\n%s", out)
			}
			running, current := d.IsRunning()
			_, markerErr := os.Stat(gatewayStoppedMarkerPath(home))
			if tc.stops {
				if running {
					t.Fatalf("a stop whose parent is not systemd left the gateway PID %d running:\n%s", current, out)
				}
				return
			}
			if !running || current != pid {
				t.Fatalf("the unit's ExecStop stopped the gateway outside the unit (PID %d; now running %v PID %d):\n%s", pid, running, current, out)
			}
			if !strings.Contains(out, "outside the systemd unit") {
				t.Fatalf("stop did not say it left the gateway running:\n%s", out)
			}
			if markerErr == nil {
				t.Fatal("stop wrote the stop marker for a gateway it left running")
			}
		})
	}
}

func TestGAP0205UnitExecStopStopsTheUnitsOwnGateway(t *testing.T) {
	gap0205RequireSystemdUserManager(t)
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("gateway: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cliRestartProbeEnv, filepath.Join(t.TempDir(), "probe-running"))
	out := gap0205RunAsUnit(t, "stop-own", home, false)
	if !strings.Contains(out, "GAP0205-CHILD stop-own err=<nil> running=false") {
		t.Fatalf("the unit's ExecStop did not stop the gateway in its own cgroup:\n%s", out)
	}
}

func TestGAP0205UnitExecStartTakesOverAGatewayOutsideTheUnit(t *testing.T) {
	gap0205RequireSystemdUserManager(t)
	for _, tc := range []struct {
		name      string
		viaShell  bool
		takesOver bool
	}{
		{name: "systemd runs start, gateway outside the unit", viaShell: false, takesOver: true},
		{name: "an agent in the unit runs start", viaShell: true, takesOver: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()
			home, d, pid := gap0205ProbeGatewayOutsideTheUnit(t, fmt.Sprintf("config_version: 8\ngateway:\n  api_port: %d\n", port))
			out := gap0205RunAsUnit(t, "start", home, tc.viaShell)
			running, current := d.IsRunning()
			if !tc.takesOver {
				if !running || current != pid || !strings.Contains(out, "already running") {
					t.Fatalf("a start whose parent is not systemd did not report the gateway PID %d already running (now running %v PID %d):\n%s", pid, running, current, out)
				}
				return
			}
			if running {
				t.Fatalf("the unit's ExecStart left the gateway outside the unit running (PID %d):\n%s", current, out)
			}
			if !strings.Contains(out, "gap0205-start-reached-launch") {
				t.Fatalf("the unit's ExecStart did not go on to start the gateway under the unit:\n%s", out)
			}
		})
	}
}
