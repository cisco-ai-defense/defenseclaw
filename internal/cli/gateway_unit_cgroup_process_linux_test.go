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
// leaves behind. Only the unit the data directory's gateway is bound to (the
// one whose ExecStart last launched it, gap0205UnitRecordFile) acts on such
// a gateway as a unit; a transient `systemd-run --user defenseclaw-gateway
// start` or `stop` acts as a shell does.
//
// Skipped where no systemd user manager runs, unless
// DC_TEST_REQUIRE_SYSTEMD_USER is set: then that is a failure.

const (
	gap0205UnitChildEnv     = "DC_TEST_GAP0205_UNIT_CHILD"
	gap0205BindEnv          = "DC_TEST_GAP0205_BIND"
	gap0205RootLeftoverEnv  = "DC_TEST_GAP0205_ROOT_LEFTOVER"
	gap0205RequireUserEnv   = "DC_TEST_REQUIRE_SYSTEMD_USER"
	gap0205UnitRecordFile   = "gateway.unit-cgroup"
	gap0205DocumentedUnit   = "/system.slice/defenseclaw-gateway.service"
	gap0205RootLeftoverName = "gap0205-root-leftover"
)

// TestGAP0205UnitProcessChild is the process systemd runs; it does nothing
// in an ordinary test run.
func TestGAP0205UnitProcessChild(t *testing.T) {
	mode := os.Getenv(gap0205UnitChildEnv)
	if mode == "" {
		return
	}
	home := config.DefaultDataPath()
	if os.Getenv(gap0205BindEnv) != "" {
		// What the unit's ExecStart records when it launches the gateway:
		// this unit is the one the data directory's gateway is bound to.
		raw, err := os.ReadFile("/proc/self/cgroup")
		cgroup, ok := systemdCgroupPath(raw)
		if err == nil && ok {
			err = os.WriteFile(filepath.Join(home, gap0205UnitRecordFile), []byte(cgroup+"\n"), 0o600)
		} else if err == nil {
			err = fmt.Errorf("unparseable cgroup %q", raw)
		}
		if err != nil {
			fmt.Printf("\nGAP0205-CHILD bind err=%v\n", err)
			return
		}
	}
	rootLeftover := os.Getenv(gap0205RootLeftoverEnv) != ""
	if rootLeftover {
		stubRootRuntimeLeftovers(t, gap0205RootLeftoverName)
	}
	switch mode {
	case "stop":
		err := runStop(stopCmd, nil)
		fmt.Printf("\nGAP0205-CHILD stop err=%v\n", err)
	case "start":
		// A start that got past every refusal ends where it launches the
		// gateway (the parent made the log file a directory); without that
		// guard or the root-leftover stub it would launch this test binary.
		if info, err := os.Stat(daemon.New(home).LogFile()); !rootLeftover && (err != nil || !info.IsDir()) {
			fmt.Printf("\nGAP0205-CHILD start refused: no launch guard\n")
			return
		}
		err := runStart(startCmd, nil)
		fmt.Printf("\nGAP0205-CHILD start err=%v\n", err)
	case "stop-own":
		d := daemon.New(home)
		pid, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"})
		if err != nil {
			fmt.Printf("\nGAP0205-CHILD stop-own start err=%v\n", err)
			return
		}
		reapCLIProbe(t, pid)
		waitForCLIProbe(t, d, os.Getenv(cliRestartProbeEnv))
		err = runStop(stopCmd, nil)
		running, _ := d.IsRunning()
		fmt.Printf("\nGAP0205-CHILD stop-own err=%v running=%v\n", err, running)
	}
}

func gap0205RequireSystemdUserManager(t *testing.T) {
	t.Helper()
	skip := t.Skipf
	if os.Getenv(gap0205RequireUserEnv) != "" {
		skip = t.Fatalf
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		skip("systemd-run is not installed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "systemd-run", "--user", "--wait", "--quiet", "--collect", "true").CombinedOutput(); err != nil {
		skip("no systemd user manager: %v %s", err, strings.TrimSpace(string(out)))
	}
}

// gap0205Unit is how the child runs. bind: the unit is the one the gateway
// is bound to. viaShell puts a shell between systemd and the child: an
// SSM-, Salt- or CI-agent-like caller that inherits INVOCATION_ID and the
// unit's cgroup but whose parent is not systemd. rootLeftover: the start
// refuses over (stubbed) root-owned runtime leftovers.
type gap0205Unit struct {
	bind, viaShell, rootLeftover bool
}

// gap0205RunAsUnit runs the child as a transient systemd user service, the
// way `systemd-run --user defenseclaw-gateway <mode>` runs it; a bound unit
// is named, as a unit file's service is.
func gap0205RunAsUnit(t *testing.T, mode, home string, unit gap0205Unit) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--user", "--wait", "--pipe", "--quiet", "--collect", "--same-dir"}
	if unit.bind {
		// The unit a gateway is bound to has a name of its own: the names
		// systemd-run makes up for one command are never bound.
		args = append(args, fmt.Sprintf("--unit=dc-gap0205-%d-%d.service", os.Getpid(), time.Now().UnixNano()))
	}
	env := []string{
		gap0205UnitChildEnv + "=" + mode,
		"DEFENSECLAW_HOME=" + home,
		testProcessGuardChildEnv + "=" + strconv.Itoa(os.Getpid()),
		cliRestartProbeEnv + "=" + os.Getenv(cliRestartProbeEnv),
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	if unit.bind {
		env = append(env, gap0205BindEnv+"=1")
	}
	if unit.rootLeftover {
		env = append(env, gap0205RootLeftoverEnv+"=1")
	}
	for _, e := range env {
		args = append(args, "--setenv="+e)
	}
	command := []string{exe, "-test.run=^TestGAP0205UnitProcessChild$", "-test.count=1"}
	if unit.viaShell {
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

// An unloadable config: stop signals the verified PID and sends no request
// to a port.
const gap0205UnloadableConfig = "gateway: [unterminated\n"

func gap0205ValidConfig(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return fmt.Sprintf("config_version: 8\ngateway:\n  api_port: %d\n", port)
}

// gap0205BindDocumentedUnit records the documented system unit as the one
// the gateway is bound to: a transient unit is never that unit.
func gap0205BindDocumentedUnit(t *testing.T, home string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, gap0205UnitRecordFile), []byte(gap0205DocumentedUnit+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// gap0205GuardLaunch makes the gateway log file a directory, so a start
// that gets past every refusal fails where it launches the gateway.
func gap0205GuardLaunch(t *testing.T, d *daemon.Daemon) {
	t.Helper()
	if err := os.Rename(d.LogFile(), d.LogFile()+".probe"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(d.LogFile(), 0o700); err != nil {
		t.Fatal(err)
	}
}

func gap0205RequireUntouched(t *testing.T, d *daemon.Daemon, pid int, out, what string) {
	t.Helper()
	if running, current := d.IsRunning(); !running || current != pid {
		t.Fatalf("%s: the gateway PID %d outside the unit was stopped (now running %v PID %d):\n%s", what, pid, running, current, out)
	}
	if strings.Contains(out, "Stopping gateway sidecar") {
		t.Fatalf("%s: started to stop the gateway outside the unit:\n%s", what, out)
	}
}

// Review round 4, P2-1: `systemd-run --user defenseclaw-gateway start` is a
// systemd unit's ExecStart, but not the unit the gateway is bound to. It
// used to stop the running gateway and start one inside the transient unit,
// which systemd then killed with the unit.
func TestGAP0205TransientUnitStartLeavesTheGatewayUntouched(t *testing.T) {
	gap0205RequireSystemdUserManager(t)
	for _, tc := range []struct {
		name       string
		documented bool
	}{
		{name: "no unit recorded"},
		{name: "the documented unit recorded", documented: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, d, pid := gap0205ProbeGatewayOutsideTheUnit(t, gap0205ValidConfig(t))
			if tc.documented {
				gap0205BindDocumentedUnit(t, home)
			}
			// The stub is the launch guard: a start that stops the gateway
			// then refuses there.
			out := gap0205RunAsUnit(t, "start", home, gap0205Unit{rootLeftover: true})
			gap0205RequireUntouched(t, d, pid, out, "systemd-run start")
			if !strings.Contains(out, "already running") || !strings.Contains(out, "GAP0205-CHILD start err=<nil>") {
				t.Fatalf("systemd-run start did not report the gateway already running and exit 0:\n%s", out)
			}
		})
	}
}

// Review round 4, P2-1, the other way: `systemd-run --user defenseclaw-gateway
// stop` stops the gateway as a stop from a shell does; it used to exit 0 and
// stop nothing.
func TestGAP0205TransientUnitStopStopsTheGatewayAsAShellDoes(t *testing.T) {
	gap0205RequireSystemdUserManager(t)
	for _, tc := range []struct {
		name       string
		documented bool
	}{
		{name: "no unit recorded"},
		{name: "the documented unit recorded", documented: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, d, pid := gap0205ProbeGatewayOutsideTheUnit(t, gap0205UnloadableConfig)
			if tc.documented {
				gap0205BindDocumentedUnit(t, home)
			}
			out := gap0205RunAsUnit(t, "stop", home, gap0205Unit{})
			if !strings.Contains(out, "GAP0205-CHILD stop err=<nil>") {
				t.Fatalf("systemd-run stop did not exit 0:\n%s", out)
			}
			if running, current := d.IsRunning(); running {
				t.Fatalf("systemd-run stop left the gateway PID %d running (PID %d now):\n%s", pid, current, out)
			}
			if _, err := os.Stat(gatewayStoppedMarkerPath(home)); err != nil {
				t.Fatalf("systemd-run stop wrote no stop marker: %v\n%s", err, out)
			}
		})
	}
}

// Review round 4, P2-2: the bound unit's start refuses what would fail it
// before it stops the gateway outside the unit, as restart does. It used to
// stop that gateway first, so every Restart=on-failure retry failed with no
// gateway left.
func TestGAP0205BoundUnitStartRefusalLeavesTheGatewayOutsideRunning(t *testing.T) {
	gap0205RequireSystemdUserManager(t)
	home, d, pid := gap0205ProbeGatewayOutsideTheUnit(t, gap0205ValidConfig(t))
	out := gap0205RunAsUnit(t, "start", home, gap0205Unit{bind: true, rootLeftover: true})
	gap0205RequireUntouched(t, d, pid, out, "refused unit start")
	if strings.Contains(out, "GAP0205-CHILD start err=<nil>") || !strings.Contains(out, gap0205RootLeftoverName) {
		t.Fatalf("the unit start did not refuse over the root-owned leftovers:\n%s", out)
	}
}

func TestGAP0205BoundUnitExecStopLeavesAGatewayOutsideTheUnitRunning(t *testing.T) {
	gap0205RequireSystemdUserManager(t)
	for _, tc := range []struct {
		name     string
		config   func(*testing.T) string
		viaShell bool
		stops    bool
	}{
		{name: "systemd runs stop, unloadable config", config: func(*testing.T) string { return gap0205UnloadableConfig }},
		{name: "systemd runs stop, valid config", config: gap0205ValidConfig},
		{name: "an agent in the unit runs stop", config: func(*testing.T) string { return gap0205UnloadableConfig }, viaShell: true, stops: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, d, pid := gap0205ProbeGatewayOutsideTheUnit(t, tc.config(t))
			out := gap0205RunAsUnit(t, "stop", home, gap0205Unit{bind: true, viaShell: tc.viaShell})
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
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(gap0205UnloadableConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cliRestartProbeEnv, filepath.Join(t.TempDir(), "probe-running"))
	out := gap0205RunAsUnit(t, "stop-own", home, gap0205Unit{bind: true})
	if !strings.Contains(out, "GAP0205-CHILD stop-own err=<nil> running=false") {
		t.Fatalf("the unit's ExecStop did not stop the gateway in its own cgroup:\n%s", out)
	}
}

func TestGAP0205BoundUnitExecStartTakesOverAGatewayOutsideTheUnit(t *testing.T) {
	gap0205RequireSystemdUserManager(t)
	for _, tc := range []struct {
		name      string
		viaShell  bool
		takesOver bool
	}{
		{name: "systemd runs start, gateway outside the unit", takesOver: true},
		{name: "an agent in the unit runs start", viaShell: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, d, pid := gap0205ProbeGatewayOutsideTheUnit(t, gap0205ValidConfig(t))
			gap0205GuardLaunch(t, d)
			out := gap0205RunAsUnit(t, "start", home, gap0205Unit{bind: true, viaShell: tc.viaShell})
			if !tc.takesOver {
				gap0205RequireUntouched(t, d, pid, out, "a start whose parent is not systemd")
				if !strings.Contains(out, "already running") {
					t.Fatalf("a start whose parent is not systemd did not report the gateway PID %d already running:\n%s", pid, out)
				}
				return
			}
			if running, current := d.IsRunning(); running {
				t.Fatalf("the unit's ExecStart left the gateway outside the unit running (PID %d):\n%s", current, out)
			}
			if !strings.Contains(out, "starting it under the unit") || !strings.Contains(out, "start daemon:") {
				t.Fatalf("the unit's ExecStart did not go on to launch the gateway under the unit:\n%s", out)
			}
		})
	}
}
