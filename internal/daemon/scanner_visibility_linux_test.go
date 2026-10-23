// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"golang.org/x/sys/unix"
)

const (
	scanGatewayEnv        = "DC_DAEMON_SCAN_GATEWAY"
	scanGatewayIgnoreTerm = "DC_DAEMON_SCAN_GATEWAY_IGNORE_TERM"
)

// TestDaemonScanGatewayProbe is the gateway the tests below start: it runs two
// tracked scans that never end on their own, each with a child, and records
// its own dumpable state while they run.
func TestDaemonScanGatewayProbe(t *testing.T) {
	base := os.Getenv(scanGatewayEnv)
	if base == "" {
		return
	}
	if os.Getenv(scanGatewayIgnoreTerm) == "1" {
		signal.Ignore(syscall.SIGTERM)
	}
	if err := RegisterCurrentProcess(); err != nil {
		os.Exit(2)
	}
	for _, name := range []string{"first", "second"} {
		go func() {
			cmd := processutil.CommandContext(context.Background(), "/bin/sh", "-c",
				`sh -c 'read -r p _ < /proc/self/stat; echo "$p" > "$0.tmp"; mv "$0.tmp" "$0"; exec sleep 600' "$1.child" &
read -r p _ < /proc/self/stat; echo "$p" > "$1.tmp"; mv "$1.tmp" "$1"; while :; do sleep 1; done`,
				"sh", base+"."+name)
			_ = processutil.RunTracked(cmd)
		}()
	}
	for _, name := range []string{"first", "second"} {
		for _, file := range []string{base + "." + name, base + "." + name + ".child"} {
			for {
				if _, err := os.Stat(file); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		os.Exit(3)
	}
	if err := os.WriteFile(base+".running", []byte(strconv.Itoa(dumpable)), 0o600); err != nil {
		os.Exit(2)
	}
	for {
		time.Sleep(time.Second)
	}
}

// scanProcesses waits until the probe gateway at base runs both scans and
// returns their host PIDs (each scanner and its child).
func scanProcesses(t *testing.T, base string) []int {
	t.Helper()
	waitForScanMarker(t, base+".running")
	if raw, err := os.ReadFile(base + ".running"); err != nil || string(raw) != "1" {
		t.Fatalf("gateway dumpable while scans run = %q, %v; want 1", raw, err)
	}
	var pids []int
	for _, file := range []string{".first", ".first.child", ".second", ".second.child"} {
		raw, err := os.ReadFile(base + file)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || !processExists(pid) {
			t.Fatalf("scan process %s = %q, %v; not running", file, raw, err)
		}
		pids = append(pids, pid)
	}
	return pids
}

func waitForScanMarker(t *testing.T, marker string) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", marker)
		}
	}
}

func requireScanProcessesEnded(t *testing.T, pids []int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		alive := []int{}
		for _, pid := range pids {
			if processExists(pid) {
				alive = append(alive, pid)
			}
		}
		if len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			for _, pid := range alive {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			t.Fatalf("scan processes %v outlived their gateway", alive)
		}
	}
}

// requireGatewayVisible checks what daemon status and a stale-gateway proof
// read while scans run: the gateway's executable and environment in /proc,
// liveness and the strong identity that authorizes stop and restart.
func requireGatewayVisible(t *testing.T, d *Daemon, pid int, executable string) {
	t.Helper()
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	if live, err := os.Readlink(proc + "/exe"); err != nil || live != executable {
		t.Fatalf("gateway executable during scan = %q, %v; want %q", live, err, executable)
	}
	if _, err := os.ReadFile(proc + "/environ"); err != nil {
		t.Fatalf("read gateway environment during scan: %v", err)
	}
	if running, got := d.IsRunning(); !running || got != pid {
		t.Fatalf("IsRunning during scan = (%v, %d), want (true, %d)", running, got, pid)
	}
	if !d.HasManagedProcessIdentity(pid) {
		t.Fatal("gateway lost its strong process identity during a scan")
	}
}

// r104 W25 review: while a scan ran, the gateway was non-dumpable, so status
// lost its identity, stop refused it, and restart could not stop it. Status,
// restart, stop and a forced stop must work while scans run, and every scan
// process must end with the gateway that owns it.
func TestDaemonStatusRestartAndStopDuringAScan(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	d := New(t.TempDir())
	args := []string{"-test.run=^TestDaemonScanGatewayProbe$"}
	first := filepath.Join(t.TempDir(), "gateway")
	t.Setenv(scanGatewayEnv, first)
	pid, err := d.Start(args)
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop(time.Second) })
	scans := scanProcesses(t, first)
	requireGatewayVisible(t, d, pid, executable)

	// The replacement ignores SIGTERM, so the last stop has to force it.
	second := filepath.Join(t.TempDir(), "gateway")
	t.Setenv(scanGatewayEnv, second)
	t.Setenv(scanGatewayIgnoreTerm, "1")
	restarted, err := d.Restart(args, 5*time.Second)
	if err != nil || restarted == pid {
		t.Fatalf("restart during a scan = %d, %v", restarted, err)
	}
	if processExists(pid) {
		t.Fatalf("old gateway %d still runs after restart", pid)
	}
	requireScanProcessesEnded(t, scans)
	scans = scanProcesses(t, second)
	requireGatewayVisible(t, d, restarted, executable)

	if err := d.Stop(300 * time.Millisecond); err != nil {
		t.Fatalf("forced stop during a scan: %v", err)
	}
	if running, _ := d.IsRunning(); running || processExists(restarted) {
		t.Fatal("gateway still runs after stop")
	}
	requireScanProcessesEnded(t, scans)
}

// An upgrade replaces the gateway's file while it runs. Status must still see
// it as this data directory's gateway, and the authenticated stop the upgrade
// uses must reach it, while scans run.
func TestDaemonSeesAReplacedGatewayDuringAScan(t *testing.T) {
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	copyExecutable(t, source, installed)
	base := filepath.Join(t.TempDir(), "gateway")
	gateway := exec.Command(installed, "-test.run=^TestDaemonScanGatewayProbe$")
	gateway.Env = append(os.Environ(), scanGatewayEnv+"="+base)
	gateway.Stdout, gateway.Stderr = os.Stdout, os.Stderr
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_ = gateway.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = gateway.Process.Kill()
		<-exited
	})
	d := New(t.TempDir())
	identity, err := processStartIdentity(gateway.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.writePIDInfo(gateway.Process.Pid, installed, identity); err != nil {
		t.Fatal(err)
	}
	scans := scanProcesses(t, base)
	requireGatewayVisible(t, d, gateway.Process.Pid, installed)

	upgrade := installed + ".new"
	copyExecutable(t, source, upgrade)
	if err := os.Rename(upgrade, installed); err != nil {
		t.Fatal(err)
	}
	if running, pid := d.IsRunning(); !running || pid != gateway.Process.Pid {
		t.Fatalf("IsRunning on a replaced gateway during a scan = (%v, %d)", running, pid)
	}
	if !d.RunsReplacedExecutable() || !d.HasAuthenticatedMigrationProcessIdentity(gateway.Process.Pid) {
		t.Fatal("a replaced gateway was not recognized during a scan")
	}
	accepted := func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
	if err := d.StopGracefully(5*time.Second, accepted); err != nil {
		t.Fatalf("authenticated stop of a replaced gateway during a scan: %v", err)
	}
	<-exited
	requireScanProcessesEnded(t, scans)
}

func copyExecutable(t *testing.T, source, target string) {
	t.Helper()
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
