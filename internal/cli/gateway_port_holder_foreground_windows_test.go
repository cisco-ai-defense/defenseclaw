// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

func TestGAP0694ForegroundGatewayHelper(t *testing.T) {
	if os.Getenv("DC_GAP0694_HELPER") == "1" {
		time.Sleep(30 * time.Second)
	}
}

// TestGAP0694WindowsForegroundGatewayUsesOwnerImageAndHome starts a gateway
// stand-in from a link named defenseclaw-gateway.exe, with no gateway.pid
// and this home's runtime record naming it: status must call it this
// account's gateway, and a different home, image or stale record must not.
func TestGAP0694WindowsForegroundGatewayUsesOwnerImageAndHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "defenseclaw-gateway.exe")
	if err := os.Link(self, path); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(path, "-test.run=^TestGAP0694ForegroundGatewayHelper$")
	child.Env = append(os.Environ(), "DC_GAP0694_HELPER=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	writeGatewayRuntimeRecordForTest(t, home, child.Process.Pid, 0o600)

	oldHolder, oldState, oldExecutable := gatewayPortHolder, gatewayManagedState, gatewayExecutable
	t.Cleanup(func() {
		gatewayPortHolder, gatewayManagedState, gatewayExecutable = oldHolder, oldState, oldExecutable
	})
	gatewayExecutable = func() (string, error) { return path, nil }
	gatewayManagedState = func() (bool, int) { return false, 0 }
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: child.Process.Pid, UID: -1}, nil
	}
	if !sameHomeGatewayProcess(child.Process.Pid, home) {
		t.Fatal("foreground process proof did not resolve")
	}
	if problem := foreignGatewayListener(config.DefaultConfig()); problem != "" {
		t.Fatalf("same-home foreground gateway reported foreign: %s", problem)
	}

	other := t.TempDir()
	if sameHomeGatewayProcess(child.Process.Pid, other) {
		t.Fatal("a home without a runtime record matched the foreground gateway")
	}
	writeGatewayRuntimeRecordForTest(t, other, os.Getpid(), 0o600)
	if sameHomeGatewayProcess(child.Process.Pid, other) {
		t.Fatal("a runtime record naming another PID matched the foreground gateway")
	}
	unprotected := t.TempDir()
	writeGatewayRuntimeRecordForTest(t, unprotected, child.Process.Pid, 0o644)
	if sameHomeGatewayProcess(child.Process.Pid, unprotected) {
		t.Fatal("a runtime record others can read matched the foreground gateway")
	}

	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(home, "gateway-api.json"), stale, stale); err != nil {
		t.Fatal(err)
	}
	if problem := foreignGatewayListener(config.DefaultConfig()); !strings.Contains(problem, "not by this account's gateway") {
		t.Fatalf("a runtime record older than the process = %q", problem)
	}
	writeGatewayRuntimeRecordForTest(t, home, child.Process.Pid, 0o600)

	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	otherImage := filepath.Join(t.TempDir(), "defenseclaw-gateway.exe")
	if err := os.WriteFile(otherImage, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if sameHomeGatewayProcessPlatform(child.Process.Pid, home, otherImage) {
		t.Fatal("a different gateway image matched the foreground gateway")
	}
	if !sameHomeGatewayProcessPlatform(child.Process.Pid, home, path) {
		t.Fatal("the restored runtime record no longer matched")
	}
}

func TestGAP0694SameWindowsAccountComparesTokenUsers(t *testing.T) {
	own, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if !own.User.Sid.IsWellKnown(windows.WinLocalSystemSid) && !sameWindowsAccount(own.User.Sid, own.User.Sid) {
		t.Fatal("this account's own token user did not match")
	}
	if sameWindowsAccount(own.User.Sid, everyone) {
		t.Fatal("another SID matched this account")
	}
	if sameWindowsAccount(system, system) {
		t.Fatal("LocalSystem counted as a per-user account")
	}
	if sameWindowsAccount(nil, own.User.Sid) || sameWindowsAccount(own.User.Sid, nil) {
		t.Fatal("a missing SID matched")
	}
}
