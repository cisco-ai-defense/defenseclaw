// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// TestGAP0705LinuxForegroundGatewayOnDefaultHome starts a gateway stand-in
// the way an account runs `defenseclaw-gateway` in a terminal: HOME set,
// DEFENSECLAW_HOME not. Status must call it this account's gateway for
// HOME/.defenseclaw, and not for another home or account.
func TestGAP0705LinuxForegroundGatewayOnDefaultHome(t *testing.T) {
	userHome := t.TempDir()
	home := filepath.Join(userHome, config.DefaultDataDirName)
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", home)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	if err := os.Link(executable, path); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(path, "-test.run=^TestCoworkTransientGatewayHelperProcess$")
	child.Env = []string{"HOME=" + userHome, "DC_COWORK_GATEWAY_HELPER=1"}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	oldHolder, oldState, oldExecutable := gatewayPortHolder, gatewayManagedState, gatewayExecutable
	t.Cleanup(func() {
		gatewayPortHolder, gatewayManagedState, gatewayExecutable = oldHolder, oldState, oldExecutable
	})
	gatewayExecutable = func() (string, error) { return path, nil }
	gatewayManagedState = func() (bool, int) { return false, 0 }
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: child.Process.Pid, UID: os.Getuid()}, nil
	}
	for deadline := time.Now().Add(5 * time.Second); !sameHomeGatewayProcess(child.Process.Pid, home) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !sameHomeGatewayProcess(child.Process.Pid, home) {
		t.Fatal("foreground process proof did not resolve for the default home")
	}
	if problem := foreignGatewayListener(config.DefaultConfig()); problem != "" {
		t.Fatalf("default-home foreground gateway reported foreign: %s", problem)
	}
	if sameHomeGatewayProcess(child.Process.Pid, t.TempDir()) {
		t.Fatal("another home matched the default-home foreground gateway")
	}
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: child.Process.Pid, UID: os.Getuid() + 1}, nil
	}
	if problem := foreignGatewayListener(config.DefaultConfig()); !strings.Contains(problem, "not by this account's gateway") {
		t.Fatalf("other-account gateway accepted: %q", problem)
	}
}
