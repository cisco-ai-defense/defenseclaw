// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

func TestCoworkTransientGatewayHelperProcess(t *testing.T) {
	if os.Getenv("DC_COWORK_GATEWAY_HELPER") == "1" {
		time.Sleep(30 * time.Second)
	}
}

func TestTransientGatewayStatusUsesSameHomeAndAccount(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childPath := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	if err := os.Link(executable, childPath); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(childPath, "-test.run=^TestCoworkTransientGatewayHelperProcess$")
	child.Env = []string{"DEFENSECLAW_HOME=" + home, "DC_COWORK_GATEWAY_HELPER=1"}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	previousHolder, previousState, previousExecutable := gatewayPortHolder, gatewayManagedState, gatewayExecutable
	t.Cleanup(func() {
		gatewayPortHolder, gatewayManagedState, gatewayExecutable = previousHolder, previousState, previousExecutable
	})
	gatewayExecutable = func() (string, error) { return childPath, nil }
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: child.Process.Pid, UID: os.Getuid()}, nil
	}
	gatewayManagedState = func() (bool, int) { return false, 0 }
	// Wait until the helper's /proc entries name it, so the check below
	// does not race the child's start.
	for deadline := time.Now().Add(5 * time.Second); !sameHomeGatewayProcess(child.Process.Pid, home) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	cfg := config.DefaultConfig()
	if problem := foreignGatewayListener(cfg); problem != "" {
		t.Fatalf("same-home transient gateway reported foreign: %s", problem)
	}

	otherPath := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.OpenFile(otherPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	other := exec.Command(otherPath, "-test.run=^TestCoworkTransientGatewayHelperProcess$")
	other.Env = child.Env
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = other.Process.Kill()
		_ = other.Wait()
	})
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: other.Process.Pid, UID: os.Getuid()}, nil
	}
	if problem := foreignGatewayListener(cfg); !strings.Contains(problem, "not by this account's gateway") {
		t.Fatalf("different executable accepted: %q", problem)
	}
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: child.Process.Pid, UID: os.Getuid()}, nil
	}

	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	if problem := foreignGatewayListener(cfg); !strings.Contains(problem, "not by this account's gateway") {
		t.Fatalf("other-home gateway accepted: %q", problem)
	}
	t.Setenv("DEFENSECLAW_HOME", home)
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: child.Process.Pid, UID: os.Getuid() + 1}, nil
	}
	if problem := foreignGatewayListener(cfg); !strings.Contains(problem, "not by this account's gateway") {
		t.Fatalf("other-account gateway accepted: %q", problem)
	}
}
