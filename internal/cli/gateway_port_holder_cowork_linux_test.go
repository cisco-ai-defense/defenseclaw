// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

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

	previousHolder, previousState := gatewayPortHolder, gatewayManagedState
	t.Cleanup(func() { gatewayPortHolder, gatewayManagedState = previousHolder, previousState })
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: child.Process.Pid, UID: os.Getuid()}, nil
	}
	gatewayManagedState = func() (bool, int) { return false, 0 }
	cfg := config.DefaultConfig()
	if problem := foreignGatewayListener(cfg); problem != "" {
		t.Fatalf("same-home transient gateway reported foreign: %s", problem)
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
