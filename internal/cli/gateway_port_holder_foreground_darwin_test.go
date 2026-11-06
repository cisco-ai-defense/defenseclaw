// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

func TestGAP0629ForegroundGatewayHelper(t *testing.T) {
	if os.Getenv("DC_GAP0629_HELPER") == "1" {
		time.Sleep(30 * time.Second)
	}
}

func TestGAP0629DarwinForegroundGatewayUsesOwnerImageAndHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	if err := os.Link(self, path); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(path, "-test.run=^TestGAP0629ForegroundGatewayHelper$")
	child.Env = []string{"DEFENSECLAW_HOME=" + home, "DC_GAP0629_HELPER=1"}
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
		t.Fatal("foreground process proof did not resolve")
	}
	if problem := foreignGatewayListener(config.DefaultConfig()); problem != "" {
		t.Fatalf("same-home foreground gateway reported foreign: %s", problem)
	}
	if sameHomeGatewayProcess(child.Process.Pid, t.TempDir()) {
		t.Fatal("different home matched the foreground gateway")
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	otherImage := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	if err := os.WriteFile(otherImage, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if sameHomeGatewayProcessPlatform(child.Process.Pid, home, otherImage) {
		t.Fatal("a different gateway image matched the foreground gateway")
	}
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: child.Process.Pid, UID: os.Getuid() + 1}, nil
	}
	if problem := foreignGatewayListener(config.DefaultConfig()); !strings.Contains(problem, "not by this account's gateway") {
		t.Fatalf("different listener account = %q", problem)
	}
}

func TestDarwinForegroundProcessHomeReadsExplicitAndDefaultHomes(t *testing.T) {
	raw := func(entries ...string) []byte {
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, 1)
		data = append(data, []byte("/bin/gateway\x00\x00gateway\x00")...)
		for _, entry := range entries {
			data = append(data, []byte(entry+"\x00")...)
		}
		return append(data, 0)
	}
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"explicit", []string{"HOME=/Users/account", "DEFENSECLAW_HOME=/Users/account/gateway home"}, "/Users/account/gateway home"},
		{"default", []string{"HOME=/Users/account"}, "/Users/account/.defenseclaw"},
		{"duplicate", []string{"HOME=/Users/account", "HOME=/Users/other"}, ""},
		{"relative", []string{"DEFENSECLAW_HOME=relative"}, ""},
		{"no home", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := darwinForegroundProcessHome(raw(tc.env...))
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("process home = %q, %v; want %q", got, ok, tc.want)
			}
		})
	}
}
