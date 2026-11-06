// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// The same-home root process is a diagnostic, never an authorized token peer.
// PID 1 supplies a real root-owned start identity without starting a service.
func TestGAP0605RootListenerHasAccountRemedy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root caller")
	}
	command, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		t.Skipf("root process command unavailable: %v", err)
	}
	comm := strings.TrimSpace(string(command))
	if comm == "" {
		t.Skip("root process command is empty")
	}
	stat, err := os.ReadFile("/proc/1/stat")
	if err != nil {
		t.Skipf("root process start identity unavailable: %v", err)
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		t.Fatal("root process stat is malformed")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		t.Fatal("root process stat is incomplete")
	}
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	write := func(identity string) {
		t.Helper()
		record, err := json.Marshal(map[string]any{
			"pid": 1, "executable": filepath.Join("/opt/defenseclaw", comm),
			"data_dir": home, "start_identity": identity,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "gateway.pid"), record, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldHolder := gatewayPortHolder
	t.Cleanup(func() { gatewayPortHolder = oldHolder })
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: 1, UID: 0}, nil
	}
	cfg := config.DefaultConfig()
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = 18970
	write(fields[19])
	if problem := foreignGatewayListener(cfg); problem != "Your DefenseClaw gateway is running as root." {
		t.Fatalf("same-home root listener = %q", problem)
	}
	if remedy := foreignGatewayListenerFix(cfg); !strings.Contains(remedy, "sudo defenseclaw-gateway stop") || strings.Contains(remedy, "--api-port") {
		t.Fatalf("same-home root listener remedy = %q", remedy)
	}
	write("different")
	if problem := foreignGatewayListener(cfg); !strings.Contains(problem, "another account") {
		t.Fatalf("stale record misclassified: %q", problem)
	}
}
