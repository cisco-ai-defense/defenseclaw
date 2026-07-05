// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// This is the native disposable collision regression: it binds an ephemeral
// loopback port in the test process, runs the real Windows ownership collector,
// and verifies startup refuses it without touching a DefenseClaw home.
func TestNativeWindowsDisposableForeignCollisionPreflight(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = listener.Addr().(*net.TCPAddr).Port
	withStartupListenerInspector(t, daemon.ListenerOwnerPID)
	_, _, err = inspectConfiguredListener(fakeDaemonState{}, cfg, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "foreign process") {
		t.Fatalf("error = %v, want native foreign-listener rejection", err)
	}
}

func TestNativeWindowsDisposableStartAndRestartCollisionHaveNoSideEffects(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	port := listener.Addr().(*net.TCPAddr).Port
	configText := fmt.Sprintf("gateway:\n  api_bind: 127.0.0.1\n  api_port: %d\n  token: disposable-test-token\n", port)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	watchdogPath := filepath.Join(home, watchdogPIDFile)
	const watchdogSentinel = "foreign-watchdog-sentinel"
	if err := os.WriteFile(watchdogPath, []byte(watchdogSentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	oldHost, oldPort := sidecarHost, sidecarPort
	sidecarHost, sidecarPort = "", 0
	t.Cleanup(func() { sidecarHost, sidecarPort = oldHost, oldPort })

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{name: "start", run: func() error { return runStart(startCmd, nil) }},
		{name: "restart", run: func() error { return runRestart(restartCmd, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil || !strings.Contains(err.Error(), "foreign process") {
				t.Fatalf("error = %v, want foreign collision", err)
			}
			if _, err := os.Stat(filepath.Join(home, daemon.PIDFileName)); !os.IsNotExist(err) {
				t.Fatalf("gateway PID state created on collision: %v", err)
			}
			got, err := os.ReadFile(watchdogPath)
			if err != nil || string(got) != watchdogSentinel {
				t.Fatalf("watchdog state changed on collision: content=%q error=%v", got, err)
			}
		})
	}
}
