// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPerUserNativeRegisteredArgsAndScriptTwin(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".defenseclaw")
	args := []string{"hook", "--connector", "claudecode", "--hook-home", home, "--api-addr", "127.0.0.1:18970"}
	gotHome, gotAddr, ok := registeredArgs(args)
	if !ok || gotHome != home || gotAddr != "127.0.0.1:18970" {
		t.Fatalf("registered args = %q, %q, %v", gotHome, gotAddr, ok)
	}
	for _, twin := range [][]string{
		{"hook", "--connector", "codex", "--hook-home", home},
		{"hook", "--connector", "claudecode", "--hook-home", home, "--api-addr", "example.test:18970"},
		{"hook", "--connector", "claudecode", "--hook-home", "relative"},
	} {
		if _, _, ok := registeredArgs(twin); ok {
			t.Fatalf("unregistered command accepted: %q", twin)
		}
	}
}

func TestPerUserNativeCursorImportTwin(t *testing.T) {
	if !cursorEvent(strings.NewReader(`{"cursor_version":"1","tool_input":{"command":"echo ok"}}`)) {
		t.Fatal("Cursor import marker was missed")
	}
	if cursorEvent(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_input":{"command":"echo ok"}}`)) {
		t.Fatal("Claude Code event was identified as Cursor")
	}
}

func TestPerUserNativeGatewayAllowAndBlock(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".defenseclaw")
	hooks := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".hook-claudecode.token"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command, reply string
		wantCode             int
		wantBlock            bool
	}{
		{"benign twin", "echo ok", `{"action":"allow"}`, 0, false},
		{"protected", "echo protected", `{"action":"block","reason":"policy"}`, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/claude-code/hook" || r.Header.Get("Authorization") != "Bearer fixture" {
					t.Errorf("gateway request lacks registered path or token")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, tc.reply)
			}))
			defer server.Close()
			var out, errOut bytes.Buffer
			payload := `{"hook_event_name":"PreToolUse","session_id":"session","tool_name":"Bash","tool_input":{"command":` + fmt.Sprintf("%q", tc.command) + `}}`
			code := run(home, strings.TrimPrefix(server.URL, "http://"), strings.NewReader(payload), &out, &errOut, time.Now())
			if code != tc.wantCode || strings.Contains(errOut.String(), "policy") != tc.wantBlock {
				t.Fatalf("code=%d output=%q stderr=%q", code, out.String(), errOut.String())
			}
		})
	}
}

func TestPerUserNativeSidecarAddressAndUntrustedTwin(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".hookcfg")
	for _, tc := range []struct {
		name, content, want string
	}{
		{"current", `{"version":2,"gateway_addr":"127.0.0.1:18971"}`, "127.0.0.1:18971"},
		{"legacy last value", "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18971\n", "127.0.0.1:18971"},
		{"malformed JSON twin", `{"version":2,"gateway_addr":"127.0.0.1:18971"`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := sidecarAddress(path); got != tc.want {
				t.Fatalf("sidecar address = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPerUserNativeGatewayRecordAndTwin(t *testing.T) {
	accountHome := t.TempDir()
	binDir := filepath.Join(accountHome, ".local", "bin")
	home := filepath.Join(accountHome, ".defenseclaw")
	hooks := filepath.Join(home, "hooks")
	for _, dir := range []string{binDir, hooks} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self := filepath.Join(binDir, "defenseclaw-hook-user")
	gateway := filepath.Join(binDir, "defenseclaw-gateway")
	for _, file := range []string{self, gateway} {
		if err := os.WriteFile(file, []byte("fixture\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	record := filepath.Join(hooks, ".gateway-helper")
	if err := os.WriteFile(record, []byte(gateway+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := trustedGatewayAt(self, home); got != gateway {
		t.Fatalf("trusted gateway = %q, want %q", got, gateway)
	}
	if err := os.WriteFile(record, []byte(filepath.Join(binDir, "other")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := trustedGatewayAt(self, home); got != "" {
		t.Fatalf("other gateway record was accepted: %q", got)
	}
}

func TestPerUserNativeManagedRuntimeMarkerAndAbsentTwin(t *testing.T) {
	root := t.TempDir()
	linux := filepath.Join(root, "linux", "managed-runtime.json")
	mac := filepath.Join(root, "mac", "managed-runtime.json")
	if managedRuntimePresentAt(linux, mac) {
		t.Fatal("absent runtime marker changed personal hook behavior")
	}
	if err := os.MkdirAll(filepath.Dir(linux), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(linux, []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !managedRuntimePresentAt(linux, mac) {
		t.Fatal("managed runtime marker was missed")
	}
	if err := os.Remove(linux); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(mac), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), mac); err != nil {
		t.Fatal(err)
	}
	if !managedRuntimePresentAt(linux, mac) {
		t.Fatal("managed runtime symlink was missed")
	}
}

func TestPerUserNativeInheritedHomeKeepsScriptBehavior(t *testing.T) {
	if managedRuntimePresent() {
		t.Skip("managed runtime takes precedence")
	}
	root := t.TempDir()
	home := filepath.Join(root, ".defenseclaw")
	hooks := filepath.Join(home, "hooks")
	alternate := filepath.Join(root, "alternate")
	for _, dir := range []string{hooks, alternate} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(hooks, "claude-code-hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$DEFENSECLAW_HOME\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", alternate)
	var out, errOut bytes.Buffer
	if code := run(home, "", strings.NewReader("{}"), &out, &errOut, time.Now()); code != 0 || out.String() != alternate {
		t.Fatalf("inherited home: code=%d output=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestPerUserNativeGatewayColdStartLeaseAndStoppedTwin(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(home, "defenseclaw-gateway")
	marker := filepath.Join(home, "started")
	if err := os.WriteFile(gateway, []byte("#!/bin/sh\nprintf '%s' \"$1 $2\" > \"$DEFENSECLAW_HOME/started\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cold-start.lock"),
		[]byte(fmt.Sprintf("%d previous\n", time.Now().Add(-121*time.Second).Unix())), 0o600); err != nil {
		t.Fatal(err)
	}
	recovery := gatewayRecovery(gateway, home)
	if err := recovery(context.Background(), errors.New("refused")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(filepath.Join(home, ".cold-start.lock")); os.IsNotExist(err) {
			if data, err := os.ReadFile(marker); err == nil && string(data) == "start --hook-cold-start" {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "start --hook-cold-start" {
		t.Fatalf("gateway start = %q, %v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(home, ".cold-start.lock")); !os.IsNotExist(err) {
		t.Fatalf("cold start lease remains: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "gateway.stopped"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recovery(context.Background(), errors.New("refused")); err == nil {
		t.Fatal("stopped gateway started")
	}
}

func TestPerUserNativeOutageModeAndClosedTwin(t *testing.T) {
	dataDir := t.TempDir()
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(dataDir, "defenseclaw-gateway")
	if err := os.WriteFile(gateway, []byte("#!/bin/sh\n[ \"$1\" = hook-outage-mode ] && [ \"$3\" = claudecode ] && [ \"$5\" = \"$DEFENSECLAW_HOME/hooks\" ] && printf open\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := outageMode(gateway, hookDir); got != "open" {
		t.Fatalf("configured outage mode = %q", got)
	}
	if err := os.WriteFile(gateway, []byte("#!/bin/sh\nprintf closed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := outageMode(gateway, hookDir); got != "closed" {
		t.Fatalf("closed twin outage mode = %q", got)
	}
}
