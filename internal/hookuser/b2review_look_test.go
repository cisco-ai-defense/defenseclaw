// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookuser

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// S8 b2 review: a legacy script killed by a signal is a block for every
// caller (Claude Code reads exit 255 as a non-blocking error).
func TestB2ReviewLegacyScriptKilledIsABlock(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(home, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(home, "hooks", "claude-code-hook.sh")
	for _, tc := range []struct {
		body string
		want int
	}{
		{"#!/bin/sh\nkill -9 $$\n", 2},
		{"#!/bin/sh\nexit 2\n", 2},
		{"#!/bin/sh\nexit 0\n", 0},
		// The script's own non-2 status (fail mode open boot errors) is
		// kept for hook-user's own registration.
		{"#!/bin/sh\nexit 1\n", 1},
	} {
		if err := os.WriteFile(script, []byte(tc.body), 0o700); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		if got := runLegacyScript(home, strings.NewReader("{}"), &out, &errOut); got != tc.want {
			t.Fatalf("%q: exit %d, want %d", tc.body, got, tc.want)
		}
	}
}

const lookChildEnv = "DC_TEST_B2_LOOK_CHILD"

// trustedAccount is an account folder with the native hook's trusted gateway
// beside it (trustedGatewayAt): gatewayScript is the gateway's body.
func trustedAccount(t *testing.T, gatewayScript string) (account, native, home string) {
	t.Helper()
	account = t.TempDir()
	bin := filepath.Join(account, ".local", "bin")
	home = filepath.Join(account, ".defenseclaw")
	hooks := filepath.Join(home, "hooks")
	for _, dir := range []string{bin, hooks} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	native = filepath.Join(bin, "defenseclaw-hook-user")
	gateway := filepath.Join(bin, "defenseclaw-gateway")
	for path, body := range map[string]string{
		native:                                  "fixture\n",
		gateway:                                 gatewayScript,
		filepath.Join(hooks, ".gateway-helper"): gateway + "\n",
		filepath.Join(hooks, ".hook-claudecode.token"): "fixture\n",
		filepath.Join(home, "config.yaml"):             "fixture\n",
	} {
		mode := os.FileMode(0o600)
		if path == native || path == gateway {
			mode = 0o700
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	if trustedGatewayAt(native, home) != gateway {
		t.Fatal("fixture gateway is not trusted")
	}
	return account, native, home
}

// S8 b2 review M3: when the watchdog answers a call the gateway took and
// never answered, the process exits through ExitStoppingLooks, so the
// outage look it started (here a gateway that never ends) dies with it.
func TestB2ReviewWatchdogExitStopsTheLook(t *testing.T) {
	if spec := os.Getenv(lookChildEnv); spec != "" {
		parts := strings.SplitN(spec, "|", 3)
		account, native, home := parts[0], parts[1], parts[2]
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			var held []net.Conn
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				held = append(held, c) // taken, never answered
			}
		}()
		payload := `{"hook_event_name":"PreToolUse","session_id":"s","cwd":` + strconv.Quote(account) +
			`,"tool_name":"Bash","tool_input":{"command":"echo ok"}}`
		var out, errOut bytes.Buffer
		Run(native, home, ln.Addr().String(), strings.NewReader(payload), &out, &errOut, time.Now())
		t.Fatal("Run returned: the watchdog did not answer")
	}
	account, native, home := trustedAccount(t,
		"#!/bin/sh\n[ \"$1\" = hook-outage-mode ] || exit 0\necho $$ > \"$DEFENSECLAW_HOME/look.pid\"\nexec sleep 30\n")
	cmd := exec.Command(os.Args[0], "-test.run=^TestB2ReviewWatchdogExitStopsTheLook$", "-test.paniconexit0=false")
	cmd.Env = append(os.Environ(), lookChildEnv+"="+account+"|"+native+"|"+home)
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("hook process did not end")
	}
	data, err := os.ReadFile(filepath.Join(home, "look.pid"))
	if err != nil {
		t.Fatalf("no outage look started before the deadline: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		t.Fatalf("look pid %q", data)
	}
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("the outage look outlived the hook process")
		}
	}
}
