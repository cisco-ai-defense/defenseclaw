// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package systemd

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestParseListenEnv(t *testing.T) {
	fds, err := parseListenEnv(42, envMap(map[string]string{
		"LISTEN_PID": "42", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "api:hook",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(fds) != 2 || fds[0] != (inheritedFD{fd: 3, name: "api"}) || fds[1] != (inheritedFD{fd: 4, name: "hook"}) {
		t.Fatalf("unexpected descriptors: %+v", fds)
	}
	unnamed, err := parseListenEnv(7, envMap(map[string]string{"LISTEN_PID": "7", "LISTEN_FDS": "1"}))
	if err != nil || len(unnamed) != 1 || unnamed[0].name != "unknown" {
		t.Fatalf("unnamed descriptor: %+v %v", unnamed, err)
	}
	for name, env := range map[string]map[string]string{
		"absent":          {},
		"other process":   {"LISTEN_PID": "41", "LISTEN_FDS": "1"},
		"zero descriptor": {"LISTEN_PID": "42", "LISTEN_FDS": "0"},
	} {
		if _, err := parseListenEnv(42, envMap(env)); !errors.Is(err, ErrNotActivated) {
			t.Errorf("%s: err = %v, want ErrNotActivated", name, err)
		}
	}
	for name, env := range map[string]map[string]string{
		"bad pid":         {"LISTEN_PID": "x", "LISTEN_FDS": "1"},
		"bad count":       {"LISTEN_PID": "42", "LISTEN_FDS": "-1"},
		"too many":        {"LISTEN_PID": "42", "LISTEN_FDS": "65"},
		"name mismatch":   {"LISTEN_PID": "42", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "api"},
		"duplicate name":  {"LISTEN_PID": "42", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "api:api"},
		"empty name":      {"LISTEN_PID": "42", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "api:"},
		"control in name": {"LISTEN_PID": "42", "LISTEN_FDS": "1", "LISTEN_FDNAMES": "a\npi"},
	} {
		if _, err := parseListenEnv(42, envMap(env)); err == nil || errors.Is(err, ErrNotActivated) {
			t.Errorf("%s: err = %v, want a hard error", name, err)
		}
	}
}

func TestWatchdogInterval(t *testing.T) {
	if got, ok := watchdogInterval(9, envMap(map[string]string{"WATCHDOG_USEC": "60000000"})); !ok || got != time.Minute {
		t.Fatalf("interval = %v %v", got, ok)
	}
	if _, ok := watchdogInterval(9, envMap(map[string]string{"WATCHDOG_USEC": "60000000", "WATCHDOG_PID": "8"})); ok {
		t.Fatal("watchdog for another pid must be ignored")
	}
	if _, ok := watchdogInterval(9, envMap(map[string]string{"WATCHDOG_USEC": "0"})); ok {
		t.Fatal("zero interval must be ignored")
	}
}

func TestNotifySocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unixgram is unavailable on Windows")
	}
	if sent, err := notifySocket("", StateReady); sent || err != nil {
		t.Fatalf("no NOTIFY_SOCKET must be a silent no-op: %v %v", sent, err)
	}
	if _, err := notifySocket("relative/path", StateReady); err == nil {
		t.Fatal("relative NOTIFY_SOCKET must be rejected")
	}
	dir, err := os.MkdirTemp("/tmp", "dcn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "n.sock")
	server, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	sent, err := notifySocket(path, StateReady)
	if err != nil || !sent {
		t.Fatalf("notify: %v %v", sent, err)
	}
	buffer := make([]byte, 64)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := server.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != StateReady {
		t.Fatalf("received %q", got)
	}
	if _, err := notifySocket(path, "READY=1\x00"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("NUL state must be refused: %v", err)
	}
}

func TestSharedListenerSurvivesViewClose(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	shared := newSharedListener(base)
	accept := func(view net.Listener) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			conn, err := view.Accept()
			if err == nil {
				_ = conn.Close()
			}
			done <- err
		}()
		client, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("accept timed out")
		}
	}
	first := shared.view()
	accept(first)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed view accept = %v", err)
	}
	second := shared.view()
	if second.Addr().String() != base.Addr().String() {
		t.Fatalf("view address %s != %s", second.Addr(), base.Addr())
	}
	accept(second)
}
