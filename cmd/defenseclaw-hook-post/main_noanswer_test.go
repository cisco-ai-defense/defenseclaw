// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const listenHelperEnv = "R107NA_HOOKPOST_HELPER_LISTEN"

// TestHookPostListenHelper is not a test: with listenHelperEnv set it is a
// second process of this account that listens on that address until killed.
func TestHookPostListenHelper(t *testing.T) {
	addr := os.Getenv(listenHelperEnv)
	if addr == "" {
		t.Skip("helper process only")
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		os.Exit(3)
	}
	defer l.Close()
	_, _ = os.Stdout.WriteString("ready\n")
	time.Sleep(time.Minute)
	os.Exit(0)
}

// TestHookPostNoAnswerExitNamesOnlyAProvenRestart pins hook-post's exit
// status of a call this account's listener took and never answered (review
// M01, M02; lead ruling on rel-1-0-6 GAP-0295, review r2): 9 (the
// hung-gateway refusal) unless a start or restart holds the start lock and
// the process behind the call's connection changed (here: another process
// owns the port by the deadline), then 10 (the restart outage). gateway.pid
// decides nothing: removed, naming a dead pid, garbage or a link before the
// call, the same gateway up and slow is 9.
func TestHookPostNoAnswerExitNamesOnlyAProvenRestart(t *testing.T) {
	writePIDRecord := func(dir, data string) { _ = os.WriteFile(filepath.Join(dir, "gateway.pid"), []byte(data), 0o600) }
	for _, tc := range []struct {
		name     string
		lock     bool
		before   func(dir string)
		takeover bool
		want     int
	}{
		{"no lock, same gateway", false, func(string) {}, false, hookexec.PerUserPostNoAnswerExit},
		{"lock held, same gateway up and slow", true, func(string) {}, false, hookexec.PerUserPostNoAnswerExit},
		{"lock held, gateway.pid removed before the call, same gateway up", true, func(dir string) { _ = os.Remove(filepath.Join(dir, "gateway.pid")) }, false, hookexec.PerUserPostNoAnswerExit},
		{"lock held, gateway.pid names a dead pid, same gateway up", true, func(dir string) { writePIDRecord(dir, `{"pid":4206789}`) }, false, hookexec.PerUserPostNoAnswerExit},
		{"lock held, gateway.pid garbage, same gateway up", true, func(dir string) { writePIDRecord(dir, "not a record") }, false, hookexec.PerUserPostNoAnswerExit},
		{"lock held, gateway.pid a link, same gateway up", true, func(dir string) {
			_ = os.Remove(filepath.Join(dir, "gateway.pid"))
			_ = os.Symlink("/dev/null", filepath.Join(dir, "gateway.pid"))
		}, false, hookexec.PerUserPostNoAnswerExit},
		{"no lock, another process takes the port", false, func(string) {}, true, hookexec.PerUserPostNoAnswerExit},
		{"lock held, another process takes the port during the call", true, func(string) {}, true, hookexec.PerUserPostRestartNoAnswerExit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writePIDRecord(dir, `{"pid":`+itoa(os.Getpid())+`}`)
			tc.before(dir)
			if tc.lock {
				f, err := os.OpenFile(filepath.Join(dir, "gateway.start.lock"), os.O_CREATE|os.O_RDONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan struct{})
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.takeover {
					// The gateway gives up its port and another process of
					// this account listens there; this connection stays open.
					_ = server.Listener.Close()
					startListenHelper(t, server.Listener.Addr().String())
				}
				select {
				case <-done:
				case <-r.Context().Done():
				}
			}))
			defer server.Close()
			defer close(done)
			t.Setenv(hookPostDeadlineEnv, "1800")
			t.Setenv(hookPostDataDirEnv, dir)
			addr := strings.TrimPrefix(server.URL, "http://")
			frame := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{\"hook_event_name\":\"PreToolUse\"}\x00Content-Type\x00application/json\x00")
			var out, errOut bytes.Buffer
			got := runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "2", "--curl-output"}, bytes.NewReader(frame), &out, &errOut)
			if got != tc.want {
				t.Fatalf("exit %d, want %d (stderr %q)", got, tc.want, errOut.String())
			}
		})
	}
}

func startListenHelper(t *testing.T, addr string) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHookPostListenHelper$")
	cmd.Env = append(os.Environ(), listenHelperEnv+"="+addr)
	out, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		t.Error("cannot start the listen helper")
		return
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Errorf("listen helper did not listen on %s: %q %v", addr, line, err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
