// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"io"
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
	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
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
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(io.Discard, conn) }()
		}
	}()
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
	// The proof after the deadline runs on a clock the test controls: it ends
	// on its result, never on the speed of the host, and asks for its product
	// budget (checked below).
	clock := proofclocktest.Install(t)
	defer requireProofBudgets(t, clock)
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

// requireProofBudgets checks that the restart proofs a hook-post run started
// on clock asked for the 300 ms proof budget and for nothing longer than the
// longest proof budget, 500 ms.
func requireProofBudgets(t *testing.T, clock *proofclocktest.Clock) {
	t.Helper()
	budget := false
	for _, d := range clock.Requested() {
		if d > 500*time.Millisecond {
			t.Errorf("a proof started a timer of %v, longer than any proof budget", d)
		}
		budget = budget || d == 300*time.Millisecond
	}
	if !budget {
		t.Errorf("no proof started its 300 ms budget (timers %v)", clock.Requested())
	}
}

func startListenHelper(t *testing.T, addr string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHookPostListenHelper$")
	cmd.Env = append(os.Environ(), listenHelperEnv+"="+addr)
	out, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		t.Error("cannot start the listen helper")
		return nil
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Errorf("listen helper did not listen on %s: %q %v", addr, line, err)
	}
	return cmd
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestHookPostRefusedWithStartLock(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(hookPostDataDirEnv, dir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	frame := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{\"hook_event_name\":\"PreToolUse\"}\x00Content-Type\x00application/json\x00")
	check := func(want int) {
		t.Helper()
		args := []string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"}
		if got := runMain(args, bytes.NewReader(frame), io.Discard, io.Discard); got != want {
			t.Fatalf("refused hook-post exit %d, want %d", got, want)
		}
	}
	check(hookexec.PerUserPostOutageExit)
	f, err := os.OpenFile(filepath.Join(dir, "gateway.start.lock"), os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	check(hookexec.PerUserPostOutageExit)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	check(hookexec.PerUserPostRestartOutageExit)
	t.Setenv(hookPostDataDirEnv, "")
	check(hookexec.PerUserPostOutageExit)
}

// A gateway that accepts a call and then closes before a status can be the
// stopping side of the same restart. The helper classifies it while the
// start lock is held, before the new listener or PID record can race it.
func TestHookPostDroppedCallWithStartLock(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(hookPostDataDirEnv, dir)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	frame := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{\"hook_event_name\":\"PreToolUse\"}\x00Content-Type\x00application/json\x00")
	check := func(want int) {
		t.Helper()
		args := []string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"}
		if got := runMain(args, bytes.NewReader(frame), io.Discard, io.Discard); got != want {
			t.Fatalf("dropped hook-post exit %d, want %d", got, want)
		}
	}
	check(hookexec.PerUserPostOutageExit)
	f, err := os.OpenFile(filepath.Join(dir, "gateway.start.lock"), os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	check(hookexec.PerUserPostRestartOutageExit)
}
