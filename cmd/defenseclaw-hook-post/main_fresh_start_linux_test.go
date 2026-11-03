// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

func TestGAP0295FreshGatewayNoAnswerUsesOutageExit(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	cmd := startListenHelper(t, addr)
	if cmd == nil {
		t.Fatal("listener did not start")
	}
	identity, ok := procidentity.Of(cmd.Process.Pid)
	if !ok {
		t.Fatal("fresh listener identity unavailable")
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(map[string]any{
		"pid": cmd.Process.Pid, "executable": executable, "data_dir": dir,
		"start_time": time.Now().Add(-time.Second).Unix(), "start_identity": identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(dir, "gateway.pid")
	if err := os.WriteFile(pidPath, record, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookPostDataDirEnv, dir)
	t.Setenv(hookPostDeadlineEnv, "800")
	frame := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\"}\x00Content-Type\x00application/json\x00")
	args := []string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"}
	if got := runMain(args, bytes.NewReader(frame), io.Discard, io.Discard); got != hookexec.PerUserPostRestartNoAnswerExit {
		t.Fatalf("fresh gateway no-answer exit = %d, want outage", got)
	}
	var bad map[string]any
	if err := json.Unmarshal(record, &bad); err != nil {
		t.Fatal(err)
	}
	bad["start_identity"] = "other"
	badRecord, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidPath, badRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runMain(args, bytes.NewReader(frame), io.Discard, io.Discard); got != hookexec.PerUserPostNoAnswerExit {
		t.Fatalf("unverified gateway no-answer exit = %d, want closed", got)
	}
}

const freshAnsweredHelperEnv = "DC_TEST_FRESH_ANSWERED_HELPER"

func TestGAP0295FreshAnsweredHelper(t *testing.T) {
	addr := os.Getenv(freshAnsweredHelperEnv)
	if addr == "" {
		t.Skip("helper only")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	_, _ = os.Stdout.WriteString("ready\n")
	_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"action":"allow"}`))
			return
		}
		select {}
	}))
}

func TestGAP0295FirstAnswerEndsFreshWindow(t *testing.T) {
	checkGAP0295FirstAnswerEndsFreshWindow(t, true)
}

func TestGAP0295ObservedAnswerBeforePIDPublication(t *testing.T) {
	checkGAP0295FirstAnswerEndsFreshWindow(t, false)
}

func checkGAP0295FirstAnswerEndsFreshWindow(t *testing.T, publishBeforeAnswer bool) {
	t.Helper()
	dir := t.TempDir()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	_ = free.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP0295FreshAnsweredHelper$")
	cmd.Env = append(os.Environ(), freshAnsweredHelperEnv+"="+addr)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper ready: %q %v", line, err)
	}
	identity, ok := procidentity.Of(cmd.Process.Pid)
	if !ok {
		t.Fatal("identity unavailable")
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(map[string]any{
		"pid": cmd.Process.Pid, "executable": executable, "data_dir": dir,
		"start_time": time.Now().Add(-time.Second).Unix(), "start_identity": identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeRecord := func() {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "gateway.pid"), record, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if publishBeforeAnswer {
		writeRecord()
	}
	t.Setenv(hookPostDataDirEnv, dir)
	t.Setenv(hookPostDeadlineEnv, "800")
	args := []string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"}
	first := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\"}\x00Content-Type\x00application/json\x00")
	var errOutput bytes.Buffer
	if got := runMain(args, bytes.NewReader(first), io.Discard, &errOutput); got != 0 {
		t.Fatalf("first answer status = %d: %s", got, errOutput.String())
	}
	if !publishBeforeAnswer {
		writeRecord()
	}
	second := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"rm -rf ~/.defenseclaw\"}}\x00Content-Type\x00application/json\x00")
	if got := runMain(args, bytes.NewReader(second), io.Discard, io.Discard); got != hookexec.PerUserPostNoAnswerExit {
		t.Fatalf("post-answer no-answer exit = %d, want closed", got)
	}
}
