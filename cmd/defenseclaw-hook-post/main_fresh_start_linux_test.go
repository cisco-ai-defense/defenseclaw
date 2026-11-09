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
	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
)

func TestGAP0295FreshGatewayNoAnswerUsesOutageExit(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	cmd := startGAP0295FreshServer(t, addr, freshUnansweredHelperEnv)
	identity, ok := procidentity.Recorded(cmd.Process.Pid)
	if !ok {
		t.Fatal("fresh listener identity unavailable")
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	clock, start := freshHookPostClock(t, cmd.Process.Pid)
	defer requireProofBudgets(t, clock)
	record, err := json.Marshal(map[string]any{
		"pid": cmd.Process.Pid, "executable": executable, "data_dir": dir,
		"start_time": start.Add(-time.Second).Unix(), "start_identity": identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(dir, "gateway.pid")
	if err := os.WriteFile(pidPath, record, 0o600); err != nil {
		t.Fatal(err)
	}
	dateGatewayRecord(t, pidPath, start)
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
	dateGatewayRecord(t, pidPath, start)
	var proof bytes.Buffer
	if got := runMain(args, bytes.NewReader(frame), &proof, io.Discard); got != hookexec.PerUserPostNoAnswerExit {
		t.Fatalf("unverified gateway no-answer exit = %d, want closed", got)
	}
	if got := proof.String(); got != "DCPOSTPROOF1:not_fresh" {
		t.Fatalf("unverified gateway proof result = %q, want not_fresh", got)
	}
}

const freshAnsweredHelperEnv = "DC_TEST_FRESH_ANSWERED_HELPER"
const freshUnansweredHelperEnv = "DC_TEST_FRESH_UNANSWERED_HELPER"

func TestGAP0295FreshAnsweredHelper(t *testing.T) {
	addr := os.Getenv(freshAnsweredHelperEnv)
	unanswered := false
	if addr == "" {
		addr = os.Getenv(freshUnansweredHelperEnv)
		unanswered = addr != ""
	}
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
		if !unanswered && calls.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"action":"allow"}`))
			return
		}
		select {}
	}))
}

func startGAP0295FreshServer(t *testing.T, addr, envName string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP0295FreshAnsweredHelper$")
	cmd.Env = append(os.Environ(), envName+"="+addr)
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
	return cmd
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
	cmd := startGAP0295FreshServer(t, addr, freshAnsweredHelperEnv)
	identity, ok := procidentity.Recorded(cmd.Process.Pid)
	if !ok {
		t.Fatal("identity unavailable")
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	clock, start := freshHookPostClock(t, cmd.Process.Pid)
	defer requireProofBudgets(t, clock)
	record, err := json.Marshal(map[string]any{
		"pid": cmd.Process.Pid, "executable": executable, "data_dir": dir,
		"start_time": start.Add(-time.Second).Unix(), "start_identity": identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeRecord := func() {
		t.Helper()
		pidPath := filepath.Join(dir, "gateway.pid")
		if err := os.WriteFile(pidPath, record, 0o600); err != nil {
			t.Fatal(err)
		}
		dateGatewayRecord(t, pidPath, start)
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
	var proof bytes.Buffer
	if got := runMain(args, bytes.NewReader(second), &proof, io.Discard); got != hookexec.PerUserPostNoAnswerExit {
		t.Fatalf("post-answer no-answer exit = %d, want closed", got)
	}
	if got := proof.String(); got != "DCPOSTPROOF1:answered_before" {
		t.Fatalf("post-answer proof result = %q, want answered_before", got)
	}
}

// freshHookPostClock installs the proof clock for a test that runs hook-post
// against a real gateway process, standing one second after the start of
// that process: the 12 s fresh-gateway window is read on this clock, so the
// speed of the host cannot age the gateway. It returns the process start.
func freshHookPostClock(t *testing.T, pid int) (*proofclocktest.Clock, time.Time) {
	t.Helper()
	start, ok := procidentity.StartTime(pid)
	if !ok {
		t.Fatal("fresh listener start time unavailable")
	}
	clock := proofclocktest.Install(t)
	clock.Set(start.Add(time.Second))
	return clock, start
}

// dateGatewayRecord sets the modification time of the gateway record that the
// native hook reads for the recency of the start.
func dateGatewayRecord(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}
