// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
