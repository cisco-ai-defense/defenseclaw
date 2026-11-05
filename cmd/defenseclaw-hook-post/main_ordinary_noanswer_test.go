// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestGAP0518HookPostOrdinaryDeadlineKeepsProtectedClosed(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(done)
	cwd := t.TempDir()
	t.Setenv(hookPostDeadlineEnv, "400")
	t.Setenv(hookPostDataDirEnv, t.TempDir())
	addr := strings.TrimPrefix(server.URL, "http://")
	for _, tc := range []struct {
		name, command string
		want          int
	}{
		{"ordinary", "echo hello", hookexec.PerUserPostOrdinaryNoAnswerExit},
		{"protected", "cp source ~/.ssh/authorized_keys", hookexec.PerUserPostNoAnswerExit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` +
				strconv.Quote(cwd) + `,"tool_input":{"command":` + strconv.Quote(tc.command) + `}}`
			frame := append([]byte("DCPOST1\x00/api/v1/claude-code/hook\x00"), []byte(body)...)
			frame = append(frame, []byte("\x00Content-Type\x00application/json\x00")...)
			got := runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"},
				bytes.NewReader(frame), io.Discard, io.Discard)
			if got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}
