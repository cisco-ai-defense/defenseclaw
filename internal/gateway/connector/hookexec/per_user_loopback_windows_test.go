// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Windows dials the first normalised IPv4 endpoint: every IPv4 spelling the
// shared table accepts reaches a same-account gateway through the tuple
// check, and an IPv6-only spelling is refused before any connection.
func TestPerUserWindowsPostsToEveryIPv4LoopbackSpelling(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	for _, host := range []string{"127.0.0.1", "localhost", "LOCALHOST", "[::ffff:127.0.0.1]"} {
		addr := fmt.Sprintf("%s:%d", host, port)
		reply, err := PostPerUserHook(context.Background(), addr, "/api/v1/opencode/hook", nil, []byte(`{"tool_input":"ordinary edit"}`))
		if err != nil || reply.Status != http.StatusOK {
			t.Fatalf("same-account POST to %s: reply=%+v err=%v", addr, reply, err)
		}
	}
	if _, err := PostPerUserHook(context.Background(), fmt.Sprintf("[::1]:%d", port), "/api/v1/opencode/hook", nil, nil); err == nil {
		t.Fatal("IPv6-only target was accepted on Windows")
	}
}
