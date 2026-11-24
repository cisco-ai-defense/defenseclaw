// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestPortStreamForwardsOnlyItsScope (S3, B3.2): a port:N token opens
// port/N only and its bytes reach 127.0.0.1:N; nothing listening is a
// nothing_listening text message; the relay's own port and ports under
// 1024 are refused.
func TestPortStreamForwardsOnlyItsScope(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 64)
				n, _ := c.Read(b)
				_, _ = c.Write([]byte("echo:" + string(b[:n])))
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s, _, ec := testServer(t, []string{"sh"})
	s.opts.Config.Relay.Listen = "0.0.0.0:7681"
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ws := "ws" + strings.TrimPrefix(srv.URL, "http") + "/dcrelay/1/port/"
	tok := func(scope string) string {
		return ec.token(t, claims(time.Now(), func(c map[string]any) { c["dc.scope"] = scope }), TokenType)
	}
	conn, _, err := portDial(ws+port, tok("port:"+port))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, b, err := conn.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || string(b) != "echo:hi" {
		t.Fatalf("forward: %d %q %v", kind, b, err)
	}
	conn.Close()

	// A token for another port, or a terminal token, opens nothing.
	for _, scope := range []string{"port:1", ""} {
		_, resp, err := portDial(ws+port, tok(scope))
		if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("scope %q: %v %v, want 403", scope, resp, err)
		}
	}
	// Nothing listening: one text message, nothing_listening.
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	_, fp, _ := net.SplitHostPort(free.Addr().String())
	free.Close()
	conn, _, err = portDial(ws+fp, tok("port:"+fp))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, b, err = conn.ReadMessage()
	var pe PortError
	if err != nil || kind != websocket.TextMessage || json.Unmarshal(b, &pe) != nil || pe.Code != PortErrNothingListening {
		t.Fatalf("nothing listening: %d %q %v", kind, b, err)
	}
	conn.Close()
	// The relay's own port and low ports are never forwarded.
	for p, want := range map[int]int{7681: http.StatusForbidden, 22: http.StatusNotFound, 80: http.StatusNotFound} {
		_, resp, err := portDial(ws+strconv.Itoa(p), tok("port:"+strconv.Itoa(p)))
		if err == nil || resp == nil || resp.StatusCode != want {
			t.Fatalf("port %d: %v %v, want %d", p, resp, err, want)
		}
	}
}

func portDial(url, token string) (*websocket.Conn, *http.Response, error) {
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}, HandshakeTimeout: 5 * time.Second}
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	return d.Dial(url, h)
}
