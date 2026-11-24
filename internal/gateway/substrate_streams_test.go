// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

func tixStreamReq(ws bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if ws {
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "keep-alive, Upgrade")
	}
	return r
}

// TestSubstrateStreamOpenRefusals (S2b, B3.2/B3.3): the admin switches,
// the target, a relay too old for streams, a plain request and the
// per-actor cap each refuse with their own reason and a refused row; an
// admitted stream carries its dc.scope and writes open and close rows.
func TestSubstrateStreamOpenRefusals(t *testing.T) {
	streams := registry.Registration{Atespace: "tix", Name: "a", UID: "0001", RelayStreams: "mcp,port,tls"}
	old := registry.Registration{Atespace: "tix", Name: "a", UID: "0001", RelayStreams: "tls"}
	off := config.SubstrateInteractiveConfig{PortForward: config.SubstratePortForwardConfig{Enabled: "off"}}
	for _, tc := range []struct {
		name    string
		ic      config.SubstrateInteractiveConfig
		managed bool
		reg     registry.Registration
		rest    string
		ws      bool
		status  int
		reason  string
		scope   string
	}{
		{"terminal untouched", off, false, old, "ws", false, 200, "", ""},
		{"port off", off, false, streams, "port/3000", true, 403, "port_forward_off", ""},
		{"port bad", config.SubstrateInteractiveConfig{}, false, streams, "port/03000", true, 404, "not_found", ""},
		{"port not allowed", config.SubstrateInteractiveConfig{}, false, streams, "port/22", true, 403, "port_not_allowed", ""},
		{"relay too old", config.SubstrateInteractiveConfig{}, false, old, "port/3000", true, 409, "relay_too_old", ""},
		{"plain request", config.SubstrateInteractiveConfig{}, false, streams, "port/3000", false, 400, "websocket_required", ""},
		{"port open", config.SubstrateInteractiveConfig{}, true, streams, "port/3000", true, 200, "", "port:3000"},
		{"mcp off in managed", config.SubstrateInteractiveConfig{}, true, streams, "mcp/docs", true, 403, "mcp_bridge_off", ""},
		{"mcp bad name", config.SubstrateInteractiveConfig{}, false, streams, "mcp/Docs", true, 404, "not_found", ""},
		{"mcp open", config.SubstrateInteractiveConfig{}, false, streams, "mcp/docs", true, 200, "", "mcp:docs"},
	} {
		au := &tixAudit{}
		ic := tc.ic
		st := &substrateState{cfg: SubstrateConfig{Managed: tc.managed, Interactive: func() config.SubstrateInteractiveConfig { return ic }}, audit: au.fn}
		s, status, reason := (&APIServer{}).substrateStreamOpen(st, tixStreamReq(tc.ws), tc.reg, tc.rest)
		if status != tc.status || reason != tc.reason {
			t.Fatalf("%s: got %d %s", tc.name, status, reason)
		}
		if tc.scope == "" {
			// A refusal writes its refused row (GAP-0817); the
			// terminal route writes none here.
			var want []string
			if tc.status != http.StatusOK {
				kind, _, _ := strings.Cut(tc.rest, "/")
				want = []string{"substrate." + kind + ".refused"}
			}
			if s != nil || !slices.Equal(au.events, want) {
				t.Fatalf("%s: no stream and rows %v expected, got %v %v", tc.name, want, s, au.events)
			}
			continue
		}
		if s.scope != tc.scope {
			t.Fatalf("%s: scope %q", tc.name, s.scope)
		}
		s.close(t.Context())
		kind := relay.RoutePort
		if tc.rest[:3] == "mcp" {
			kind = relay.RouteMCP
		}
		if !slices.Equal(au.events, []string{"substrate." + kind + ".open", "substrate." + kind + ".close"}) {
			t.Fatalf("%s: rows %v", tc.name, au.events)
		}
	}
}

// TestSubstrateStreamCap: max_streams forwards per actor, then
// too_many_streams; closing one frees its slot; MCP has its own cap.
func TestSubstrateStreamCap(t *testing.T) {
	reg := registry.Registration{Atespace: "tix", Name: "a", UID: "0001", RelayStreams: "mcp,port,tls"}
	ic := config.SubstrateInteractiveConfig{PortForward: config.SubstratePortForwardConfig{MaxStreams: 2},
		MCPBridge: config.SubstrateMCPBridgeConfig{MaxServers: 1}}
	st := &substrateState{cfg: SubstrateConfig{Interactive: func() config.SubstrateInteractiveConfig { return ic }}}
	a := &APIServer{}
	s1, _, _ := a.substrateStreamOpen(st, tixStreamReq(true), reg, "port/3000")
	s2, _, _ := a.substrateStreamOpen(st, tixStreamReq(true), reg, "port/3001")
	if s1 == nil || s2 == nil {
		t.Fatal("two forwards fit max_streams 2")
	}
	if _, status, reason := a.substrateStreamOpen(st, tixStreamReq(true), reg, "port/3002"); status != 429 || reason != "too_many_streams" {
		t.Fatalf("third forward: %d %s", status, reason)
	}
	if m, _, _ := a.substrateStreamOpen(st, tixStreamReq(true), reg, "mcp/docs"); m == nil {
		t.Fatal("the MCP cap is separate from the forward cap")
	}
	other := reg
	other.UID = "0002"
	if o, _, _ := a.substrateStreamOpen(st, tixStreamReq(true), other, "port/3000"); o == nil {
		t.Fatal("the cap is per actor")
	}
	s1.close(t.Context())
	s1.close(t.Context()) // a second close frees nothing more
	if s3, _, _ := a.substrateStreamOpen(st, tixStreamReq(true), reg, "port/3002"); s3 == nil {
		t.Fatal("a closed forward frees its slot")
	}
	if _, status, _ := a.substrateStreamOpen(st, tixStreamReq(true), reg, "port/3003"); status != 429 {
		t.Fatalf("still capped at 2: %d", status)
	}
}

// TestSubstrateStreamConnCountsAndIdleCloses: the relay connection of a
// stream counts bytes both ways and is closed after idle_close with no
// bytes, with an idle row.
func TestSubstrateStreamConnCountsAndIdleCloses(t *testing.T) {
	old := substrateStreamIdleTick
	substrateStreamIdleTick = 10 * time.Millisecond
	t.Cleanup(func() { substrateStreamIdleTick = old })
	var mu sync.Mutex
	var rows []string
	st := &substrateState{audit: func(_ context.Context, _, _ string, d map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		rows = append(rows, d["event"].(string))
	}}
	idled := func() bool { mu.Lock(); defer mu.Unlock(); return slices.Contains(rows, "substrate.port.idle") }
	s := &substrateStream{st: st, kind: relay.RoutePort, target: "3000", idle: 60 * time.Millisecond, release: func() {}}
	s.last.Store(time.Now().UnixNano())
	a, b := net.Pipe()
	c := s.wrap(a)
	go func() {
		buf := make([]byte, 8)
		_, _ = b.Read(buf)
		_, _ = b.Write([]byte("hello"))
	}()
	if _, err := c.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, err := c.Read(buf); err != nil || n != 5 {
		t.Fatalf("read %d %v", n, err)
	}
	if s.in.Load() != 3 || s.out.Load() != 5 {
		t.Fatalf("bytes in %d out %d", s.in.Load(), s.out.Load())
	}
	deadline := time.Now().Add(2 * time.Second)
	for !idled() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := c.Read(buf); err == nil {
		t.Fatal("an idle stream must be closed")
	}
	var nilStream *substrateStream
	if nilStream.wrap(b) != b {
		t.Fatal("a terminal route keeps its connection as is")
	}
	nilStream.close(t.Context())
}
