// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

type tixRows struct {
	mu   sync.Mutex
	rows []map[string]any
}

func (a *tixRows) fn(_ context.Context, _, _ string, d map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, d)
}

func (a *tixRows) last(event string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.rows) - 1; i >= 0; i-- {
		if a.rows[i]["event"] == event {
			return a.rows[i]
		}
	}
	return nil
}

func (a *tixRows) count(event string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, r := range a.rows {
		if r["event"] == event {
			n++
		}
	}
	return n
}

// GAP-0816: a stream opened while its switch was on ends on the next tick
// once the live config no longer admits it (switch off, port taken out of
// ports, managed auto for the MCP bridge), with a close row giving
// reason admin_off. A stream the config still admits keeps running.
func TestGAP0816LiveConfigClosesOpenStreams(t *testing.T) {
	old := substrateStreamIdleTick
	substrateStreamIdleTick = 5 * time.Millisecond
	t.Cleanup(func() { substrateStreamIdleTick = old })
	reg := registry.Registration{Atespace: "tix", Name: "a", UID: "0001", RelayStreams: "mcp,port,tls"}
	on := config.SubstrateInteractiveConfig{MCPBridge: config.SubstrateMCPBridgeConfig{Enabled: "on"}}
	for _, tc := range []struct {
		name    string
		managed bool
		rest    string
		after   config.SubstrateInteractiveConfig
		closes  bool
	}{
		{"port switch off", false, "port/3000", config.SubstrateInteractiveConfig{PortForward: config.SubstratePortForwardConfig{Enabled: "off"}}, true},
		{"port left ports", false, "port/3000", config.SubstrateInteractiveConfig{PortForward: config.SubstratePortForwardConfig{Ports: "4000-4999"}}, true},
		{"mcp switch off", false, "mcp/docs", config.SubstrateInteractiveConfig{MCPBridge: config.SubstrateMCPBridgeConfig{Enabled: "off"}}, true},
		{"mcp managed auto", true, "mcp/docs", config.SubstrateInteractiveConfig{}, true},
		{"port still allowed", false, "port/3000", config.SubstrateInteractiveConfig{PortForward: config.SubstratePortForwardConfig{Ports: "3000"}}, false},
	} {
		var flipped atomic.Bool
		au := &tixRows{}
		after := tc.after
		st := &substrateState{audit: au.fn, cfg: SubstrateConfig{Managed: tc.managed, Interactive: func() config.SubstrateInteractiveConfig {
			if flipped.Load() {
				return after
			}
			return on
		}}}
		s, status, reason := (&APIServer{}).substrateStreamOpen(st, tixStreamReq(true), reg, tc.rest)
		if status != http.StatusOK {
			t.Fatalf("%s: open %d %s", tc.name, status, reason)
		}
		a, b := net.Pipe()
		go func() {
			buf := make([]byte, 64)
			for {
				if _, err := b.Read(buf); err != nil {
					return
				}
			}
		}()
		c := s.wrap(a)
		flipped.Store(true)
		closed := false
		for end := time.Now().Add(500 * time.Millisecond); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
			if _, err := c.Write([]byte("x")); err != nil {
				closed = true
				break
			}
		}
		if closed != tc.closes {
			t.Fatalf("%s: closed=%v, want %v", tc.name, closed, tc.closes)
		}
		_ = c.Close()
		_ = b.Close()
		s.close(context.Background())
		want := "ended"
		if tc.closes {
			want = "admin_off"
		}
		row := au.last("substrate." + s.kind + ".close")
		if row == nil || row["reason"] != want {
			t.Fatalf("%s: close row %v, want reason %s", tc.name, row, want)
		}
		if au.count("substrate."+s.kind+".idle") != 0 {
			t.Fatalf("%s: an idle row for a stream with traffic", tc.name)
		}
	}
}

// GAP-0817: every refusal writes a substrate.port|mcp.refused row with the
// reason, person, actor and target, at most one per actor, kind and reason
// in each window; the next row counts the refusals held back.
func TestGAP0817RefusedRowsRateLimited(t *testing.T) {
	now := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
	au := &tixRows{}
	st := &substrateState{audit: au.fn, now: func() time.Time { return now }, cfg: SubstrateConfig{Interactive: func() config.SubstrateInteractiveConfig {
		return config.SubstrateInteractiveConfig{PortForward: config.SubstratePortForwardConfig{Enabled: "off", MaxStreams: 1}}
	}}}
	reg := registry.Registration{Atespace: "tix", Name: "a", UID: "0001", RelayStreams: "mcp,port,tls"}
	for i := 0; i < 5; i++ {
		if _, status, _ := (&APIServer{}).substrateStreamOpen(st, tixStreamReq(true), reg, "port/3000"); status != http.StatusForbidden {
			t.Fatalf("open %d", status)
		}
	}
	if n := au.count("substrate.port.refused"); n != 1 {
		t.Fatalf("%d refused rows in one window, want 1", n)
	}
	row := au.last("substrate.port.refused")
	if row["reason"] != "port_forward_off" || row["port"] != "3000" || row["actor"] != "a" || row["atespace"] != "tix" || row["actor_uid"] != "0001" {
		t.Fatalf("refused row %v", row)
	}
	// Another reason is its own row; the same reason waits for the window.
	(&APIServer{}).substrateStreamOpen(st, tixStreamReq(true), reg, "mcp/Docs")
	if row := au.last("substrate.mcp.refused"); row == nil || row["reason"] != "not_found" {
		t.Fatalf("mcp refused row %v", row)
	}
	now = now.Add(substrateStreamRefusedEvery)
	(&APIServer{}).substrateStreamOpen(st, tixStreamReq(true), reg, "port/3000")
	if n, row := au.count("substrate.port.refused"), au.last("substrate.port.refused"); n != 2 || row["held_back"] != 4 {
		t.Fatalf("after the window: %d rows, last %v (want held_back 4)", n, row)
	}
}

// GAP-0862: a refused row names an invalid target only quoted and cut to
// 64 bytes, so a request path writes no raw newline or long text into the
// audit log; a valid port or NAME is kept as is.
func TestGAP0862RefusedTargetQuotedAndCut(t *testing.T) {
	au := &tixRows{}
	st := &substrateState{audit: au.fn, cfg: SubstrateConfig{Interactive: func() config.SubstrateInteractiveConfig {
		return config.SubstrateInteractiveConfig{PortForward: config.SubstratePortForwardConfig{Enabled: "off"}}
	}}}
	reg := registry.Registration{Atespace: "tix", Name: "a", UID: "0001", RelayStreams: "mcp,port,tls"}
	long := "x\nFAKE row/" + strings.Repeat("y", 300)
	(&APIServer{}).substrateStreamOpen(st, tixStreamReq(true), reg, "port/"+long)
	got, _ := au.last("substrate.port.refused")["port"].(string)
	if strings.ContainsAny(got, "\n\r") || len(got) > 2*substrateStreamLogTargetMax || !strings.HasPrefix(got, `"x\nFAKE row/`) || !strings.HasSuffix(got, `"...`) {
		t.Fatalf("refused row port %q, want the target quoted and cut to %d bytes", got, substrateStreamLogTargetMax)
	}
	for kind, target := range map[string]string{"port": "3000", "mcp": "docs"} {
		if got := substrateStreamLogTarget(kind, target); got != target {
			t.Fatalf("%s %q logged as %q, want it unchanged", kind, target, got)
		}
	}
}
