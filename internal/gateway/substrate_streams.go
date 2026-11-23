// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// substrateStream is one open port forward or MCP bridge on attach (B3.2,
// B3.3). The attach route opens it after the owner check
// (substrateFindSession refuses every other person, admins included, with
// not_your_agent), so a stream needs no owner rule of its own.
type substrateStream struct {
	st                     *substrateState
	kind                   string // relay.RoutePort or relay.RouteMCP
	scope                  string // the token's dc.scope: port:N or mcp:NAME
	space, name, uid, user string
	target                 string // the port or the MCP server name
	start                  time.Time
	idle                   time.Duration
	in, out                atomic.Int64
	last                   atomic.Int64 // unix nanos of the last byte
	release                func()
}

// substrateStreamCounts counts open streams per actor UID and kind.
type substrateStreamCounts struct {
	mu   sync.Mutex
	open map[string]int
}

func (c *substrateStreamCounts) take(key string, limit int) (release func(), ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open == nil {
		c.open = map[string]int{}
	}
	if c.open[key] >= limit {
		return nil, false
	}
	c.open[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.open[key]--; c.open[key] <= 0 {
				delete(c.open, key)
			}
		})
	}, true
}

// interactive is substrate.interactive in force (hot).
func (st *substrateState) interactive() config.SubstrateInteractiveConfig {
	if st.cfg.Interactive == nil {
		return config.SubstrateInteractiveConfig{}
	}
	return st.cfg.Interactive()
}

// substrateStreamOpen admits a port or mcp attach route for reg (nil, 200
// for every other route). The refusals, in order: the admin switch (403
// port_forward_off, mcp_bridge_off), the target (404 not_found, 403
// port_not_allowed), a template whose relay predates streams (409
// relay_too_old), a plain request (400 websocket_required) and the
// per-actor cap (429 too_many_streams); an mcp stream also needs a server
// name its block lists do not refuse (403 mcp_server_blocked).
func (a *APIServer) substrateStreamOpen(st *substrateState, r *http.Request, reg registry.Registration, rest string) (*substrateStream, int, string) {
	head, target, _ := strings.Cut(rest, "/")
	if head != relay.RoutePort && head != relay.RouteMCP {
		return nil, http.StatusOK, ""
	}
	ic := st.interactive()
	limit := ic.EffectiveMaxStreams()
	switch head {
	case relay.RoutePort:
		if !ic.PortForwardOn() {
			return nil, http.StatusForbidden, "port_forward_off"
		}
		n, err := strconv.Atoi(target)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != target {
			return nil, http.StatusNotFound, "not_found"
		}
		if !ic.PortAllowed(n) {
			return nil, http.StatusForbidden, "port_not_allowed"
		}
	case relay.RouteMCP:
		if !ic.MCPBridgeOn(st.cfg.Managed) {
			return nil, http.StatusForbidden, "mcp_bridge_off"
		}
		if !relay.MCPNameRE.MatchString(target) {
			return nil, http.StatusNotFound, "not_found"
		}
		// T6 ruling 2: the MCP block and allow lists (an operator block,
		// asset_policy.mcp.denied, an admission verdict) apply to NAME
		// when the bridge opens, not only to each tools/call.
		if blocked, why := a.substrateMCPServerBlocked(r.Context(), reg, target); blocked {
			if st.audit != nil {
				st.audit(r.Context(), "WARN", "mcp stream refused for "+reg.Atespace+"/"+reg.Name+" ("+target+"): "+why,
					map[string]any{"event": "substrate.mcp.blocked", "atespace": reg.Atespace, "actor": reg.Name,
						"actor_uid": reg.UID, "mcp": target, "reason": "mcp_server_blocked", "detail": why})
			}
			return nil, http.StatusForbidden, "mcp_server_blocked"
		}
		limit = ic.EffectiveMaxServers()
	}
	// A stream needs a relay that serves it, over TLS: the signed kit of
	// the actor's template names both (kitspec writes them together; a
	// route name is its kit stream name).
	if !reg.RelayServes(kit.StreamTLS) || !reg.RelayServes(head) {
		return nil, http.StatusConflict, "relay_too_old"
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !headerHasToken(r.Header, "Connection", "upgrade") {
		return nil, http.StatusBadRequest, "websocket_required"
	}
	release, ok := st.streams.take(reg.UID+"/"+head, limit)
	if !ok {
		return nil, http.StatusTooManyRequests, "too_many_streams"
	}
	s := &substrateStream{st: st, kind: head, scope: head + ":" + target, space: reg.Atespace, name: reg.Name, uid: reg.UID,
		target: target, start: st.clock(), idle: ic.EffectiveIdleClose(), release: release}
	if s.idle <= 0 {
		s.idle = config.DefaultSubstrateIdleClose
	}
	if c, ok := substrateCallerFrom(r.Context()); ok {
		s.user = c.person.ID()
	}
	s.last.Store(s.start.UnixNano())
	s.audit(r.Context(), "open", nil)
	return s, http.StatusOK, ""
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

// audit writes substrate.port.<what> or substrate.mcp.<what>.
func (s *substrateStream) audit(ctx context.Context, what string, extra map[string]any) {
	if s.st.audit == nil {
		return
	}
	d := map[string]any{"event": "substrate." + s.kind + "." + what, "atespace": s.space, "actor": s.name,
		"actor_uid": s.uid, "person": s.user, s.kind: s.target}
	for k, v := range extra {
		d[k] = v
	}
	s.st.audit(ctx, "INFO", s.kind+" stream "+what+" for "+s.space+"/"+s.name+" ("+s.target+")", d)
}

// close ends the stream: the per-actor slot and a close row with bytes
// and duration.
func (s *substrateStream) close(ctx context.Context) {
	if s == nil {
		return
	}
	s.release()
	s.audit(context.WithoutCancel(ctx), "close", map[string]any{"bytes_in": s.in.Load(), "bytes_out": s.out.Load(),
		"duration_ms": s.st.clock().Sub(s.start).Milliseconds()})
}

// wrap counts the bytes on the relay connection and closes it after idle
// with no bytes either way (substrate.interactive.idle_close).
func (s *substrateStream) wrap(c net.Conn) net.Conn {
	if s == nil || c == nil {
		return c
	}
	sc := &substrateStreamConn{Conn: c, s: s, done: make(chan struct{})}
	go sc.watch()
	return sc
}

type substrateStreamConn struct {
	net.Conn
	s    *substrateStream
	done chan struct{}
	once sync.Once
}

func (c *substrateStreamConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.s.out.Add(int64(n))
		c.s.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *substrateStreamConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.s.in.Add(int64(n))
		c.s.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *substrateStreamConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// substrateStreamIdleTick bounds how late an idle stream is closed.
var substrateStreamIdleTick = time.Minute

func (c *substrateStreamConn) watch() {
	tick := substrateStreamIdleTick
	if c.s.idle < 4*tick {
		tick = c.s.idle / 4
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-t.C:
			if now.Sub(time.Unix(0, c.s.last.Load())) >= c.s.idle {
				c.s.audit(context.Background(), "idle", map[string]any{"idle_close_s": int(c.s.idle / time.Second)})
				_ = c.Close()
				return
			}
		}
	}
}

// substrateMCPServerBlocked reports whether the MCP block lists refuse the
// server name for the actor's connector, the same lookup a hook's MCP
// tool call gets (mcpServerRuntimeBlock: fail closed on a lookup error).
func (a *APIServer) substrateMCPServerBlocked(ctx context.Context, reg registry.Registration, name string) (bool, string) {
	if a == nil || a.store == nil {
		return false, ""
	}
	ctx = a.substrateEvaluationContext(ctx, reg, sandboxauth.RouteHook)
	deny, _, why := mcpServerRuntimeBlock(a.toolPolicyEngine(ctx), "", sandboxauth.CanonicalConnector(reg.Connector), name)
	return deny, why
}
