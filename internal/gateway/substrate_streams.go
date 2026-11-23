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
	port                   int    // the port of a port stream
	start                  time.Time
	idle                   time.Duration
	in, out                atomic.Int64
	last                   atomic.Int64 // unix nanos of the last byte
	ended                  atomic.Value // string: why the gateway ended it (idle_close, admin_off)
	release                func()
}

// substrateStreamCounts counts open streams per actor UID and kind on this
// gateway replica (GAP-0818: the caps are per replica, as the schema says;
// a shared count would need a leader round trip on every open and close).
type substrateStreamCounts struct {
	mu   sync.Mutex
	open map[string]int
	// refused is when a refused row was last written per actor, kind and
	// reason, and how many refusals it has held back since (GAP-0817).
	refused map[string]*substrateStreamRefusal
}

type substrateStreamRefusal struct {
	at   time.Time
	held int
}

// substrateStreamRefusedEvery bounds refused rows: one per actor, kind and
// reason in each window, the next one counting those held back.
var substrateStreamRefusedEvery = 10 * time.Second

// refusedRow reports whether a refused row for key is due now, and how many
// refusals for key it has held back since the last row.
func (c *substrateStreamCounts) refusedRow(key string, now time.Time) (held int, due bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refused == nil {
		c.refused = map[string]*substrateStreamRefusal{}
	}
	if r := c.refused[key]; r != nil && now.Sub(r.at) < substrateStreamRefusedEvery {
		r.held++
		return 0, false
	}
	if len(c.refused) >= 1024 {
		for k, r := range c.refused {
			if now.Sub(r.at) >= substrateStreamRefusedEvery {
				delete(c.refused, k)
			}
		}
	}
	if r := c.refused[key]; r != nil {
		held = r.held
	}
	c.refused[key] = &substrateStreamRefusal{at: now}
	return held, true
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
// per-actor cap on this replica (429 too_many_streams); an mcp stream also
// needs a server name its block lists do not refuse (403 mcp_server_blocked).
// Each refusal writes a rate-limited substrate.port|mcp.refused row (GAP-0817).
func (a *APIServer) substrateStreamOpen(st *substrateState, r *http.Request, reg registry.Registration, rest string) (*substrateStream, int, string) {
	head, target, _ := strings.Cut(rest, "/")
	if head != relay.RoutePort && head != relay.RouteMCP {
		return nil, http.StatusOK, ""
	}
	s, status, reason := a.substrateStreamAdmit(st, r, reg, head, target)
	if status != http.StatusOK {
		substrateStreamRefused(st, r, reg, head, target, reason)
	}
	return s, status, reason
}

// substrateStreamRefused writes substrate.port|mcp.refused for one refusal,
// at most one row per actor, kind and reason in each window.
func substrateStreamRefused(st *substrateState, r *http.Request, reg registry.Registration, kind, target, reason string) {
	if st.audit == nil {
		return
	}
	held, due := st.streams.refusedRow(reg.UID+"/"+kind+"/"+reason, st.clock())
	if !due {
		return
	}
	person := ""
	if c, ok := substrateCallerFrom(r.Context()); ok {
		person = c.person.ID()
	}
	target = substrateStreamLogTarget(kind, target)
	st.audit(r.Context(), "INFO", kind+" stream refused for "+reg.Atespace+"/"+reg.Name+" ("+target+"): "+reason, map[string]any{
		"event": "substrate." + kind + ".refused", "reason": reason, "atespace": reg.Atespace, "actor": reg.Name,
		"actor_uid": reg.UID, "person": person, kind: target, "held_back": held})
}

// substrateStreamLogTargetMax caps the bytes of an invalid target a
// refused row keeps.
const substrateStreamLogTargetMax = 64

// substrateStreamLogTarget is the target a refused row names: the target
// itself when it is a valid port or NAME, else its first 64 bytes, quoted,
// so a request path writes no raw or long text into the audit log
// (GAP-0862). A refusal can come before the target is checked
// (port_forward_off, mcp_bridge_off).
func substrateStreamLogTarget(kind, target string) string {
	switch kind {
	case relay.RoutePort:
		if n, err := strconv.Atoi(target); err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == target {
			return target
		}
	case relay.RouteMCP:
		if relay.MCPNameRE.MatchString(target) {
			return target
		}
	}
	more := ""
	if len(target) > substrateStreamLogTargetMax {
		target, more = target[:substrateStreamLogTargetMax], "..."
	}
	return strconv.QuoteToASCII(target) + more
}

func (a *APIServer) substrateStreamAdmit(st *substrateState, r *http.Request, reg registry.Registration, head, target string) (*substrateStream, int, string) {
	ic := st.interactive()
	port := 0
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
		port = n
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
		target: target, port: port, start: st.clock(), idle: ic.EffectiveIdleClose(), release: release}
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

// close ends the stream: the per-actor slot and a close row with bytes,
// duration and why it ended (ended, idle_close or admin_off).
func (s *substrateStream) close(ctx context.Context) {
	if s == nil {
		return
	}
	s.release()
	reason, _ := s.ended.Load().(string)
	if reason == "" {
		reason = "ended"
	}
	s.audit(context.WithoutCancel(ctx), "close", map[string]any{"bytes_in": s.in.Load(), "bytes_out": s.out.Load(),
		"duration_ms": s.st.clock().Sub(s.start).Milliseconds(), "reason": reason})
}

// allowed reports whether the live substrate.interactive still admits the
// stream (GAP-0816): its switch is on (managed auto included) and, for a
// port, the port is still in ports.
func (s *substrateStream) allowed(ic config.SubstrateInteractiveConfig) bool {
	if s.kind == relay.RoutePort {
		return ic.PortForwardOn() && ic.PortAllowed(s.port)
	}
	return ic.MCPBridgeOn(s.st.cfg.Managed)
}

// wrap counts the bytes on the relay connection and closes it after idle
// with no bytes either way (substrate.interactive.idle_close), or as soon as
// a tick finds the live config no longer admits it (admin_off).
func (s *substrateStream) wrap(c net.Conn) net.Conn {
	if s == nil || c == nil {
		return c
	}
	sc := &substrateStreamConn{Conn: c, s: s, done: make(chan struct{})}
	// The tick is read here, not in the watcher, so the watcher never
	// reads the package setting while a caller changes it.
	tick := substrateStreamIdleTick
	if s.idle < 4*tick {
		tick = s.idle / 4
	}
	go sc.watch(tick)
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

func (c *substrateStreamConn) watch(tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-t.C:
			// An admin switch to off, or a port taken out of ports,
			// ends the streams already open, not just new ones (GAP-0816).
			if !c.s.allowed(c.s.st.interactive()) {
				c.s.ended.Store("admin_off")
				_ = c.Close()
				return
			}
			if now.Sub(time.Unix(0, c.s.last.Load())) >= c.s.idle {
				c.s.ended.Store("idle_close")
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
