// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// The MCP bridge (B3.3), gateway half. The gateway never proxies an
// mcp/NAME stream as bytes: it ends the launcher's WebSocket itself, dials
// the relay's mcp/NAME route with the stream's scoped token, and moves one
// JSON-RPC message per binary frame between them. Text frames are control
// ({type: open|close|error, code}). Every agent-to-laptop tools/call is
// judged by substrateMCPVerdict, the same verdict the in-cluster MCP hook
// path and the callout route use, so a tool the guard blocks there is
// refused here too and never reaches the laptop. The agent gets a JSON-RPC
// error mcp_call_denied instead.
//
// What the laptop server receives is the gateway's own re-encoding of the
// message it judged (exact keys, no duplicates, numbers kept), so a parser
// on the laptop cannot read a different method or tool name than the one
// that was judged. A message that does not parse, a batch, or one over
// mcp_bridge.message_max_bytes is refused, never forwarded or cut.
//
// No keepalive pings are sent on either socket: idle_close counts bytes on
// the relay connection, and pings would keep an idle bridge open (S2B-6).

const (
	substrateMCPDeniedCode   = -32001 // JSON-RPC server error: the guard said no
	substrateMCPControlMax   = 512
	substrateMCPMaxHeldAsks  = 8
	substrateMCPWriteTimeout = 30 * time.Second
)

// substrateMCPAskPoll is how often a held tools/call checks its ask.
var substrateMCPAskPoll = time.Second

// substrateMCPJudge is the verdict a bridged tools/call gets: the same one
// a direct MCP call in the actor gets. A variable so the ask hold can be
// tested: no bundled rule asks on MCP arguments (they are not read as a
// shell command, so only regex rules match, and those map to alert unless
// a profile turns HILT on).
var substrateMCPJudge = (*APIServer).substrateMCPVerdict

type substrateMCPBridge struct {
	a      *APIServer
	st     *substrateState
	reg    registry.Registration
	s      *substrateStream
	max    int64
	laptop *websocket.Conn
	agent  *websocket.Conn
	lmu    sync.Mutex // laptop writes
	amu    sync.Mutex // agent writes
	held   atomic.Int32
	wg     sync.WaitGroup
}

// serveSubstrateMCPBridge runs one mcp/NAME stream. The caller has already
// admitted the stream (switch, owner, cap, audit open) and minted tok.
func (a *APIServer) serveSubstrateMCPBridge(w http.ResponseWriter, r *http.Request, st *substrateState, reg registry.Registration,
	s *substrateStream, tok string, dial func(context.Context) (net.Conn, error)) {
	d := websocket.Dialer{
		NetDialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := dial(ctx)
			return s.wrap(c), err
		},
		Subprotocols:     []string{relay.Subprotocol},
		HandshakeTimeout: 60 * time.Second,
		ReadBufferSize:   32 << 10, WriteBufferSize: 32 << 10,
	}
	agent, resp, err := d.DialContext(r.Context(), "ws://actor.invalid"+relay.Path(relay.RouteMCP+"/"+s.target),
		http.Header{"Authorization": {"Bearer " + tok}})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		st.logRefusal("mcp bridge to %s/%s (%s) failed: %v", reg.Atespace, reg.Name, s.target, err)
		writeSubstrateJSONError(w, http.StatusBadGateway, "relay_unreachable")
		return
	}
	defer agent.Close()
	up := websocket.Upgrader{Subprotocols: []string{relay.Subprotocol}, ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10}
	laptop, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer laptop.Close()
	ic := st.interactive()
	b := &substrateMCPBridge{a: a, st: st, reg: reg, s: s, max: ic.EffectiveMessageMaxBytes(), laptop: laptop, agent: agent}
	// A frame far past the limit ends the bridge; one just past it is
	// drained and refused with an error.
	hard := 4 * b.max
	if hard < 64<<10 {
		hard = 64 << 10
	}
	agent.SetReadLimit(hard)
	laptop.SetReadLimit(hard)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := func() {
		cancel()
		_ = agent.Close()
		_ = laptop.Close()
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer stop()
		b.pump(ctx, laptop, false)
	}()
	b.pump(ctx, agent, true)
	stop()
	b.wg.Wait()
}

// pump reads one side until it ends. fromAgent marks the agent (relay)
// side, whose requests are judged.
func (b *substrateMCPBridge) pump(ctx context.Context, src *websocket.Conn, fromAgent bool) {
	for {
		kind, rd, err := src.NextReader()
		if err != nil {
			return
		}
		if kind == websocket.TextMessage {
			if c, ok := substrateMCPControl(rd); ok {
				b.write(!fromAgent, websocket.TextMessage, c)
			}
			continue
		}
		if kind != websocket.BinaryMessage {
			continue
		}
		msg, err := io.ReadAll(io.LimitReader(rd, b.max+1))
		if err != nil {
			return
		}
		if int64(len(msg)) > b.max {
			if _, err := io.Copy(io.Discard, rd); err != nil {
				return
			}
			b.refuse(ctx, fromAgent, nil, "message_too_large", "the MCP message is larger than mcp_bridge.message_max_bytes")
			continue
		}
		if !fromAgent {
			// Laptop answers and laptop-side requests (sampling, roots)
			// reach the agent as they are; the model sees them through
			// the proxy guardrails on its next call.
			b.write(true, websocket.BinaryMessage, msg)
			continue
		}
		b.fromAgent(ctx, msg)
	}
}

// fromAgent judges one agent-to-laptop message and forwards its canonical
// form, or refuses it.
func (b *substrateMCPBridge) fromAgent(ctx context.Context, raw []byte) {
	canon, v, err := substrateMCPCanonical(raw)
	if err != nil {
		b.refuse(ctx, true, nil, "invalid_message", "the MCP message is not one JSON-RPC object")
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		b.refuse(ctx, true, nil, "invalid_message", "JSON-RPC batches are not bridged")
		return
	}
	id := substrateMCPID(m)
	method, isString := m["method"].(string)
	if _, has := m["method"]; has && !isString {
		b.refuse(ctx, true, id, "invalid_message", "the JSON-RPC method is not a string")
		return
	}
	if method != "tools/call" {
		b.write(false, websocket.BinaryMessage, canon)
		return
	}
	params, _ := m["params"].(map[string]any)
	tool, _ := params["name"].(string)
	if tool == "" {
		b.refuse(ctx, true, id, "invalid_message", "tools/call has no tool name")
		return
	}
	var args json.RawMessage
	if a, has := params["arguments"]; has {
		args, _ = substrateMCPEncode(a)
	}
	req := substrateCalloutRequest{V: "1", MCP: calloutapi.MCP{Server: b.s.target, Tool: tool, Transport: "stdio", Method: method}, Args: args}
	req.Actor.Atespace, req.Actor.Name = b.reg.Atespace, b.reg.Name
	verdict := substrateMCPJudge(b.a, ctx, b.reg, req)
	switch verdict.Verdict {
	case "allow":
		b.write(false, websocket.BinaryMessage, canon)
	case "ask":
		if b.st.cfg.Asks == nil || b.held.Add(1) > substrateMCPMaxHeldAsks {
			if b.st.cfg.Asks != nil {
				b.held.Add(-1)
			}
			b.deny(ctx, id, tool, verdict.Source, "the call needs an approval that cannot be asked now")
			return
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer b.held.Add(-1)
			b.hold(ctx, id, tool, canon, verdict)
		}()
	default:
		b.deny(ctx, id, tool, verdict.Source, verdict.Reason)
	}
}

// hold keeps an asked tools/call until the owner decides or the ask limit
// passes; only an approval forwards it.
func (b *substrateMCPBridge) hold(ctx context.Context, id any, tool string, canon []byte, v SubstrateCalloutVerdict) {
	reg := b.reg
	ask := asks.Ask{
		Atespace: reg.Atespace, Actor: reg.Name, UID: reg.UID, OwnerID: reg.Person.ID(), Profile: reg.Profile,
		Tool: "mcp__" + mcpToolNamePart(b.s.target) + "__" + tool, Summary: "laptop MCP call " + b.s.target + "." + tool,
		Reason: v.Reason, Severity: v.Severity,
	}
	got, err := b.st.cfg.Asks.OpenAsk(ctx, ask)
	if err != nil {
		b.deny(ctx, id, tool, v.Source, "the approval could not be asked")
		return
	}
	b.a.emitSubstrateApprovalV8(ctx, got, true, "")
	limit := config.DefaultSubstrateAskTimeout
	if b.st.cfg.UnattendedAsk != nil {
		if r := b.st.cfg.UnattendedAsk(reg.Profile); r.Timeout > 0 {
			limit = r.Timeout
		}
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(substrateMCPAskPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			b.deny(ctx, id, tool, v.Source, "the approval was not given in time")
			return
		case <-tick.C:
			list, err := b.st.cfg.Asks.List(ctx, asks.ListRequest{All: true, Atespace: reg.Atespace, Actor: reg.Name})
			if err != nil {
				continue
			}
			for _, a := range list {
				if a.ID != got.ID || a.UID != reg.UID {
					continue
				}
				switch a.State {
				case asks.StateApproved:
					b.s.audit(ctx, "approved", map[string]any{"tool": tool, "ask_id": a.ID})
					b.write(false, websocket.BinaryMessage, canon)
					return
				case asks.StatePending:
				default:
					b.deny(ctx, id, tool, v.Source, "the approval was "+a.State)
					return
				}
			}
		}
	}
}

func (b *substrateMCPBridge) deny(ctx context.Context, id any, tool, source, reason string) {
	b.s.audit(context.WithoutCancel(ctx), "denied", map[string]any{"tool": tool, "source": source, "reason": reason})
	if id == nil {
		return // a notification gets no answer, only the denied row
	}
	b.writeErr(true, id, substrateMCPDeniedCode, "mcp_call_denied", "The guard denied tool "+b.s.target+"."+tool+": "+reason)
}

// refuse answers a message the bridge does not carry. toAgent says which
// side sent it; that side gets the error.
func (b *substrateMCPBridge) refuse(ctx context.Context, toAgent bool, id any, code, why string) {
	b.s.audit(context.WithoutCancel(ctx), "denied", map[string]any{"reason": code, "detail": why})
	b.writeErr(toAgent, id, -32600, code, why)
}

// writeErr sends a JSON-RPC error; a nil id is JSON null.
func (b *substrateMCPBridge) writeErr(toAgent bool, id any, n int, code, msg string) {
	out, err := substrateMCPEncode(map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": n, "message": code + ": " + msg, "data": map[string]any{"code": code}}})
	if err == nil {
		b.write(toAgent, websocket.BinaryMessage, out)
	}
}

func (b *substrateMCPBridge) write(toAgent bool, kind int, p []byte) {
	c, mu := b.laptop, &b.lmu
	if toAgent {
		c, mu = b.agent, &b.amu
	}
	mu.Lock()
	defer mu.Unlock()
	_ = c.SetWriteDeadline(time.Now().Add(substrateMCPWriteTimeout))
	if err := c.WriteMessage(kind, p); err != nil {
		_ = c.Close()
	}
}

// substrateMCPID is a request's id, or nil for a notification or a bad id.
func substrateMCPID(m map[string]any) any {
	switch id := m["id"].(type) {
	case string, json.Number:
		return id
	}
	return nil
}

// substrateMCPCanonical parses exactly one JSON value and re-encodes it.
// Duplicate keys collapse to the one Go judged (the last), numbers stay as
// written, and no trailing data survives.
func substrateMCPCanonical(raw []byte) ([]byte, any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("trailing data after the JSON-RPC message")
	}
	out, err := substrateMCPEncode(v)
	return out, v, err
}

func substrateMCPEncode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// substrateMCPControl passes only a small {type, code} control message.
func substrateMCPControl(rd io.Reader) ([]byte, bool) {
	raw, err := io.ReadAll(io.LimitReader(rd, substrateMCPControlMax+1))
	if err != nil || len(raw) > substrateMCPControlMax {
		_, _ = io.Copy(io.Discard, rd)
		return nil, false
	}
	var c struct {
		Type string `json:"type"`
		Code string `json:"code,omitempty"`
	}
	if json.Unmarshal(raw, &c) != nil || (c.Type != "open" && c.Type != "close" && c.Type != "error") || len(c.Code) > 64 {
		return nil, false
	}
	out, err := json.Marshal(c)
	return out, err == nil
}
