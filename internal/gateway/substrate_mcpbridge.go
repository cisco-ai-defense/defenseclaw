// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
// error mcp_call_denied instead. The other methods that bring laptop data
// back (resources/read, prompts/get, completion/complete,
// resources/subscribe) get the same verdict as tool names resources_read and
// so on, with their arguments read as a tools/call's are, and a method or
// notification off the bridge allow list is refused with method-not-found
// (GAP-0841, substrateMCPJudgedMethods, substrateMCPMethodArgs,
// substrateMCPPassMethods, substrateMCPPassNotifications). Arguments past the
// bounds of the rules' reading are judged on bounded projections as well and
// are at least the unknown tier (substrateMCPBoundedVerdict, GAP-1094).
//
// What the laptop server receives is the gateway's own re-encoding of the
// message it judged (numbers kept), and the parse is strict: a message with
// a duplicate key, or a key that only folds to method, params, name or
// arguments, in the envelope or in params is refused (substrateMCPStrictKeys),
// so a case-insensitive parser on the laptop cannot read a different method,
// tool name or arguments than the ones that were judged. A message that does
// not parse, a batch, or one over mcp_bridge.message_max_bytes is refused,
// never forwarded or cut; an oversize answer from the laptop also answers the
// agent's pending request (substrateMCPBridge.tooLarge).
//
// No keepalive pings are sent on either socket: idle_close counts bytes on
// the relay connection, and pings would keep an idle bridge open (S2B-6).

const (
	substrateMCPDeniedCode   = -32001 // JSON-RPC server error: the guard said no
	substrateMCPControlMax   = 512
	substrateMCPMaxHeldAsks  = 8
	substrateMCPWriteTimeout = 30 * time.Second
	// Over-reader-limit frames may use more CPU. Only one such call per
	// actor runs at once; another gets a short bounded wait.
	substrateMCPOverCapWait = 100 * time.Millisecond
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
			b.tooLarge(ctx, fromAgent, msg)
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
	if errors.Is(err, errSubstrateMCPAmbiguous) {
		m, _ := v.(map[string]any)
		b.refuse(ctx, true, substrateMCPID(m), "invalid_message", "the MCP message has a duplicate or case-folded JSON-RPC key")
		return
	}
	if err != nil {
		b.refuse(ctx, true, nil, "invalid_message", "the MCP message is not one JSON-RPC object")
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		why := "the MCP message is not one JSON-RPC object"
		if _, batch := v.([]any); batch {
			why = "JSON-RPC batches are not bridged"
		}
		b.refuse(ctx, true, nil, "invalid_message", why)
		return
	}
	id := substrateMCPID(m)
	method, isString := m["method"].(string)
	_, hasMethod := m["method"]
	if hasMethod && !isString {
		b.refuse(ctx, true, id, "invalid_message", "the JSON-RPC method is not a string")
		return
	}
	if !hasMethod {
		// The agent's answer to a laptop request (sampling, roots,
		// elicitation) goes back as it is.
		if _, result := m["result"]; result {
			b.write(false, websocket.BinaryMessage, canon)
			return
		}
		if _, e := m["error"]; e {
			b.write(false, websocket.BinaryMessage, canon)
			return
		}
		b.refuse(ctx, true, id, "invalid_message", "the JSON-RPC message is neither a request nor a response")
		return
	}
	judgedAs, judged := substrateMCPJudgedMethods[method]
	if !judged {
		_, hasID := m["id"]
		switch {
		case substrateMCPPassMethods[method]:
			b.write(false, websocket.BinaryMessage, canon)
		case substrateMCPPassNotifications[method] && !hasID:
			b.write(false, websocket.BinaryMessage, canon)
		case strings.HasPrefix(method, "notifications/") && hasID:
			b.refuse(ctx, true, id, "invalid_message", "a JSON-RPC notification carries no id")
		default:
			if exact := substrateMCPAllowedFold[substrateMCPFold(strings.TrimSpace(method))]; exact != "" {
				b.refuse(ctx, true, id, "invalid_message", "the JSON-RPC method is not exactly "+exact)
				return
			}
			b.notBridged(ctx, id, method)
		}
		return
	}
	var c substrateMCPJudgedCall
	if method == "tools/call" {
		var args json.RawMessage
		c.tool, args, c.why = substrateMCPCall(m)
		c.args = []json.RawMessage{args}
	} else {
		c = substrateMCPMethodArgs(m, method)
		c.tool = judgedAs
	}
	if c.why != "" {
		b.refuse(ctx, true, id, "invalid_message", c.why)
		return
	}
	tool, ref := c.tool, c.ref
	verdict := b.judge(ctx, method, c)
	switch verdict.Verdict {
	case "allow":
		if len(verdict.Findings) > 0 {
			// Allowed with a finding (arguments past the reading's bounds,
			// GAP-1094): the row says so, never a silent allow.
			row := map[string]any{"tool": tool, "method": method, "source": verdict.Source, "reason": verdict.Reason,
				"findings": verdict.Findings}
			if ref != "" {
				row["ref"] = ref
			}
			b.s.audit(context.WithoutCancel(ctx), "alert", row)
		}
		b.write(false, websocket.BinaryMessage, canon)
	case "ask":
		if b.st.cfg.Asks == nil || b.held.Add(1) > substrateMCPMaxHeldAsks {
			if b.st.cfg.Asks != nil {
				b.held.Add(-1)
			}
			b.deny(ctx, id, method, tool, ref, verdict.Source, "the call needs an approval that cannot be asked now")
			return
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer b.held.Add(-1)
			b.hold(ctx, id, method, tool, ref, canon, verdict)
		}()
	default:
		b.deny(ctx, id, method, tool, ref, verdict.Source, verdict.Reason)
	}
}

// substrateMCPJudgedMethods are the agent methods that bring laptop data
// back, so each one gets the tools/call verdict before it reaches the laptop
// (GAP-0841): the value is the tool name the verdict reads, with the
// method's arguments (substrateMCPMethodArgs); a tools/call reads its own
// name and arguments.
var substrateMCPJudgedMethods = map[string]string{
	"tools/call":          "",
	"resources/read":      "resources_read",
	"resources/subscribe": "resources_subscribe",
	"prompts/get":         "prompts_get",
	"completion/complete": "completion_complete",
}

// substrateMCPPassMethods are the other agent requests the bridge carries
// unjudged: the handshake, ping, logging level, unsubscribe, the four list
// methods (what the server offers, not its data) and the task methods (MCP
// 2025-11-25), which only reach tasks a judged tools/call created. Any other
// method is refused (notBridged).
var substrateMCPPassMethods = map[string]bool{
	"initialize": true, "ping": true, "logging/setLevel": true, "resources/unsubscribe": true,
	"tools/list": true, "resources/list": true, "resources/templates/list": true, "prompts/list": true,
	"tasks/get": true, "tasks/result": true, "tasks/list": true, "tasks/cancel": true,
}

// substrateMCPPassNotifications are the client notifications of the MCP
// spec, carried without an id. Any other notifications/* method is refused
// like an unlisted method, so a name such as notifications/x/../../resources/read
// never reaches a laptop server that routes on a prefix (RV-0841 F3).
var substrateMCPPassNotifications = map[string]bool{
	"notifications/initialized": true, "notifications/cancelled": true, "notifications/progress": true,
	"notifications/roots/list_changed": true, "notifications/tasks/status": true,
}

// substrateMCPAllowedFold maps the folded form of each carried method to its
// only accepted spelling: "Tools/Call" or "resources/read " is refused as an
// invalid message, never read as the method by a lenient laptop server.
var substrateMCPAllowedFold = func() map[string]string {
	m := map[string]string{}
	for _, set := range []map[string]bool{substrateMCPPassMethods, substrateMCPPassNotifications} {
		for k := range set {
			m[substrateMCPFold(k)] = k
		}
	}
	for k := range substrateMCPJudgedMethods {
		m[substrateMCPFold(k)] = k
	}
	return m
}()

// substrateMCPJudgedCall is what the verdict of one judged message reads.
type substrateMCPJudgedCall struct {
	tool string
	args []json.RawMessage // each is judged; the strictest verdict holds
	// params, when set, is the whole params of a call whose args are parts
	// of them: judged as well, and the reading the LLM judge and AID read.
	params json.RawMessage
	ref    string // the prompt or reference it names, for its rows
	why    string // why it is refused, when it is
}

// substrateMCPMethodArgs is the arguments a judged method other than
// tools/call is judged on. resources/read and resources/subscribe carry
// them as their params. prompts/get is judged on params.arguments and
// completion/complete on the argument it completes ({argument.name:
// argument.value}) beside the context.arguments, as a tools/call's
// arguments are (RV-0841 F1); where the completed argument has the same
// name as a context argument with another value, both readings are judged.
// Both are judged on their whole params as well, so a rule that reads the
// prompt name, the completion ref or _meta holds them as before
// (RV-0841b F1). A null field carries nothing and is absent (RV-0841b F5);
// a field of another shape than the spec gives is refused, never judged as
// none.
func substrateMCPMethodArgs(m map[string]any, method string) substrateMCPJudgedCall {
	refuse := func(what string) substrateMCPJudgedCall {
		return substrateMCPJudgedCall{why: "the " + method + " " + what}
	}
	p, has := m["params"]
	if !has {
		return substrateMCPJudgedCall{args: []json.RawMessage{nil}}
	}
	params, ok := p.(map[string]any)
	if !ok {
		return refuse("params are not an object")
	}
	whole, err := substrateMCPEncode(params)
	if err != nil {
		return refuse("params do not encode")
	}
	var c substrateMCPJudgedCall
	var readings []map[string]any
	switch method {
	case "prompts/get":
		c.ref, _ = params["name"].(string)
		a, ok := substrateMCPObjectField(params, "arguments")
		if !ok {
			return refuse("arguments are not an object")
		}
		if a != nil {
			readings = append(readings, a)
		}
	case "completion/complete":
		arg, ok := substrateMCPObjectField(params, "argument")
		if !ok {
			return refuse("argument is not an object")
		}
		cx, ok := substrateMCPObjectField(params, "context")
		if !ok {
			return refuse("context is not an object")
		}
		others, ok := substrateMCPObjectField(cx, "arguments")
		if !ok {
			return refuse("context arguments are not an object")
		}
		merged := maps.Clone(others)
		if merged == nil {
			merged = map[string]any{}
		}
		if arg != nil {
			name, named := substrateMCPArgName(arg["name"])
			value, hasValue := arg["value"]
			if !named || !hasValue {
				return refuse("argument has no name or value")
			}
			if prev, clash := merged[name]; clash && !reflect.DeepEqual(prev, value) {
				readings = append(readings, maps.Clone(merged))
			}
			merged[name] = value
		}
		if len(merged) > 0 {
			readings = append([]map[string]any{merged}, readings...)
		}
		ref, _ := params["ref"].(map[string]any)
		if c.ref, _ = ref["name"].(string); c.ref == "" {
			c.ref, _ = ref["uri"].(string)
		}
	default:
		return substrateMCPJudgedCall{args: []json.RawMessage{whole}}
	}
	for _, r := range readings {
		args, err := substrateMCPEncode(r)
		if err != nil {
			return refuse("arguments do not encode")
		}
		c.args = append(c.args, args)
	}
	c.params = whole
	if len(c.ref) > 256 {
		c.ref = strings.ToValidUTF8(c.ref[:256], "")
	}
	return c
}

// substrateMCPObjectField is obj[key] when it is an object, nil when it is
// absent or null, and not ok when it is anything else.
func substrateMCPObjectField(obj map[string]any, key string) (map[string]any, bool) {
	switch v := obj[key].(type) {
	case nil:
		return nil, true
	case map[string]any:
		return v, true
	}
	return nil, false
}

// substrateMCPArgName is a completion argument's name: a non-empty string,
// or a number read as its text (a lenient server keys on it the same way).
func substrateMCPArgName(v any) (string, bool) {
	switch n := v.(type) {
	case string:
		return n, n != ""
	case json.Number:
		return n.String(), true
	case float64:
		return strconv.FormatFloat(n, 'g', -1, 64), true
	}
	return "", false
}

// judge is the strictest verdict of the call's readings; a deny ends it.
// The argument readings come first and, when the whole params are read
// too, go to the rules alone. An argument denial ends evaluation: no whole
// params reading reaches AID or the LLM judge for that denied attempt.
// Otherwise params go to every lane, as the single reading did before.
// AID and the judge may only make a verdict stricter (RV-0841c F2).
// A call judges at most substrateMCPReadingsPerArgs readings per argument
// reading, including projections and distinct alias values (RV-0841b F6).
func (b *substrateMCPBridge) judge(ctx context.Context, method string, c substrateMCPJudgedCall) SubstrateCalloutVerdict {
	if b.st != nil && substrateMCPOverCap(c) {
		key := "mcp-judge:" + b.reg.Atespace + "/" + b.reg.UID
		release, ok := b.st.streams.take(key, 1)
		if !ok {
			timer := time.NewTimer(substrateMCPOverCapWait)
			tick := time.NewTicker(10 * time.Millisecond)
			defer timer.Stop()
			defer tick.Stop()
			for !ok {
				select {
				case <-ctx.Done():
					return substrateMCPBusyVerdict()
				case <-timer.C:
					return substrateMCPBusyVerdict()
				case <-tick.C:
					release, ok = b.st.streams.take(key, 1)
				}
			}
		}
		defer release()
	}
	readings := c.args
	if c.params != nil {
		readings = append(slices.Clip(c.args), c.params)
	}
	left := substrateMCPReadingsPerArgs*max(len(c.args), 1) - len(readings)
	extraBytes := substrateMCPExtraBytesPerCall
	var out SubstrateCalloutVerdict
	for i, args := range readings {
		req := substrateCalloutRequest{V: "1", MCP: calloutapi.MCP{Server: b.s.target, Tool: c.tool, Transport: "stdio", Method: method}, Args: args}
		req.Actor.Atespace, req.Actor.Name = b.reg.Atespace, b.reg.Name
		rd := substrateMCPReading{rulesOnly: c.params != nil && i < len(c.args), left: &left, extraBytes: &extraBytes}
		v := substrateMCPJudge(b.a, withSubstrateMCPReading(ctx, rd), b.reg, req)
		if i == 0 {
			out = v
		} else {
			out = substrateMCPStricter(out, v)
		}
		if out.Verdict == "deny" {
			break
		}
	}
	return out
}

// substrateMCPOverCap admits any call that reaches a shared reader limit
// through the one-active-call actor budget. Ordinary calls do not wait.
func substrateMCPOverCap(c substrateMCPJudgedCall) bool {
	if actionfacts.ArgsLimitIssue(c.params) != "" {
		return true
	}
	for _, args := range c.args {
		if actionfacts.ArgsLimitIssue(args) != "" {
			return true
		}
	}
	return false
}

func substrateMCPBusyVerdict() SubstrateCalloutVerdict {
	return SubstrateCalloutVerdict{V: "1", Verdict: "deny", Source: "tool_rules",
		Reason: boundedTruncatedTitle + " (over-cap actor budget)", Severity: "HIGH",
		Findings: []string{evaluationLimitRuleID}}
}

// notBridged refuses a method that is not on the bridge allow list with a
// JSON-RPC method-not-found error (none for a notification) and a denied row.
func (b *substrateMCPBridge) notBridged(ctx context.Context, id any, method string) {
	const code = "mcp_method_not_bridged"
	if len(method) > 128 {
		method = strings.ToValidUTF8(method[:128], "")
	}
	b.s.audit(context.WithoutCancel(ctx), "denied", map[string]any{"reason": code, "method": method})
	if id != nil {
		b.writeErr(true, id, -32601, code, "the MCP bridge does not carry method "+method)
	}
}

// hold keeps an asked call until the owner decides or the ask limit passes;
// only an approval forwards it.
func (b *substrateMCPBridge) hold(ctx context.Context, id any, method, tool, ref string, canon []byte, v SubstrateCalloutVerdict) {
	reg := b.reg
	ask := asks.Ask{
		Atespace: reg.Atespace, Actor: reg.Name, UID: reg.UID, OwnerID: reg.Person.ID(), Profile: reg.Profile,
		Tool: "mcp__" + mcpToolNamePart(b.s.target) + "__" + tool, Summary: "laptop MCP call " + b.s.target + "." + tool,
		Reason: v.Reason, Severity: v.Severity,
	}
	got, err := b.st.cfg.Asks.OpenAsk(ctx, ask)
	if err != nil {
		b.deny(ctx, id, method, tool, ref, v.Source, "the approval could not be asked")
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
			b.deny(ctx, id, method, tool, ref, v.Source, "the approval was not given in time")
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
					row := map[string]any{"tool": tool, "method": method, "ask_id": a.ID}
					if ref != "" {
						row["ref"] = ref
					}
					b.s.audit(ctx, "approved", row)
					b.write(false, websocket.BinaryMessage, canon)
					return
				case asks.StatePending:
				default:
					b.deny(ctx, id, method, tool, ref, v.Source, "the approval was "+a.State)
					return
				}
			}
		}
	}
}

func (b *substrateMCPBridge) deny(ctx context.Context, id any, method, tool, ref, source, reason string) {
	row := map[string]any{"tool": tool, "method": method, "source": source, "reason": reason}
	if ref != "" {
		row["ref"] = ref
	}
	b.s.audit(context.WithoutCancel(ctx), "denied", row)
	if id == nil {
		return // a notification gets no answer, only the denied row
	}
	b.writeErr(true, id, substrateMCPDeniedCode, "mcp_call_denied", "The guard denied tool "+b.s.target+"."+tool+": "+reason)
}

// substrateMCPTooLargeControl tells the agent's shim that a laptop message
// was dropped when there is no request id to answer.
var substrateMCPTooLargeControl = []byte(`{"type":"error","code":"message_too_large"}`)

// tooLarge refuses a message over mcp_bridge.message_max_bytes; prefix is
// the bounded part the bridge read. The sender gets the error, with its
// request's id when the prefix shows one. When the message was an answer,
// the other side's pending request gets the error with that id, so the
// agent never waits for a laptop answer that was dropped (GAP-0839). A laptop
// message that is neither gives the agent a control error frame.
func (b *substrateMCPBridge) tooLarge(ctx context.Context, fromAgent bool, prefix []byte) {
	const code, why = "message_too_large", "the MCP message is larger than mcp_bridge.message_max_bytes"
	id, response, request := substrateMCPPrefixID(prefix)
	var senderID any
	if request {
		senderID = id
	}
	b.refuse(ctx, fromAgent, senderID, code, why)
	switch {
	case response && id != nil:
		b.writeErr(!fromAgent, id, -32600, code, why)
	case !fromAgent && !request:
		b.write(true, websocket.TextMessage, substrateMCPTooLargeControl)
	}
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

// substrateMCPCall is a tools/call's tool name and encoded arguments, or the
// reason it is refused. An arguments value that does not encode is refused,
// never judged as a call without arguments.
func substrateMCPCall(m map[string]any) (tool string, args json.RawMessage, why string) {
	params, _ := m["params"].(map[string]any)
	tool, _ = params["name"].(string)
	if tool == "" {
		return "", nil, "tools/call has no tool name"
	}
	if a, has := params["arguments"]; has {
		var err error
		if args, err = substrateMCPEncode(a); err != nil {
			return "", nil, "the tools/call arguments do not encode"
		}
	}
	return tool, args, ""
}

// substrateMCPCanonical parses exactly one JSON value and re-encodes it.
// Numbers stay as written and no trailing data survives. A message that
// fails substrateMCPStrictKeys returns errSubstrateMCPAmbiguous (with the
// decoded value, for its id); it is refused, never re-encoded.
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
	if err := substrateMCPStrictKeys(raw); err != nil {
		return nil, v, err
	}
	out, err := substrateMCPEncode(v)
	return out, v, err
}

// errSubstrateMCPAmbiguous marks a message that a parser on the laptop
// could read differently from the bridge.
var errSubstrateMCPAmbiguous = errors.New("ambiguous JSON-RPC keys")

// substrateMCPJudgedKeys maps the folded form of each key the verdict or
// the routing reads (the id, result and error that make a message a request,
// a notification or an answer, RV-0841 F3) to its only accepted spelling.
var substrateMCPJudgedKeys = func() map[string]string {
	m := map[string]string{}
	for _, k := range []string{"method", "params", "name", "arguments", "argument", "value", "context", "id", "result", "error"} {
		m[substrateMCPFold(k)] = k
	}
	return m
}()

// substrateMCPStrictKeys refuses an envelope, params object, or a
// completion/complete argument or context object that a laptop parser could
// read differently from the bridge (GAP-0838). Go's encoding/json, and so
// mark3labs/mcp-go, matches struct keys with simple Unicode case folding and
// keeps the last duplicate. So at those levels it refuses any two keys equal
// under strings.EqualFold (exact duplicates too), and any key that folds to
// one the bridge reads (substrateMCPJudgedKeys) but is not byte-exact:
// Method, paramſ (U+017F), a Kelvin sign (U+212A) and so on. Keys deeper
// down, inside arguments, are part of the arguments the verdict reads, so
// they need no rule here.
func substrateMCPStrictKeys(raw []byte) error {
	env, err := substrateMCPCheckKeys(raw, "params")
	if err != nil || env["params"] == nil {
		return err
	}
	params, err := substrateMCPCheckKeys(env["params"], "argument", "context")
	if err != nil {
		return err
	}
	for _, k := range []string{"argument", "context"} {
		if params[k] != nil {
			if _, err := substrateMCPCheckKeys(params[k]); err != nil {
				return err
			}
		}
	}
	return nil
}

// substrateMCPCheckKeys checks one object's keys and returns the values of
// the named children. A value that is not an object has no keys to check.
func substrateMCPCheckKeys(raw []byte, children ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil
	}
	out := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := t.(string)
		f := substrateMCPFold(k)
		if seen[f] {
			return nil, fmt.Errorf("%w: duplicate key %q", errSubstrateMCPAmbiguous, k)
		}
		seen[f] = true
		if exact, judged := substrateMCPJudgedKeys[f]; judged && k != exact {
			return nil, fmt.Errorf("%w: key %q is not %q", errSubstrateMCPAmbiguous, k, exact)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		if slices.Contains(children, k) {
			out[k] = val
		}
	}
	return out, nil
}

// substrateMCPFold gives one spelling per strings.EqualFold class: each rune
// becomes the smallest rune of its unicode.SimpleFold orbit.
func substrateMCPFold(k string) string {
	var sb strings.Builder
	for _, r := range k {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			low = min(low, f)
		}
		sb.WriteRune(low)
	}
	return sb.String()
}

// substrateMCPPrefixID reads an oversize message's id from its bounded
// prefix: a string or number id, nil when it is not in the prefix or is
// given twice, and whether the prefix shows a response (result or error) or
// a request (method). A prefix that shows both is neither.
func substrateMCPPrefixID(prefix []byte) (id any, response, request bool) {
	dec := json.NewDecoder(bytes.NewReader(prefix))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false, false
	}
	var found any
	ids := 0
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			break
		}
		switch k, _ := t.(string); k {
		case "id":
			ids++
			if dec.Decode(&found) != nil {
				ids = 0
			}
			continue
		case "result", "error":
			response = true
		case "method":
			request = true
		}
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			break
		}
	}
	if response && request {
		return nil, false, false
	}
	if ids == 1 {
		switch found.(type) {
		case string, json.Number:
			id = found
		}
	}
	return id, response, request
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
