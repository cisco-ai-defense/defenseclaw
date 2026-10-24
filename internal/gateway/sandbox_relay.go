// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

// Relayed sandbox calls on a managed host. A user's sandbox daemon has no
// guardrails of its own: it forwards each hook, notify, inspect and OTLP
// post its sandboxes make to the managed gateway's hook socket, unchanged
// in body and with an allowlist of headers (sandboxrelay.ForwardHeaders),
// naming the registration the sandbox was created under. The socket's
// kernel-verified peer is the authority; the registration is only a lookup
// key among that peer's own registrations.
//
// The sandbox authority admits a relayed call (sandboxRelayAdmit: the
// caller's own live registration, its connector, decide, the subject key,
// the harness version, no files header, a due re-match) and answers the
// caller's profile and policy generation. The relay then rebuilds the
// sandbox request context from the registration alone (never from the body
// or a header): the binding the existing sandbox handling keys on (action
// mode, the fixed sandbox HOME, per-sandbox session state, the image's hook
// contract and harness version, the Codex SessionStart branch), the route
// class, the sandbox user, the relay-verified registration (which gives the
// guardrail profile the peer's verified subject) and the guardrail profile.
// The connector's ordinary handler then answers. Its verdict, which the
// local ingress would hand to the in-process sandbox manager, goes into a
// request-scoped sink instead and travels back to the daemon in the
// X-DefenseClaw-Sandbox-Decision trailer.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// sandboxRelayRoute is one relayed route: its class, the connector its path
// names (hook and notify; "" where the registration names it), the path
// the handler serves on a local sandbox ingress, and that handler.
type sandboxRelayRoute struct {
	class     sandboxauth.Route
	connector string
	native    string
	handler   http.HandlerFunc
}

// sandboxRelayPrefixes are the hook-socket path prefixes the relay serves.
var sandboxRelayPrefixes = [...]string{
	sandboxrelay.PathHookPrefix, sandboxrelay.PathNotifyPrefix, sandboxrelay.PathInspectPrefix, sandboxrelay.PathOTLPPrefix,
}

// registerSandboxRelayRoutes mounts the relayed routes on the hook-socket
// mux. The handler serves exact paths only (sandboxRelayRouteTable).
func (a *APIServer) registerSandboxRelayRoutes(mux *http.ServeMux) {
	relay := a.sandboxRelayHandler()
	for _, prefix := range sandboxRelayPrefixes {
		mux.Handle(prefix, relay)
	}
}

// sandboxRelayRouteTable maps every relayed path onto its route: the hook
// route of each builtin connector with a hook handler, Codex's notify
// route, the inspect endpoints and the OTLP signals. Paths are exact, so a
// connector alias, an extra segment or an encoded path is not served. Plugin
// connectors are excluded: a sandbox runs a reviewed builtin harness.
func (a *APIServer) sandboxRelayRouteTable() map[string]sandboxRelayRoute {
	routes := make(map[string]sandboxRelayRoute)
	reg := a.connectorRegistry
	if reg == nil {
		reg = sharedDefaultRegistry()
	}
	for _, name := range reg.Names() {
		if name != sandboxauth.CanonicalConnector(name) || !connector.IsKnownBuiltinConnector(name) {
			continue
		}
		conn, ok := reg.Get(name)
		if !ok {
			continue
		}
		if endpoint, ok := conn.(connector.HookEndpoint); ok && endpoint.HookAPIPath() != "" {
			if factory, registered := connectorHookHandlerByName[name]; registered {
				routes[sandboxrelay.PathHookPrefix+name] = sandboxRelayRoute{
					class: sandboxauth.RouteHook, connector: name, native: endpoint.HookAPIPath(), handler: factory(a),
				}
			}
		}
		if endpoint, ok := conn.(connector.NotifyEndpoint); ok && name == "codex" && endpoint.NotifyAPIPath() != "" {
			routes[sandboxrelay.PathNotifyPrefix+name] = sandboxRelayRoute{
				class: sandboxauth.RouteNotify, connector: name, native: endpoint.NotifyAPIPath(), handler: a.handleCodexNotify,
			}
		}
	}
	for kind, h := range map[string]http.HandlerFunc{
		"tool": a.handleInspectTool, "request": a.handleInspectRequest,
		"response": a.handleInspectResponse, "tool-response": a.handleInspectToolResponse,
	} {
		routes[sandboxrelay.PathInspectPrefix+kind] = sandboxRelayRoute{class: sandboxauth.RouteInspect, native: "/api/v1/inspect/" + kind, handler: h}
	}
	a.addSandboxRelayOTLPRoutes(routes)
	return routes
}

// sandboxRelayState is what a relayed request carries beyond its rebuilt
// binding and the relay-verified registration. Only the relay handler
// creates one.
type sandboxRelayState struct {
	registrationID string
	tamperTier     string
	sink           *sandboxRelayDecisionSink
	// reg is the registration sandboxRelayAdmit admitted: the gateway's
	// unblock lookup of the call (sandboxRelayUnblock) reads its saved
	// decisions and floor.
	reg sandboxreg.Registration
	// egressRefusals are the daemon's untold refusals of the sandbox the
	// call carried (sandboxrelay.EgressRefusalsHeader), handed out once
	// (takeEgressRefusals).
	egressMu       sync.Mutex
	egressRefusals []SandboxEgressRefusal
}

// takeEgressRefusals hands out the refusals the call carried, once, and
// marks the answer as telling the agent of them (the trailer's
// egress_told), so the daemon marks them told.
func (s *sandboxRelayState) takeEgressRefusals() []SandboxEgressRefusal {
	s.egressMu.Lock()
	out := s.egressRefusals
	s.egressRefusals = nil
	s.egressMu.Unlock()
	if len(out) > 0 {
		s.sink.markEgressTold()
	}
	return out
}

// sandboxRelayEgressRefusals reads the refusals a relayed hook call
// carries: one EgressRefusalsHeader value, or none (several are ignored).
func sandboxRelayEgressRefusals(h http.Header) []SandboxEgressRefusal {
	values := h.Values(sandboxrelay.EgressRefusalsHeader)
	if len(values) != 1 {
		return nil
	}
	wire := sandboxrelay.ParseEgressRefusals(values[0])
	if len(wire) == 0 {
		return nil
	}
	out := make([]SandboxEgressRefusal, 0, len(wire))
	for _, r := range wire {
		out = append(out, SandboxEgressRefusal{Host: r.Host, Port: r.Port, Category: r.Category, What: r.What, Remedy: r.Remedy,
			Cut: r.Cut, Sent: r.Sent, Note: r.Note})
	}
	return out
}

// sandboxRelayWireRefusals is refusals as the relay carries them.
func sandboxRelayWireRefusals(refusals []SandboxEgressRefusal) []sandboxrelay.EgressRefusal {
	out := make([]sandboxrelay.EgressRefusal, 0, len(refusals))
	for _, r := range refusals {
		out = append(out, sandboxrelay.EgressRefusal{Host: r.Host, Port: r.Port, Category: r.Category, What: r.What, Remedy: r.Remedy,
			Cut: r.Cut, Sent: r.Sent, Note: r.Note})
	}
	return out
}

type sandboxRelayStateKey struct{}

func sandboxRelayStateFrom(ctx context.Context) *sandboxRelayState {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(sandboxRelayStateKey{}).(*sandboxRelayState)
	return state
}

// sandboxRelayBinding is the binding a relayed call acts under, from the
// registration only. Managed sandboxes are copy-only (SPEC D2), so it
// grants no host filesystem access whatever the registration says.
func sandboxRelayBinding(reg sandboxreg.Registration, class sandboxauth.Route) sandboxauth.Binding {
	return sandboxauth.Binding{
		ID:             reg.BindingID,
		SandboxID:      reg.SandboxID,
		SandboxName:    reg.SandboxName,
		Connector:      reg.Connector,
		AgentVersion:   reg.HarnessVersion,
		HookContractID: reg.HookContract,
		Routes:         []sandboxauth.Route{class},
		Workdir:        sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
		HostUser:       sandboxauth.HostUser{UID: strconv.Itoa(reg.UID), Name: reg.UserName},
		CreatedAt:      reg.CreatedAt,
		RegistrationID: reg.ID,
	}
}

// sandboxRelayContext rebuilds a relayed call's sandbox request context
// from reg, the registration sandboxRelayAdmit admitted. It carries reg as
// the relay-verified registration, which together with the request's
// kernel-verified peer is what profileRequestSubject and
// isRelayedSandboxRequest accept. What the hook socket's outer layers
// adopted from the caller's headers (a trace id for the audit envelope,
// claimed session facts) is dropped: a local sandbox ingress never adopts
// either from a sandbox. So is the enrollment exemption of the caller's
// host hooks, which never covers a sandbox.
func sandboxRelayContext(ctx context.Context, reg sandboxreg.Registration, class sandboxauth.Route) (context.Context, sandboxauth.Binding, *sandboxRelayState) {
	binding := sandboxRelayBinding(reg, class)
	ctx = withSandboxRelayRegistration(ctx, reg)
	ctx = context.WithValue(ctx, traceIDCtxKey{}, "")
	ctx = context.WithValue(ctx, claimedSessionContextKey{}, nil)
	ctx = context.WithValue(ctx, enterpriseExemptUserContextKey{}, false)
	ctx = sandboxauth.WithRequest(ctx, binding, sandboxauth.NewFSView(binding, nil))
	state := &sandboxRelayState{registrationID: reg.ID, tamperTier: reg.TamperTier, sink: &sandboxRelayDecisionSink{}, reg: reg}
	ctx = context.WithValue(ctx, sandboxRelayStateKey{}, state)
	ctx = withSandboxIngressRoute(ctx, class)
	ctx, _ = withSandboxHookOutcome(ctx)
	switch class {
	case sandboxauth.RouteHook, sandboxauth.RouteNotify:
		ctx = withAuthenticatedHookConnector(ctx, binding.Connector)
	case sandboxauth.RouteInspect:
		ctx = withAuthenticatedInspectConnector(ctx, binding.Connector)
	}
	return ctx, binding, state
}

// sandboxRelayScrubHeaders drops what a relayed call may not carry into a
// handler: credentials, cookies, identity, connector and session-fact
// claims, client refusals, client request ids and every sandbox relay
// header. The daemon's allowlist already leaves them out; this holds for a
// caller that calls the hook socket directly. X-DefenseClaw-Client stays
// (the CSRF check passed on it) and the agent surface is the relay's own
// value: a sandbox runs its harness's CLI.
func sandboxRelayScrubHeaders(h http.Header) {
	for _, name := range sandboxIdentityHeaders {
		h.Del(name)
	}
	client := http.CanonicalHeaderKey(sandboxrelay.ClientHeader)
	for _, name := range sandboxrelay.DroppedHeaders {
		if http.CanonicalHeaderKey(name) != client {
			h.Del(name)
		}
	}
	prefix := strings.ToLower(sandboxrelay.SandboxHeaderPrefix)
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), prefix) {
			delete(h, name)
		}
	}
	h.Set(sandboxrelay.AgentSurfaceHeader, sandboxrelay.AgentSurfaceValue)
}

// sandboxRelayHandler serves the relayed hook, notify, inspect and OTLP
// routes of the hook socket. The socket's peer authorization (uid 0
// refusal, the route class's budget, the peer's verified subject), CSRF
// check and body limit run before it; sandboxRelayAdmit runs first in it.
func (a *APIServer) sandboxRelayHandler() http.Handler {
	return a.sandboxRelayServe(a.sandboxRelayRouteTable())
}

// sandboxRelayServe is sandboxRelayHandler for the route table routes.
func (a *APIServer) sandboxRelayServe(routes map[string]sandboxRelayRoute) http.Handler {
	var registry *AgentRegistry
	if a.scannerCfg != nil {
		registry = InstallSharedAgentRegistry(a.scannerCfg.Agent.ID, a.scannerCfg.Agent.Name)
	} else {
		registry = InstallSharedAgentRegistry("", "")
	}
	correlate := CorrelationMiddleware(registry)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeSandboxIngressError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		route, ok := routes[r.URL.Path]
		if !ok || r.URL.RawPath != "" {
			writeSandboxIngressError(w, http.StatusNotFound, "not found")
			return
		}
		if len(r.Header.Values(sandboxrelay.RegistrationHeader)) > 1 {
			// One registration per call: never pick one of several.
			writeSandboxReason(w, sandboxrelay.ReasonRegistrationUnknown, sandboxTextRegistrationUnkn)
			return
		}
		ctx, reg, ok := a.sandboxRelayAdmit(w, r, route.connector)
		if !ok {
			return
		}
		if strings.TrimSpace(reg.BindingID) == "" || strings.TrimSpace(reg.SandboxName) == "" {
			// A live registration names the sandbox it was bound to. Without
			// it the call would act in no sandbox's state.
			w.Header().Del(sandboxrelay.ProfileHeader)
			w.Header().Del(sandboxrelay.GenerationHeader)
			writeSandboxReason(w, sandboxrelay.ReasonNotAllowed, sandboxTextNotBound)
			return
		}
		ctx, binding, state := sandboxRelayContext(ctx, reg, route.class)
		if route.class == sandboxauth.RouteHook {
			// Read before the scrub drops every sandbox relay header.
			state.egressRefusals = sandboxRelayEgressRefusals(r.Header)
		}
		r = r.WithContext(ctx)
		sandboxRelayScrubHeaders(r.Header)
		// The handler sees the path it serves on a local sandbox ingress.
		u := *r.URL
		u.Path, u.RawPath = route.native, ""
		r.URL = &u
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := PromoteSessionIfAuthenticated(r.Context())
			// Session promotion re-resolves the agent identity from the
			// registry; restore the registration's user on top of it.
			ctx = contextWithSandboxUser(ctx, binding)
			ctx = a.withGuardrailProfileDecision(ctx, binding.Connector)
			r = r.WithContext(ctx)
			if route.class == sandboxauth.RouteOTLP {
				a.serveSandboxRelayOTLP(w, r, route, binding)
				return
			}
			a.serveSandboxRelayCall(w, r, route, state)
		})
		sandboxRequestIDMiddleware(correlate(inner)).ServeHTTP(w, r)
	})
}

// serveSandboxRelayCall answers a relayed hook, notify or inspect call with
// the route's handler, its status and body unchanged, and the verdict as
// the declared trailer of a 2xx answer. sandboxRelayAdmit already set the
// profile and generation headers.
func (a *APIServer) serveSandboxRelayCall(w http.ResponseWriter, r *http.Request, route sandboxRelayRoute, state *sandboxRelayState) {
	h := w.Header()
	// Declared before the handler writes: the server then frames the answer
	// chunked and sends the trailer after the body.
	h.Set("Trailer", sandboxrelay.DecisionTrailer)
	rw := &sandboxRelayResponseWriter{ResponseWriter: w}
	route.handler(rw, r)
	if status := rw.finalStatus(); status < 200 || status > 299 {
		return
	}
	if outcome, ok := r.Context().Value(sandboxHookOutcomeKey{}).(*sandboxHookOutcome); ok && outcome.failedClosed.Load() {
		state.sink.markFailedClosed()
	}
	if value, ok := state.sink.trailer(); ok {
		h.Set(sandboxrelay.DecisionTrailer, value)
	}
}

// sandboxRelayResponseWriter keeps a relayed answer's status and never lets
// it carry Content-Length: Go drops a declared trailer silently from an
// answer with one.
type sandboxRelayResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *sandboxRelayResponseWriter) WriteHeader(status int) {
	if w.status == 0 && status >= 200 {
		w.status = status
	}
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w *sandboxRelayResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
		w.Header().Del("Content-Length")
	}
	return w.ResponseWriter.Write(p)
}

func (w *sandboxRelayResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *sandboxRelayResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *sandboxRelayResponseWriter) finalStatus() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// sandboxRelayDecisionSink receives the verdict observeSandboxHookDecision
// hands a local sandbox manager. The relay returns it in the trailer.
type sandboxRelayDecisionSink struct {
	mu           sync.Mutex
	decision     *sandboxrelay.HookDecision
	failedClosed bool
	// egressTold: the answer told the agent of the call's refusals.
	egressTold bool
}

func (s *sandboxRelayDecisionSink) markFailedClosed() {
	s.mu.Lock()
	s.failedClosed = true
	s.mu.Unlock()
}

func (s *sandboxRelayDecisionSink) markEgressTold() {
	s.mu.Lock()
	s.egressTold = true
	s.mu.Unlock()
}

func sandboxRelayDecisionSinkFrom(ctx context.Context) *sandboxRelayDecisionSink {
	if state := sandboxRelayStateFrom(ctx); state != nil {
		return state.sink
	}
	return nil
}

// put keeps d's verdict for the trailer. d carries the call's content
// reference instead of its tool input (observeSandboxHookDecision).
func (s *sandboxRelayDecisionSink) put(d SandboxHookDecision) {
	out := sandboxrelay.HookDecision{
		V:            sandboxrelay.WireVersion,
		Event:        d.Event,
		Tool:         d.Tool,
		ToolUseID:    d.ToolUseID,
		SessionID:    d.SessionID,
		CallRef:      d.CallRef,
		ResultStatus: d.ResultStatus,
		Action:       d.Action,
		WouldBlock:   d.WouldBlock,
		Severity:     d.Severity,
		Reason:       d.Reason,
		ModelError:   d.ModelError,
		ModelStatus:  d.ModelStatus,
		AlertsLow:    d.AlertsLow,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decision = &out
}

// trailer is the sink's verdict as the trailer value, or false when the
// handler recorded none.
func (s *sandboxRelayDecisionSink) trailer() (string, bool) {
	s.mu.Lock()
	d, told, failedClosed := s.decision, s.egressTold, s.failedClosed
	s.mu.Unlock()
	if d == nil {
		return "", false
	}
	out := *d
	out.EgressTold = told
	out.FailedClosed = failedClosed
	return encodeSandboxRelayDecision(out)
}

// encodeSandboxRelayDecision is d as trailer JSON of at most
// sandboxrelay.MaxHookDecisionBytes. Every string is made header-safe and
// cut to its bound; while the whole does not fit, the field whose JSON form
// (escapes included) is longest is halved. The call reference and the
// action are never halved: a cut reference pairs no call, so a reference
// that is not header-safe or over its bound, or one that still does not
// fit once every other string is empty, is left out instead.
func encodeSandboxRelayDecision(d sandboxrelay.HookDecision) (string, bool) {
	cuttable := []*string{&d.Event, &d.Tool, &d.ToolUseID, &d.SessionID, &d.ResultStatus,
		&d.Severity, &d.Reason, &d.ModelError}
	for _, f := range cuttable {
		limit := sandboxrelay.MaxHookDecisionStringBytes
		if f == &d.Reason {
			limit = sandboxrelay.MaxHookDecisionReasonBytes
		}
		*f = sandboxRelayHeaderText(*f, limit)
	}
	// The action is one of the gateway's own verdict words.
	d.Action = sandboxRelayHeaderText(d.Action, sandboxrelay.MaxHookDecisionStringBytes)
	if s := sandboxRelayHeaderText(d.CallRef, len(d.CallRef)); s != d.CallRef || len(s) > sandboxrelay.MaxHookDecisionStringBytes {
		d.CallRef = ""
	}
	for {
		raw, err := json.Marshal(d)
		if err != nil {
			return "", false
		}
		if len(raw) <= sandboxrelay.MaxHookDecisionBytes {
			return string(raw), true
		}
		var longest *string
		size := 0
		for _, f := range cuttable {
			if n := sandboxRelayJSONLen(*f); *f != "" && n > size {
				longest, size = f, n
			}
		}
		if longest == nil {
			if d.CallRef == "" {
				return "", false
			}
			d.CallRef = ""
			continue
		}
		*longest = truncateToRuneBoundary(*longest, len(*longest)/2)
	}
}

// sandboxRelayJSONLen is the length of s as a JSON string.
func sandboxRelayJSONLen(s string) int {
	raw, err := json.Marshal(s)
	if err != nil {
		return len(s)
	}
	return len(raw)
}

// sandboxRelayHeaderText is s with control characters turned into spaces,
// cut to at most limit bytes on a rune boundary.
func sandboxRelayHeaderText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	return truncateToRuneBoundary(strings.TrimSpace(s), limit)
}
