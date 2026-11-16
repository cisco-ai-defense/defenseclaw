// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// hookCallerGoneReadWait bounds the read of a request whose client has left:
// its body is whatever the socket already holds.
const hookCallerGoneReadWait = 250 * time.Millisecond

// hookCallerLeftKey marks a request admitHookCaller did not admit because
// its client had left.
type hookCallerLeftKey struct{}

func withHookCallerLeft(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), hookCallerLeftKey{}, true))
}

// hookCallerLeft reports a request whose client left before admission.
func hookCallerLeft(r *http.Request) bool {
	left, _ := r.Context().Value(hookCallerLeftKey{}).(bool)
	return left
}

// hookCallerShedKey marks a request admitHookCaller refused with a 429: the
// gateway answered it, so its hook retries and, once its budget ends, denies
// the tool call itself without the gateway ever having decided it.
type hookCallerShedKey struct{}

// hookCallerShed reports a hook call the admission limits refused with a 429.
func hookCallerShed(r *http.Request) bool {
	shed, _ := r.Context().Value(hookCallerShedKey{}).(bool)
	return shed
}

// hookCallerBodyLimit is the most of a request body the gateway reads to name
// a call it does not serve: the payload size the hook announced, else the API
// body limit.
func hookCallerBodyLimit(r *http.Request) int64 {
	limit := int64(apiRequestBodyMaxBytes)
	if n, err := strconv.ParseInt(r.Header.Get(hookexec.HookDeliveryPayloadBytesHeader), 10, 64); err == nil && n > 0 && n < limit {
		limit = n
	}
	return limit
}

// shedHookRequest returns the request admitHookCaller hands back when it
// answers 429: for a managed hook call it holds the body the hook already
// sent (what the socket holds within hookCallerGoneReadWait) and is marked
// shed, so the caller can audit the call by its tool ID. Called before the 429
// is written, since an unread body is discarded once the response starts.
// Any other request is returned as it is.
func (a *APIServer) shedHookRequest(w http.ResponseWriter, r *http.Request) *http.Request {
	if a == nil || a.logger == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() ||
		r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/hook") || r.Body == nil {
		return r
	}
	if _, ok := a.hookTokenScopeForPath(r.URL.Path); !ok {
		return r
	}
	control := http.NewResponseController(w)
	_ = control.SetReadDeadline(time.Now().Add(hookCallerGoneReadWait))
	data, _ := io.ReadAll(io.LimitReader(r.Body, hookCallerBodyLimit(r)))
	_ = control.SetReadDeadline(time.Time{})
	shed := r.WithContext(context.WithValue(r.Context(), hookCallerShedKey{}, true))
	shed.Body = io.NopCloser(bytes.NewReader(data))
	return shed
}

// recordManagedPeerCallerGone audits a hook-socket call whose client left
// before admission only when the socket would have served it as an enrolled
// account's hook call: a refused process context, a call decide refuses and
// an exempt account's call (which has its own row type) get no
// connector-hook row. The kernel-verified peer in the context attributes it.
func (a *APIServer) recordManagedPeerCallerGone(w http.ResponseWriter, r *http.Request, authorizer *managedHookAuthorizer, peer managedHookPeer) {
	if authorizer == nil || hookexec.IsManagedProcessContextReason(r.Header.Get(hookexec.ClientRefusalHeader)) {
		return
	}
	connectorName, inspect := a.managedHookRouteScope(r)
	if inspect || connectorName == "" {
		return
	}
	if decision := authorizer.decide(peer, connectorName, r.Header.Get(hookexec.AgentSurfaceHeader)); !decision.Allow || decision.Exempt {
		return
	}
	a.recordHookCallerGone(w, r)
}

// recordUserScopedCallerGone audits a call authenticated by a per-user
// credential whose client left before admission under the identity the
// credential is bound to, never the X-DefenseClaw-User-* headers: a call
// whose headers name another account would have been refused, so it gets
// no row (bindUserScopedIdentity, GAP-0702).
func (a *APIServer) recordUserScopedCallerGone(w http.ResponseWriter, r *http.Request, identity string, mark func(context.Context) context.Context) {
	ctx := context.WithValue(r.Context(), verifiedUserScopedIdentityContextKey{}, identity)
	if mark != nil {
		ctx = mark(ctx)
	}
	bound, ok := bindUserScopedIdentity(r.WithContext(ctx), identity)
	if !ok {
		return
	}
	a.recordHookCallerGone(w, bound)
}

// recordHookCallerGone audits a managed hook call whose client left before
// the gateway admitted it (GAP-0286). During a gateway stall the calls queue
// on the hook socket; the native hook gives up at its answer deadline and
// answers its agent itself, so the gateway evaluates nothing when it gets to
// the call. The call still gets its one audit row: unconfirmed, with the
// no-answer reason, under the call's session and tool IDs, as a call whose
// answer the hook never took. A neutral lifecycle event is not a decision and
// gets none. A call the admission limits refused with a 429 (shed) is
// recorded the same way, labeled hook_shed: its hook denies it itself when its
// budget ends, and without this row the denied call has none (GAP-1029).
func (a *APIServer) recordHookCallerGone(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.logger == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() ||
		r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/hook") {
		return
	}
	connectorName, ok := a.hookTokenScopeForPath(r.URL.Path)
	if !ok {
		return
	}
	shed := hookCallerShed(r)
	if shed {
		// The 429 reaches the hook before this row is written, so its retry
		// is not held by the audit write.
		_ = http.NewResponseController(w).Flush()
	}
	var payload map[string]interface{}
	if r.Body != nil {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(hookCallerGoneReadWait))
		_ = json.NewDecoder(io.LimitReader(r.Body, hookCallerBodyLimit(r))).Decode(&payload)
	}
	event := ""
	if payload != nil {
		if name, reason := hookEventEnvelope(payload); reason == "" {
			event = name
		}
	}
	if event != "" && hookexec.NeutralLifecycleEvent(connectorName, event) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), agentHookPersistGrace)
	defer cancel()
	env := audit.EnvelopeFromContext(ctx)
	if env.SessionID == "" {
		env.SessionID = hookCallerGoneString(payload, "session_id", "sessionId", "conversation_id", "conversationId")
	}
	extra := map[string]string{"hook_client_left": "before_admission"}
	if shed {
		extra = map[string]string{"hook_shed": "admission_refused"}
	}
	shedKey := ""
	if id := hookCallerGoneString(payload, "tool_use_id", "toolUseId", "tool_call_id", "toolCallId"); id != "" {
		if shed {
			// The hook retries a refused call: one row names the call. The
			// session and tool id come from the agent, so the verified
			// account is part of the key: two accounts that send the same ids
			// are two calls, each with its own row.
			caller, _ := verifiedAuditCaller(ctx)
			shedKey = caller.IDKind + "\x00" + caller.ID + "\x00" + env.SessionID + "\x00" + id
			if !a.hookShed.first(shedKey) {
				return
			}
		}
		extra["tool_use_id"] = id
		// The row is found by its tool id like every other row of the call.
		if env.ToolID == "" {
			env.ToolID = id
		}
	}
	ctx = audit.ContextWithEnvelope(ctx, env)
	if err := a.logConnectorHookAuditEnvelope(ctx, HookAuditEnvelope{
		Connector: connectorName,
		Event:     event,
		Action:    hookActionUnconfirmed,
		Reason:    hookexec.ManagedGatewayNoAnswerReason,
		Mode:      a.agentHookMode(ctx, connectorName),
		Extra:     extra,
	}); err != nil {
		// A row that was not written is not remembered: the hook's retry of
		// the refused call is the next try.
		if shedKey != "" {
			a.hookShed.forget(shedKey)
		}
		fmt.Fprintf(os.Stderr, "[gateway] hook call whose client left before admission not audited connector=%s: %v\n",
			connectorName, err)
	}
}

// hookShedLedger remembers the calls a shed row was written for, so the
// retries of one refused call leave one row. Bounded: the oldest call is
// forgotten first.
type hookShedLedger struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
}

const hookShedLedgerCalls = 4096

// first reports whether key is new, and remembers it.
func (l *hookShedLedger) first(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[key]; ok {
		return false
	}
	if l.seen == nil {
		l.seen = make(map[string]struct{}, hookShedLedgerCalls)
	}
	if len(l.order) >= hookShedLedgerCalls {
		delete(l.seen, l.order[0])
		l.order = l.order[1:]
	}
	l.seen[key] = struct{}{}
	l.order = append(l.order, key)
	return true
}

// forget drops key, so a call whose row failed to persist is recorded by its
// next try.
func (l *hookShedLedger) forget(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[key]; !ok {
		return
	}
	delete(l.seen, key)
	for i, queued := range l.order {
		if queued == key {
			l.order = append(l.order[:i], l.order[i+1:]...)
			break
		}
	}
}

// hookCallerGoneString is the first string value of keys in payload.
func hookCallerGoneString(payload map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
