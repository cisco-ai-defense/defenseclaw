// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
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
// gets none.
func (a *APIServer) recordHookCallerGone(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.logger == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() ||
		r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/hook") {
		return
	}
	connectorName, ok := a.hookTokenScopeForPath(r.URL.Path)
	if !ok {
		return
	}
	limit := int64(apiRequestBodyMaxBytes)
	if n, err := strconv.ParseInt(r.Header.Get(hookexec.HookDeliveryPayloadBytesHeader), 10, 64); err == nil && n > 0 && n < limit {
		limit = n
	}
	var payload map[string]interface{}
	if r.Body != nil {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(hookCallerGoneReadWait))
		_ = json.NewDecoder(io.LimitReader(r.Body, limit)).Decode(&payload)
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
	ctx = audit.ContextWithEnvelope(ctx, env)
	extra := map[string]string{"hook_client_left": "before_admission"}
	if id := hookCallerGoneString(payload, "tool_use_id", "toolUseId", "tool_call_id", "toolCallId"); id != "" {
		extra["tool_use_id"] = id
	}
	if err := a.logConnectorHookAuditEnvelope(ctx, HookAuditEnvelope{
		Connector: connectorName,
		Event:     event,
		Action:    hookActionUnconfirmed,
		Reason:    hookexec.ManagedGatewayNoAnswerReason,
		Mode:      a.agentHookMode(ctx, connectorName),
		Extra:     extra,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook call whose client left before admission not audited connector=%s: %v\n",
			connectorName, err)
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
