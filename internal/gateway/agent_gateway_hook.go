// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The agent-gateway hook route (issue #1394): /api/v1/agent-gateway/hook.
//
// Off by default: with connectors.agent_gateway.enabled false the route is
// not registered at all. On a per-user install it is served on the TCP API
// with the gateway token, like every hook route, and an identity claim in
// the body is never honoured. On a managed device it is served only on the
// hook socket, where the kernel names the caller: a trusted connector's
// service account (issue #1392) or an enrolled user calling for
// themselves. The body is the closed contract of
// schemas/connectors/agent-gateway-hook.json; it is mapped onto the generic
// hook vocabulary and evaluated by the same handler every connector hook
// uses, so rules, chains, correlation and lineage behave the same.

// agentGatewayEnabled reports connectors.agent_gateway.enabled from the
// configuration the gateway started with (the route is restart-required).
func (a *APIServer) agentGatewayEnabled() bool {
	cfg := a.scannerCfg
	return a != nil && cfg != nil && !cfg.SecureClientIntegration() && cfg.Connectors.AgentGateway.Enabled
}

// registerAgentGatewayRoute registers the route on mux when it is enabled:
// on a managed device on the hook socket only (hookSocket), elsewhere on
// the TCP API only.
func (a *APIServer) registerAgentGatewayRoute(mux *http.ServeMux, hookSocket bool, wrap ...func(http.Handler) http.Handler) {
	if !a.agentGatewayEnabled() {
		return
	}
	if managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) != hookSocket {
		return
	}
	h := http.Handler(a.handleAgentGatewayHook())
	for _, mw := range wrap {
		if mw != nil {
			h = mw(h)
		}
	}
	mux.Handle(connector.AgentGatewayHookPath, h)
	fmt.Fprintf(os.Stderr, "[api] registered hook endpoint: %s → %s\n", connector.AgentGatewayConnectorName, connector.AgentGatewayHookPath)
}

// agentGatewayIgnoredUntrusted is the audit value of an acting_for or
// root_session_id the route did not honour.
const agentGatewayIgnoredUntrusted = "untrusted_caller"

type agentGatewayAuditKey struct{}

// agentGatewayAudit is the route's local audit context.
type agentGatewayAudit struct {
	label               string
	actingForIgnored    bool
	rootSessionIgnored  bool
	rootSessionHonoured string
	// rootChain is set for an honoured root_session_id; the chain lane
	// fills it in when guardrail.chains.root_scope evaluates the root
	// window (agent_gateway_root_chain.go).
	rootChain *agentGatewayRootChain
}

func withAgentGatewayAudit(ctx context.Context, audit agentGatewayAudit) context.Context {
	return context.WithValue(ctx, agentGatewayAuditKey{}, audit)
}

// agentGatewayAuditExtra are the route's local audit fields: the instance
// label, the person and connector of a trusted connector's call, and the
// identity fields the route ignored.
func agentGatewayAuditExtra(ctx context.Context) map[string]string {
	extra := actingForAuditExtra(ctx)
	audit, ok := ctx.Value(agentGatewayAuditKey{}).(agentGatewayAudit)
	if !ok {
		return extra
	}
	if extra == nil {
		extra = map[string]string{}
	}
	if audit.label != "" {
		extra["connector_instance_label"] = audit.label
	}
	if audit.actingForIgnored {
		extra["acting_for_ignored"] = agentGatewayIgnoredUntrusted
	}
	if audit.rootSessionIgnored {
		extra["root_session_ignored"] = agentGatewayIgnoredUntrusted
	}
	if audit.rootSessionHonoured != "" {
		extra["root_session_id"] = audit.rootSessionHonoured
	}
	if audit.rootChain != nil && audit.rootChain.evaluated {
		// guardrail.chains.root_scope evaluated the root window too (#1391).
		extra["chain_scope"] = "session,root"
		if len(audit.rootChain.chainIDs) != 0 {
			extra["root_chain_ids"] = strings.Join(audit.rootChain.chainIDs, ",")
		}
	}
	return extra
}

func (a *APIServer) handleAgentGatewayHook() http.HandlerFunc {
	name := connector.AgentGatewayConnectorName
	unified := a.handleUnifiedConnectorHook(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			a.recordConnectorHookRejection(r.Context(), name, "unknown", "method", 0)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, apiRequestBodyMaxBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				a.recordConnectorHookRejection(r.Context(), name, "unknown", "body_too_large", apiRequestBodyMaxBytes+1)
				a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
					"error": "request body too large", "reason": hookexec.MalformedHookPayloadReason,
				})
				return
			}
			a.recordConnectorHookRejection(r.Context(), name, "unknown", "invalid_json", 0)
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body", "reason": hookexec.MalformedHookPayloadReason})
			return
		}
		ev, err := connector.DecodeAgentGatewayEvent(body)
		if err != nil {
			code := "invalid_event"
			var contract *connector.AgentGatewayContractError
			if errors.As(err, &contract) {
				code = contract.Reason
			}
			a.recordConnectorHookRejection(r.Context(), name, "unknown", code, int64(len(body)))
			a.writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "agent-gateway event refused: " + err.Error(), "code": code, "reason": hookexec.MalformedHookPayloadReason,
			})
			return
		}
		ctx, refusal, audit := a.agentGatewayIdentity(r.Context(), ev, time.Now())
		audit.label = a.agentGatewayInstanceLabel(ctx)
		ctx = withAgentGatewayAudit(ctx, audit)
		if refusal.refused() {
			a.recordActingForRefusal(ctx, ev, refusal)
			a.writeJSON(w, http.StatusForbidden, map[string]string{
				"action": "block", "error": "forbidden", "reason": refusal.Code,
			})
			return
		}
		payload, err := connector.AgentGatewayHookPayload(ev)
		if err != nil {
			code := "invalid_event"
			var contract *connector.AgentGatewayContractError
			if errors.As(err, &contract) {
				code = contract.Reason
			}
			a.recordConnectorHookRejection(ctx, name, ev.Event, code, int64(len(body)))
			a.writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "agent-gateway event refused: " + err.Error(), "code": code, "reason": hookexec.MalformedHookPayloadReason,
			})
			return
		}
		mapped, err := json.Marshal(payload)
		if err != nil {
			a.recordConnectorHookRejection(ctx, name, ev.Event, "invalid_event", int64(len(body)))
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent-gateway event refused", "reason": hookexec.MalformedHookPayloadReason})
			return
		}
		next := r.WithContext(withAgentGatewayHookCaller(ctx))
		next.Body = io.NopCloser(bytes.NewReader(mapped))
		next.ContentLength = int64(len(mapped))
		next.Header = r.Header.Clone()
		next.Header.Set("Content-Length", strconv.Itoa(len(mapped)))
		unified(w, next)
	}
}

// withAgentGatewayHookCaller marks the request as authenticated for the
// agent-gateway connector, as every connector hook route marks its caller.
// Only an authenticated caller reaches the route: the gateway token on a
// per-user install, the kernel-verified hook-socket peer on a managed device
// (managedHookPeerAuth marks it already). With the mark the evaluator applies
// the projections of an authenticated hook: an mcp__<server>__<tool> name is
// judged by its action tool, so a call gets the native hook's decision on
// the same arguments (rel-1-0-6:GAP-0131). A request another connector
// authenticated, or a sandbox relay, keeps its own mark.
func withAgentGatewayHookCaller(ctx context.Context) context.Context {
	if authenticatedHookConnector(ctx) != "" || isSandboxHookRequest(ctx) {
		return ctx
	}
	return withAuthenticatedHookConnector(ctx, connector.AgentGatewayConnectorName)
}

// agentGatewayInstanceLabel is the label of the calling gateway: the trusted
// connector's name, else connectors.agent_gateway.instance_name.
func (a *APIServer) agentGatewayInstanceLabel(ctx context.Context) string {
	if af, ok := actingForFromContext(ctx); ok {
		return af.Connector
	}
	if a.scannerCfg == nil {
		return ""
	}
	return strings.TrimSpace(a.scannerCfg.Connectors.AgentGateway.InstanceName)
}

// agentGatewayIdentity decides the identity fields of one event. A trusted
// connector's service account on the hook socket must name the person it
// acts for; anyone else's acting_for and root_session_id are ignored and
// audited, and never change the verdict.
func (a *APIServer) agentGatewayIdentity(ctx context.Context, ev connector.AgentGatewayEvent, now time.Time) (context.Context, actingForRefusal, agentGatewayAudit) {
	var audit agentGatewayAudit
	if peer, eligible := actingForCallerEligible(ctx); eligible {
		if entry, listed := trustedConnectorForAccount(strconv.Itoa(peer.UID)); listed {
			if ev.ActingFor == nil {
				return ctx, actingForRefusal{Code: actingForRefusedRequired, Cause: "absent"}, audit
			}
			if trustedConnectorCallerIsAdmin(ctx, peer) {
				// Checked on every call, not only at the refresh.
				return withActingForRefusalConnector(ctx, entry.Name, ev.ActingFor.User),
					actingForRefusal{Code: actingForRefusedConnectorDisabled, Cause: "account_is_administrator"}, audit
			}
			af, refusal := resolveActingFor(entry, ev.ActingFor.User, now)
			if refusal.refused() {
				return withActingForRefusalConnector(ctx, entry.Name, ev.ActingFor.User), refusal, audit
			}
			if !pinActingForSession(entry.AccountID, "session\x00"+ev.SessionID, af.Person.UserID, now) {
				return withActingForRefusalConnector(ctx, entry.Name, ev.ActingFor.User),
					actingForRefusal{Code: actingForRefusedSessionMismatch, Cause: "session_id"}, audit
			}
			ctx = attachActingFor(ctx, af)
			if ev.RootSessionID != "" {
				if !pinActingForSession(entry.AccountID, "root\x00"+ev.RootSessionID, af.Person.UserID, now) {
					return ctx, actingForRefusal{Code: actingForRefusedSessionMismatch, Cause: "root_session_id"}, audit
				}
				audit.rootSessionHonoured = ev.RootSessionID
				audit.rootChain = &agentGatewayRootChain{}
			}
			return ctx, actingForRefusal{}, audit
		}
		if ev.ActingFor != nil && trustedConnectorStateNow().honoured && trustedConnectorStateNow().unresolved {
			// An entry's account has not resolved yet; this caller may be it.
			return ctx, actingForRefusal{Code: actingForRefusedConnectorDisabled, Cause: "account_unresolved"}, audit
		}
	}
	audit.actingForIgnored = ev.ActingFor != nil
	audit.rootSessionIgnored = ev.RootSessionID != ""
	return ctx, actingForRefusal{}, audit
}

// attachActingFor binds the person to the request: profile selection,
// agent ids, records and audit name the person; the verified subject and
// the hook peer stay the connector's service account.
func attachActingFor(ctx context.Context, af actingFor) context.Context {
	ctx = withActingFor(ctx, af)
	id := AgentIdentityFromContext(ctx)
	id.UserID, id.UserIDKind, id.UserName = af.Person.UserID, af.Person.IDKind, sanitizeLLMEventUser(af.Person.UserName)
	return ContextWithAgentIdentity(ctx, id)
}

type actingForRefusalConnectorKey struct{}

type actingForRefusalConnector struct{ name, user string }

func withActingForRefusalConnector(ctx context.Context, name, user string) context.Context {
	return context.WithValue(ctx, actingForRefusalConnectorKey{}, actingForRefusalConnector{name: name, user: user})
}

// recordActingForRefusal writes the local audit row and the rejection
// metric of a refused acting_for (event identity.acting_for.refused). The
// metric carries the code only; the local audit also names the connector
// and the person asked for.
func (a *APIServer) recordActingForRefusal(ctx context.Context, ev connector.AgentGatewayEvent, refusal actingForRefusal) {
	name := connector.AgentGatewayConnectorName
	extra := map[string]string{"event": "identity.acting_for.refused", "acting_for_refusal": refusal.Cause}
	if who, ok := ctx.Value(actingForRefusalConnectorKey{}).(actingForRefusalConnector); ok {
		extra["trusted_connector"] = who.name
		extra["acting_for_user"] = sanitizeLLMEventUser(who.user)
	}
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		extra["trusted_connector_account_id"] = strconv.Itoa(peer.UID)
		if entry, listed := trustedConnectorForAccount(strconv.Itoa(peer.UID)); listed && extra["trusted_connector"] == "" {
			extra["trusted_connector"] = entry.Name
		}
	}
	fmt.Fprintf(os.Stderr, "[identity] agent-gateway acting_for refused connector=%q reason=%s cause=%s\n",
		extra["trusted_connector"], refusal.Code, refusal.Cause)
	a.recordHookRejectionMetricsV8(ctx, name, ev.Event, refusal.Code)
	if a.logger != nil {
		_ = a.logConnectorHookAuditEnvelope(ctx, HookAuditEnvelope{
			Connector: name, Event: ev.Event, Result: "refused", Action: "block", Reason: refusal.Code, Extra: extra,
		})
	}
}
