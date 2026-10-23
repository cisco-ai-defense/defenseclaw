// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/google/uuid"
)

const sandboxHookReceiptWindow = 15 * time.Second

// A sandbox relay buffers each request and response. It cannot use the native
// hook's full-duplex request-body receipt. Claude and Codex sandbox tool hooks
// instead acknowledge an offered answer with a second, authenticated call on
// their existing hook route. Older hooks ignore the additive receipt ID and
// keep an unconfirmed audit result after the bounded receipt window.
func (a *APIServer) wantsSandboxHookReceipt(ctx context.Context, connectorName, event string, resp agentHookResponse) bool {
	if a == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() ||
		(resp.Action != "allow" && resp.Action != "alert" && resp.Action != "confirm") ||
		(connectorName != "claudecode" && connectorName != "codex") ||
		!hookexec.DeliveryReceiptEvent(connectorName, event) {
		return false
	}
	_, ok := sandboxauth.FromContext(ctx)
	return ok
}

func sandboxHookReceiptID(raw []byte) (string, bool) {
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil || len(body) != 2 {
		return "", false
	}
	var id, result string
	if json.Unmarshal(body["delivery_receipt"], &id) != nil ||
		json.Unmarshal(body["result"], &result) != nil || result != "ack" {
		return "", false
	}
	return id, true
}

func (a *APIServer) handleSandboxHookReceipt(w http.ResponseWriter, r *http.Request, connectorName, id string) {
	binding, ok := sandboxauth.FromContext(r.Context())
	if !ok || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() ||
		binding.Connector != connectorName || uuid.Validate(id) != nil {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "sandbox hook receipt is not authorized"})
		return
	}
	path := filepath.Join(a.pendingHookDir(), id+".json")
	if !livePendingHooks.claim(path) {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sandbox hook receipt is still in progress"})
		return
	}
	defer livePendingHooks.release(path)
	info, err := os.Lstat(path)
	if err != nil {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "sandbox hook receipt is unavailable"})
		return
	}
	p, err := readPendingHookOccurrence(path, id, fs.FileInfoToDirEntry(info))
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sandbox hook receipt could not be read"})
		return
	}
	if p.SandboxReceipt == nil || p.Request.ConnectorName != connectorName ||
		p.SandboxReceipt.BindingID != binding.ID ||
		p.SandboxReceipt.RegistrationID != binding.RegistrationID {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "sandbox hook receipt is not authorized"})
		return
	}
	if p.Final != nil && p.Final.Action != p.SandboxReceipt.Proposed.Action {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sandbox hook was closed"})
		return
	}
	if a.store == nil || !a.store.Ready() {
		if p.Final != nil {
			// A prior acknowledgement wrote the row before publishing this
			// final state. A retry may return the same answer during a new
			// store outage without inventing a different verdict.
			a.writeJSON(w, http.StatusOK, map[string]bool{"received": true})
			return
		}
		// No allow row can have been written by this acknowledgement. The
		// hook takes the 503 closed; recovery must audit that same block.
		_, _ = p.setFinal(failedClosedHookDelivery(p.SandboxReceipt.response(),
			hookexec.ManagedGatewayNoAnswerReason), time.Duration(p.ElapsedNanos))
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit is unavailable"})
		return
	}
	if p.Final != nil {
		action, found, err := a.store.StoredHookDecisionAction(r.Context(), p.ID)
		if err != nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit outcome is uncertain"})
			return
		}
		if found && action == p.Final.Action {
			// The relay may retry after losing the receipt's reply. The
			// same audited answer is returned without counting the hook or
			// dispatching its notification a second time.
			a.writeJSON(w, http.StatusOK, map[string]bool{"received": true})
			return
		}
	}
	if time.Since(p.SandboxReceipt.OfferedAt) >= sandboxHookReceiptWindow && p.Final == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sandbox hook receipt expired"})
		return
	}
	req := p.Request.request(p.ID, p.BodyBytes)
	req.sandboxReceiptAcknowledgment = true
	req.pendingEnvelopeIdentity = &p.SandboxReceipt.EnvelopeIdentity
	req.pendingSandboxCallRef = p.SandboxReceipt.CallRef
	resp := p.SandboxReceipt.response()
	ctx, cancel := agentHookPersistenceContext(r.Context())
	defer cancel()
	ctx = audit.ContextWithEnvelope(ctx, p.Envelope)
	ctx = ContextWithAgentIdentity(ctx, p.Identity)
	ctx = enrichAgentHookContext(ctx, req)
	ctx = withRedactionDecision(ctx, resp.RedactionEnabled)
	firstAcknowledgment := p.Final == nil
	result := a.finalizeAgentHook(ctx, connectorName, req, resp, p.RawEventIDs,
		nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
	if !result.AuditPersisted {
		// A late store error can follow a committed row. In that case the
		// row is the authority and the hook may take the same allow. If
		// the lookup itself fails, keep the occurrence for recovery.
		action, found, lookupErr := a.store.StoredHookDecisionAction(ctx, p.ID)
		if lookupErr != nil || found && action != resp.Action {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit outcome is uncertain"})
			return
		}
		if found {
			result = a.finalizeAgentHook(ctx, connectorName, req, resp, p.RawEventIDs,
				nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
		}
	}
	if !result.AuditPersisted {
		// The response has not been handed to the agent. Close this failed
		// check before the sandbox hook can return a successful result.
		closed := failedClosedHookDelivery(resp, hookexec.ManagedGatewayNoAnswerReason)
		_, _ = p.setFinal(closed, time.Duration(p.ElapsedNanos))
		_ = a.finalizeAgentHook(ctx, connectorName, req, closed, p.RawEventIDs,
			nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit is unavailable"})
		return
	}
	if p.Final == nil {
		// The row is authoritative if this rewrite fails: recovery checks
		// its occurrence ID before filling a missing hook_decision.
		_, _ = p.setFinal(resp, time.Duration(p.ElapsedNanos))
	}
	if firstAcknowledgment {
		a.dispatchFinalizedAgentHookNotification(ctx, req, resp, result)
	}
	a.writeJSON(w, http.StatusOK, map[string]bool{"received": true})
}
