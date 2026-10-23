// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/google/uuid"
)

const sandboxHookReceiptWindow = 15 * time.Second

// The relay buffers each request and response, so its hook acknowledges an
// offered tool answer with a second call on the same authenticated route.
// Older images ignore the additive receipt ID and remain unconfirmed.
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

// Striped locks serialize receipt retries with journal recovery. Their fixed
// size avoids an unbounded map of one lock per hook call.
var sandboxReceiptLocks [64]sync.Mutex

func sandboxHookReceiptLock(id string) *sync.Mutex {
	var hash uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		hash = (hash ^ uint32(id[i])) * 16777619
	}
	return &sandboxReceiptLocks[hash%uint32(len(sandboxReceiptLocks))]
}

// scheduleSandboxHookReceiptRecovery finalizes an unanswered sandbox proposal
// after its bounded receipt window. It also removes acknowledged journal rows
// after the window for an idempotent retry has passed.
func (a *APIServer) scheduleSandboxHookReceiptRecovery(id string) {
	time.AfterFunc(sandboxHookReceiptWindow, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if a.store == nil {
			return
		}
		entry, found, err := a.store.HookDelivery(ctx, id)
		if err == nil && found {
			_ = a.recoverPendingHook(ctx, entry)
		}
	})
}

func (a *APIServer) markSandboxHookReceiptSettled(ctx context.Context, p *pendingHookOccurrence, result hookFinalizationResult) {
	if !result.AuditPersisted || !result.DecisionSettled {
		return
	}
	p.Settled = true
	err := a.recordSandboxHookReceiptState(ctx, p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] sandbox hook receipt journal settlement failed id=%s: %v\n", p.ID, err)
	}
}

func (a *APIServer) recordSandboxHookReceiptState(ctx context.Context, p *pendingHookOccurrence) error {
	encoded, err := json.Marshal(p)
	if err != nil {
		return err
	}
	stored, err := a.store.RecordHookDeliveryVerdict(ctx, p.ID, encoded, pendingHookJournalLimits)
	if err != nil {
		return err
	}
	if !stored {
		return errors.New("sandbox hook receipt journal row disappeared")
	}
	return nil
}

func (a *APIServer) handleSandboxHookReceipt(w http.ResponseWriter, r *http.Request, connectorName, id string) {
	binding, ok := sandboxauth.FromContext(r.Context())
	if !ok || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() ||
		binding.Connector != connectorName || uuid.Validate(id) != nil {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "sandbox hook receipt is not authorized"})
		return
	}
	lock := sandboxHookReceiptLock(id)
	lock.Lock()
	defer lock.Unlock()
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit is unavailable"})
		return
	}
	entry, found, err := a.store.HookDelivery(r.Context(), id)
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit is unavailable"})
		return
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "sandbox hook receipt is unavailable"})
		return
	}
	var p pendingHookOccurrence
	if json.Unmarshal(entry.Occurrence, &p) != nil || p.ID != id || p.SandboxReceipt == nil ||
		p.Request.ConnectorName != connectorName {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sandbox hook receipt is invalid"})
		return
	}
	if p.SandboxReceipt.BindingID != binding.ID ||
		p.SandboxReceipt.RegistrationID != binding.RegistrationID {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "sandbox hook receipt is not authorized"})
		return
	}
	// The audit row is authoritative when the first acknowledgement's reply
	// was lost. The journal remains for this bounded retry window.
	action, recorded, err := a.store.StoredHookDecisionAction(r.Context(), p.ID)
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit outcome is uncertain"})
		return
	}
	if recorded {
		if action == p.Proposed.Action {
			// Re-send the original verdict trailer when the relay lost the
			// first acknowledgement's response. No audit or metric is
			// emitted a second time.
			if sandboxRelayDecisionSinkFrom(r.Context()) != nil {
				req := p.request()
				req.pendingSandboxCallRef = p.SandboxReceipt.CallRef
				a.observeSandboxHookDecision(r.Context(), req, p.SandboxReceipt.response(p.Proposed))
			}
			a.writeJSON(w, http.StatusOK, map[string]bool{"received": true})
		} else {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sandbox hook was closed"})
		}
		return
	}
	if p.Final != nil || time.Since(p.SandboxReceipt.OfferedAt) >= sandboxHookReceiptWindow {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sandbox hook receipt expired or closed"})
		return
	}
	req := p.request()
	req.sandboxReceiptAcknowledgment = true
	req.pendingSandboxCallRef = p.SandboxReceipt.CallRef
	resp := p.SandboxReceipt.response(p.Proposed)
	ctx, cancel := agentHookPersistenceContext(r.Context())
	defer cancel()
	ctx = audit.ContextWithEnvelope(ctx, p.Envelope)
	ctx = ContextWithAgentIdentity(ctx, p.Identity)
	ctx = enrichAgentHookContext(ctx, req)
	ctx = withRedactionDecision(ctx, resp.RedactionEnabled)
	// A sandbox receipt has no already-delivered answer to replay. Remote
	// destinations see its verdict only after the local audit row commits.
	ctx = observability.WithRemoteExport(ctx, observability.RemoteExportAfterLocalWrite)

	// Before attempting the allow audit, journal the 503 fallback. If the
	// audit cannot be committed or the process dies, recovery audits the
	// block the hook takes. A committed allow row supersedes this fallback.
	closed := failedClosedHookDelivery(resp, hookexec.ManagedGatewayNoAnswerReason)
	fallback := pendingResponse(closed)
	p.Final = &fallback
	if err := a.recordSandboxHookReceiptState(ctx, &p); err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit is unavailable"})
		return
	}
	result := a.finalizeAgentHook(ctx, connectorName, req, resp, p.RawEventIDs,
		nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
	if !result.AuditPersisted {
		// A write can return an error after it committed. Confirm its exact
		// action before telling the hook to use the proposed answer.
		action, recorded, err = a.store.StoredHookDecisionAction(ctx, p.ID)
		if err != nil || !recorded || action != resp.Action {
			if err == nil && !recorded {
				closedResult := a.finalizeAgentHook(ctx, connectorName, req, closed, p.RawEventIDs,
					nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
				a.markSandboxHookReceiptSettled(ctx, &p, closedResult)
				if closedResult.AuditPersisted {
					a.dispatchFinalizedAgentHookNotification(ctx, req, closed, closedResult)
				}
			}
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hook audit outcome is uncertain"})
			return
		}
	}
	a.markSandboxHookReceiptSettled(ctx, &p, result)
	a.dispatchFinalizedAgentHookNotification(ctx, req, resp, result)
	a.writeJSON(w, http.StatusOK, map[string]bool{"received": true})
}
