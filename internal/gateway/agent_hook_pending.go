// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/google/uuid"
)

// A receipt-capable managed hook can act on an answer before the gateway's
// terminal audit write. This private spool is durable before the answer is
// offered. It contains only the facts needed to recover an unconfirmed
// occurrence; no raw hook body, tool arguments, or response output is stored.
const (
	pendingHookDirName         = "pending-hook-decisions"
	maxPendingHookBytes        = 128 << 10
	pendingHookRecoveredReason = "managed hook receipt recovered after gateway restart"
)

type pendingHookRequest struct {
	ConnectorName          string
	HookEventName          string
	SessionID              string
	TurnID                 string
	AgentID                string
	AgentName              string
	AgentType              string
	ToolInvocationID       string
	ToolName               string
	CorrelationUnavailable bool
}

func pendingRequest(req agentHookRequest) pendingHookRequest {
	return pendingHookRequest{
		ConnectorName: req.ConnectorName, HookEventName: req.HookEventName,
		SessionID: req.SessionID, TurnID: req.TurnID,
		AgentID: req.AgentID, AgentName: req.AgentName, AgentType: req.AgentType,
		ToolInvocationID: req.ToolInvocationID, ToolName: req.ToolName,
		CorrelationUnavailable: req.CorrelationUnavailable,
	}
}

func (p pendingHookRequest) request(id string, bodyBytes int64) agentHookRequest {
	return agentHookRequest{
		ConnectorName: p.ConnectorName, HookEventName: p.HookEventName,
		SessionID: p.SessionID, TurnID: p.TurnID,
		AgentID: p.AgentID, AgentName: p.AgentName, AgentType: p.AgentType,
		ToolInvocationID: p.ToolInvocationID, ToolName: p.ToolName,
		CorrelationUnavailable: p.CorrelationUnavailable,
		pendingOccurrenceID:    id, pendingBodyBytes: bodyBytes, pendingRecovery: true,
	}
}

type pendingHookResponse struct {
	Action           string
	RawAction        string
	Severity         string
	Mode             string
	WouldBlock       bool
	EvaluationID     string
	RuleIDs          []string
	RedactionEnabled *bool
}

func pendingResponse(resp agentHookResponse) pendingHookResponse {
	return pendingHookResponse{
		Action: resp.Action, RawAction: resp.RawAction, Severity: resp.Severity,
		Mode: resp.Mode, WouldBlock: resp.WouldBlock,
		EvaluationID: resp.EvaluationID, RuleIDs: resp.RuleIDs,
		RedactionEnabled: resp.RedactionEnabled,
	}
}

func (p pendingHookResponse) response() agentHookResponse {
	reason := pendingHookRecoveredReason
	if p.Action == hookActionUnconfirmed {
		reason = hookexec.ManagedGatewayNoAnswerReason
	}
	return agentHookResponse{
		Action: p.Action, RawAction: p.RawAction, Severity: p.Severity,
		Mode: p.Mode, Reason: reason, SourceReason: reason,
		WouldBlock: p.WouldBlock, EvaluationID: p.EvaluationID,
		RuleIDs: p.RuleIDs, RedactionEnabled: p.RedactionEnabled,
	}
}

type pendingHookOccurrence struct {
	ID           string
	Request      pendingHookRequest
	Unconfirmed  pendingHookResponse
	Final        *pendingHookResponse
	Envelope     audit.CorrelationEnvelope
	Identity     AgentIdentity
	RawEventIDs  []string
	Extra        map[string]string
	BodyBytes    int64
	ElapsedNanos int64
	Panicked     bool
	path         string
}

func (a *APIServer) pendingHookDir() string {
	dir := a.configDataDir()
	if dir == "" && a != nil && a.store != nil {
		dir = filepath.Dir(a.store.DatabasePath())
	}
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, pendingHookDirName)
}

func (a *APIServer) beginPendingHookOccurrence(
	ctx context.Context, req agentHookRequest, proposed agentHookResponse,
	rawEventIDs []string, bodyBytes int64, elapsed time.Duration,
	panicked bool, extra map[string]string,
) (*pendingHookOccurrence, error) {
	if a == nil || a.store == nil || a.logger == nil || !a.store.Ready() {
		return nil, errors.New("hook audit store is unavailable")
	}
	dir := a.pendingHookDir()
	if dir == "" {
		return nil, errors.New("hook pending state directory is unavailable")
	}
	id := uuid.NewString()
	p := &pendingHookOccurrence{
		ID: id, Request: pendingRequest(req),
		Unconfirmed: pendingResponse(unconfirmedHookDelivery(proposed)),
		Envelope:    audit.EnvelopeFromContext(ctx), Identity: AgentIdentityFromContext(ctx),
		RawEventIDs: rawEventIDs, Extra: extra, BodyBytes: bodyBytes,
		ElapsedNanos: int64(elapsed), Panicked: panicked,
		path: filepath.Join(dir, id+".json"),
	}
	if err := p.save(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *pendingHookOccurrence) save() error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(data) > maxPendingHookBytes {
		return fmt.Errorf("hook pending occurrence exceeds %d bytes", maxPendingHookBytes)
	}
	if err := safefile.WritePrivate(p.path, data); err != nil {
		return err
	}
	return syncDaemonDir(filepath.Dir(p.path))
}

func (p *pendingHookOccurrence) setFinal(resp agentHookResponse, elapsed time.Duration) error {
	final := pendingResponse(resp)
	p.Final = &final
	p.ElapsedNanos = int64(elapsed)
	return p.save()
}

func (p *pendingHookOccurrence) remove() error {
	if err := os.Remove(p.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDaemonDir(filepath.Dir(p.path))
}

// recoverPendingHookOccurrences runs before the new gateway accepts hooks.
// A pending entry with no durable receipt outcome is deliberately unconfirmed:
// a restart cannot infer what the previous process's confirmation reached.
func (a *APIServer) ensurePendingHookRecovery(ctx context.Context) error {
	a.pendingHookRecoveryOnce.Do(func() {
		a.pendingHookRecoveryErr = a.recoverPendingHookOccurrences(ctx)
	})
	return a.pendingHookRecoveryErr
}

func (a *APIServer) recoverPendingHookOccurrences(ctx context.Context) error {
	if a == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() {
		return nil
	}
	dir := a.pendingHookDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := safefile.ValidatePrivateDirectory(dir); err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		// An interrupted atomic rewrite can leave its unpublished temp.
		// The last published JSON file is still the recovery authority.
		if strings.HasPrefix(name, ".safefile-") {
			continue
		}
		id, ok := strings.CutSuffix(name, ".json")
		if !ok || entry.Type() != 0 || uuid.Validate(id) != nil {
			return fmt.Errorf("invalid hook pending occurrence %q", name)
		}
		path := filepath.Join(dir, name)
		if err := safefile.ValidatePrivateFile(path); err != nil {
			return err
		}
		data, err := safefile.ReadRegularFileBounded(path, maxPendingHookBytes)
		if err != nil {
			return err
		}
		var p pendingHookOccurrence
		if err := json.Unmarshal(data, &p); err != nil || p.ID != id ||
			p.Request.ConnectorName == "" || p.Request.HookEventName == "" ||
			p.BodyBytes < 0 || p.BodyBytes > apiRequestBodyMaxBytes {
			return fmt.Errorf("invalid hook pending occurrence %q", name)
		}
		p.path = path
		req := p.Request.request(p.ID, p.BodyBytes)
		resp := p.Unconfirmed.response()
		if p.Final != nil {
			resp = p.Final.response()
		}
		persistCtx := audit.ContextWithEnvelope(ctx, p.Envelope)
		persistCtx = ContextWithAgentIdentity(persistCtx, p.Identity)
		persistCtx = enrichAgentHookContext(persistCtx, req)
		persistCtx = withRedactionDecision(persistCtx, resp.RedactionEnabled)
		result := a.finalizeAgentHook(persistCtx, req.ConnectorName, req, resp,
			p.RawEventIDs, nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
		if !result.AuditPersisted || !result.DecisionPersisted {
			return fmt.Errorf("hook pending occurrence %s could not be audited", p.ID)
		}
		if err := p.remove(); err != nil {
			return err
		}
	}
	return nil
}
