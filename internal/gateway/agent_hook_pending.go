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
	"sync"
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
	// The handler owns its occurrence from before it is published until it
	// returns; recovery in this process leaves it alone.
	livePendingHooks.claim(p.path)
	if err := p.save(); err != nil {
		livePendingHooks.release(p.path)
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

// release ends the handler's ownership. An occurrence it could not audit
// stays on disk for recovery.
func (p *pendingHookOccurrence) release() {
	if p != nil {
		livePendingHooks.release(p.path)
	}
}

// pendingHookOwners is the set of pending occurrences a goroutine of this
// process is working on: a live handler between its offer and its terminal
// audit, or a recovery pass. A config reload builds a new APIServer while
// the old server's handlers can still be running, so ownership is per
// process, not per server.
type pendingHookOwners struct {
	mu    sync.Mutex
	paths map[string]struct{}
}

var livePendingHooks = pendingHookOwners{paths: map[string]struct{}{}}

func (o *pendingHookOwners) claim(path string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, owned := o.paths[path]; owned {
		return false
	}
	o.paths[path] = struct{}{}
	return true
}

func (o *pendingHookOwners) release(path string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.paths, path)
}

// defaultPendingHookRetryInterval is how often recovery retries occurrences
// it could not audit yet (the audit store was not ready or not writable).
const defaultPendingHookRetryInterval = 30 * time.Second

// pendingHookQuarantineSuffix marks an occurrence file recovery refused. It
// is kept for inspection and no longer read.
const pendingHookQuarantineSuffix = ".invalid"

// pendingHookReported keeps one finding per problem per process, so a retry
// loop or an API restart does not repeat the same alert.
var pendingHookReported = struct {
	mu   sync.Mutex
	seen map[string]struct{}
}{seen: map[string]struct{}{}}

// ensurePendingHookRecovery runs one recovery pass before the first API
// listener of this server serves hooks. Recovery never stops the gateway: an
// entry it cannot read is skipped or quarantined with a finding, and an entry
// it cannot audit yet stays on disk and is retried in the background.
func (a *APIServer) ensurePendingHookRecovery(ctx context.Context) {
	a.pendingHookRecoveryOnce.Do(func() {
		if a.recoverPendingHookOccurrences(ctx) {
			go a.retryPendingHookRecovery(ctx)
		}
	})
}

func (a *APIServer) retryPendingHookRecovery(ctx context.Context) {
	interval := a.pendingHookRetryInterval
	if interval <= 0 {
		interval = defaultPendingHookRetryInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !a.recoverPendingHookOccurrences(ctx) {
			return
		}
	}
}

// reportPendingHookProblem records a recovery finding once per process: a
// gateway error line and a HIGH alert row when the audit store accepts it.
func (a *APIServer) reportPendingHookProblem(kind, entry string, err error) {
	key := kind + "\x00" + entry + "\x00" + err.Error()
	pendingHookReported.mu.Lock()
	_, seen := pendingHookReported.seen[key]
	pendingHookReported.seen[key] = struct{}{}
	pendingHookReported.mu.Unlock()
	if seen {
		return
	}
	fmt.Fprintf(os.Stderr, "[gateway] hook pending recovery %s entry=%q: %v\n", kind, entry, err)
	if a.logger != nil {
		_ = a.logger.LogAlert("hook-audit", "HIGH",
			"managed hook pending decision recovery: "+kind,
			map[string]any{"entry": entry, "problem": kind, "error": err.Error()})
	}
}

// recoverPendingHookOccurrences audits the occurrences an earlier process
// (or an earlier server of this process) left behind. A pending entry with no
// durable receipt outcome is deliberately unconfirmed: a restart cannot infer
// what the previous process's confirmation reached. It reports whether an
// entry is still waiting for a later pass.
func (a *APIServer) recoverPendingHookOccurrences(ctx context.Context) (retry bool) {
	if a == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() {
		return false
	}
	dir := a.pendingHookDir()
	if dir == "" {
		return false
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		a.reportPendingHookProblem("unreadable directory", pendingHookDirName, err)
		return true
	}
	if err := safefile.ValidatePrivateDirectory(dir); err != nil {
		// Nothing in a directory that is not private is trusted. Its
		// entries wait until the directory is repaired.
		a.reportPendingHookProblem("directory protection drift", pendingHookDirName, err)
		return true
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return true
		}
		if a.recoverPendingHookEntry(ctx, dir, entry) {
			retry = true
		}
	}
	return retry
}

// recoverPendingHookEntry handles one directory entry and reports whether it
// must be retried. A panic in one entry is a finding, never a gateway exit.
func (a *APIServer) recoverPendingHookEntry(ctx context.Context, dir string, entry fs.DirEntry) (retry bool) {
	name := entry.Name()
	// An interrupted atomic rewrite can leave its unpublished temp. The last
	// published JSON file is still the recovery authority.
	if strings.HasPrefix(name, ".safefile-") || strings.HasSuffix(name, pendingHookQuarantineSuffix) {
		return false
	}
	id, ok := strings.CutSuffix(name, ".json")
	if !ok || uuid.Validate(id) != nil {
		// Not ours (a Finder or editor file, a subdirectory): left alone.
		a.reportPendingHookProblem("foreign entry skipped", name, errors.New("not a pending occurrence"))
		return false
	}
	path := filepath.Join(dir, name)
	if !livePendingHooks.claim(path) {
		// A handler of this process still owns it, or another recovery
		// pass is replaying it.
		return false
	}
	defer livePendingHooks.release(path)
	defer func() {
		if recovered := recover(); recovered != nil {
			a.reportPendingHookProblem("recovery panic", name, fmt.Errorf("%v", recovered))
			retry = true
		}
	}()
	p, err := readPendingHookOccurrence(path, id, entry)
	if errors.Is(err, fs.ErrNotExist) {
		// Finalized and removed after this pass listed the directory.
		return false
	}
	if err != nil {
		return a.quarantinePendingHookOccurrence(path, name, err)
	}
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
		// Kept on disk: stable IDs make a later pass skip whichever
		// record already landed.
		a.reportPendingHookProblem("audit not persisted yet", name,
			fmt.Errorf("audit=%t hook_decision=%t", result.AuditPersisted, result.DecisionPersisted))
		return true
	}
	if err := p.remove(); err != nil {
		a.reportPendingHookProblem("cleanup failed", name, err)
		return true
	}
	return false
}

func readPendingHookOccurrence(path, id string, entry fs.DirEntry) (*pendingHookOccurrence, error) {
	if !entry.Type().IsRegular() {
		return nil, fmt.Errorf("entry type %s is not a regular file", entry.Type())
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return nil, err
	}
	data, err := safefile.ReadRegularFileBounded(path, maxPendingHookBytes)
	if err != nil {
		return nil, err
	}
	var p pendingHookOccurrence
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.ID != id || p.Request.ConnectorName == "" || p.Request.HookEventName == "" ||
		p.BodyBytes < 0 || p.BodyBytes > apiRequestBodyMaxBytes {
		return nil, errors.New("occurrence fields are invalid")
	}
	p.path = path
	return &p, nil
}

// quarantinePendingHookOccurrence renames an occurrence recovery refused, so
// later passes skip it, and records the finding. It reports a retry only
// when the rename itself failed.
func (a *APIServer) quarantinePendingHookOccurrence(path, name string, cause error) bool {
	a.reportPendingHookProblem("invalid occurrence quarantined", name, cause)
	if err := os.Rename(path, path+pendingHookQuarantineSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
		a.reportPendingHookProblem("quarantine failed", name, err)
		return true
	}
	_ = syncDaemonDir(filepath.Dir(path))
	return false
}
