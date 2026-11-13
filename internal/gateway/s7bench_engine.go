// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package gateway

// Benchmark-only handle on the real gateway (built only with -tags s7bench).
// It boots the sidecar exactly as NewSidecar does, wires an API server the
// way runAPI does, and answers hook payloads through the same unified
// connector handler a running gateway serves. Layer probes call the hook
// judge's own context builder, decision model and tool judge, so nothing
// here re-implements a verdict.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// S7Engine is one booted gateway generation and its hook handler.
type S7Engine struct {
	sc        *Sidecar
	api       *APIServer
	hook      http.HandlerFunc
	hooks     map[string]http.HandlerFunc
	connector string
	profile   string
	store     *audit.Store
	stopGuard context.CancelFunc
	guardDone chan struct{}
	passes    atomic.Int64
	peakWAL   atomic.Int64
}

// S7NewEngine boots the sidecar generation for cfg and returns the
// connector's hook handler.
func S7NewEngine(cfg *config.Config, connectorName string) (*S7Engine, error) {
	return S7NewEngineMulti(cfg, connectorName, nil)
}

// S7NewEngineMulti boots one generation with the hook handlers of connectorName and of every name in more, so a corpus can
// send each case to the handler of its own connector.
func S7NewEngineMulti(cfg *config.Config, connectorName string, more []string) (*S7Engine, error) {
	store, err := audit.NewStore(filepath.Join(cfg.DataDir, "audit.db"))
	if err != nil {
		return nil, fmt.Errorf("audit store: %w", err)
	}
	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("audit store init: %w", err)
	}
	// No audit logger: the hook answers without the v8 audit runtime
	// (errHookAuditNotConfigured), so an audit fault never shapes a verdict.
	var logger *audit.Logger
	sc, err := NewSidecar(cfg, store, logger)
	if err != nil {
		return nil, err
	}
	api := newAPIServer("127.0.0.1:0", sc.health, sc.client, store, logger, cloneConfig(sc.currentConfig()))
	api.SetGenerationSource(sc.Generation)
	if g := sc.Generation(); g != nil {
		api.setGuardrailProfiles(g.Profiles)
	} else {
		api.initGuardrailProfiles(api.scannerCfg)
	}
	if j := sc.sharedJudge(); j != nil {
		api.SetHookJudge(j)
	}
	if g := currentGeneration(); g != nil {
		api.SetHookDecisionJudge(g.decisionJudge)
	}
	hooks := map[string]http.HandlerFunc{connectorName: api.handleUnifiedConnectorHook(connectorName)}
	for _, name := range more {
		if _, ok := hooks[name]; !ok {
			hooks[name] = api.handleUnifiedConnectorHook(name)
		}
	}
	e := &S7Engine{
		sc: sc, api: api, connector: connectorName,
		hook:    hooks[connectorName],
		hooks:   hooks,
		profile: cfg.Guardrail.RulePack,
		store:   store,
	}
	e.startWALGuard()
	return e, nil
}

// Hook answers one hook payload through the connector's handler.
func (e *S7Engine) Hook(ctx context.Context, body []byte) (int, []byte) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+e.connector, bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.hook(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// HookFor answers one hook payload through the named connector's handler.
func (e *S7Engine) HookFor(ctx context.Context, connectorName string, body []byte) (int, []byte) {
	h, ok := e.hooks[connectorName]
	if !ok {
		h, connectorName = e.hook, e.connector
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+connectorName, bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	if connectorName == "codex" {
		// Codex hooks are installer-bound: the hook command passes the event and the protected contract id out of band.
		var probe struct {
			Event string `json:"hook_event_name"`
		}
		_ = json.Unmarshal(body, &probe)
		req.Header.Set("X-DefenseClaw-Hook-Event", probe.Event)
		req.Header.Set("X-DefenseClaw-Hook-Contract", e.api.hookProfileForRequest(ctx, "codex").ContractID)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// HasJudge reports whether the generation wired a hook judge, and whether it
// carries a decision model.
func (e *S7Engine) HasJudge() (bool, bool) {
	j := e.api.hookJudge.Load()
	return j != nil, j != nil && j.decision != nil
}

// S7Finding is one rule finding of the trusted-action evaluation.
type S7Finding struct {
	RuleID      string  `json:"rule"`
	Severity    string  `json:"sev"`
	Confidence  float64 `json:"conf,omitempty"`
	Disposition string  `json:"disp"`
	Route       string  `json:"route,omitempty"`
}

// S7Det is the deterministic evaluation of one tool call: findings with
// their disposition (enforceable, detect_only, audit, advisory), the parse
// status and dialect, as the hook's trusted-action dispatch sees the call.
type S7Det struct {
	Tool       string      `json:"tool"`
	Parse      string      `json:"parse"`
	Dialect    string      `json:"dialect"`
	Severity   string      `json:"sev"`
	EnforceSev string      `json:"enforce_sev"`
	Action     string      `json:"action"`
	Eligible   bool        `json:"eligible"`
	Findings   []S7Finding `json:"findings,omitempty"`
	IssueCodes []string    `json:"issues,omitempty"`
}

// Deterministic evaluates the call the way evaluateAgentHook projects it.
func (e *S7Engine) Deterministic(ctx context.Context, toolName string, args json.RawMessage, cwd string) S7Det {
	return e.DeterministicFor(ctx, e.connector, toolName, args, cwd)
}

// DeterministicFor is Deterministic for the named connector.
func (e *S7Engine) DeterministicFor(ctx context.Context, connectorName, toolName string, args json.RawMessage, cwd string) S7Det {
	actionTool := agentHookTrustedActionTool(connectorName, toolName, runtime.GOOS)
	trusted, toolCWD := agentHookTrustedActionArgs(connectorName, toolName, args)
	if toolCWD == "" {
		toolCWD = cwd
	}
	in := actionfacts.Input{Tool: actionTool, Args: trusted, CWD: toolCWD}
	r := EvaluateDeterministicAction(ctx, in, string(args), connectorName, e.profile)
	out := S7Det{Tool: actionTool, Parse: r.ParseStatus, Dialect: r.Dialect, Severity: r.Severity,
		EnforceSev: r.EnforceableSeverity, Action: r.Action, Eligible: r.EnforcementEligible, IssueCodes: r.IssueCodes}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, S7Finding{RuleID: f.RuleID, Severity: f.Severity, Confidence: f.Confidence, Disposition: f.Disposition, Route: f.Route})
	}
	return out
}

// S7DM is one decision-model answer.
type S7DM struct {
	Called    bool    `json:"called"`
	Choice    string  `json:"choice,omitempty"`
	Risk      float64 `json:"risk"`
	Route     string  `json:"route"`
	LatencyMs int64   `json:"latency_ms"`
	Failure   string  `json:"failure,omitempty"`
}

// S7Judge is one tool-judge verdict.
type S7Judge struct {
	Called     bool     `json:"called"`
	Action     string   `json:"action,omitempty"`
	Severity   string   `json:"sev,omitempty"`
	Findings   []string `json:"findings,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Scanner    string   `json:"scanner,omitempty"`
	Confidence float64  `json:"conf,omitempty"`
	LatencyMs  int64    `json:"latency_ms"`
}

// ObservePrompt records the session's user intent as a UserPromptSubmit does.
func (e *S7Engine) ObservePrompt(ctx context.Context, sessionID, prompt string) {
	if j := e.api.hookJudge.Load(); j != nil {
		j.ObserveSessionPrompt(ContextWithSessionID(ctx, sessionID), prompt)
	}
}

// Layers runs the hook judge's own sample builder (session intent plus the
// last seven calls), then the decision model and the LLM tool judge on that
// sample, independently, so cascades can be composed from the same answers.
func (e *S7Engine) Layers(ctx context.Context, sessionID, toolName, args string, wantDM, wantJudge bool) (S7DM, S7Judge) {
	var dm S7DM
	var jv S7Judge
	j := e.api.hookJudge.Load()
	if j == nil {
		return dm, jv
	}
	ctx = ContextWithSessionID(ctx, sessionID)
	sample, eligible := j.prepareToolJudgeSample(ctx, toolName, args)
	if !eligible {
		dm.Route, dm.Failure = "ineligible", "args shorter than the judge minimum"
		jv.Action = "allow"
		return dm, jv
	}
	state := j.takeDecisionState(sample, toolName, args)
	if wantDM && j.decision != nil {
		res := j.decision.decide(ctx, state)
		dm = S7DM{Called: !res.skipped, Choice: res.choice, Risk: res.risk, LatencyMs: res.latencyMs, Failure: strings.TrimSpace(string(res.failure) + " " + res.failureCause)}
		switch res.route {
		case decisionAllow:
			dm.Route = "allow"
		case decisionBlock:
			dm.Route = "block"
		default:
			dm.Route = "escalate"
		}
	}
	if wantJudge {
		t0 := time.Now()
		v := j.runToolJudgeLLM(ctx, toolName, args, sample)
		jv.Called = true
		jv.LatencyMs = time.Since(t0).Milliseconds()
		if v != nil {
			jv.Action, jv.Severity, jv.Findings, jv.Reason, jv.Scanner, jv.Confidence = v.Action, v.Severity, v.Findings, v.Reason, v.Scanner, v.Confidence
		}
	}
	return dm, jv
}

// startWALGuard runs the product's own audit WAL guard pass (auditWALGuardPass, the one runAuditWALGuard calls every 2 s in a running
// gateway) in a goroutine. The harness never calls Sidecar.Run, so without this nothing checkpoints and the audit WAL grows without
// bound under a sustained hook load (7-24 GB per run seen on dc-build-1). The pass runs every 500 ms here because the harness
// drives far more calls per second than a host does.
func (e *S7Engine) startWALGuard() {
	ctx, cancel := context.WithCancel(context.Background())
	e.stopGuard = cancel
	e.guardDone = make(chan struct{})
	go func() {
		defer close(e.guardDone)
		var alarm auditWALAlarm
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			auditWALGuardPass(ctx, e.store, &alarm, time.Now(), io.Discard)
			e.passes.Add(1)
			if st, err := os.Stat(e.store.DatabasePath() + "-wal"); err == nil && st.Size() > e.peakWAL.Load() {
				e.peakWAL.Store(st.Size())
			}
		}
	}()
}

// Close stops the WAL guard.
func (e *S7Engine) Close() {
	if e.stopGuard != nil {
		e.stopGuard()
		<-e.guardDone
	}
}

// S7Stats is the audit store's size and checkpoint settings at the end of a run.
type S7Stats struct {
	DBBytes           int64             `json:"audit_db_bytes"`
	WALBytesFinal     int64             `json:"audit_wal_bytes_final"`
	WALBytesPeakSeen  int64             `json:"audit_wal_bytes_peak_seen"`
	GuardPasses       int64             `json:"wal_guard_passes"`
	Pragmas           map[string]string `json:"pragmas_in_effect_new_connection"`
	StoreDSNPragmas   string            `json:"store_dsn_pragmas_note"`
	WALJournalLimit   int64             `json:"journal_size_limit_bytes"`
	WALHardLimitBytes int64             `json:"wal_hard_limit_bytes"`
}

// Stats reports the audit database and WAL sizes and the SQLite settings (journal_mode, wal_autocheckpoint, synchronous, journal_size_limit)
// as a fresh connection sees them; the store's own connection sets journal_mode(WAL) and the pragmas listed in audit.openSQLiteWithPragmas.
func (e *S7Engine) Stats(ctx context.Context) S7Stats {
	out := S7Stats{Pragmas: map[string]string{}, GuardPasses: e.passes.Load(), WALBytesPeakSeen: e.peakWAL.Load(), WALJournalLimit: 64 << 20, WALHardLimitBytes: audit.WALHardLimitBytes,
		StoreDSNPragmas: "journal_mode(WAL) + audit-tier pragmas from audit.openSQLiteWithPragmas; main pool 1 connection; wal_autocheckpoint left at the SQLite default (1000 pages) on the store connection"}
	path := e.store.DatabasePath()
	if st, err := os.Stat(path); err == nil {
		out.DBBytes = st.Size()
	}
	if st, err := os.Stat(path + "-wal"); err == nil {
		out.WALBytesFinal = st.Size()
	}
	if db, err := sql.Open("sqlite", "file:"+path+"?mode=ro"); err == nil {
		defer db.Close()
		for _, pr := range []string{"journal_mode", "wal_autocheckpoint", "synchronous", "journal_size_limit"} {
			var v string
			if err := db.QueryRowContext(ctx, "PRAGMA "+pr).Scan(&v); err == nil {
				out.Pragmas[pr] = v
			}
		}
	}
	return out
}
