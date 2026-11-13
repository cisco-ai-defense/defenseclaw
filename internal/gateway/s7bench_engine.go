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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
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
	connector string
	profile   string
	judgeRec  *s7RecordingProvider
}

// S7NewEngine boots the sidecar generation for cfg and returns the
// connector's hook handler.
func S7NewEngine(cfg *config.Config, connectorName string) (*S7Engine, error) {
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
	// The harness has no real user home to follow links through, so the
	// effect lane uses a lexical resolver: a path resolves to itself. Member
	// names are still matched lexically (writing ~/.ssh/authorized_keys is
	// known regardless). Real symlink-through-link attacks are not exercised
	// here; that is a documented harness limit.
	effectResolverOverride = func(path string) (string, bool) { return path, true }
	// The harness reads the effect verdict per case from Deterministic (the
	// same effectShadowRun core); the hook's async live run is not needed.
	effectShadowLiveOff = true
	return &S7Engine{
		sc: sc, api: api, connector: connectorName,
		hook:    api.handleUnifiedConnectorHook(connectorName),
		profile: cfg.Guardrail.RulePack,
	}, nil
}

// Hook answers one hook payload through the connector's handler. headers
// (name, value pairs) are set on the request, e.g. the hook's answer wait.
func (e *S7Engine) Hook(ctx context.Context, body []byte, headers ...string) (code int, out []byte) {
	defer func() {
		if r := recover(); r != nil {
			code, out = 500, []byte(`{"action":"allow","reason":"panic"}`)
		}
	}()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+e.connector, bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	e.hook(rec, req)
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
	// Effect is the effect-model rule lane verdict (guardrail.effects_rules
	// shadow or on), computed beside today's answer for the disagreement
	// measurement. Nil when the lane is off.
	Effect     *EffectShadowResult `json:"effect,omitempty"`
	EffectFull *EffectShadowResult `json:"effect_full,omitempty"`
}

// Deterministic evaluates the call the way evaluateAgentHook projects it.
func (e *S7Engine) Deterministic(ctx context.Context, toolName string, args json.RawMessage, cwd string) (det S7Det) {
	defer func() {
		if r := recover(); r != nil {
			det = S7Det{Tool: toolName, Parse: "panic"}
		}
	}()
	actionTool := agentHookTrustedActionTool(e.connector, toolName, runtime.GOOS)
	trusted, toolCWD := agentHookTrustedActionArgs(e.connector, toolName, args)
	if toolCWD == "" {
		toolCWD = cwd
	}
	in := actionfacts.Input{Tool: actionTool, Args: trusted, CWD: toolCWD, ActiveHome: benchActiveHome(toolCWD)}
	r := EvaluateDeterministicAction(ctx, in, string(args), e.connector, e.profile)
	out := S7Det{Tool: actionTool, Parse: r.ParseStatus, Dialect: r.Dialect, Severity: r.Severity,
		EnforceSev: r.EnforceableSeverity, Action: r.Action, Eligible: r.EnforcementEligible, IssueCodes: r.IssueCodes}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, S7Finding{RuleID: f.RuleID, Severity: f.Severity, Confidence: f.Confidence, Disposition: f.Disposition, Route: f.Route})
	}
	out.Effect = r.EffectShadow
	out.EffectFull = r.EffectShadowFull
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

// benchActiveHome derives the session home from a tool working directory so
// the effect lane roots its protected sets correctly in the harness. It is
// the first two path components (/home/<user>), else the cwd, else a default.
func benchActiveHome(cwd string) string {
	if cwd == "" {
		return "/home/bench"
	}
	parts := strings.Split(strings.TrimPrefix(cwd, "/"), "/")
	if len(parts) >= 2 && parts[0] == "home" {
		return "/home/" + parts[1]
	}
	return cwd
}
