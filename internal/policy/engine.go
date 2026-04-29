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

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/open-policy-agent/opa/ast"           //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/rego"          //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage"       //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage/inmem" //nolint:staticcheck // v0 compat; migrate to opa/v1 later

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// Engine evaluates OPA Rego policies for admission, guardrail, firewall,
// sandbox, audit, and skill_actions domains.
type Engine struct {
	mu      sync.RWMutex
	regoDir string
	store   storage.Store
	otel    *telemetry.Provider
}

// New creates an Engine. regoDir is the path to the directory containing
// the Rego modules and data.json (e.g. policies/rego/). If regoDir itself
// does not contain .rego files but a "rego" subdirectory does, the
// subdirectory is used instead.
func New(regoDir string) (*Engine, error) {
	regoDir = resolveRegoDir(regoDir)
	store, err := loadStore(regoDir)
	if err != nil {
		return nil, err
	}
	return &Engine{regoDir: regoDir, store: store}, nil
}

// SetOTelProvider attaches the shared telemetry provider for policy.evaluate
// spans and RecordPolicyEvaluation metrics. Safe to call with nil.
func (e *Engine) SetOTelProvider(p *telemetry.Provider) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.otel = p
	e.mu.Unlock()
}

// resolveRegoDir returns regoDir if it contains .rego files or data.json,
// otherwise tries the "rego" subdirectory (policy_dir layout).
func resolveRegoDir(dir string) string {
	if hasRegoFiles(dir) {
		return dir
	}
	sub := filepath.Join(dir, "rego")
	if hasRegoFiles(sub) {
		return sub
	}
	return dir
}

func hasRegoFiles(dir string) bool {
	matches, err := filepath.Glob(filepath.Join(dir, "*.rego"))
	if err != nil {
		return false
	}
	return len(matches) > 0
}

// Reload re-reads data.json and all .rego files, replacing the in-memory
// store atomically. Returns a compilation error if the new modules fail
// to compile so the caller can decide whether to keep the old state.
func (e *Engine) Reload() error {
	store, err := loadStore(e.regoDir)
	if err != nil {
		return err
	}

	modules, err := readModules(e.regoDir, e)
	if err != nil {
		return err
	}
	if err := compileModules(modules); err != nil {
		return err
	}

	e.mu.Lock()
	e.store = store
	e.mu.Unlock()
	return nil
}

// RegoDir returns the directory the engine loads Rego files from.
func (e *Engine) RegoDir() string {
	return e.regoDir
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

// Evaluate runs the admission policy against the provided input and returns
// the verdict, reason, file_action, install_action, and runtime_action.
func (e *Engine) Evaluate(ctx context.Context, input AdmissionInput) (*AdmissionOutput, error) {
	result, err := e.eval(ctx, "data.defenseclaw.admission", input)
	if err != nil {
		e.emitPolicyLoadOrEvalError(ctx, err)
		return &AdmissionOutput{
			Verdict:       "rejected",
			Reason:        "policy evaluation failed — denied by default",
			FileAction:    "quarantine",
			InstallAction: "block",
			RuntimeAction: "block",
		}, nil
	}
	return &AdmissionOutput{
		Verdict:       stringVal(result, "verdict"),
		Reason:        stringVal(result, "reason"),
		FileAction:    stringVal(result, "file_action"),
		InstallAction: stringVal(result, "install_action"),
		RuntimeAction: stringVal(result, "runtime_action"),
	}, nil
}

// ---------------------------------------------------------------------------
// Guardrail
// ---------------------------------------------------------------------------

// EvaluateGuardrail runs the LLM guardrail policy against combined scanner results.
func (e *Engine) EvaluateGuardrail(ctx context.Context, input GuardrailInput) (*GuardrailOutput, error) {
	result, err := e.eval(ctx, "data.defenseclaw.guardrail", input)
	if err != nil {
		return nil, fmt.Errorf("policy: guardrail eval: %w", err)
	}

	sources := toStringSlice(result, "scanner_sources")
	return &GuardrailOutput{
		Action:          stringVal(result, "action"),
		Severity:        stringVal(result, "severity"),
		Reason:          stringVal(result, "reason"),
		ScannerSources:  sources,
		TaintEscalation: extractTaintEscalation(result),
	}, nil
}

// extractTaintEscalation pulls guardrail.rego's `taint_escalation`
// block out of the result map. The Rego policy emits this block only
// when session taint context bumped severity, so callers can treat a
// non-nil return as "this verdict was influenced by taint".
//
// Defensive against partial / type-mismatched output: any field that
// fails to type-assert is silently dropped, which is preferable to
// failing the whole evaluation just because Rego shipped a
// numerically-typed integer.
func extractTaintEscalation(result map[string]interface{}) *GuardrailTaintEscalation {
	raw, ok := result["taint_escalation"]
	if !ok || raw == nil {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok || len(m) == 0 {
		return nil
	}
	out := &GuardrailTaintEscalation{
		Path:                  stringVal(m, "path"),
		Tier:                  stringVal(m, "tier"),
		Steps:                 intVal(m, "steps"),
		BaseSeverityRank:      intVal(m, "base_severity_rank"),
		EffectiveSeverityRank: intVal(m, "effective_severity_rank"),
		TaintedFiles:          toStringSlice(m, "tainted_files"),
		Sources:               toStringSlice(m, "sources"),
		EventsSinceSource:     intVal(m, "events_since_source"),
		NetworkDestExcluded:   boolVal(m, "network_dest_excluded"),
	}
	// Treat an empty path/tier as "no escalation"; the Rego policy
	// shouldn't emit this block in that state, but be defensive.
	if out.Path == "" && out.Tier == "" && out.Steps == 0 {
		return nil
	}
	return out
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

// EvaluateFirewall runs the egress firewall policy for a given destination.
func (e *Engine) EvaluateFirewall(ctx context.Context, input FirewallInput) (*FirewallOutput, error) {
	result, err := e.eval(ctx, "data.defenseclaw.firewall", input)
	if err != nil {
		return nil, fmt.Errorf("policy: firewall eval: %w", err)
	}
	return &FirewallOutput{
		Action:   stringVal(result, "action"),
		RuleName: stringVal(result, "rule_name"),
	}, nil
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

// EvaluateSandbox runs the sandbox policy for skill endpoint/permission shaping.
func (e *Engine) EvaluateSandbox(ctx context.Context, input SandboxInput) (*SandboxOutput, error) {
	result, err := e.eval(ctx, "data.defenseclaw.sandbox", input)
	if err != nil {
		return nil, fmt.Errorf("policy: sandbox eval: %w", err)
	}
	return &SandboxOutput{
		AllowedEndpoints:  toStringSlice(result, "allowed_endpoints"),
		DeniedEndpoints:   toStringSlice(result, "denied_endpoints"),
		DeniedFromRequest: toStringSlice(result, "denied_from_request"),
		Permissions:       toStringSlice(result, "permissions"),
		AllowedSkills:     toStringSlice(result, "allowed_skills"),
	}, nil
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// EvaluateAudit runs the audit retention/export policy for a given event.
func (e *Engine) EvaluateAudit(ctx context.Context, input AuditInput) (*AuditOutput, error) {
	result, err := e.eval(ctx, "data.defenseclaw.audit", input)
	if err != nil {
		return nil, fmt.Errorf("policy: audit eval: %w", err)
	}
	return &AuditOutput{
		Retain:       boolVal(result, "retain"),
		RetainReason: stringVal(result, "retain_reason"),
		ExportTo:     toStringSlice(result, "export_to"),
	}, nil
}

// ---------------------------------------------------------------------------
// Skill Actions
// ---------------------------------------------------------------------------

// EvaluateSkillActions runs the skill_actions policy to map severity to actions.
func (e *Engine) EvaluateSkillActions(ctx context.Context, input SkillActionsInput) (*SkillActionsOutput, error) {
	result, err := e.eval(ctx, "data.defenseclaw.skill_actions", input)
	if err != nil {
		return nil, fmt.Errorf("policy: skill_actions eval: %w", err)
	}
	return &SkillActionsOutput{
		RuntimeAction: stringVal(result, "runtime_action"),
		FileAction:    stringVal(result, "file_action"),
		InstallAction: stringVal(result, "install_action"),
		ShouldBlock:   boolVal(result, "should_block"),
	}, nil
}

// ---------------------------------------------------------------------------
// Compile
// ---------------------------------------------------------------------------

// Compile performs a one-time compilation check of the Rego modules,
// useful for fast-failing at startup.
func (e *Engine) Compile() error {
	modules, err := readModules(e.regoDir, e)
	if err != nil {
		return err
	}
	return compileModules(modules)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (e *Engine) eval(ctx context.Context, query string, input interface{}) (map[string]interface{}, error) {
	start := time.Now()
	e.mu.RLock()
	store := e.store
	otelProv := e.otel
	e.mu.RUnlock()

	inputMap, err := toMap(input)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}
	rawIn, _ := json.Marshal(inputMap)
	sum := sha256.Sum256(rawIn)
	inputHash := hex.EncodeToString(sum[:16])
	policyID := e.policyStableID()

	ctx, span := otel.Tracer("defenseclaw").Start(ctx, "defenseclaw.policy.evaluate", trace.WithSpanKind(trace.SpanKindInternal))
	span.SetAttributes(
		attribute.String("policy_id", policyID),
		attribute.String("input_hash", inputHash),
		attribute.String("policy.query", query),
	)

	modules, err := readModules(e.regoDir, e)
	if err != nil {
		durationMs := float64(time.Since(start).Milliseconds())
		e.finishPolicyEvalSpan(span, policyID, inputHash, "error", durationMs, err)
		e.recordPolicyEvalMetrics(ctx, otelProv, policyID, "error", durationMs)
		return nil, err
	}
	span.SetAttributes(attribute.Int("policy.module_count", len(modules)))

	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Store(store),
		rego.Input(inputMap),
	}
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}

	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		durationMs := float64(time.Since(start).Milliseconds())
		e.finishPolicyEvalSpan(span, policyID, inputHash, "error", durationMs, err)
		e.recordPolicyEvalMetrics(ctx, otelProv, policyID, "error", durationMs)
		return nil, err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		err := fmt.Errorf("empty result set")
		durationMs := float64(time.Since(start).Milliseconds())
		e.finishPolicyEvalSpan(span, policyID, inputHash, "empty", durationMs, err)
		e.recordPolicyEvalMetrics(ctx, otelProv, policyID, "empty", durationMs)
		return nil, err
	}

	result, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		err := fmt.Errorf("unexpected result type %T", rs[0].Expressions[0].Value)
		durationMs := float64(time.Since(start).Milliseconds())
		e.finishPolicyEvalSpan(span, policyID, inputHash, "error", durationMs, err)
		e.recordPolicyEvalMetrics(ctx, otelProv, policyID, "error", durationMs)
		return nil, err
	}

	resultStr := stringVal(result, "verdict")
	if resultStr == "" {
		resultStr = "ok"
	}
	durationMs := float64(time.Since(start).Milliseconds())
	e.finishPolicyEvalSpan(span, policyID, inputHash, resultStr, durationMs, nil)
	e.recordPolicyEvalMetrics(ctx, otelProv, policyID, resultStr, durationMs)
	return result, nil
}

func (e *Engine) policyStableID() string {
	sum := sha256.Sum256([]byte(e.regoDir))
	return hex.EncodeToString(sum[:6])
}

func (e *Engine) finishPolicyEvalSpan(span trace.Span, policyID, inputHash, result string, durationMs float64, err error) {
	if span == nil {
		return
	}
	span.SetAttributes(
		attribute.Float64("duration_ms", durationMs),
		attribute.String("result", result),
		attribute.String("policy_id", policyID),
		attribute.String("input_hash", inputHash),
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

func (e *Engine) recordPolicyEvalMetrics(ctx context.Context, otel *telemetry.Provider, policyID, verdict string, durationMs float64) {
	if otel == nil {
		return
	}
	otel.RecordPolicyEvaluation(ctx, policyID, verdict)
	otel.RecordPolicyLatency(ctx, policyID, durationMs)
}

func (e *Engine) emitPolicyLoadOrEvalError(ctx context.Context, err error) {
	e.mu.RLock()
	otel := e.otel
	e.mu.RUnlock()
	if otel == nil || !otel.Enabled() {
		return
	}
	msg := err.Error()
	otel.EmitGatewayEvent(gatewaylog.Event{
		Timestamp: time.Now().UTC(),
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(gatewaylog.SubsystemPolicy),
			Code:      string(gatewaylog.ErrCodePolicyLoadFailed),
			Message:   "OPA policy evaluation failed",
			Cause:     msg,
		},
	})
}

func loadStore(regoDir string) (storage.Store, error) {
	raw, err := readDataJSON(regoDir)
	if err != nil {
		return nil, fmt.Errorf("policy: read data.json: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("policy: parse data.json: %w", err)
	}

	mergeSupplementalData(regoDir, data, "data-sandbox.json")

	return inmem.NewFromObject(data), nil
}

// mergeSupplementalData reads a JSON file from regoDir and merges its
// top-level keys into data. Missing files are silently skipped.
func mergeSupplementalData(regoDir string, data map[string]interface{}, filename string) {
	path := filepath.Join(regoDir, filename)
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var extra map[string]interface{}
	if err := json.Unmarshal(raw, &extra); err != nil {
		return
	}
	for k, v := range extra {
		data[k] = v
	}
}

func readModules(regoDir string, eng *Engine) (map[string]string, error) {
	pattern := filepath.Join(regoDir, "*.rego")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("policy: glob rego files: %w", err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("policy: no .rego files found in %s", regoDir)
	}

	modules := make(map[string]string, len(matches))
	for _, path := range matches {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("policy: read %s: %w", path, readErr)
		}
		base := filepath.Base(path)
		if _, parseErr := ast.ParseModuleWithOpts(base, string(raw), ast.ParserOptions{RegoVersion: ast.RegoV1}); parseErr != nil {
			if eng != nil {
				_ = eng.quarantineBadRegoModule(path, raw)
			}
			return nil, fmt.Errorf("policy: parse %s: %w", path, parseErr)
		}
		modules[base] = string(raw)
	}
	return modules, nil
}

func (e *Engine) quarantineBadRegoModule(srcPath string, raw []byte) error {
	destDir := filepath.Join(e.regoDir, ".policy_quarantine")
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return err
	}
	dest := filepath.Join(destDir, fmt.Sprintf("%s.%d.bak", filepath.Base(srcPath), time.Now().UnixNano()))
	if err := os.WriteFile(dest, raw, 0o600); err != nil {
		return err
	}
	return os.Remove(srcPath)
}

func compileModules(modules map[string]string) error {
	parsed := make(map[string]*ast.Module, len(modules))
	for name, src := range modules {
		mod, parseErr := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if parseErr != nil {
			return fmt.Errorf("policy: parse %s: %w", name, parseErr)
		}
		parsed[name] = mod
	}

	compiler := ast.NewCompiler()
	compiler.Compile(parsed)
	if compiler.Failed() {
		return fmt.Errorf("policy: compile: %v", compiler.Errors)
	}
	return nil
}

func toMap(v interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func stringVal(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// intVal pulls an integer out of an OPA result map. OPA's JSON
// numbers ride in as either json.Number or float64 depending on the
// runtime path; both shapes are handled. Returns 0 when missing or
// unconvertible.
func intVal(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		if iv, err := n.Int64(); err == nil {
			return int(iv)
		}
		if fv, err := n.Float64(); err == nil {
			return int(fv)
		}
	}
	return 0
}

func boolVal(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		return false
	}
	return b
}

func toStringSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key]
	if !ok {
		return nil
	}

	switch v := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}
