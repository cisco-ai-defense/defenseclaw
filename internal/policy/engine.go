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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"           //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/rego"          //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage"       //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage/inmem" //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

// Engine evaluates OPA Rego policies for admission, guardrail, firewall,
// sandbox, audit, and skill_actions domains.
type Engine struct {
	mu      sync.RWMutex
	regoDir string
	store   storage.Store
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

// resolveRegoDir picks the directory the OPA store should load from when
// the caller passes a parent like “~/.defenseclaw/policies“. The canonical
// install layout writes Rego modules under “<dir>/rego/“; older releases
// (≤0.3.x) wrote them flat at “<dir>/“. A buggy upgrade path could leave
// BOTH copies on disk — and the loader would silently pick the wrong one
// because the previous ordering preferred the parent first.
//
// The bug surfaced as: HILT confirmation never triggered for prompt-side
// findings. With both layouts present, the loader picked the stale flat
// “guardrail.rego“ (no “confirm“ branch, no “_hilt_*“ rules) while
// reading the up-to-date “data.guardrail.hilt“ from “<dir>/rego/data.json“
// via the fallback path in “readDataJSON“. Net effect: every HIGH-severity
// prompt finding came back as “alert“ instead of “confirm“, and the
// HILT dialog only appeared on tool calls (which run through a separate,
// non-Rego decision tree in “internal/gateway/decision.go“).
//
// Fix: always prefer “<dir>/rego/“ when it has .rego files. The flat
// layout is honored only when no nested “rego/“ directory exists, so
// existing single-layout installs (and unit tests that drop .rego files
// directly into “t.TempDir()“) keep working unchanged.
//
// A complementary Python migration (“_migrate_0_5_0“ in
// “cli/defenseclaw/migrations.py“) deletes the stale flat copies on
// upgrade so operators don't carry the residue forever.
func resolveRegoDir(dir string) string {
	sub := filepath.Join(dir, "rego")
	if hasRegoFiles(sub) {
		return sub
	}
	if hasRegoFiles(dir) {
		return dir
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
		Action:         stringVal(result, "action"),
		Severity:       stringVal(result, "severity"),
		Reason:         stringVal(result, "reason"),
		ScannerSources: sources,
	}, nil
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
	e.mu.RLock()
	store := e.store
	e.mu.RUnlock()

	inputMap, err := toMap(input)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}
	modules, err := readModules(e.regoDir, e)
	if err != nil {
		return nil, err
	}

	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Store(store),
		rego.Input(inputMap),
		// PR #141 audit H4: harden the OPA evaluator against
		// user-supplied Rego that ships in policy bundles. The
		// default builtins surface includes:
		//   - http.send         — outbound network from the eval path
		//   - opa.runtime       — leaks build/host info
		//   - net.lookup_ip_addr — DNS probing primitive
		// These are network/info-disclosure vectors that policy
		// authors should never need from inside a guardrail rule.
		// StrictBuiltinErrors flips silent builtin failures into hard
		// evaluation errors so a banned builtin can never be reached
		// behind a `with` shim and silently noop into a `pass` verdict.
		rego.UnsafeBuiltins(map[string]struct{}{
			"http.send":          {},
			"opa.runtime":        {},
			"net.lookup_ip_addr": {},
		}),
		rego.StrictBuiltinErrors(true),
	}
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}

	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return nil, err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		err := fmt.Errorf("empty result set")
		return nil, err
	}

	result, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		err := fmt.Errorf("unexpected result type %T", rs[0].Expressions[0].Value)
		return nil, err
	}
	return result, nil
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
