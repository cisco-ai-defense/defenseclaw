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
	"sort"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"  //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/rego" //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

const (
	admissionQuery = "data.defenseclaw.admission"
	guardrailQuery = "data.defenseclaw.guardrail"
)

// DefaultThresholds is input.thresholds when a guardrail caller passes none:
// block at CRITICAL, alert at MEDIUM, full Cisco AI Defense trust.
var DefaultThresholds = ThresholdsInput{Block: 4, Alert: 2, CiscoTrustLevel: "full"}

// Engine evaluates the admission and guardrail Rego policies. It loads only
// .rego modules: every policy input (admission, block/allow lists,
// thresholds, HILT) comes from config.yaml through the evaluation input, so
// there is no data.json. The queries are prepared once per load; Reload
// re-reads the modules and swaps them atomically.
type Engine struct {
	mu                sync.RWMutex
	regoDir           string
	quarantineInvalid bool
	prepared          *Prepared
}

// New creates an Engine from the Rego modules in regoDir. If regoDir itself
// does not contain .rego files but a "rego" subdirectory does, the
// subdirectory is used instead. A module that fails to parse is moved to
// <regoDir>/.policy_quarantine and the load fails.
func New(regoDir string) (*Engine, error) {
	e := &Engine{regoDir: resolveRegoDir(regoDir), quarantineInvalid: true}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

// NewExact creates a read-only Engine for a caller that has already selected
// the policy layout. It never quarantines or removes a Rego module when
// parsing fails.
func NewExact(regoDir string) (*Engine, error) {
	e := &Engine{regoDir: regoDir}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
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
// reading the up-to-date HILT data from the nested directory. Net effect:
// every HIGH-severity
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Only a genuinely absent directory permits legacy fallback. An
		// inaccessible or non-directory canonical path is evidence that must
		// fail closed when the engine attempts to load it.
		_, statErr := os.Lstat(dir)
		return !os.IsNotExist(statErr)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".rego" {
			return true
		}
	}
	return false
}

// Reload re-reads every .rego module and prepares the queries again,
// replacing them atomically. On a parse or compile error the previous
// modules stay in use and the error is returned.
func (e *Engine) Reload() error {
	modules, err := readModules(e.regoDir, e.quarantineTarget())
	if err != nil {
		return err
	}
	prepared, err := prepareModules(context.Background(), modules)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.prepared = prepared
	e.mu.Unlock()
	return nil
}

// Compile re-checks that the modules on disk still parse and compile,
// without replacing the prepared queries.
func (e *Engine) Compile() error {
	modules, err := readModules(e.regoDir, e.quarantineTarget())
	if err != nil {
		return err
	}
	return compileModules(modules)
}

// RegoDir returns the directory the engine loads Rego files from.
func (e *Engine) RegoDir() string {
	return e.regoDir
}

// Prepared returns the queries prepared by the last successful load.
func (e *Engine) Prepared() *Prepared {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.prepared
}

// Prepare reads the .rego modules of regoDir (or its rego/ subdirectory,
// as New does) without quarantining, and prepares the admission and
// guardrail queries once. The gateway calls it once per configuration
// generation; every evaluation reuses the prepared queries.
func Prepare(ctx context.Context, regoDir string) (*Prepared, error) {
	modules, err := readModules(resolveRegoDir(regoDir), nil)
	if err != nil {
		return nil, err
	}
	return prepareModules(ctx, modules)
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

// Evaluate runs the admission policy against the provided input and returns
// the verdict, reason, file_action, install_action, and runtime_action. An
// evaluation failure is a fail-closed rejection, never an error.
func (e *Engine) Evaluate(ctx context.Context, input AdmissionInput) (*AdmissionOutput, error) {
	return e.Prepared().EvaluateAdmission(ctx, input)
}

// EvaluateAdmission evaluates the prepared admission query. An evaluation
// failure is a fail-closed rejection, never an error.
func (p *Prepared) EvaluateAdmission(ctx context.Context, input AdmissionInput) (*AdmissionOutput, error) {
	var result map[string]interface{}
	var err error
	if p == nil {
		err = fmt.Errorf("policy: no prepared admission query")
	} else {
		result, err = evalPrepared(ctx, p.Admission, input)
	}
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
	return e.Prepared().EvaluateGuardrail(ctx, input)
}

// EvaluateGuardrail evaluates the prepared guardrail query. A nil
// input.Thresholds uses DefaultThresholds.
func (p *Prepared) EvaluateGuardrail(ctx context.Context, input GuardrailInput) (*GuardrailOutput, error) {
	if p == nil {
		return nil, fmt.Errorf("policy: guardrail eval: no prepared guardrail query")
	}
	if input.Thresholds == nil {
		defaults := DefaultThresholds
		input.Thresholds = &defaults
	}
	result, err := evalPrepared(ctx, p.Guardrail, input)
	if err != nil {
		return nil, fmt.Errorf("policy: guardrail eval: %w", err)
	}
	return &GuardrailOutput{
		Action:         stringVal(result, "action"),
		Severity:       stringVal(result, "severity"),
		Reason:         stringVal(result, "reason"),
		ScannerSources: toStringSlice(result, "scanner_sources"),
	}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (e *Engine) quarantineTarget() *Engine {
	if e.quarantineInvalid {
		return e
	}
	return nil
}

// regoOptions hardens the OPA evaluator against user-supplied Rego that
// ships in policy bundles (PR #141 audit H4). The default builtins include
// http.send (outbound network), opa.runtime (build/host info) and
// net.lookup_ip_addr (DNS probing); policy authors never need them.
// StrictBuiltinErrors turns silent builtin failures into evaluation errors
// so a banned builtin can never be reached behind a `with` shim and noop
// into a pass verdict.
func regoOptions(query string, modules map[string]string) []func(*rego.Rego) {
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.UnsafeBuiltins(map[string]struct{}{
			"http.send":          {},
			"opa.runtime":        {},
			"net.lookup_ip_addr": {},
		}),
		rego.StrictBuiltinErrors(true),
	}
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		opts = append(opts, rego.Module(name, modules[name]))
	}
	return opts
}

func prepareModules(ctx context.Context, modules map[string]string) (*Prepared, error) {
	if err := compileModules(modules); err != nil {
		return nil, err
	}
	admission, err := rego.New(regoOptions(admissionQuery, modules)...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: prepare admission: %w", err)
	}
	guardrail, err := rego.New(regoOptions(guardrailQuery, modules)...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: prepare guardrail: %w", err)
	}
	return &Prepared{Admission: admission, Guardrail: guardrail, RegoDigest: regoDigest(modules)}, nil
}

// regoDigest is "sha256:" + the hex sha256 of the sorted (name, bytes) pairs.
func regoDigest(modules map[string]string) string {
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		fmt.Fprintf(h, "%d:%s%d:", len(name), name, len(modules[name]))
		h.Write([]byte(modules[name]))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func evalPrepared(ctx context.Context, query rego.PreparedEvalQuery, input interface{}) (map[string]interface{}, error) {
	inputMap, err := toMap(input)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}
	rs, err := query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("empty result set")
	}
	result, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", rs[0].Expressions[0].Value)
	}
	return result, nil
}

func readModules(regoDir string, eng *Engine) (map[string]string, error) {
	entries, err := os.ReadDir(regoDir)
	if err != nil {
		return nil, fmt.Errorf("policy: read rego directory: %w", err)
	}

	modules := make(map[string]string)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".rego" {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil, fmt.Errorf("policy: inspect %s: %w", entry.Name(), infoErr)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("policy: Rego module %s is not a regular file", entry.Name())
		}

		path := filepath.Join(regoDir, entry.Name())
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("policy: read %s: %w", path, readErr)
		}
		base := entry.Name()
		if _, parseErr := ast.ParseModuleWithOpts(base, string(raw), ast.ParserOptions{RegoVersion: ast.RegoV1}); parseErr != nil {
			if eng != nil {
				_ = eng.quarantineBadRegoModule(path, raw)
			}
			return nil, fmt.Errorf("policy: parse %s: %w", path, parseErr)
		}
		modules[base] = string(raw)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("policy: no .rego files found in %s", regoDir)
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
		if err := checkNoLegacyData(name, mod); err != nil {
			return err
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

// checkNoLegacyData refuses an admission or guardrail module that reads
// data.* outside data.defenseclaw: a pre-9 module that still expects
// data.json (data.config, data.actions, data.guardrail, ...). Since 9 every
// such value is evaluation input, so a stale module would see none of them
// and fail open (admission "warning", guardrail "allow"); refusing it sends
// the gateway to the config-driven fallback instead.
func checkNoLegacyData(name string, mod *ast.Module) error {
	if mod == nil || mod.Package == nil {
		return nil
	}
	pkg := mod.Package.Path.String()
	if pkg != admissionQuery && pkg != guardrailQuery {
		return nil
	}
	var legacy string
	ast.WalkRefs(mod, func(ref ast.Ref) bool {
		if legacy != "" || len(ref) < 2 || !ref[0].Equal(ast.DefaultRootDocument) {
			return legacy != ""
		}
		if key, ok := ref[1].Value.(ast.String); ok && string(key) != "defenseclaw" {
			legacy = "data." + string(key)
		}
		return legacy != ""
	})
	if legacy != "" {
		return fmt.Errorf("policy: %s reads %s, which config_version 9 no longer provides "+
			"(the data.json values moved into config.yaml); replace it with the shipped module "+
			"(defenseclaw-gateway config migrate --to 9 refreshes it)", name, legacy)
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
