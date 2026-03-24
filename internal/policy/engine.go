package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/ast"            //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/rego"           //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage"        //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage/inmem"  //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

// Engine evaluates OPA Rego policies for the admission gate.
type Engine struct {
	regoDir string
	store   storage.Store
}

// New creates an Engine. regoDir is the path to the directory containing
// the Rego modules and data.json (e.g. policies/rego/).
func New(regoDir string) (*Engine, error) {
	dataPath := filepath.Join(regoDir, "data.json")
	raw, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, fmt.Errorf("policy: read data.json: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("policy: parse data.json: %w", err)
	}

	store := inmem.NewFromObject(data)
	return &Engine{regoDir: regoDir, store: store}, nil
}

// Evaluate runs the admission policy against the provided input and returns
// the verdict, reason, and file_action.
func (e *Engine) Evaluate(ctx context.Context, input AdmissionInput) (*AdmissionOutput, error) {
	modules, err := e.loadModules()
	if err != nil {
		return nil, err
	}

	inputMap, err := toMap(input)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal input: %w", err)
	}

	opts := []func(*rego.Rego){
		rego.Query("data.defenseclaw.admission"),
		rego.Store(e.store),
		rego.Input(inputMap),
	}
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}

	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: eval: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("policy: empty result set")
	}

	result, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("policy: unexpected result type %T", rs[0].Expressions[0].Value)
	}

	out := &AdmissionOutput{
		Verdict:    stringVal(result, "verdict"),
		Reason:     stringVal(result, "reason"),
		FileAction: stringVal(result, "file_action"),
	}
	return out, nil
}

// Compile performs a one-time compilation check of the Rego modules,
// useful for fast-failing at startup.
func (e *Engine) Compile() error {
	modules, err := e.loadModules()
	if err != nil {
		return err
	}

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

func (e *Engine) loadModules() (map[string]string, error) {
	pattern := filepath.Join(e.regoDir, "*.rego")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("policy: glob rego files: %w", err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("policy: no .rego files found in %s", e.regoDir)
	}

	modules := make(map[string]string, len(matches))
	for _, path := range matches {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("policy: read %s: %w", path, readErr)
		}
		modules[filepath.Base(path)] = string(raw)
	}
	return modules, nil
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
