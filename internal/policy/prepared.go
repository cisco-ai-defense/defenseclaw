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
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/open-policy-agent/opa/rego"          //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage"       //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage/inmem" //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

const (
	admissionQuery = "data.defenseclaw.admission"
	guardrailQuery = "data.defenseclaw.guardrail"
)

// Prepare reads the .rego modules of regoDir (or its rego/ subdirectory)
// once and prepares the admission and guardrail queries. The gateway calls
// it once per configuration generation; every evaluation reuses the
// prepared queries. A module that fails to parse or compile is an error and
// nothing on disk is moved. data.json is optional input while admission
// still reads it.
func Prepare(ctx context.Context, regoDir string) (*Prepared, error) {
	regoDir = resolveRegoDir(regoDir)
	modules, err := readModules(regoDir, nil)
	if err != nil {
		return nil, err
	}
	if err := compileModules(modules); err != nil {
		return nil, err
	}
	store, err := loadOptionalStore(regoDir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, name := range names {
		fmt.Fprintf(digest, "%d:%s%d:", len(name), name, len(modules[name]))
		digest.Write([]byte(modules[name]))
	}
	admission, err := prepareQuery(ctx, admissionQuery, names, modules, store)
	if err != nil {
		return nil, fmt.Errorf("policy: prepare admission: %w", err)
	}
	guardrail, err := prepareQuery(ctx, guardrailQuery, names, modules, store)
	if err != nil {
		return nil, fmt.Errorf("policy: prepare guardrail: %w", err)
	}
	return &Prepared{
		Admission:  admission,
		Guardrail:  guardrail,
		RegoDigest: "sha256:" + hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

func prepareQuery(ctx context.Context, query string, names []string, modules map[string]string, store storage.Store) (rego.PreparedEvalQuery, error) {
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Store(store),
		// Same hardening as Engine.eval: no network or host-information
		// builtins, and builtin errors are evaluation errors.
		rego.UnsafeBuiltins(map[string]struct{}{
			"http.send":          {},
			"opa.runtime":        {},
			"net.lookup_ip_addr": {},
		}),
		rego.StrictBuiltinErrors(true),
	}
	for _, name := range names {
		opts = append(opts, rego.Module(name, modules[name]))
	}
	return rego.New(opts...).PrepareForEval(ctx)
}

func loadOptionalStore(regoDir string) (storage.Store, error) {
	raw, err := readDataJSON(regoDir)
	if errors.Is(err, fs.ErrNotExist) {
		return inmem.New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("policy: read data.json: %w", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("policy: parse data.json: %w", err)
	}
	return inmem.NewFromObject(data), nil
}

// EvaluateGuardrail runs the prepared guardrail query.
func (p *Prepared) EvaluateGuardrail(ctx context.Context, input GuardrailInput) (*GuardrailOutput, error) {
	if p == nil {
		return nil, errors.New("policy: guardrail policy is not prepared")
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

// EvaluateAdmission runs the prepared admission query. Like
// Engine.Evaluate, an evaluation failure is a fail-closed rejection.
func (p *Prepared) EvaluateAdmission(ctx context.Context, input AdmissionInput) (*AdmissionOutput, error) {
	if p == nil {
		return nil, errors.New("policy: admission policy is not prepared")
	}
	result, err := evalPrepared(ctx, p.Admission, input)
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
		return nil, errors.New("empty result set")
	}
	result, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", rs[0].Expressions[0].Value)
	}
	return result, nil
}
