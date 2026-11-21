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
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"  //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/rego" //nolint:staticcheck // v0 compat; migrate to opa/v1 later

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The cascade policy is the customer's Rego final-decision hook
// (guardrail.cascade.policy.module): one module, package
// defenseclaw.cascade, whose partial set rule `decisions` holds
// {"action", "reason", "id"} objects. The gateway takes the strictest
// decision and clamps it to the administrator's limits; no decision leaves
// the cascade's action. It is a separate module from policies/rego, so an
// upgrade never overwrites it, and it is pinned by its sha256.

const (
	// CascadePackage is the package the module must declare.
	CascadePackage = "defenseclaw.cascade"
	cascadeQuery   = "data.defenseclaw.cascade.decisions"
	// maxCascadeDecisions bounds what one evaluation may return.
	maxCascadeDecisions = 32
	maxCascadeReason    = 200
	maxCascadeID        = 64
)

// CascadeDecision is one element of data.defenseclaw.cascade.decisions.
type CascadeDecision struct {
	Action string
	Reason string
	// ID names the rule that made the decision (the "id" field, else the
	// reason), so explain and the audit row can say which rule set the
	// final action.
	ID string
}

// CascadePolicy is a prepared cascade module.
type CascadePolicy struct {
	query  rego.PreparedEvalQuery
	Digest string
}

func init() {
	config.RegisterCascadePolicyCheck(func(src []byte) error {
		_, err := PrepareCascade(context.Background(), src)
		return err
	})
}

// PrepareCascade parses, checks and prepares a cascade module.
func PrepareCascade(ctx context.Context, src []byte) (*CascadePolicy, error) {
	if len(src) == 0 {
		return nil, errors.New("empty module")
	}
	mod, err := ast.ParseModuleWithOpts("cascade.rego", string(src), ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if got := strings.TrimPrefix(mod.Package.Path.String(), "data."); got != CascadePackage {
		return nil, fmt.Errorf("the module declares package %s, want package %s", got, CascadePackage)
	}
	compiler := ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{"cascade.rego": mod})
	if compiler.Failed() {
		return nil, fmt.Errorf("compile: %v", compiler.Errors)
	}
	query, err := rego.New(regoOptions(cascadeQuery, map[string]string{"cascade.rego": string(src)})...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare: %w", err)
	}
	sum := sha256.Sum256(src)
	return &CascadePolicy{query: query, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// Evaluate runs the module on input. An undefined decisions rule is no
// decision. A decision that is not an object with a known action, or more
// than 32 decisions, is an error: the caller treats the call as unknown.
func (p *CascadePolicy) Evaluate(ctx context.Context, input map[string]any) ([]CascadeDecision, error) {
	if p == nil {
		return nil, nil
	}
	rs, err := p.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	raw, ok := rs[0].Expressions[0].Value.([]any)
	if !ok {
		return nil, fmt.Errorf("decisions is %T, want a set of objects", rs[0].Expressions[0].Value)
	}
	if len(raw) > maxCascadeDecisions {
		return nil, fmt.Errorf("%d decisions, at most %d", len(raw), maxCascadeDecisions)
	}
	out := make([]CascadeDecision, 0, len(raw))
	for i, item := range raw {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("decision %d is %T, want an object", i, item)
		}
		action, _ := obj["action"].(string)
		action = strings.ToLower(strings.TrimSpace(action))
		if config.CascadeActionRank(action) < 0 || action == "ask" || action == "deny" {
			return nil, fmt.Errorf("decision %d: action %q is not one of allow, log, alert, confirm, block", i, obj["action"])
		}
		reason, _ := obj["reason"].(string)
		id, _ := obj["id"].(string)
		reason, id = bound(strings.TrimSpace(reason), maxCascadeReason), bound(strings.TrimSpace(id), maxCascadeID)
		if id == "" {
			id = bound(reason, maxCascadeID)
		}
		out = append(out, CascadeDecision{Action: action, Reason: reason, ID: id})
	}
	return out, nil
}

func bound(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}
