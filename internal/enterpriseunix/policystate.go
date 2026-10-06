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

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// codePolicyNotApplied warns that the running gateway reports a different
// effective policy than the committed config computes to.
const codePolicyNotApplied = "policy_not_applied"

// The effective policy (spec P0 section 5) is reported on every lifecycle
// result: the digest the committed config computes to, its
// config_generation, and whether the running gateway reports the same
// digest on /health. policy-state.json, next to deployment.json, records
// the last applied state; deployment.json itself is not extended because an
// earlier release decodes it strictly and must still read it after a
// rollback.

func (e *Env) policyStatePath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), enterprisestatus.PolicyStateFileName)
}

func (e *Env) loadPolicyState() (*enterprisestatus.PolicyStateRecord, error) {
	data, err := readBounded(e.policyStatePath(), maxInputBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record enterprisestatus.PolicyStateRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parse %s: %w", enterprisestatus.PolicyStateFileName, err)
	}
	return &record, nil
}

func (e *Env) savePolicyState(record enterprisestatus.PolicyStateRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFileAtomic(e.policyStatePath(), append(data, '\n'), 0o600, rootOwner())
}

// gatewayPolicyDigest is policy.effective_digest from a /health body, ""
// when the gateway does not publish it.
func gatewayPolicyDigest(body []byte) string {
	var health struct {
		Policy *struct {
			EffectiveDigest string `json:"effective_digest"`
		} `json:"policy"`
	}
	if json.Unmarshal(body, &health) != nil || health.Policy == nil {
		return ""
	}
	return health.Policy.EffectiveDigest
}

// computePolicy runs the installed gateway's `policy digest` with the
// service environment, so the digest is computed by the binary the gateway
// runs, from the config and assets it loads. ok is false when that binary
// cannot (an earlier release, or a status run that cannot read the inputs).
func (l *lifecycle) computePolicy(ctx context.Context) (digest string, configGeneration uint64, ok bool) {
	out, err := l.env.runGatewayCLI(ctx, "policy", "digest", "--json")
	if err != nil || out.ExitCode != 0 {
		return "", 0, false
	}
	var report struct {
		EffectiveDigest  string `json:"effective_digest"`
		ConfigGeneration uint64 `json:"config_generation"`
	}
	if json.Unmarshal(out.Stdout, &report) != nil || report.EffectiveDigest == "" {
		return "", 0, false
	}
	return report.EffectiveDigest, report.ConfigGeneration, true
}

// describePolicy fills Result.Policy. The digest is computed from the
// installed config (computePolicy); when that is not possible the last
// applied record stands in. A change action records policy-state.json once the gateway reports
// the computed digest, and warns when it reports another one.
func (l *lifecycle) describePolicy(ctx context.Context, reported string) {
	env, r := l.env, l.result
	state := &enterprisestatus.PolicyState{GatewayReportedDigest: reported}
	computed := false
	if digest, generation, ok := l.computePolicy(ctx); ok {
		state.EffectiveDigest, state.ConfigGeneration, computed = digest, generation, true
	}
	if !computed {
		if record, err := env.loadPolicyState(); err == nil && record != nil {
			state.EffectiveDigest, state.ConfigGeneration = record.EffectiveDigest, record.ConfigGeneration
		}
	}
	if state.EffectiveDigest == "" && reported == "" {
		return
	}
	state.Applied = state.EffectiveDigest != "" && state.EffectiveDigest == reported
	r.Policy = state
	if l.opts.Action == ActionStatus || l.opts.Action == ActionVerify || !computed || !r.Readiness.Gateway {
		return
	}
	if !state.Applied {
		r.AddWarning(codePolicyNotApplied, fmt.Sprintf(
			"the gateway reports effective policy %s but the installed config computes to %s; it applies the config on its next reload",
			shortDigest(reported), shortDigest(state.EffectiveDigest)))
		return
	}
	if err := env.savePolicyState(enterprisestatus.PolicyStateRecord{
		EffectiveDigest:  state.EffectiveDigest,
		ConfigGeneration: state.ConfigGeneration,
		AppliedAt:        env.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		r.AddWarning(codeState, "could not record "+enterprisestatus.PolicyStateFileName+": "+err.Error())
	}
}

// shortDigest is "sha256:" and the first 12 hex digits, or "none".
func shortDigest(digest string) string {
	if digest == "" {
		return "none"
	}
	if len(digest) > len("sha256:")+12 {
		return digest[:len("sha256:")+12]
	}
	return digest
}
