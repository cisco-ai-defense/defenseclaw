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

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// codePolicyNotApplied reports that the running gateway enforces a different
// effective policy than the committed config computes to.
const codePolicyNotApplied = "policy_not_applied"

// codePolicyReloadRejected reports that the gateway rejected its last policy
// reload and keeps enforcing the previous policy. Verify treats this as an error.
const codePolicyReloadRejected = "policy_reload_rejected"

// codePolicyUnverified warns, on every action, that the installed gateway
// could not compute the effective policy and no applied record stands in, so
// the result carries no policy object.
const codePolicyUnverified = "policy_unverified"

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

// gatewayPolicyHealth is policy.effective_digest and the current config or
// policy reload error from /health, "" for what the gateway does not publish.
func gatewayPolicyHealth(body []byte) (digest, reloadError string) {
	var health struct {
		Config struct {
			State     string `json:"state"`
			LastError string `json:"last_error"`
		} `json:"config"`
		Policy *struct {
			EffectiveDigest string `json:"effective_digest"`
			LastReloadError string `json:"last_reload_error"`
		} `json:"policy"`
	}
	if json.Unmarshal(body, &health) != nil || health.Policy == nil {
		return "", ""
	}
	reloadError = health.Policy.LastReloadError
	if reloadError == "" && health.Config.State == "error" {
		reloadError = health.Config.LastError
		if reloadError == "" {
			reloadError = "gateway config.state=error"
		}
	}
	return health.Policy.EffectiveDigest, reloadError
}

// computePolicy runs the installed gateway's `policy digest` with the
// service environment, so the digest is computed by the binary the gateway
// runs, from the config and assets it loads. err says why that binary
// cannot (an earlier release, or a status run that cannot read the inputs).
func (l *lifecycle) computePolicy(ctx context.Context) (digest string, configGeneration uint64, err error) {
	if c := l.noopPolicy; c != nil {
		l.noopPolicy = nil
		return c.digest, c.generation, nil
	}
	out, err := l.env.runGatewayCLI(ctx, "policy", "digest", "--json")
	if err == nil && out.ExitCode != 0 {
		err = fmt.Errorf("exit status %d", out.ExitCode)
	}
	if err != nil {
		if reason := firstLine(string(out.Stderr)); reason != "" {
			if len(reason) > 300 {
				reason = reason[:300]
			}
			err = fmt.Errorf("%w: %s", err, reason)
		}
		return "", 0, fmt.Errorf("policy digest: %w", err)
	}
	var report struct {
		EffectiveDigest  string `json:"effective_digest"`
		ConfigGeneration uint64 `json:"config_generation"`
	}
	if json.Unmarshal(out.Stdout, &report) != nil || report.EffectiveDigest == "" {
		return "", 0, errors.New("policy digest reported no effective policy digest")
	}
	return report.EffectiveDigest, report.ConfigGeneration, nil
}

// generationMismatch says how the generation the gateway reports differs
// from the installed config's generation record, "" when it is the same one.
// The hot settle of ensure, status and verify all use it (GAP-0943).
func generationMismatch(gateway bundleHealth, installed configwrite.GenerationState) string {
	switch {
	case gateway.configGeneration != installed.Generation:
		return fmt.Sprintf("gateway reports config generation %d, not lifecycle generation %d", gateway.configGeneration, installed.Generation)
	case gateway.bundleID != installed.BundleID || gateway.bundleVersion != installed.BundleVersion:
		return fmt.Sprintf("gateway reports bundle %q version %d, not lifecycle bundle %q version %d", gateway.bundleID, gateway.bundleVersion, installed.BundleID, installed.BundleVersion)
	}
	return ""
}

// installedGenerationMismatch is generationMismatch for the installed
// config.yaml outside bundle mode, where signed bundles confirm their own
// generation. A gateway that omits the generation does not confirm a recorded
// lifecycle generation, even when its policy digest matches.
func (l *lifecycle) installedGenerationMismatch(gateway bundleHealth) string {
	env := l.env
	if l.bundle != nil || env.bundleMode() {
		return ""
	}
	installed, err := configwrite.ReadGenerationState(env.P(env.Layout.ConfigPath))
	if err != nil {
		return "cannot read lifecycle generation record: " + err.Error()
	}
	if installed.Generation == 0 {
		return "lifecycle generation record has no generation"
	}
	if installed.BundleID != "" {
		return ""
	}
	return generationMismatch(gateway, installed)
}

// computedPolicy is one computePolicy answer.
type computedPolicy struct {
	digest     string
	generation uint64
}

// gatewayPolicyDigest is policy.effective_digest from a /health body.
func gatewayPolicyDigest(body []byte) string {
	digest, _ := gatewayPolicyHealth(body)
	return digest
}

// describePolicy fills Result.Policy. The digest is computed from the
// installed config (computePolicy); when that is not possible the last
// applied record stands in. With neither there is no digest to report and
// Result.Policy stays nil, as on Windows: the lifecycle-result schema
// requires effective_digest to be a sha256 digest. A change action records
// policy-state.json once the gateway reports the computed digest, and warns
// when it reports another one. A reload the gateway rejected (reloadError)
// is never "applied", and every action reports it, with or without a digest:
// the gateway keeps enforcing the previous policy. Neither is a gateway that
// runs another lifecycle generation than the installed config records. Verify
// and a committed change (confirmCommitted) fail on these; status warns.
func (l *lifecycle) describePolicy(ctx context.Context, reported, reloadError string, gateway bundleHealth) {
	env, r := l.env, l.result
	report := r.AddWarning
	if l.opts.Action == ActionVerify || l.confirmCommitted {
		report = r.AddError
	}
	state := &enterprisestatus.PolicyState{GatewayReportedDigest: reported, LastReloadError: reloadError}
	computed := false
	// A same-build bundle already had its rendered policy computed during
	// verification. Match the installed bytes and writer record to this
	// transaction before using that digest, including before the receipt is
	// confirmed.
	// Avoid a third full generation build in a separate CLI during hot apply.
	if l.bundle != nil && l.bundle.receipt != nil {
		rc := l.bundle.receipt
		wantSHA := rc.ConfigSHA256
		if wantSHA == "" {
			wantSHA = l.bundle.configSHA
		}
		if rc.DigestComparable && rc.ExpectedDigest != "" && wantSHA != "" {
			path := env.P(env.Layout.ConfigPath)
			if sha, err := sha256File(path); err == nil && sha == wantSHA {
				if generation, err := configwrite.ReadGenerationState(path); err == nil &&
					generation.BundleID == rc.BundleID && generation.BundleVersion == rc.Version &&
					generation.ConfigSHA256 == sha {
					state.EffectiveDigest, state.ConfigGeneration, computed = rc.ExpectedDigest, generation.Generation, true
				}
			}
		}
	}
	var computeErr error
	if !computed {
		var digest string
		var generation uint64
		if digest, generation, computeErr = l.computePolicy(ctx); computeErr == nil {
			state.EffectiveDigest, state.ConfigGeneration, computed = digest, generation, true
		}
	}
	if !computed {
		if record, err := env.loadPolicyState(); err == nil && record != nil {
			state.EffectiveDigest, state.ConfigGeneration = record.EffectiveDigest, record.ConfigGeneration
		}
	}
	if reloadError != "" {
		message := "the gateway reports a policy error and keeps enforcing the policy it last built: " + reloadError +
			"; fix the asset or the config it names, and the gateway clears this when the next reload succeeds"
		report(codePolicyReloadRejected, message)
	}
	if state.EffectiveDigest == "" {
		// Without a computed digest or an applied record, no action can
		// certify the policy the gateway enforces. Verify and a committed
		// change fail with the cause; status and a no-op ensure warn.
		reason := "no effective policy digest or applied policy record is available"
		if computeErr != nil {
			reason = computeErr.Error()
		}
		report(codePolicyUnverified, "the effective policy the gateway enforces could not be checked: "+reason)
		return
	}
	generation := l.installedGenerationMismatch(gateway)
	state.Applied = state.EffectiveDigest == reported && reloadError == "" && generation == ""
	r.Policy = state
	if !state.Applied && computed && r.Readiness.Gateway && reloadError == "" {
		message := fmt.Sprintf(
			"the gateway reports effective policy %s but the installed config computes to %s; the gateway keeps enforcing the policy it last built",
			shortDigest(reported), shortDigest(state.EffectiveDigest))
		if state.EffectiveDigest == reported {
			message = generation + "; the gateway keeps enforcing the generation it last applied"
		}
		report(codePolicyNotApplied, message)
	}
	if l.opts.Action == ActionStatus || l.opts.Action == ActionVerify || !computed || !r.Readiness.Gateway || !state.Applied {
		return
	}
	if err := env.savePolicyState(env.withBundleFields(enterprisestatus.PolicyStateRecord{
		EffectiveDigest:  state.EffectiveDigest,
		ConfigGeneration: state.ConfigGeneration,
		AppliedAt:        env.Now().UTC().Format(time.RFC3339),
	})); err != nil {
		r.AddWarning(stateWriteCode(err, codeState), "could not record "+enterprisestatus.PolicyStateFileName+": "+err.Error())
	}
}

// gatewayKernelPolicy reads, from a /health body, the kernel_policy digest
// the sensor helper reports it applies (policy.kernel.kernel_policy) and the
// kernel_policy component of the gateway's policy generation
// (policy.components.kernel_policy, present only where the deployment loads
// kernel controls). Either is "" when the gateway does not publish it.
func gatewayKernelPolicy(body []byte) (applied, generation string) {
	var health struct {
		Policy *struct {
			Components map[string]string `json:"components"`
			Kernel     *struct {
				KernelPolicy string `json:"kernel_policy"`
			} `json:"kernel"`
		} `json:"policy"`
	}
	if json.Unmarshal(body, &health) != nil || health.Policy == nil {
		return "", ""
	}
	if health.Policy.Kernel != nil {
		applied = health.Policy.Kernel.KernelPolicy
	}
	return applied, health.Policy.Components["kernel_policy"]
}

// describeKernelPolicy warns when the sensor helper applies another kernel
// control set than the gateway's policy generation names: the helper did
// not restart into this build. Both are compared as the 12-digit prefix an
// administrator approves.
func (l *lifecycle) describeKernelPolicy(applied, generation string) {
	if applied == "" || generation == "" || shortDigest(applied) == shortDigest(generation) {
		return
	}
	l.result.AddWarning(codeKernelPolicyNotApplied, tetragonMessage(codeKernelPolicyNotApplied,
		tetragonFacts{Variant: variantGeneration, Applied: shortDigest(applied), Digest: shortDigest(generation)}))
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
