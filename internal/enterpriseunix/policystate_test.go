// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// policyDigestRunner answers the installed gateway's `policy digest --json`;
// an empty digest makes it fail, as it does when a pack no longer matches its pin.
type policyDigestRunner struct {
	*fakeRunner
	digest string
	// refusal, when set, is why the gateway binary refuses the policy.
	refusal string
}

func (r *policyDigestRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if strings.Join(args, " ") == "policy digest --json" {
		if r.refusal != "" {
			return CommandResult{Stderr: []byte("Error: policy digest: " + r.refusal + "\n"), ExitCode: 1}, errors.New("exit status 1")
		}
		if r.digest == "" {
			return CommandResult{Stderr: []byte("policy digest: pack digest mismatch"), ExitCode: 1}, nil
		}
		return CommandResult{Stdout: []byte(`{"effective_digest":"` + r.digest + `","config_generation":4}`)}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

// servePolicyHealth makes a running gateway answer /health with the policy
// digest and last reload error the pointers hold at the time of the probe.
func servePolicyHealth(h *testHost, reported, reloadError *string) {
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		gateway := unitGateway
		if h.env.GOOS == "darwin" {
			gateway = labelGateway
		}
		if !h.healthy || !h.services.isActive(gateway) {
			return 0, nil, errors.New("connection refused")
		}
		return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d,"last_reload_error":%q},"inspection":{"local":"active","ai_defense":"disabled"}}`,
			*reported, installedGenerationOf(h), *reloadError)), nil
	}
}

// TestEnsureReportsTheAppliedPolicy covers the result's policy object: the
// digest the installed config computes to, whether the gateway reports the
// same one, policy-state.json once it does, and a warning when it does not.
// deployment.json still loads with a field this release does not know, so a
// later release can extend it.
func TestEnsureReportsTheAppliedPolicy(t *testing.T) {
	const computed = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	h := newTestHost(t, "linux")
	h.env.Runner = &policyDigestRunner{fakeRunner: h.runner, digest: computed}
	reported, reloadError := computed, ""
	servePolicyHealth(h, &reported, &reloadError)
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireOK(t, r)
	if r.Policy == nil || !r.Policy.Applied || r.Policy.EffectiveDigest != computed || r.Policy.ConfigGeneration != 4 {
		t.Fatalf("install policy = %+v, want %s applied at config generation 4", r.Policy, computed)
	}
	if record, err := h.env.loadPolicyState(); err != nil || record == nil || record.EffectiveDigest != computed {
		t.Fatalf("policy-state.json = %+v, %v", record, err)
	}

	reported = "sha256:" + strings.Repeat("0", 64)
	// A repair that restarted the gateway into another policy did not repair
	// it: it fails with both digests, as verify does (GAP-0943).
	r = h.run(Options{Action: ActionRepair})
	if r.OK || r.Policy == nil || r.Policy.Applied || r.Policy.GatewayReportedDigest != reported ||
		!strings.Contains(messagesOf(r.Errors, codePolicyNotApplied), shortDigest(reported)) {
		t.Fatalf("repair with a stale gateway: policy = %+v, errors = %+v", r.Policy, r.Errors)
	}

	// A reload the gateway rejected leaves the digests equal, but the policy
	// is not applied, and status says so without a change action (GAP-0044).
	reported, reloadError = computed, "pack digest mismatch"
	r = h.run(Options{Action: ActionStatus})
	if r.Policy == nil || r.Policy.Applied || r.Policy.LastReloadError != reloadError || !hasWarning(r, codePolicyReloadRejected) {
		t.Fatalf("status with a rejected reload: policy = %+v, warnings = %+v", r.Policy, r.Warnings)
	}
	// GAP-0587: a change action does not add "reports X but computes to X".
	if r = h.run(Options{Action: ActionRepair}); r.OK || messagesOf(r.Errors, codePolicyNotApplied) != "" || hasWarning(r, codePolicyNotApplied) ||
		!strings.Contains(messagesOf(r.Errors, codePolicyReloadRejected), reloadError) {
		t.Fatalf("repair with a rejected reload: errors = %+v warnings = %+v", r.Errors, r.Warnings)
	}

	raw, err := os.ReadFile(h.env.deploymentPath())
	if err != nil {
		t.Fatal(err)
	}
	extended := strings.Replace(string(raw), "{", `{"added_by_a_later_release": true,`, 1)
	if err := os.WriteFile(h.env.deploymentPath(), []byte(extended), 0o600); err != nil {
		t.Fatal(err)
	}
	if record, err := h.env.loadDeployment(); err != nil || record == nil {
		t.Fatalf("loadDeployment with an unknown field = %v, %v", record, err)
	}
}

// An unapplied policy leaves the previously built policy enforcing. A rejected
// reload does so even when its digest matches the installed config. Status
// must not certify security coverage and verify must name the cause.
func TestUnappliedGatewayPolicyCannotVerifyComplete(t *testing.T) {
	const digest = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			h.env.Runner = &policyDigestRunner{fakeRunner: h.runner, digest: digest}
			reported, reloadError := digest, ""
			servePolicyHealth(h, &reported, &reloadError)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			ledger, err := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true})
			if err != nil {
				t.Fatal(err)
			}
			h.publishLedger(ledger)
			if r := h.run(Options{Action: ActionVerify}); !r.SecurityComplete {
				t.Fatalf("healthy verify incomplete: errors %+v warnings %+v", r.Errors, r.Warnings)
			}
			reported = "sha256:" + strings.Repeat("0", 64)
			status := h.run(Options{Action: ActionStatus})
			if status.SecurityComplete || status.Policy == nil || status.Policy.Applied ||
				!strings.Contains(messagesOf(status.Warnings, codePolicyNotApplied), shortDigest(reported)) {
				t.Fatalf("unapplied policy status: complete %v policy %+v warnings %+v", status.SecurityComplete, status.Policy, status.Warnings)
			}
			verify := h.run(Options{Action: ActionVerify})
			if verify.OK || verify.SecurityComplete || verify.Policy == nil || verify.Policy.Applied ||
				!strings.Contains(messagesOf(verify.Errors, codePolicyNotApplied), shortDigest(reported)) {
				t.Fatalf("unapplied policy verify: exit %d complete %v policy %+v errors %+v", verify.ExitCode, verify.SecurityComplete, verify.Policy, verify.Errors)
			}

			reported = digest
			reloadError = "pack digest mismatch"
			status = h.run(Options{Action: ActionStatus})
			if status.SecurityComplete || status.Policy == nil || status.Policy.Applied ||
				!strings.Contains(messagesOf(status.Warnings, codePolicyReloadRejected), reloadError) {
				t.Fatalf("rejected reload status: complete %v policy %+v warnings %+v", status.SecurityComplete, status.Policy, status.Warnings)
			}
			verify = h.run(Options{Action: ActionVerify})
			if verify.OK || verify.SecurityComplete || verify.Policy == nil || verify.Policy.Applied ||
				!strings.Contains(messagesOf(verify.Errors, codePolicyReloadRejected), reloadError) {
				t.Fatalf("rejected reload verify: exit %d complete %v policy %+v errors %+v", verify.ExitCode, verify.SecurityComplete, verify.Policy, verify.Errors)
			}
			reloadError = ""
			if r := h.run(Options{Action: ActionVerify}); !r.OK || !r.SecurityComplete || r.Policy == nil || !r.Policy.Applied {
				t.Fatalf("recovered verify: exit %d complete %v policy %+v errors %+v", r.ExitCode, r.SecurityComplete, r.Policy, r.Errors)
			}
		})
	}
}

// TestPolicyOmittedWhenTheDigestIsUnknown covers a gateway that reports a
// digest while the installed config's policy cannot be built (a pack that no
// longer matches its pin) and no policy-state.json records an earlier one:
// the result has no policy object, because the lifecycle-result schema
// requires effective_digest to be a sha256 digest, and the gateway's
// rejected reload is still warned about.
func TestPolicyOmittedWhenTheDigestIsUnknown(t *testing.T) {
	const computed = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	h := newTestHost(t, "linux")
	runner := &policyDigestRunner{fakeRunner: h.runner, digest: computed}
	h.env.Runner = runner
	reported, reloadError := computed, ""
	servePolicyHealth(h, &reported, &reloadError)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))

	if err := os.Remove(h.env.policyStatePath()); err != nil {
		t.Fatal(err)
	}
	runner.digest, reloadError = "", "pack digest mismatch"
	r := h.run(Options{Action: ActionStatus})
	if r.Policy != nil {
		t.Fatalf("status with no computable digest: policy = %+v, want none", r.Policy)
	}
	if !hasWarning(r, codePolicyReloadRejected) {
		t.Fatalf("the rejected reload is not warned about: %+v", r.Warnings)
	}
	if raw, err := json.Marshal(r); err != nil || strings.Contains(string(raw), `"effective_digest"`) {
		t.Fatalf("result JSON = %s, %v; it must not carry an effective_digest", raw, err)
	}
}

// Status and verify name the policy digest they could not compute instead of
// omitting the policy block silently (rel-1-0-4 GAP-0594, the Unix side): the
// warning carries the installed gateway's reason.
func TestPolicyOmittedNamesTheDigestItCouldNotCompute(t *testing.T) {
	const computed = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	for name, c := range map[string]struct {
		refusal, want string
	}{
		"exit status": {want: "pack digest mismatch"},
		"refused":     {refusal: "rule pack \"p\" does not match its pin", want: "does not match its pin"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			runner := &policyDigestRunner{fakeRunner: h.runner, digest: computed}
			h.env.Runner = runner
			reported, reloadError := computed, ""
			servePolicyHealth(h, &reported, &reloadError)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			if err := os.Remove(h.env.policyStatePath()); err != nil {
				t.Fatal(err)
			}
			runner.digest, runner.refusal = "", c.refusal
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				var message string
				for _, w := range r.Warnings {
					if w.Code == codePolicyUnverified {
						message = w.Message
					}
				}
				if r.Policy != nil || !strings.Contains(message, c.want) {
					t.Fatalf("%s: policy = %+v, warnings = %+v, want %s naming %q", action, r.Policy, r.Warnings, codePolicyUnverified, c.want)
				}
			}
		})
	}
}

// GAP-0133: a sandbox pack under the policies directory edited in place
// leaves config.yaml and every installed file as applied, but the config now
// computes to another effective policy than the running gateway reports.
// ensure is no noop then: it records the next config_generation and starts
// the gateway again, which loads the edit; the following ensure is a noop
// with the policy applied. A gateway that rejected its last reload is not
// restarted again for the same difference.
func TestEnsureAppliesAPolicyAssetEditedInPlace(t *testing.T) {
	before := "sha256:" + strings.Repeat("ab12", 16)
	after := "sha256:" + strings.Repeat("cd34", 16)
	h := newTestHost(t, "linux")
	runner := &policyDigestRunner{fakeRunner: h.runner, digest: before}
	h.env.Runner = runner
	reported, reloadError := before, ""
	servePolicyHealth(h, &reported, &reloadError)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	generation := func() uint64 {
		t.Helper()
		state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
		if err != nil {
			t.Fatal(err)
		}
		return state.Generation
	}
	gatewayStarts := func(from int) int {
		h.services.mu.Lock()
		defer h.services.mu.Unlock()
		n := 0
		for _, call := range h.services.calls[from:] {
			if call == "start "+unitGateway || call == "restart "+unitGateway {
				n++
			}
		}
		return n
	}
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if !r.Noop || r.NoopReason != "up_to_date" {
		t.Fatalf("ensure with nothing changed: noop %v (%s)", r.Noop, r.NoopReason)
	}
	first := generation()

	runner.digest = after
	// A started gateway loads the edited pack.
	h.services.afterStart = func(u Unit) {
		if u.Name == unitGateway {
			reported = runner.digest
		}
	}
	h.services.afterRestart = h.services.afterStart
	h.services.mu.Lock()
	mark := len(h.services.calls)
	h.services.mu.Unlock()
	r = h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if r.Noop {
		t.Fatalf("ensure after the pack edit was a noop (%s); warnings %+v", r.NoopReason, r.Warnings)
	}
	if got := generation(); got != first+1 {
		t.Fatalf("config_generation = %d, want %d", got, first+1)
	}
	if gatewayStarts(mark) == 0 {
		t.Fatal("the gateway was not started again to load the edited pack")
	}

	// The gateway now runs the edited pack.
	reported = after
	r = h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if !r.Noop || r.Policy == nil || !r.Policy.Applied || r.Policy.EffectiveDigest != after {
		t.Fatalf("ensure after the gateway loaded the edit: noop %v policy %+v", r.Noop, r.Policy)
	}

	// A reload the gateway rejected is reported, not restarted for again.
	runner.digest, reloadError = before, "pack digest mismatch"
	if r = h.run(Options{Action: ActionEnsure}); !r.Noop || !hasWarning(r, codePolicyReloadRejected) {
		t.Fatalf("ensure with a rejected reload: noop %v warnings %+v", r.Noop, r.Warnings)
	}
}

// GAP-0229: a sandbox pack edited in place into one that does not load
// (`policy digest` refuses it, as the gateway would at start) is no change
// ensure applies: the run records no config_generation, does not restart
// the gateway, which keeps the policy it loaded, and fails with the reason.
// Restoring the pack makes the next ensure a plain noop again.
func TestEnsureRefusesAPolicyAssetThatDoesNotLoad(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab12", 16)
	h := newTestHost(t, "linux")
	runner := &policyDigestRunner{fakeRunner: h.runner, digest: digest}
	h.env.Runner = runner
	reported, reloadError := digest, ""
	servePolicyHealth(h, &reported, &reloadError)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	generation := func() uint64 {
		t.Helper()
		state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
		if err != nil {
			t.Fatal(err)
		}
		return state.Generation
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	first := generation()

	reason := `generation: sandbox pack /etc/defenseclaw/policies/sandbox/corp/pack.yaml does not load: network.mode: "unbuildable" must be one of open, allowlist, deny`
	runner.refusal = reason
	h.services.mu.Lock()
	mark := len(h.services.calls)
	h.services.mu.Unlock()
	r := h.run(Options{Action: ActionEnsure})
	requireError(t, r, codeConfigRefused)
	if got := messagesOf(r.Errors, codeConfigRefused); !strings.Contains(got, "network.mode") || !strings.Contains(got, "keeps the last good policy") {
		t.Fatalf("refusal message: %q", got)
	}
	if !r.Noop || r.NoopReason != "policy_refused" {
		t.Fatalf("ensure with a policy that does not load: noop %v (%s)", r.Noop, r.NoopReason)
	}
	if got := generation(); got != first {
		t.Fatalf("config_generation moved to %d for a policy that does not load", got)
	}
	h.services.mu.Lock()
	for _, call := range h.services.calls[mark:] {
		if call == "start "+unitGateway || call == "restart "+unitGateway || call == "stop "+unitGateway {
			t.Errorf("ensure touched the gateway for a policy that does not load: %s", call)
		}
	}
	h.services.mu.Unlock()

	runner.refusal = ""
	r = h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if !r.Noop || r.NoopReason != "up_to_date" {
		t.Fatalf("ensure after the pack was restored: noop %v (%s)", r.Noop, r.NoopReason)
	}
}
