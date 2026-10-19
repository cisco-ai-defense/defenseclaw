// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestBindResolvedPolicyNeverReloadsChangedPackOrCallerInputs(t *testing.T) {
	cfg, flags, options := policyTestInput()
	packPath := filepath.Join(t.TempDir(), "fixed-pack.yaml")
	pack := "version: 1\nname: fixed\nextends: balanced\negress:\n  block: [blocked.example]\n"
	if err := os.WriteFile(packPath, []byte(pack), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.OpenShell.Pack = packPath
	cfg.OpenShell.Egress.Allow = []string{"operator.example"}
	flags.RepoPolicy = &packs.RepoPolicy{Digest: "sha256:" + strings.Repeat("b", 64), Masks: []string{"repo-secret"}}
	run, _, err := ResolveHostRun(cfg, flags, options)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := BindResolvedExecutionPolicy(run, options)
	if err != nil {
		t.Fatal(err)
	}
	planning, _, err := run.PlanningPolicy()
	if err != nil || planning.Digest() != first.effective.Digest() {
		t.Fatal("host planning did not receive the same resolved policy", err)
	}
	planning.Egress.Allow[0] = "changed-planning-copy.example"
	// A second resolution would now fail. Binding must keep the exact earlier
	// tuple, even after its caller changes source files, config and flags.
	if err := os.WriteFile(packPath, []byte("fixed invalid replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveExecutionPolicy(cfg, flags, options); err == nil {
		t.Fatal("test replacement must fail a fresh source resolution")
	}
	cfg.OpenShell.Egress.Allow[0] = "changed.example"
	cfg.OpenShell.LLM = config.OpenShellLLMAnthropic
	cfg.OpenShell.Enabled = false
	flags.RepoPolicy.Masks[0] = "changed"
	second, _, err := BindResolvedExecutionPolicy(run, options)
	if err != nil || first.Digest() != second.Digest() || !bytes.Equal(first.Snapshot(), second.Snapshot()) {
		t.Fatal("binding reloaded or combined different source snapshots", err)
	}
	if second.DecideEgress("blocked.example", 443).Allowed ||
		!second.DecideEgress("operator.example", 443).Allowed ||
		!slices.Contains(second.effective.Workspace.Masks, "repo-secret") {
		t.Fatal("retained effective authority drifted from the resolved run")
	}
	broker, err := second.effective.EgressOptions(nil)
	if err != nil || slices.Contains(broker.Allow, "registry.npmjs.org") ||
		!slices.Contains(broker.Allow, "operator.example") {
		t.Fatal("binding promoted the curated allowlist into operator authority", err)
	}
	if slices.Contains(second.RequiredCapabilities(), HostCredentials) {
		t.Fatal("later config changed the bound LLM credential requirements")
	}
	info, receipt := policyEvidence(second)
	stale := options.Authority
	stale.Generation++
	wantCode(t, second.AdmitPolicy(info, receipt, stale), sandboxapi.CodePolicyRejected)
}

func TestBindResolvedPolicyPreservesCommonProjectionClampsAndFatalRefusals(t *testing.T) {
	cfg, flags, options := policyTestInput()
	cfg.OpenShell.Workdir.Masks = []string{"legacy-mask"}
	cfg.OpenShell.Admin.MaxResources.CPU = "500m"
	cfg.Sandbox = &config.SandboxConfig{Enabled: true, LLM: config.OpenShellLLMNone,
		Runtimes:  config.SandboxRuntimesConfig{OpenShell: config.SandboxRuntimeConfig{Enabled: true}},
		Workdir:   config.OpenShellWorkdirConfig{Masks: []string{"common-mask"}},
		Resources: config.OpenShellResourcesConfig{CPU: "2"}, KeepHeadless: true}
	run, violations, err := ResolveHostRun(cfg, flags, options)
	if err != nil || len(violations) == 0 {
		t.Fatal("test needs a visible administrative clamp", err)
	}
	policy, boundViolations, err := BindResolvedExecutionPolicy(run, options)
	if err != nil || !slices.Equal(violations, boundViolations) ||
		policy.effective.Resources.CPU != "500m" || !slices.Contains(policy.effective.Workspace.Masks, "common-mask") {
		t.Fatal("single shared resolution lost projection or administrative clamps", err)
	}
	if componentValue(t, policy, PolicyCommon)["keep_headless"] != true {
		t.Fatal("settings outside packs.Effective were lost")
	}
	cfg.Sandbox = nil
	cfg.OpenShell.Admin.AllowedHarnesses = []string{"codex"}
	run, violations, err = ResolveHostRun(cfg, flags, options)
	if err != nil || packs.FirstFatal(violations) == nil {
		t.Fatal("test needs a refused harness", err)
	}
	_, _, err = BindResolvedExecutionPolicy(run, options)
	wantCode(t, err, sandboxapi.CodeAdminViolation)
	for _, empty := range []*HostResolvedRun{nil, {}} {
		_, _, err := BindResolvedExecutionPolicy(empty, options)
		wantCode(t, err, sandboxapi.CodePolicyRejected)
	}
}

func TestHostResolvedRunCannotRebindOlderPolicyToNewAuthority(t *testing.T) {
	cfg, flags, options := policyTestInput()
	run, _, err := ResolveHostRun(cfg, flags, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []PolicyAuthorityBinding{
		{SnapshotID: options.Authority.SnapshotID, Generation: options.Authority.Generation + 1},
		{SnapshotID: "different-host-owner", Generation: options.Authority.Generation},
	} {
		changed := options
		changed.Authority = authority
		_, _, err := BindResolvedExecutionPolicy(run, changed)
		wantCode(t, err, sandboxapi.CodePolicyRejected)
	}
	for _, change := range []func(*PolicyOptions){
		func(o *PolicyOptions) { o.Offline = !o.Offline },
		func(o *PolicyOptions) { o.Terminal = !o.Terminal },
		func(o *PolicyOptions) { o.Harness.Version = "another-valid-version" },
		func(o *PolicyOptions) { o.Harness.HookContract = "another-valid-hook-contract" },
		func(o *PolicyOptions) { o.Harness.Artifact.Digest = "sha256:" + strings.Repeat("c", 64) },
	} {
		changed := options
		change(&changed)
		_, _, err := BindResolvedExecutionPolicy(run, changed)
		wantCode(t, err, sandboxapi.CodePolicyRejected)
	}
	if _, err := json.Marshal(run); err == nil {
		t.Fatal("owned host snapshot was serialized as authority")
	}
	var decoded HostResolvedRun
	if json.Unmarshal([]byte(`{}`), &decoded) == nil {
		t.Fatal("wire data constructed a host authority snapshot")
	}
	if _, _, err := decoded.PlanningPolicy(); err == nil {
		t.Fatal("empty host snapshot acquired planning authority")
	}
}
