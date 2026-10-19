// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func policyTestInput() (*config.Config, packs.Flags, PolicyOptions) {
	return &config.Config{OpenShell: config.OpenShellConfig{
			Enabled: true, LLM: config.OpenShellLLMNone,
			Workdir: config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy},
		}}, packs.Flags{Harness: "claudecode"}, PolicyOptions{
			Authority: PolicyAuthorityBinding{SnapshotID: "synthetic-host-authority", Generation: 1},
			Harness: HarnessIdentity{
				Version: "synthetic-claude", HookContract: "synthetic-hooks",
				Artifact: ArtifactIdentity{Kind: OCIImage, Digest: "sha256:" + strings.Repeat("a", 64)},
			},
		}
}

func mustPolicy(t *testing.T, cfg *config.Config, flags packs.Flags, options PolicyOptions) *ExecutionPolicy {
	t.Helper()
	p, _, err := ResolveExecutionPolicy(cfg, flags, options)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func policyEvidence(p *ExecutionPolicy) (RuntimeInfo, PolicyReceipt) {
	info := qualifiedInfo()
	info.Identity.Runtime, info.Identity.Backend, info.Identity.Driver = OpenShell, "openshell", "docker"
	info.Supported, info.Unavailable = p.RequiredCapabilities(), nil
	info.Harnesses = map[string]HarnessVerification{p.effective.Harness: {
		Identity: p.options.Harness, Supported: p.RequiredCapabilities(),
	}}
	receipt := PolicyReceipt{Runtime: info.Identity, Harness: p.options.Harness, PolicyDigest: p.Digest()}
	for _, component := range p.Components() {
		receipt.Components = append(receipt.Components, PolicyComponentBinding{Name: component.Name, Digest: component.Digest})
	}
	return info, receipt
}

func componentValue(t *testing.T, p *ExecutionPolicy, name PolicyComponentName) map[string]any {
	t.Helper()
	for _, component := range p.Components() {
		if component.Name == name {
			var value map[string]any
			if err := json.Unmarshal(component.Value, &value); err != nil {
				t.Fatal(err)
			}
			return value
		}
	}
	t.Fatalf("missing %s", name)
	return nil
}

func TestExecutionPolicyPreservesCommonProjectionAndAdministrativeClamps(t *testing.T) {
	cfg, flags, options := policyTestInput()
	cfg.OpenShell.Resources.CPU = "2"
	cfg.OpenShell.Admin.MaxResources.CPU = "500m"
	cfg.OpenShell.Resources.Memory = "2Gi"
	cfg.OpenShell.Admin.MaxResources.Memory = "512Mi"
	cfg.OpenShell.Admin.EgressBlock = []string{"blocked.example"}
	cfg.OpenShell.Workdir.Masks = []string{"legacy-secret"}
	cfg.Sandbox = &config.SandboxConfig{Enabled: true, LLM: config.OpenShellLLMNone,
		Runtimes:     config.SandboxRuntimesConfig{OpenShell: config.SandboxRuntimeConfig{Enabled: true}},
		Workdir:      config.OpenShellWorkdirConfig{Masks: []string{"common-secret"}},
		KeepHeadless: true,
	}
	p, violations, err := ResolveExecutionPolicy(cfg, flags, options)
	if err != nil || len(violations) == 0 {
		t.Fatalf("expected a visible resource clamp, got %v, %v", violations, err)
	}
	if p.effective.Resources.CPU != "500m" || !slices.Contains(p.effective.Workspace.Masks, "common-secret") {
		t.Fatal("resolved common policy or resource floor was lost")
	}
	if decision := p.DecideEgress("blocked.example", 443); decision.Allowed || decision.Rule != packs.RuleAdminBlock {
		t.Fatalf("administrative egress floor was lost: %+v", decision)
	}
	common := componentValue(t, p, PolicyCommon)
	if common["llm"] != config.OpenShellLLMNone || common["keep_headless"] != true {
		t.Fatal("common settings outside packs.Effective were dropped")
	}
	if componentValue(t, p, PolicyResources)["cpu_millicores"] != float64(500) || !slices.Contains(p.RequiredCapabilities(), CPUHardLimit) {
		t.Fatal("exact normalized CPU enforcement requirement was lost")
	}
	if componentValue(t, p, PolicyResources)["memory_bytes"] != float64(512<<20) || !slices.Contains(p.RequiredCapabilities(), MemoryHardLimit) {
		t.Fatal("exact normalized memory enforcement requirement was lost")
	}
}

func TestExecutionPolicyRetainsCuratedAndOperatorBrokerAuthority(t *testing.T) {
	cfg, flags, options := policyTestInput()
	cfg.OpenShell.Pack = "balanced"
	cfg.OpenShell.Egress.Allow = []string{"operator.example"}
	p := mustPolicy(t, cfg, flags, options)
	broker, err := p.effective.EgressOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.effective.Egress.Allow, "registry.npmjs.org") || slices.Contains(broker.Allow, "registry.npmjs.org") || !slices.Contains(broker.Allow, "operator.example") {
		t.Fatal("curated entries were promoted to operator private-network grants")
	}
	if !p.DecideEgress("registry.npmjs.org", 443).Allowed || !p.DecideEgress("operator.example", 443).Allowed || p.DecideEgress("127.0.0.1", 443).Allowed {
		t.Fatal("retained host evaluator lost broker or host-guard behavior")
	}
	var view packs.Effective
	wire, err := json.Marshal(componentValue(t, p, PolicyAuthority)["resolved"])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, &view); err != nil {
		t.Fatal(err)
	}
	if decision := view.DecideEgress("registry.npmjs.org", 443); decision.Rule != packs.RuleInvalid {
		t.Fatal("inspection view acquired live broker authority")
	}
}

func TestExecutionPolicyCopiesAllMutableInputsAndViews(t *testing.T) {
	cfg, flags, options := policyTestInput()
	cfg.OpenShell.Egress.Block = []string{"blocked.example"}
	flags.RepoPolicy = &packs.RepoPolicy{Digest: "sha256:" + strings.Repeat("b", 64), Masks: []string{"repo-secret"}}
	p := mustPolicy(t, cfg, flags, options)
	before, digest := p.Snapshot(), p.Digest()
	cfg.OpenShell.Egress.Block[0] = "different.example"
	flags.RepoPolicy.Masks[0] = "changed-after-resolution"
	view := p.Snapshot()
	view[0] = '!'
	components := p.Components()
	components[0].Value[0] = '!'
	components[0].Digest = "changed"
	required := p.RequiredCapabilities()
	required[0] = "changed"
	if p.Digest() != digest || !bytes.Equal(before, p.Snapshot()) {
		t.Fatal("execution policy aliased its input or inspection output")
	}
	if p.DecideEgress("blocked.example", 443).Allowed || !slices.Contains(p.effective.Workspace.Masks, "repo-secret") {
		t.Fatal("private authority was mutable through caller input")
	}
	var decoded ExecutionPolicy
	if err := json.Unmarshal(before, &decoded); err == nil {
		t.Fatal("inspection JSON was accepted as a policy authority handle")
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("policy authority was serialized instead of using the explicit inspection copy")
	}
	info, receipt := policyEvidence(p)
	wantCode(t, decoded.AdmitPolicy(info, receipt, options.Authority), sandboxapi.CodePolicyRejected)
}

func TestExecutionPolicyRequiresEveryExactComponentAndIdentity(t *testing.T) {
	cfg, flags, options := policyTestInput()
	p := mustPolicy(t, cfg, flags, options)
	info, receipt := policyEvidence(p)
	if err := p.AdmitPolicy(info, receipt, options.Authority); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PolicyReceipt){
		"runtime": func(r *PolicyReceipt) { r.Runtime.Version = "other-runtime" },
		"harness": func(r *PolicyReceipt) { r.Harness.Version = "other-harness" },
		"policy":  func(r *PolicyReceipt) { r.PolicyDigest = "sha256:" + strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			mutate(&changed)
			wantCode(t, p.AdmitPolicy(info, changed, options.Authority), sandboxapi.CodePolicyRejected)
		})
	}
	for name, mutate := range map[string]func(*PolicyReceipt){
		"missing":   func(r *PolicyReceipt) { r.Components = r.Components[1:] },
		"duplicate": func(r *PolicyReceipt) { r.Components[1] = r.Components[0] },
		"unknown":   func(r *PolicyReceipt) { r.Components[0].Name = "unreviewed-feature" },
		"changed":   func(r *PolicyReceipt) { r.Components[0].Digest = "sha256:" + strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			changed.Components = slices.Clone(receipt.Components)
			mutate(&changed)
			wantCode(t, p.AdmitPolicy(info, changed, options.Authority), sandboxapi.CodePolicyViolation)
		})
	}
	info.Supported = slices.DeleteFunc(info.Supported, func(cap Capability) bool { return cap == StrictFilesystem })
	wantCode(t, p.AdmitPolicy(info, receipt, options.Authority), sandboxapi.CodePolicyViolation)
}

func TestExecutionPolicyCannotEnableAnotherRuntimeOrUseStalePolicy(t *testing.T) {
	cfg, flags, options := policyTestInput()
	p := mustPolicy(t, cfg, flags, options)
	info, receipt := policyEvidence(p)
	info.Identity.Runtime, info.Identity.Backend, info.Identity.Driver = Axis, "mxc", "bubblewrap"
	receipt.Runtime = info.Identity
	wantCode(t, p.AdmitPolicy(info, receipt, options.Authority), sandboxapi.CodeDisabled)
	info, receipt = policyEvidence(p)
	cfg.OpenShell.Egress.Block = []string{"new-policy.example"}
	newPolicy := mustPolicy(t, cfg, flags, options)
	if newPolicy.Digest() == p.Digest() {
		t.Fatal("policy change did not change the execution policy identity")
	}
	wantCode(t, newPolicy.AdmitPolicy(info, receipt, options.Authority), sandboxapi.CodePolicyRejected)
}

func TestExecutionPolicyAuthorityBindingPreventsStaleHostReceipt(t *testing.T) {
	cfg, flags, options := policyTestInput()
	p := mustPolicy(t, cfg, flags, options)
	info, receipt := policyEvidence(p)
	if err := p.AdmitPolicy(info, receipt, options.Authority); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*PolicyOptions){
		"snapshot":   func(o *PolicyOptions) { o.Authority.SnapshotID = "different-host-authority" },
		"generation": func(o *PolicyOptions) { o.Authority.Generation++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := options
			change(&changed)
			next := mustPolicy(t, cfg, flags, changed)
			if p.effective.Digest() != next.effective.Digest() || p.Digest() == next.Digest() {
				t.Fatal("host authority rotation must change IR identity even when policy content is unchanged")
			}
			wantCode(t, next.AdmitPolicy(info, receipt, changed.Authority), sandboxapi.CodePolicyRejected)
			wantCode(t, p.AdmitPolicy(info, receipt, changed.Authority), sandboxapi.CodePolicyRejected)
		})
	}
	for _, binding := range []PolicyAuthorityBinding{
		{}, {SnapshotID: "synthetic", Generation: 0}, {Generation: 1},
		{SnapshotID: "bad\nidentity", Generation: 1},
	} {
		changed := options
		changed.Authority = binding
		_, _, err := ResolveExecutionPolicy(cfg, flags, changed)
		wantCode(t, err, sandboxapi.CodeInvalid)
		wantCode(t, p.AdmitPolicy(info, receipt, binding), sandboxapi.CodePolicyRejected)
	}
}

func TestExecutionPolicyStrictDoesNotMeanOffline(t *testing.T) {
	cfg, flags, options := policyTestInput()
	cfg.OpenShell.Profile = config.OpenShellProfileStrict
	p := mustPolicy(t, cfg, flags, options)
	if !slices.Contains(p.RequiredCapabilities(), BrokerEgress) || slices.Contains(p.RequiredCapabilities(), OfflineNetwork) {
		t.Fatal("strict provider/hook routing was mistaken for completely offline execution")
	}
	options.Offline = true
	offline := mustPolicy(t, cfg, flags, options)
	if !slices.Contains(offline.RequiredCapabilities(), OfflineNetwork) || slices.Contains(offline.RequiredCapabilities(), BrokerEgress) || offline.DecideEgress("example.com", 443).Allowed {
		t.Fatal("explicit offline requirement was lost")
	}
	cfg.OpenShell.LLM = config.OpenShellLLMAuto
	if _, _, err := ResolveExecutionPolicy(cfg, flags, options); err == nil {
		t.Fatal("offline execution accepted model credentials")
	}
}

func TestExecutionPolicyRejectsOffMasterFatalHarnessAndOrganizationDenial(t *testing.T) {
	cfg, flags, options := policyTestInput()
	cfg.OpenShell.Enabled = false
	cfg.OpenShell.Pack = "does-not-exist"
	_, _, err := ResolveExecutionPolicy(cfg, flags, options)
	wantCode(t, err, sandboxapi.CodeDisabled)
	cfg, flags, options = policyTestInput()
	cfg.OpenShell.Admin.AllowedHarnesses = []string{"codex"}
	_, _, err = ResolveExecutionPolicy(cfg, flags, options)
	wantCode(t, err, sandboxapi.CodeAdminViolation)
	cfg, flags, options = policyTestInput()
	denied := false
	cfg.OpenShell.Admin.Allowed = &denied
	_, _, err = ResolveExecutionPolicy(cfg, flags, options)
	wantCode(t, err, sandboxapi.CodeAdminViolation)
}

func TestExecutionPolicyCommonSnapshotHasEverySharedField(t *testing.T) {
	values, err := commonPolicyValues(config.OpenShellConfig{})
	if err != nil {
		t.Fatal(err)
	}
	common := reflect.TypeFor[config.SandboxConfig]()
	for i := range common.NumField() {
		field := common.Field(i)
		if field.PkgPath != "" || field.Name == "Runtime" || field.Name == "Runtimes" {
			continue
		}
		key, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if _, ok := values[key]; !ok {
			t.Fatalf("common field %s silently omitted from immutable policy", key)
		}
	}
}
