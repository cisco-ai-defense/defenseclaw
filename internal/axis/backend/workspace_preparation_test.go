// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows || linux

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

func workspacePolicyFixture(t *testing.T, change func(*config.Config, *packs.Flags)) (*sandboxruntime.ExecutionPolicy, sandboxruntime.Spec, HostStageLocation) {
	t.Helper()
	_, spec := resolved(t, "")
	spec.Identity.Runtime.HostOS, spec.Identity.Runtime.ExecutionOS = runtime.GOOS, runtime.GOOS
	if runtime.GOOS == "windows" {
		spec.Identity.Runtime.Driver = "process_container"
	}
	// Metadata only; these names are never opened by the pure option/binding tests.
	base := filepath.Join(filepath.VolumeName(t.TempDir())+string(filepath.Separator), "axis-inert-policy-fixture")
	project := filepath.Join(base, "project")
	cfg := &config.Config{OpenShell: config.OpenShellConfig{Enabled: true, LLM: config.OpenShellLLMNone,
		Workdir: config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy, Masks: []string{"private.*"}, Unmask: []string{"private.example"}, MaxUploadMB: 17, GitDepth: 7}}}
	flags := packs.Flags{Harness: "claudecode", Project: project, ProjectReal: project}
	if change != nil {
		change(cfg, &flags)
	}
	policy, _, err := sandboxruntime.ResolveExecutionPolicy(cfg, flags, sandboxruntime.PolicyOptions{Harness: spec.HarnessIdentity, Offline: true,
		Authority: sandboxruntime.PolicyAuthorityBinding{SnapshotID: "inert-workspace-owner", Generation: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return policy, spec, HostStageLocation{DataDir: filepath.Join(base, "private-data"), Home: filepath.Join(base, "home")}
}

func TestPolicyHostStageOptionsUseOneResolvedWorkspace(t *testing.T) {
	policy, spec, location := workspacePolicyFixture(t, nil)
	opts, component, err := policyHostStageOptions(policy, spec, location)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Name != spec.Identity.Name || opts.DataDir != location.DataDir || opts.Home != location.Home ||
		opts.Project != filepath.Join(filepath.Dir(location.Home), "project") || opts.MaxBytes != 17<<20 || opts.GitDepth != 7 ||
		!slices.Contains(opts.Masks, "private.*") || !slices.Contains(opts.Unmask, "private.example") ||
		opts.Detector != nil || opts.DisableContentScan || opts.RemoteRoot != "" || opts.Replace {
		t.Fatal("host capture inputs differ from the owned policy or permit scanner/transport overrides")
	}
	if component.Name != sandboxruntime.PolicyWorkspace || component.Digest == "" {
		t.Fatal("workspace component identity was lost")
	}
	opts.Masks[0] = "changed-caller-copy"
	second, secondComponent, err := policyHostStageOptions(policy, spec, location)
	if err != nil || slices.Contains(second.Masks, "changed-caller-copy") || secondComponent != component {
		t.Fatal("mutable staging options changed the retained execution policy")
	}
}

func TestPolicyHostStageRejectsUnknownWorkspaceSemantics(t *testing.T) {
	policy, _, _ := workspacePolicyFixture(t, nil)
	var original []byte
	for _, component := range policy.Components() {
		if component.Name == sandboxruntime.PolicyWorkspace {
			original = component.Value
		}
	}
	for _, field := range []string{"top", "posture", "undo_ignored"} {
		var document map[string]json.RawMessage
		if err := json.Unmarshal(original, &document); err != nil {
			t.Fatal(err)
		}
		target := document
		if field != "top" {
			target = nil
			if err := json.Unmarshal(document[field], &target); err != nil {
				t.Fatal(err)
			}
		}
		target["future_enforcement_requirement"] = json.RawMessage(`true`)
		if field != "top" {
			encoded, err := json.Marshal(target)
			if err != nil {
				t.Fatal(err)
			}
			document[field] = encoded
		}
		changed, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeWorkspacePolicyValues(changed); !errors.Is(err, ErrPolicy) {
			t.Fatal("a future workspace requirement was silently omitted from preparation")
		}
	}
	if _, err := decodeWorkspacePolicyValues(append(slices.Clone(original), []byte(` {}`)...)); !errors.Is(err, ErrPolicy) {
		t.Fatal("a second policy object was ignored")
	}
}

func TestPolicyHostStageOptionsRefuseIncompatibleSourceAndPosture(t *testing.T) {
	for _, kind := range []string{"mount", "alias", "missing-source", "over-cap", "mount-undo"} {
		t.Run(kind, func(t *testing.T) {
			policy, spec, location := workspacePolicyFixture(t, func(cfg *config.Config, flags *packs.Flags) {
				switch kind {
				case "mount":
					cfg.OpenShell.Workdir.Mode = config.OpenShellWorkdirMount
				case "alias":
					flags.Project += "-alias"
				case "missing-source":
					flags.Project, flags.ProjectReal = "", ""
				case "over-cap":
					cfg.OpenShell.Workdir.MaxUploadMB = 501
				case "mount-undo":
					cfg.OpenShell.Workdir.UndoIgnored.Enabled = true
				}
			})
			if _, _, err := policyHostStageOptions(policy, spec, location); !errors.Is(err, ErrPolicy) {
				t.Fatalf("incompatible capture was accepted: %v", err)
			}
		})
	}
	policy, spec, location := workspacePolicyFixture(t, nil)
	for _, change := range []func(*sandboxruntime.Spec){
		func(s *sandboxruntime.Spec) { s.HostWorkspace = "caller-selected-stage" },
		func(s *sandboxruntime.Spec) { s.GuestWorkspace = "/other" },
		func(s *sandboxruntime.Spec) { s.Identity.Runtime.Driver = "other" },
	} {
		changed := spec
		change(&changed)
		if _, _, err := policyHostStageOptions(policy, changed, location); !errors.Is(err, ErrPolicy) {
			t.Fatal("changed runtime or caller-selected workspace was accepted")
		}
	}
}

func TestWorkspacePreparationCannotAcknowledgeLifecycleOrChangeOwner(t *testing.T) {
	policy, spec, location := workspacePolicyFixture(t, nil)
	opts, component, err := policyHostStageOptions(policy, spec, location)
	if err != nil {
		t.Fatal(err)
	}
	assets := &Assets{workspacePreparation: &workspacePreparation{policy: policy, identity: spec.Identity, component: component,
		summary: workspace.HostStageSummary{Project: opts.Project, SourceIdentity: "inert-source-identity"}}}
	if err := validateWorkspacePreparation(policy, spec, assets); err != nil {
		t.Fatal(err)
	}
	plan, receipt, err := compilePolicy(policy, spec, assets)
	var unsupported *UnsupportedPolicy
	if !errors.As(err, &unsupported) || !slices.Contains(unsupported.Components, sandboxruntime.PolicyWorkspace) ||
		len(plan.Argv) != 0 || !reflect.DeepEqual(receipt, sandboxruntime.PolicyReceipt{}) {
		t.Fatal("capture preparation acknowledged unimplemented review/export/on-exit semantics")
	}
	other, _, _ := workspacePolicyFixture(t, nil)
	if err := validateWorkspacePreparation(other, spec, assets); !errors.Is(err, ErrPolicy) {
		t.Fatal("a separately resolved policy reused the stage association")
	}
	changed := spec
	changed.Identity.ID += "-other"
	if err := validateWorkspacePreparation(policy, changed, assets); !errors.Is(err, ErrPolicy) {
		t.Fatal("another session reused the stage association")
	}
	assets.cleanupOnly = true
	if err := validateWorkspacePreparation(policy, spec, assets); !errors.Is(err, ErrPolicy) {
		t.Fatal("cleanup-only assets gained preparation evidence")
	}
}

func TestPolicyHostStageCanceledOrMalformedInputsRefuseBeforeCapture(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assets, err := PreparePolicyHostStageAssets(ctx, nil, sandboxruntime.Spec{}, HostStageLocation{}, bridgeprocess.Inputs{}, nil, nil)
	if assets != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preparation reached policy or filesystem work")
	}
	policy, spec, location := workspacePolicyFixture(t, nil)
	assets, err = PreparePolicyHostStageAssets(context.Background(), policy, spec, location, bridgeprocess.Inputs{}, nil, nil)
	if assets != nil || !errors.Is(err, ErrAssets) {
		t.Fatal("invalid held inputs reached capture of the deliberately absent source")
	}
}
