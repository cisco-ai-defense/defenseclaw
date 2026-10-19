// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// HostStageLocation is selected by the trusted host owner. Neither field is
// accepted from a guest, attachment request or serialized execution policy.
type HostStageLocation struct {
	DataDir string
	Home    string
}

type workspacePreparation struct {
	policy    *sandboxruntime.ExecutionPolicy
	identity  sandboxruntime.SessionIdentity
	component sandboxruntime.PolicyComponentBinding
	summary   workspace.HostStageSummary
}

// Decode every current workspace field, including fields whose execution
// semantics are still unsupported. A future resolver field cannot be ignored.
type workspacePolicyValues struct {
	Posture struct {
		Mode        string   `json:"mode"`
		Masks       []string `json:"masks"`
		Unmask      []string `json:"unmask"`
		Review      []string `json:"review"`
		MaxUploadMB int      `json:"max_upload_mb"`
		GitDepth    int      `json:"git_depth"`
		OnExit      string   `json:"on_exit"`
	} `json:"posture"`
	Undo struct {
		Enabled bool
		MaxMB   int
		Dirs    []string
	} `json:"undo_ignored"`
	Project   string   `json:"project"`
	Real      string   `json:"project_real"`
	Protected []string `json:"protected_policy_sources"`
}

func decodeWorkspacePolicyValues(data []byte) (workspacePolicyValues, error) {
	var values workspacePolicyValues
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&values); err != nil || decoder.Decode(new(any)) != io.EOF {
		return workspacePolicyValues{}, ErrPolicy
	}
	return values, nil
}

func policyHostStageOptions(policy *sandboxruntime.ExecutionPolicy, spec sandboxruntime.Spec, location HostStageLocation) (workspace.StageOptions, sandboxruntime.PolicyComponentBinding, error) {
	if policy.Digest() == "" || spec.Identity.Validate() != nil || spec.Identity.Runtime.Runtime != sandboxruntime.Axis ||
		spec.Identity.Runtime.HostOS != runtime.GOOS || spec.Identity.Runtime.ExecutionOS != runtime.GOOS ||
		spec.Identity.Runtime.Backend != "mxc" || spec.GuestWorkspace != "/work" || spec.HostWorkspace != "" {
		return workspace.StageOptions{}, sandboxruntime.PolicyComponentBinding{}, ErrPolicy
	}
	driver := "bubblewrap"
	if runtime.GOOS == "windows" {
		driver = "process_container"
	} else if runtime.GOOS != "linux" {
		return workspace.StageOptions{}, sandboxruntime.PolicyComponentBinding{}, workspace.ErrUnsupportedPlatform
	}
	if spec.Identity.Runtime.Driver != driver || location.DataDir == "" || location.Home == "" {
		return workspace.StageOptions{}, sandboxruntime.PolicyComponentBinding{}, ErrPolicy
	}
	var found *sandboxruntime.PolicyComponent
	for _, component := range policy.Components() {
		if component.Name == sandboxruntime.PolicyWorkspace {
			if found != nil {
				return workspace.StageOptions{}, sandboxruntime.PolicyComponentBinding{}, ErrPolicy
			}
			copy := component
			found = &copy
		}
	}
	if found == nil {
		return workspace.StageOptions{}, sandboxruntime.PolicyComponentBinding{}, ErrPolicy
	}
	values, err := decodeWorkspacePolicyValues(found.Value)
	if err != nil {
		return workspace.StageOptions{}, sandboxruntime.PolicyComponentBinding{}, ErrPolicy
	}
	// This producer has a conservative canonical-source and 500 MiB floor.
	// Refuse an incompatible requested posture rather than changing its limits.
	if values.Posture.Mode != config.OpenShellWorkdirCopy || values.Project == "" || values.Project != values.Real ||
		!filepath.IsAbs(values.Real) || filepath.Clean(values.Real) != values.Real ||
		values.Posture.MaxUploadMB <= 0 || int64(values.Posture.MaxUploadMB) > workspace.DefaultCopyMaxBytes>>20 || values.Posture.GitDepth <= 0 ||
		values.Undo.Enabled {
		return workspace.StageOptions{}, sandboxruntime.PolicyComponentBinding{}, ErrPolicy
	}
	return workspace.StageOptions{
		Name: spec.Identity.Name, Project: values.Real, DataDir: location.DataDir, Home: location.Home,
		Protected: slices.Clone(values.Protected), Masks: slices.Clone(values.Posture.Masks), Unmask: slices.Clone(values.Posture.Unmask),
		GitDepth: values.Posture.GitDepth, MaxBytes: int64(values.Posture.MaxUploadMB) << 20,
	}, sandboxruntime.PolicyComponentBinding{Name: found.Name, Digest: found.Digest}, nil
}

// PreparePolicyHostStageAssets captures the workspace using the exact resolved
// host policy and transfers it into held asset custody. Callers cannot override
// masks, limits, protected sources, the default secret detector or content scan.
// No image, child, namespace or sandbox is executed by this producer.
//
// The initial floor is copied canonical projects on supported Windows/Linux
// hosts. This is preparation evidence only: review/on-exit/undo, export and
// native mount enforcement remain unsupported by the complete policy compiler.
// The runtime catalog stays closed. The production factory must separately
// admit runtime availability, current authority and every policy component.
//
// As with NewHostStageAssets, a nonnil error result owns partial cleanup only;
// retain and Close it. Supplied images/files transfer only on complete success.
func PreparePolicyHostStageAssets(ctx context.Context, policy *sandboxruntime.ExecutionPolicy, spec sandboxruntime.Spec, location HostStageLocation, inputs bridgeprocess.Inputs, read, write []string) (*Assets, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	opts, component, err := policyHostStageOptions(policy, spec, location)
	if err != nil {
		return nil, err
	}
	if err := validateHostStageInputs(spec.Identity, inputs, read, write); err != nil {
		return nil, err
	}
	stage, err := workspace.PrepareHostStage(ctx, opts)
	if err != nil {
		if stage != nil {
			return &Assets{identity: spec.Identity, cleanupOnly: true, releaseStage: stage.Close}, err
		}
		return nil, err
	}
	assets, err := NewHostStageAssets(ctx, spec.Identity, inputs, read, write, stage)
	if assets != nil {
		if err == nil {
			assets.workspacePreparation = &workspacePreparation{policy: policy, identity: spec.Identity, component: component, summary: stage.Summary()}
		}
		return assets, err
	}
	// A nil handoff result leaves the prepared stage with this producer. A
	// cleanup refusal must retain its exact owner rather than drop the stage.
	if cleanupErr := stage.Close(); cleanupErr != nil {
		return &Assets{identity: spec.Identity, cleanupOnly: true, releaseStage: stage.Close}, errors.Join(err, cleanupErr)
	}
	return nil, err
}

func validateWorkspacePreparation(policy *sandboxruntime.ExecutionPolicy, spec sandboxruntime.Spec, assets *Assets) error {
	if assets == nil || assets.workspacePreparation == nil {
		return nil // No binding means no preparation evidence or acknowledgement.
	}
	prepared := assets.workspacePreparation
	if prepared.policy != policy || prepared.identity != spec.Identity || assets.cleanupOnly || assets.closed ||
		prepared.summary.SourceIdentity == "" || prepared.summary.Project == "" {
		return ErrPolicy
	}
	for _, component := range policy.Components() {
		if component.Name == sandboxruntime.PolicyWorkspace && prepared.component == (sandboxruntime.PolicyComponentBinding{Name: component.Name, Digest: component.Digest}) {
			return nil
		}
	}
	return ErrPolicy
}
