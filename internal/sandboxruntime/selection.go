// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"maps"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Select resolves only runtime precedence: explicit, configured, then legacy
// OpenShell. Installation, platform, enablement and policy admission follow
// separately. In particular, a Windows host does not imply an AXIS fallback.
func Select(requested, configured ID) (ID, error) {
	for _, id := range []ID{requested, configured} {
		if id != "" && id != Auto && !runtimeID(id) {
			return "", sandboxapi.Errorf(sandboxapi.CodeInvalid, "unknown sandbox runtime %q", id)
		}
	}
	if requested != "" && requested != Auto {
		return requested, nil
	}
	if configured != "" && configured != Auto {
		return configured, nil
	}
	return OpenShell, nil
}

// SelectExisting ignores the current default. Empty recorded identity is the
// supported legacy OpenShell record; auto is never a valid recorded runtime.
// An explicit different runtime requires creating a new session.
func SelectExisting(recorded, requested ID) (ID, error) {
	if recorded == "" {
		recorded = OpenShell
	}
	if !runtimeID(recorded) {
		return "", sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox records invalid runtime %q", recorded)
	}
	if requested == "" || requested == Auto {
		return recorded, nil
	}
	if !runtimeID(requested) {
		return "", sandboxapi.Errorf(sandboxapi.CodeInvalid, "unknown sandbox runtime %q", requested)
	}
	if requested != recorded {
		return "", sandboxapi.Errorf(sandboxapi.CodeConflict, "existing sandbox uses %s; create a new session to use %s", recorded, requested)
	}
	return recorded, nil
}

// BackendSelection is an explicit platform and runtime request. Backend may be
// omitted only when exactly one candidate matches; map order or availability
// must never silently choose a different enforcement substrate.
type BackendSelection struct {
	Runtime      ID
	Backend      string
	HostOS       string
	ExecutionOS  string
	Architecture string
}

// SelectBackend consumes trusted adapter discovery, not configuration supplied
// capabilities. It neither starts nor probes a runtime. Capability and harness
// requirements must still be checked on the returned evidence before execution.
func SelectBackend(request BackendSelection, candidates []RuntimeInfo) (RuntimeInfo, error) {
	if !runtimeID(request.Runtime) || !osName(request.HostOS) || !osName(request.ExecutionOS) || !architecture(request.Architecture) || request.Backend != "" && !concreteName(request.Backend) {
		return RuntimeInfo{}, sandboxapi.Errorf(sandboxapi.CodeInvalid, "sandbox backend selection requires a concrete runtime and platform")
	}
	var matched []RuntimeInfo
	for _, candidate := range candidates {
		id := candidate.Identity
		if id.Runtime == request.Runtime && id.HostOS == request.HostOS && id.ExecutionOS == request.ExecutionOS && id.Architecture == request.Architecture && (request.Backend == "" || id.Backend == request.Backend) {
			matched = append(matched, candidate)
		}
	}
	if len(matched) == 0 {
		return RuntimeInfo{}, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "sandbox runtime %s has no installed backend for the requested platform", request.Runtime)
	}
	if len(matched) != 1 {
		return RuntimeInfo{}, sandboxapi.Errorf(sandboxapi.CodeConflict, "sandbox runtime %s has ambiguous backend evidence; select one exact backend", request.Runtime)
	}
	if err := matched[0].Require(); err != nil {
		return RuntimeInfo{}, err
	}
	return cloneInfo(matched[0]), nil
}

func runtimeID(id ID) bool { return id == OpenShell || id == Axis }

func cloneInfo(info RuntimeInfo) RuntimeInfo {
	info.Supported = slices.Clone(info.Supported)
	info.Unavailable = maps.Clone(info.Unavailable)
	info.Harnesses = maps.Clone(info.Harnesses)
	for name, verification := range info.Harnesses {
		verification.Supported = slices.Clone(verification.Supported)
		info.Harnesses[name] = verification
	}
	return info
}
