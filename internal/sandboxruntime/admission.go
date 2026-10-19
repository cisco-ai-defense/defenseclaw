// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

var (
	artifactDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identityName   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	sessionID      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sessionName    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

func concreteName(value string) bool { return value != "auto" && identityName.MatchString(value) }
func osName(value string) bool       { return value == "linux" || value == "darwin" || value == "windows" }
func architecture(value string) bool { return value == "amd64" || value == "arm64" }

func boundedText(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if r < ' ' || r == 127 {
			return false
		}
	}
	return true
}

func (a ArtifactIdentity) Validate() error {
	if (a.Kind != OCIImage && a.Kind != ExecutableBundle) || !artifactDigest.MatchString(a.Digest) {
		return fmt.Errorf("sandbox artifact requires an explicit kind and canonical sha256 digest")
	}
	return nil
}

func (id RuntimeIdentity) Validate() error {
	if !runtimeID(id.Runtime) || !concreteName(id.Backend) || !concreteName(id.Driver) || !osName(id.HostOS) || !osName(id.ExecutionOS) || !architecture(id.Architecture) || !boundedText(id.Version) {
		return fmt.Errorf("sandbox runtime identity must pin a concrete runtime, backend, driver, platform and version")
	}
	if id.Runtime == OpenShell && (id.HostOS == "windows" || id.ExecutionOS != "linux") {
		return fmt.Errorf("OpenShell requires a Linux or macOS host and a Linux workload")
	}
	return id.Artifact.Validate()
}

func (id HarnessIdentity) Validate() error {
	if !boundedText(id.Version) || !boundedText(id.HookContract) {
		return fmt.Errorf("sandbox harness identity requires an exact version and hook contract")
	}
	return id.Artifact.Validate()
}

func (id SessionIdentity) Validate() error {
	if !boundedText(id.Owner) || !sessionID.MatchString(id.ID) || !sessionName.MatchString(id.Name) {
		return fmt.Errorf("sandbox session requires an owner and valid immutable identity")
	}
	return id.Runtime.Validate()
}

// ValidateOwnedSession compares host-owned expectation with an observed
// instance. Matching a name or PID alone never grants lifecycle authority.
func ValidateOwnedSession(expected, observed SessionIdentity) error {
	if expected.Validate() != nil || observed.Validate() != nil || expected != observed {
		return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox instance does not match its recorded owner and runtime identity")
	}
	return nil
}

func knownCapability(cap Capability) bool {
	switch cap {
	case Headless, Interactive, CopyWorkspace, LiveMount, StrictFilesystem,
		OfflineNetwork, BrokerEgress, ManagedHooks, HostCredentials,
		ExecutableCredentialBinding, PersistentSessions, PolicyUpdate, ImageBuild,
		CPUHardLimit, MemoryHardLimit, ProcessTreeContainment, UntrustedExecution,
		SkipPermissions, MCPImport, MCPRemoteBroker:
		return true
	}
	return false
}

func validCapabilities(caps []Capability) bool {
	for i, cap := range caps {
		if !knownCapability(cap) || slices.Contains(caps[:i], cap) {
			return false
		}
	}
	return true
}

// Has reports a declared capability, not admission. Require also checks
// availability, pinned identity and contradictory discovery before execution.
func (info RuntimeInfo) Has(cap Capability) bool {
	return knownCapability(cap) && slices.Contains(info.Supported, cap)
}

// Require admits only explicitly qualified capabilities. Empty discovery or a
// missing capability is never interpreted as a permissive runtime default.
func (info RuntimeInfo) Require(required ...Capability) error {
	if !runtimeID(info.Identity.Runtime) {
		return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox discovery reports an invalid runtime identity")
	}
	if !info.Available {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "sandbox runtime %s is unavailable: %s", info.Identity.Runtime, info.Reason)
	}
	if info.Identity.Validate() != nil || !boundedText(info.Posture) || !validCapabilities(info.Supported) {
		return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox discovery lacks valid pinned identity and capability evidence")
	}
	for cap, reason := range info.Unavailable {
		if !knownCapability(cap) || !boundedText(reason) || info.Has(cap) {
			return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox capability evidence is contradictory or invalid")
		}
	}
	for _, cap := range required {
		if !knownCapability(cap) {
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "unknown sandbox capability %q", cap)
		}
		if !info.Has(cap) {
			reason := info.Unavailable[cap]
			if reason == "" {
				reason = "no verified enforcement or transport evidence is available for this capability"
			}
			return &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation,
				Message: fmt.Sprintf("sandbox runtime %s lacks required capability %s", info.Identity.Runtime, cap), Detail: reason}
		}
	}
	return nil
}

// RequireHarness needs independent evidence for the exact harness artifact;
// runtime-level support never certifies newly changed agent or hook bytes.
func (info RuntimeInfo) RequireHarness(harness string, expected HarnessIdentity, required ...Capability) error {
	if err := info.Require(required...); err != nil {
		return err
	}
	verification, ok := info.Harnesses[harness]
	if !concreteName(harness) || expected.Validate() != nil || !ok || verification.Identity != expected || !validCapabilities(verification.Supported) {
		return sandboxapi.Errorf(sandboxapi.CodePolicyViolation, "sandbox harness lacks matching immutable version, artifact and hook evidence")
	}
	for _, cap := range verification.Supported {
		if !info.Has(cap) {
			return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox harness capability exceeds its runtime evidence")
		}
	}
	for _, cap := range required {
		if !slices.Contains(verification.Supported, cap) {
			return sandboxapi.Errorf(sandboxapi.CodePolicyViolation, "sandbox harness %s lacks required capability %s", harness, cap)
		}
	}
	return nil
}
