// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestArtifactIdentityRequiresRealKindAndCanonicalDigest(t *testing.T) {
	for _, kind := range []ArtifactKind{OCIImage, ExecutableBundle} {
		if err := (ArtifactIdentity{kind, "sha256:" + strings.Repeat("a", 64)}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, identity := range []ArtifactIdentity{
		{}, {"unregistered", "sha256:" + strings.Repeat("a", 64)},
		{OCIImage, strings.Repeat("a", 64)},
		{ExecutableBundle, "sha256:" + strings.Repeat("A", 64)},
		{ExecutableBundle, "sha256:short"},
	} {
		if identity.Validate() == nil {
			t.Fatalf("invalid artifact identity accepted: %+v", identity)
		}
	}
}

func TestRuntimeAdmissionRequiresPositiveEvidence(t *testing.T) {
	info := qualifiedInfo()
	if err := info.Require(Headless, StrictFilesystem); err != nil {
		t.Fatal(err)
	}
	wantCode(t, info.Require(Interactive), sandboxapi.CodePolicyViolation)
	var refusal *sandboxapi.Error
	if !errors.As(info.Require(Interactive), &refusal) || refusal.Detail != info.Unavailable[Interactive] {
		t.Fatal("capability refusal lost the adapter's unsupported reason")
	}
	wantCode(t, info.Require("unregistered"), sandboxapi.CodeInvalid)
	wantCode(t, (RuntimeInfo{}).Require(), sandboxapi.CodePolicyRejected)
	for _, change := range []func(*RuntimeInfo){
		func(i *RuntimeInfo) { i.Identity.Artifact = ArtifactIdentity{} },
		func(i *RuntimeInfo) { i.Identity.Backend = "auto" },
		func(i *RuntimeInfo) { i.Identity.Runtime = Auto },
		func(i *RuntimeInfo) { i.Identity.Version = "" },
		func(i *RuntimeInfo) { i.Posture = "" },
		func(i *RuntimeInfo) { i.Supported = append(i.Supported, Headless) },
		func(i *RuntimeInfo) { i.Supported = append(i.Supported, "unregistered") },
		func(i *RuntimeInfo) { i.Unavailable[Headless] = "contradictory" },
		func(i *RuntimeInfo) { i.Unavailable[Interactive] = "" },
	} {
		invalid := qualifiedInfo()
		change(&invalid)
		wantCode(t, invalid.Require(Headless), sandboxapi.CodePolicyRejected)
	}
	info.Available, info.Reason = false, "installation absent"
	wantCode(t, info.Require(Headless), sandboxapi.CodeUnavailable)
}

func TestLegacySelectionDoesNotMakeOpenShellAvailableOnWindows(t *testing.T) {
	selected, err := Select("", "")
	if err != nil || selected != OpenShell {
		t.Fatalf("legacy default changed: %q, %v", selected, err)
	}
	info := qualifiedInfo()
	info.Identity.Runtime, info.Identity.Backend, info.Identity.Driver = selected, "openshell", "docker"
	info.Identity.HostOS, info.Identity.ExecutionOS = "windows", "linux"
	wantCode(t, info.Require(Headless), sandboxapi.CodePolicyRejected)
	info.Identity.HostOS = "darwin"
	if err := info.Require(Headless); err != nil {
		t.Fatalf("OpenShell macOS host with Linux workload rejected: %v", err)
	}
}

func TestHarnessEvidenceCannotBeInheritedFromRuntime(t *testing.T) {
	info := qualifiedInfo()
	info.Supported = append(info.Supported, ManagedHooks)
	want := HarnessIdentity{Version: "synthetic-agent", HookContract: "synthetic-hook-contract", Artifact: info.Identity.Artifact}
	wantCode(t, info.RequireHarness("claudecode", want, ManagedHooks), sandboxapi.CodePolicyViolation)
	info.Harnesses = map[string]HarnessVerification{"claudecode": {Identity: want, Supported: []Capability{Headless}}}
	wantCode(t, info.RequireHarness("claudecode", want, ManagedHooks), sandboxapi.CodePolicyViolation)
	info.Harnesses["claudecode"] = HarnessVerification{Identity: want, Supported: []Capability{Headless, ManagedHooks}}
	if err := info.RequireHarness("claudecode", want, ManagedHooks); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*HarnessIdentity){
		func(h *HarnessIdentity) { h.Version = "different-agent" },
		func(h *HarnessIdentity) { h.HookContract = "different-hooks" },
		func(h *HarnessIdentity) { h.Artifact.Kind = OCIImage },
		func(h *HarnessIdentity) { h.Artifact.Digest = "sha256:" + strings.Repeat("b", 64) },
	} {
		changed := want
		mutate(&changed)
		wantCode(t, info.RequireHarness("claudecode", changed, ManagedHooks), sandboxapi.CodePolicyViolation)
	}
	info.Harnesses["claudecode"] = HarnessVerification{Identity: want, Supported: []Capability{Interactive}}
	wantCode(t, info.RequireHarness("claudecode", want), sandboxapi.CodePolicyRejected)
}

func TestSessionCustodyPinsOwnerRuntimeAndArtifacts(t *testing.T) {
	id := SessionIdentity{Owner: "synthetic-owner", ID: "dc-synthetic-instance", Name: "synthetic-session", Runtime: qualifiedInfo().Identity}
	if err := ValidateOwnedSession(id, id); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SessionIdentity){
		func(s *SessionIdentity) { s.Owner = "different-owner" },
		func(s *SessionIdentity) { s.ID = "different-instance" },
		func(s *SessionIdentity) { s.Runtime.Backend = "mxc" },
		func(s *SessionIdentity) { s.Runtime.Version = "different-version" },
		func(s *SessionIdentity) { s.Runtime.Artifact.Digest = "sha256:" + strings.Repeat("b", 64) },
		func(s *SessionIdentity) { s.Runtime.Runtime = Auto },
	} {
		observed := id
		mutate(&observed)
		wantCode(t, ValidateOwnedSession(id, observed), sandboxapi.CodePolicyRejected)
	}
}
