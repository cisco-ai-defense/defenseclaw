// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func qualifiedInfo() RuntimeInfo {
	return RuntimeInfo{
		Identity: RuntimeIdentity{
			Runtime: Axis, Backend: "axis_native", Driver: "landlock",
			HostOS: "linux", ExecutionOS: "linux", Architecture: "amd64", Version: "synthetic-test-version",
			Artifact: ArtifactIdentity{Kind: ExecutableBundle, Digest: "sha256:" + strings.Repeat("a", 64)},
		},
		Available: true, Posture: "synthetic-test-evidence",
		Supported:   []Capability{Headless, StrictFilesystem},
		Unavailable: map[Capability]string{Interactive: "synthetic terminal evidence absent"},
	}
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if !sandboxapi.IsCode(err, code) {
		t.Fatalf("wanted %s refusal, got %v", code, err)
	}
}

func TestSelectPreservesLegacyAndExplicitPrecedence(t *testing.T) {
	for _, tc := range []struct {
		requested, configured, want ID
	}{
		{"", "", OpenShell}, {Auto, Auto, OpenShell},
		{"", Axis, Axis}, {Auto, Axis, Axis},
		{OpenShell, Axis, OpenShell}, {Axis, OpenShell, Axis},
	} {
		got, err := Select(tc.requested, tc.configured)
		if err != nil || got != tc.want {
			t.Fatalf("Select(%q, %q) = %q, %v; want %q", tc.requested, tc.configured, got, err, tc.want)
		}
	}
	for _, pair := range [][2]ID{{"typo", Axis}, {Axis, "typo"}, {"AXIS", ""}} {
		_, err := Select(pair[0], pair[1])
		wantCode(t, err, sandboxapi.CodeInvalid)
	}
}

func TestExistingSessionDoesNotFollowChangedDefault(t *testing.T) {
	for _, requested := range []ID{"", Auto, OpenShell} {
		got, err := SelectExisting(OpenShell, requested)
		if err != nil || got != OpenShell {
			t.Fatalf("recorded runtime changed: %q, %v", got, err)
		}
	}
	if got, err := SelectExisting("", ""); err != nil || got != OpenShell {
		t.Fatalf("legacy record not preserved: %q, %v", got, err)
	}
	_, err := SelectExisting(OpenShell, Axis)
	wantCode(t, err, sandboxapi.CodeConflict)
	_, err = SelectExisting(Auto, Axis)
	wantCode(t, err, sandboxapi.CodePolicyRejected)
	_, err = SelectExisting(Axis, "unknown")
	wantCode(t, err, sandboxapi.CodeInvalid)
}

func TestBackendSelectionNeverFallsBack(t *testing.T) {
	info := qualifiedInfo()
	req := BackendSelection{Runtime: Axis, Backend: "mxc", HostOS: "linux", ExecutionOS: "linux", Architecture: "amd64"}
	_, err := SelectBackend(req, []RuntimeInfo{info})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	missing := info
	missing.Identity.Backend = "mxc"
	missing.Available, missing.Reason = false, "strict filesystem unsupported"
	_, err = SelectBackend(req, []RuntimeInfo{missing, info})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	if !strings.Contains(err.Error(), missing.Reason) {
		t.Fatal("selected backend refusal lost its reason")
	}
	req.Backend = ""
	_, err = SelectBackend(req, []RuntimeInfo{missing, info})
	wantCode(t, err, sandboxapi.CodeConflict)
	req.Backend = "auto"
	_, err = SelectBackend(req, []RuntimeInfo{info})
	wantCode(t, err, sandboxapi.CodeInvalid)
	req.Backend, req.Runtime = "axis_native", OpenShell
	_, err = SelectBackend(req, []RuntimeInfo{info})
	wantCode(t, err, sandboxapi.CodeUnavailable)
}

func TestBackendSelectionRequiresExactPlatformAndCopiesEvidence(t *testing.T) {
	info := qualifiedInfo()
	info.Harnesses = map[string]HarnessVerification{
		"claudecode": {Identity: HarnessIdentity{Version: "synthetic-agent", HookContract: "synthetic-hook-contract", Artifact: info.Identity.Artifact}, Supported: []Capability{Headless}},
	}
	req := BackendSelection{Runtime: Axis, Backend: "axis_native", HostOS: "windows", ExecutionOS: "windows", Architecture: "amd64"}
	_, err := SelectBackend(req, []RuntimeInfo{info})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	req.HostOS, req.ExecutionOS = "linux", "linux"
	selected, err := SelectBackend(req, []RuntimeInfo{info})
	if err != nil || selected.Identity != info.Identity {
		t.Fatalf("exact backend did not select: %v", err)
	}
	selected.Supported[0] = Interactive
	selected.Unavailable[Interactive] = "changed copy"
	selected.Harnesses["claudecode"].Supported[0] = Interactive
	if info.Supported[0] != Headless || info.Unavailable[Interactive] == "changed copy" || info.Harnesses["claudecode"].Supported[0] != Headless {
		t.Fatal("selected evidence aliases mutable adapter discovery")
	}
}
