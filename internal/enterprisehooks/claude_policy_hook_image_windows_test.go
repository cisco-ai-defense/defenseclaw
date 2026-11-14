// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// hookImageFixtureLayout puts a transition image and a launch image of one
// install bin beside the fixture's trusted hook, with the fixture's
// protections, and admits both to the hook trust check.
func hookImageFixtureLayout(t *testing.T, fixture windowsManagedInstallFixture) (transition, launch string) {
	t.Helper()
	bin := filepath.Join(filepath.Dir(filepath.Dir(fixture.hookExe)), "bin")
	launchDir := filepath.Join(bin, "hooks", "0123456789abcdef")
	transition = filepath.Join(bin, "defenseclaw-hook.exe")
	launch = filepath.Join(launchDir, "defenseclaw-hook.exe")
	if err := os.MkdirAll(launchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{bin, filepath.Dir(launchDir), launchDir} {
		setWindowsTestPathExactOwner(t, dir, fixture.targetSID)
		if err := setWindowsUserPathProtection(dir, fixture.targetSID, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{transition, launch} {
		if err := os.WriteFile(path, []byte("test native hook"), 0o700); err != nil {
			t.Fatal(err)
		}
		setWindowsTestPathExactOwner(t, path, fixture.targetSID)
		if err := setWindowsUserPathProtection(path, fixture.targetSID, false); err != nil {
			t.Fatal(err)
		}
	}
	return transition, launch
}

func hookImageClaudeSetup(hook string) connector.SetupOpts {
	return withWindowsClaudeManagedHooksOnly(connector.SetupOpts{
		APIAddr:                  "127.0.0.1:18970",
		HookFailMode:             canonicalHookFailMode(""),
		SecureClientHookDelivery: secureClientHookDelivery(),
		ManagedEnterprise:        true,
		HookExecutable:           hook,
		HookContractID:           connector.ResolveHookContract("claudecode", "").Contract.ContractID,
	})
}

// GAP-0751: the first upgrade to the launch image runs an ensure pass over
// the Claude machine policy the transition image published. It is this
// deployment's and moves to the launch image with its contract; it used to
// be refused as another deployment's, which stopped the switch.
func TestClaudeMachinePolicyOfAnEarlierHookImageMovesToTheLaunchImage(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, nil)
	transition, launch := hookImageFixtureLayout(t, fixture)
	before := hookImageClaudeSetup(transition)
	published, err := connector.NewClaudeCodeConnector().ManagedHookPolicy(before)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installWindowsClaudeManagedPolicy(published, before, fixture.targetSID); err != nil {
		t.Fatalf("publish the transition image's policy: %v", err)
	}
	after := hookImageClaudeSetup(launch)
	body, err := connector.NewClaudeCodeConnector().ManagedHookPolicy(after)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installWindowsClaudeManagedPolicy(body, after, nil); err != nil {
		t.Fatalf("ensure over the transition image's policy: %v", err)
	}
	policy, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(policy), strings.ReplaceAll(launch, `\`, `\\`)) ||
		strings.Contains(string(policy), strings.ReplaceAll(transition, `\`, `\\`)) {
		t.Fatalf("policy was not moved to the launch image:\n%s", policy)
	}
	stateBody, err := os.ReadFile(filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile))
	if err != nil {
		t.Fatal(err)
	}
	var state windowsClaudeManagedPolicyState
	if err := json.Unmarshal(stateBody, &state); err != nil {
		t.Fatal(err)
	}
	if state.HookExecutable != launch || len(state.TargetSIDs) != 1 {
		t.Fatalf("ownership record = %+v; want the launch image and the enrolled SID", state)
	}
	// A hook of another install root is still another deployment.
	other := hookImageClaudeSetup(filepath.Join(filepath.Dir(filepath.Dir(fixture.hookExe)), "other", "bin", "defenseclaw-hook.exe"))
	otherBody, err := connector.NewClaudeCodeConnector().ManagedHookPolicy(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installWindowsClaudeManagedPolicy(otherBody, other, nil); err == nil {
		t.Fatal("another install root's hook took over the policy")
	}
}

// Missing-policy recovery authenticates a record an earlier image of this
// install wrote against that image's render (GAP-0751); a digest no recorded
// render produces is still refused.
func TestClaudeRecordedPolicyDigestOfAnEarlierHookImage(t *testing.T) {
	record := windowsClaudeManagedPolicyState{
		SchemaVersion:      2,
		HookExecutable:     hookImageTestTransition,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
	}
	rendered, err := renderWindowsClaudeRecordedPolicy(record, windowsClaudeRecordedPolicyContracts()[0], true)
	if err != nil {
		t.Fatal(err)
	}
	if !windowsClaudeRecordedPolicyDigestMatches(record, windowsManagedPolicyDigest(rendered)) {
		t.Fatal("the recorded render of the transition image was not recognized")
	}
	if windowsClaudeRecordedPolicyDigestMatches(record, windowsManagedPolicyDigest([]byte("{}\n"))) {
		t.Fatal("an arbitrary policy digest was authenticated")
	}
}
