// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"testing"
)

// GAP-0644: a protected target an earlier release wrote waits for its
// account's next sign-in on both profiles (a Secure Client upgrade with a
// signed-out enrolled account failed the same way), so the release check
// reads the target on both; one it cannot pin to its profile is no wait.
func TestWindowsProtectedTargetFromOtherReleaseReadsTheTargetOnBothProfiles(t *testing.T) {
	previous := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
	opts := InstallOptions{ConnectorName: "codex", UserHome: `C:\Users\does-not-exist`, OwnerSID: "S-1-12-1-1-2-3-1002"}
	for _, standalone := range []bool{false, true} {
		windowsEnterpriseStandaloneProcess = func() bool { return standalone }
		if _, other, err := WindowsProtectedTargetFromOtherRelease(opts); other || err == nil {
			t.Fatalf("standalone=%t, unpinned profile: other=%t err=%v, want an error and no wait", standalone, other, err)
		}
		if WindowsSecureClientProfileProcess() == standalone {
			t.Fatalf("standalone=%t: WindowsSecureClientProfileProcess = %t", standalone, !standalone)
		}
	}
}

// Setup's verify runs outside LocalSystem; only that exact refusal is
// recognised, wrapped or not.
func TestIsWindowsEnterpriseNotLocalSystem(t *testing.T) {
	if !IsWindowsEnterpriseNotLocalSystem(errWindowsEnterpriseNotLocalSystem) ||
		!IsWindowsEnterpriseNotLocalSystem(fmt.Errorf("session check: %w", errWindowsEnterpriseNotLocalSystem)) {
		t.Fatal("the not-LocalSystem refusal was not recognised")
	}
	if IsWindowsEnterpriseNotLocalSystem(errors.New("enterprise hooks: WTS query failed: access is denied")) ||
		IsWindowsEnterpriseNotLocalSystem(nil) {
		t.Fatal("another error was taken for the not-LocalSystem refusal")
	}
}

// GAP-0980: the wait of a signed-out account for the connectors whose hook a
// machine policy registers rests on that policy being in force: the vendor
// policy file the guardian publishes (Copilot, OpenCode) must be present and
// trusted, any other connector has no such proof, and an untrusted or missing
// file is no wait.
func TestWindowsProtectedTargetHasMachineHookRegistrationNeedsThePolicyInForce(t *testing.T) {
	previousPath, previousTrust, previousOpenCode := windowsRuntimeOnlyPolicyPath, windowsRuntimeOnlyPolicyTrustCheck, windowsOpenCodeMachinePolicyInForce
	previousStandalone := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() {
		windowsRuntimeOnlyPolicyPath, windowsRuntimeOnlyPolicyTrustCheck, windowsOpenCodeMachinePolicyInForce = previousPath, previousTrust, previousOpenCode
		windowsEnterpriseStandaloneProcess = previousStandalone
	})
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	var trusted []string
	trustErr := error(nil)
	windowsRuntimeOnlyPolicyPath = func(name string) (string, error) { return `C:\ProgramData\test\` + name + ".json", nil }
	windowsRuntimeOnlyPolicyTrustCheck = func(path string) error {
		trusted = append(trusted, path)
		return trustErr
	}
	openCodeInForce := true
	windowsOpenCodeMachinePolicyInForce = func() bool { return openCodeInForce }

	for _, name := range []string{"copilot", "opencode"} {
		trusted, trustErr = nil, nil
		registered, err := WindowsProtectedTargetHasMachineHookRegistration(InstallOptions{ConnectorName: name})
		if err != nil || !registered || len(trusted) != 1 {
			t.Fatalf("%s with its policy in force: registered=%t err=%v trusted=%v, want a proof", name, registered, err, trusted)
		}
		trustErr = errors.New("policy file is writable by standard users")
		if registered, err = WindowsProtectedTargetHasMachineHookRegistration(InstallOptions{ConnectorName: name}); registered || err == nil {
			t.Fatalf("%s with an untrusted policy: registered=%t err=%v, want no proof and the reason", name, registered, err)
		}
	}
	// OpenCode on the per-user plugin route registers nothing machine-side.
	trustErr, openCodeInForce = nil, false
	if registered, err := WindowsProtectedTargetHasMachineHookRegistration(InstallOptions{ConnectorName: "opencode"}); registered || err != nil {
		t.Fatalf("opencode without its machine policy: registered=%t err=%v, want no proof", registered, err)
	}
	// Claude Code, Codex and the connectors that register in the account's
	// own agent configuration have no proof here.
	for _, name := range []string{"claudecode", "codex", "hermes", "amp", "devin", "antigravity", "kiro", "unknown"} {
		trusted = nil
		if registered, err := WindowsProtectedTargetHasMachineHookRegistration(InstallOptions{ConnectorName: name}); registered || err != nil || len(trusted) != 0 {
			t.Fatalf("%s: registered=%t err=%v trusted=%v, want no proof and no policy read", name, registered, err, trusted)
		}
	}
	// Cursor: an account that does not resolve is no proof.
	if registered, err := WindowsProtectedTargetHasMachineHookRegistration(InstallOptions{
		ConnectorName: "cursor", UserHome: `C:\Users\does-not-exist`, OwnerSID: "S-1-12-1-1-2-3-1002",
	}); registered || err == nil {
		t.Fatalf("cursor with an unpinned account: registered=%t err=%v, want an error and no proof", registered, err)
	}
}

func TestWindowsMachineHookRegistrationConnectorIsExactlyTheMachinePolicyOnes(t *testing.T) {
	for name, want := range map[string]bool{
		"copilot": true, "opencode": true, "cursor": true, " Copilot ": true,
		"claudecode": false, "codex": false, "hermes": false, "amp": false, "devin": false, "antigravity": false, "kiro": false, "": false,
	} {
		if got := WindowsMachineHookRegistrationConnector(name); got != want {
			t.Fatalf("WindowsMachineHookRegistrationConnector(%q) = %t, want %t", name, got, want)
		}
	}
}
