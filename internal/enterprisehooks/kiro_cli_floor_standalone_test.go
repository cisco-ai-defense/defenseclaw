// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Managed Windows Kiro resolves to its reviewed contract, which still covers
// the kiro-cli builds 1.0.3 enrolled so those rows keep being repaired. The
// standalone profile enrolls, and follows a version change to, only
// KiroCLIHookFloor and later, as the not-gated floor does on Unix.
func TestStandaloneKiroCLIFloorRefusalGatesTheManagedWindowsContract(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	for raw, refused := range map[string]bool{
		"2.24.1":                         true,
		"kiro-cli 2.26.1":                true,
		"2.27.1":                         false,
		"2.30.0":                         false,
		"1.0.190" + KiroIDEVersionSuffix: false, // the IDE has its own contract floor
	} {
		resolution := connector.ResolveWindowsManagedKiroHookContract(raw)
		if resolution.Status != connector.HookCompatibilityKnown {
			t.Fatalf("fixture %s must resolve to a managed contract: %s (%s)", raw, resolution.Status, resolution.Reason)
		}
		reason := kiroCLIFloorRefusal(resolution)
		if refused != (reason != "") || (refused && !strings.Contains(reason, "is below 2.27.1")) {
			t.Fatalf("%s refusal = %q, want refused=%t", raw, reason, refused)
		}
		if accepted := standaloneAcceptsAgentVersionChange(resolution); accepted == refused {
			t.Fatalf("%s version change accepted = %t, want %t", raw, accepted, !refused)
		}
	}
	// Every other resolution is gated elsewhere.
	if reason := kiroCLIFloorRefusal(connector.ResolveHookContract("kiro", "2.22.0")); reason == "" {
		t.Fatal("not-gated Kiro escaped the shared floor")
	}
	if reason := kiroCLIFloorRefusal(connector.ResolveHookContract("codex", "0.140.0")); reason != "" {
		t.Fatalf("codex refused: %s", reason)
	}
}

func TestKiroCLIFloorRefusesNewHooksInEveryModeAndProfile(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	conn := connector.NewKiroConnector()
	for _, standalone := range []bool{true, false} {
		t.Run(map[bool]string{true: "standalone", false: "secure-client"}[standalone], func(t *testing.T) {
			setStandaloneProfileForTest(t, standalone)
			if !standalone {
				useSecureClientHookDelivery(t)
			}
			for _, mode := range []string{"observe", "action"} {
				opts := connector.SetupOpts{DataDir: t.TempDir(), AgentVersion: "kiro-cli 2.26.1"}
				_, err := prepareHookContract(mode, conn, opts)
				if err == nil || !strings.Contains(err.Error(), "is below 2.27.1") {
					t.Fatalf("%s new Kiro hooks in %s: %v, want floor refusal", mode, map[bool]string{true: "standalone", false: "secure-client"}[standalone], err)
				}
				opts.AgentVersion = "kiro-cli 2.27.1"
				if _, err := prepareHookContract(mode, conn, opts); err != nil {
					t.Fatalf("%s Kiro at the floor in %s: %v", mode, map[bool]string{true: "standalone", false: "secure-client"}[standalone], err)
				}
				opts.AgentVersion = "1.0.181" + KiroIDEVersionSuffix
				if _, err := prepareHookContract(mode, conn, opts); err == nil || !strings.Contains(err.Error(), "Kiro IDE") {
					t.Fatalf("%s new IDE below its global-hook floor: %v", mode, err)
				}
				opts.AgentVersion = "1.0.182" + KiroIDEVersionSuffix
				if _, err := prepareHookContract(mode, conn, opts); err != nil {
					t.Fatalf("%s IDE at its global-hook floor: %v", mode, err)
				}
			}
			t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "1")
			if _, err := prepareHookContract("observe", conn, connector.SetupOpts{
				DataDir: t.TempDir(), AgentVersion: "kiro-cli 2.26.1",
			}); err == nil || !strings.Contains(err.Error(), "is below 2.27.1") {
				t.Fatalf("contract drift override bypassed Kiro's hook floor: %v", err)
			}
			t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
		})
	}
}

func TestSecureClientKeepsAnEarlierKiroCLIEnrollmentAcrossUpgrade(t *testing.T) {
	useSecureClientHookDelivery(t)
	setStandaloneProfileForTest(t, false)
	conn := connector.NewKiroConnector()
	opts := connector.SetupOpts{DataDir: t.TempDir(), AgentVersion: "kiro-cli 2.24.1", HookFailMode: "open"}
	opts.HookContractID = connector.BestEffortHookContract(resolveHookContract("kiro", opts.AgentVersion)).ContractID
	if err := connector.SaveHookContractLockEntry(opts.DataDir, connector.NewHookContractLockEntry(opts, conn, "1.0.3")); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareHookContract("observe", conn, opts); err != nil {
		t.Fatalf("earlier enrolled CLI lost its interactive hook repair: %v", err)
	}
	opts.AgentVersion = "kiro-cli 2.26.1"
	if _, err := prepareHookContract("observe", conn, opts); err == nil || !strings.Contains(err.Error(), "is below 2.27.1") {
		t.Fatalf("a different below-floor build was followed: %v", err)
	}
}

func TestEarlierKiroIDEBelowGlobalHookFloorCannotBeRepairedAsProtected(t *testing.T) {
	useSecureClientHookDelivery(t)
	setStandaloneProfileForTest(t, false)
	conn := connector.NewKiroConnector()
	opts := connector.SetupOpts{DataDir: t.TempDir(), AgentVersion: "1.0.181" + KiroIDEVersionSuffix, HookFailMode: "open"}
	opts.HookContractID = connector.BestEffortHookContract(resolveHookContract("kiro", opts.AgentVersion)).ContractID
	if err := connector.SaveHookContractLockEntry(opts.DataDir, connector.NewHookContractLockEntry(opts, conn, "1.0.3")); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareHookContract("observe", conn, opts); err == nil || !strings.Contains(err.Error(), "Kiro IDE version 1.0.181") {
		t.Fatalf("old IDE without global hooks was treated as protected: %v", err)
	}
}
