//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0151: a managed account whose Hermes printed "Hermes Agent v0.18.0
// (2026.5.1)", below the hermes-hooks-v1 floor, was enrolled at 0.18.0; the
// guardian rendered Hermes hooks with no contract in observe mode, and status
// and verify said coverage_complete and security_complete. The enumerator now
// enrolls no row for a version without a hook contract, or one it cannot
// read, and reports it as hook_contract_unverified. The real Hermes git
// install that prints only its release date (2026.9.24, which is 0.21.5)
// keeps its contract and its row.
func TestEnumerateUnixEnrollsNoHermesWithoutAHookContract(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	home := makeHome(t, homes, "r103t8h")
	enumerate := func(version, reason string) (Manifest, UnixEnumerationReport) {
		t.Helper()
		opts := UnixEnumerateOptions{
			Resolver: &fakeResolver{
				accounts: map[string]unixidentity.Account{
					"r103t8h": {Name: "r103t8h", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"},
				},
				listed: []string{"r103t8h"},
			},
			HomeRoots: []string{homes},
			UIDMin:    uid, UIDMax: uid + 1,
			Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
				if version != "" {
					return map[string]string{"hermes": version}, nil, nil
				}
				return nil, map[string]string{"hermes": reason}, nil
			},
		}
		manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("hermes"), connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		return manifest, report
	}

	for _, tc := range []struct {
		name, version, reason, message string
	}{
		{name: "below the floor", version: "0.18.0", message: "hermes 0.18.0 for user r103t8h is not protected: version 0.18.0 is not verified against a known hook contract"},
		{name: "release date before the first contract", version: "2026.5.1", message: "hermes 2026.5.1 for user r103t8h is not protected: version 2026.5.1 is not verified against a known hook contract"},
		{name: "version not readable", reason: UnixAgentUnversionedReasonPrefix + filepath.Join(home, ".local", "bin", "hermes"), message: "hermes for user r103t8h is not protected: installed, but its version could not be read"},
	} {
		manifest, report := enumerate(tc.version, tc.reason)
		if len(manifest.Targets) != 0 {
			t.Fatalf("%s: rows = %+v, want none (no row, so the guardian renders no hook)", tc.name, manifest.Targets)
		}
		if len(report.Unprotected) != 1 {
			t.Fatalf("%s: unprotected = %+v, want the Hermes install", tc.name, report.Unprotected)
		}
		got := report.Unprotected[0]
		if got.Code != UnprotectedCodeHookContractUnverified || got.Version != tc.version ||
			!strings.Contains(got.Message(), tc.message) || !strings.Contains(got.Message(), "runs without DefenseClaw hooks") {
			t.Fatalf("%s: unprotected entry = %+v, message %q", tc.name, got, got.Message())
		}
		// The record status and verify read keeps the code.
		data, err := MarshalUnprotectedAgents(report.Unprotected)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseUnprotectedAgents(data)
		if err != nil || len(parsed) != 1 || parsed[0].Code != UnprotectedCodeHookContractUnverified {
			t.Fatalf("%s: record round trip = %+v %v", tc.name, parsed, err)
		}
	}

	for _, version := range []string{"2026.9.24", "0.21.5+4977.g12e4d3e"} {
		manifest, report := enumerate(version, "")
		if len(manifest.Targets) != 1 || manifest.Targets[0].AgentVersion != version || len(report.Unprotected) != 0 {
			t.Fatalf("Hermes %s: rows = %+v unprotected = %+v, want one enrolled row", version, manifest.Targets, report.Unprotected)
		}
	}
}

// The guardian's install refuses a Hermes version without a hook contract in
// observe mode too, so a row enrolled by an earlier build renders no hooks
// and status names it hook_contract_unverified; the Hermes release-date
// version keeps hermes-hooks-v2.
func TestStandaloneInstallRendersNoHermesHooksWithoutAHookContract(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	for _, version := range []string{"0.18.0", "vunknown"} {
		refused := opts
		refused.AgentVersion = version
		if _, err := Install(context.Background(), refused); err == nil ||
			!strings.Contains(err.Error(), "is not verified against a known hook contract") {
			t.Fatalf("observe install of Hermes %q = %v, want the hook_contract_unverified refusal", version, err)
		}
		if _, err := os.Stat(filepath.Join(home, ".defenseclaw", "hooks", "hermes-hook.sh")); !os.IsNotExist(err) {
			t.Fatalf("Hermes %q: hook script rendered (%v)", version, err)
		}
		if data, _ := os.ReadFile(filepath.Join(home, ".hermes", "config.yaml")); strings.Contains(string(data), "hermes-hook.sh") {
			t.Fatalf("Hermes %q: config.yaml registers the hook:\n%s", version, data)
		}
	}

	covered := opts
	covered.AgentVersion = "2026.9.24"
	if _, err := Install(context.Background(), covered); err != nil {
		t.Fatalf("install of the Hermes release-date version: %v", err)
	}
	if lock := connector.LoadHookContractLockEntry(filepath.Join(home, ".defenseclaw"), "hermes"); lock.ContractID != "hermes-hooks-v2" {
		t.Fatalf("lock contract = %q (%+v), want hermes-hooks-v2", lock.ContractID, lock)
	}

	// The Secure Client profile keeps its rule: only action mode refuses.
	setStandaloneProfileForTest(t, false)
	if err := validateHookContract("observe", connector.NewHermesConnector(), connector.SetupOpts{AgentVersion: "0.18.0"}); err != nil {
		t.Fatalf("Secure Client observe = %v, want unchanged", err)
	}
}
