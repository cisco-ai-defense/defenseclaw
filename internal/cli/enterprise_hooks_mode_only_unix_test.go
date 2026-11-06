//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// The Linux and macOS guardian workers share this path. A policy-only mode
// change must leave an already-correct Hermes target untouched, while a
// changed hook still receives a repair on the next pass.
func TestGAP0638GAP0642ManagedHermesModeOnlyEnsureKeepsTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the standalone worker runs as the account")
	}
	previousStandalone := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandalone) })
	home := t.TempDir()
	t.Setenv("HOME", home)
	configDir := filepath.Join(home, ".hermes")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "hermes", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "observe", HookFailMode: "closed", AgentVersion: "0.21.5",
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("initial Hermes install: %v", err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	lockPath := filepath.Join(dataDir, "hook_contract_lock.json")
	scriptPath := filepath.Join(dataDir, "hooks", "hermes-hook.sh")
	lockBefore, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	scriptBefore, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	opts.GuardrailMode = "action"
	opts.AllowMissingHookConfigRepair = true
	request := enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply, Standalone: true,
		Targets: []enterpriseHookWorkerTarget{{
			Index: 0, Mode: enterpriseHookWorkerModeVerifyOrRepair, PreviouslyProtected: true,
			Options: enterpriseHookWorkerOptionsFrom(opts),
		}},
	}
	response := runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK || response.Targets[0].Repaired {
		t.Fatalf("%s mode-only ensure reported repair: %+v", runtime.GOOS, response.Targets)
	}
	lockAfter, err := os.ReadFile(lockPath)
	if err != nil || string(lockAfter) != string(lockBefore) {
		t.Fatalf("mode-only ensure changed the contract lock: equal=%t err=%v", string(lockAfter) == string(lockBefore), err)
	}
	scriptAfter, err := os.Stat(scriptPath)
	if err != nil || !os.SameFile(scriptBefore, scriptAfter) || !scriptBefore.ModTime().Equal(scriptAfter.ModTime()) {
		t.Fatalf("mode-only ensure rewrote the Hermes hook: same=%t err=%v", err == nil && os.SameFile(scriptBefore, scriptAfter), err)
	}
	if err := os.WriteFile(scriptPath, []byte("changed hook\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	response = runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK || !response.Targets[0].Repaired {
		t.Fatalf("changed Hermes hook was not repaired: %+v", response.Targets)
	}
}

func TestGAP0638GAP0642PolicyRerenderIsNotReportedAsDamage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the standalone worker runs as the account")
	}
	previousStandalone := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandalone) })
	for _, tc := range []struct {
		name   string
		change bool
	}{
		{name: "policy only"},
		{name: "policy and changed hook", change: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			opts := enterprisehooks.InstallOptions{
				ConnectorName: "kiro", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
				APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
				APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("d", 64),
				GuardrailMode: "observe", HookFailMode: "open", AgentVersion: "2.27.1",
			}
			if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
				t.Fatalf("initial Kiro install: %v", err)
			}
			if tc.change {
				path := filepath.Join(home, ".defenseclaw", "hooks", "kiro-hook.sh")
				if err := os.WriteFile(path, []byte("changed hook\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			opts.GuardrailMode, opts.HookFailMode = "action", "closed"
			opts.AllowMissingHookConfigRepair = true
			request := enterpriseHookWorkerRequest{
				Operation: enterpriseHookWorkerOpApply, Standalone: true,
				Targets: []enterpriseHookWorkerTarget{{
					Index: 0, Mode: enterpriseHookWorkerModeVerifyOrRepair, PreviouslyProtected: true,
					Options: enterpriseHookWorkerOptionsFrom(opts),
				}},
			}
			response := runEnterpriseHookWorkerApply(context.Background(), request)
			if len(response.Targets) != 1 || !response.Targets[0].OK || response.Targets[0].Repaired != tc.change {
				t.Fatalf("policy reconciliation classification = %+v, want repaired=%t", response.Targets, tc.change)
			}
			if _, err := enterprisehooks.Verify(context.Background(), opts); err != nil {
				t.Fatalf("reconciled Kiro runtime did not verify: %v", err)
			}
		})
	}
}
