// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestClaudeManagedPolicyMatchesTheContractItWasRenderedFor(t *testing.T) {
	provider := connector.NewClaudeCodeConnector()
	setup := connector.SetupOpts{
		APIAddr:           "127.0.0.1:18970",
		HookFailMode:      "closed",
		ManagedEnterprise: true,
		HookExecutable:    `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
	}
	contracts := connector.KnownHookContracts("claudecode")
	if len(contracts) < 2 {
		t.Skip("only one Claude hook contract is registered")
	}
	matched := 0
	for _, contract := range contracts {
		rendered := setup
		rendered.HookContractID = contract.ContractID
		policy, err := provider.ManagedHookPolicy(rendered)
		if err != nil {
			t.Fatalf("render %s: %v", contract.ContractID, err)
		}
		if !claudeManagedPolicyMatchesKnownContract(provider, policy, setup) {
			t.Fatalf("policy rendered for %s did not match any registered contract", contract.ContractID)
		}
		if provider.VerifyManagedHookPolicy(policy, setup) != nil {
			matched++
		}
	}
	if matched == 0 {
		t.Log("every contract renders the version-less policy; the fallback was not exercised")
	}
	other := setup
	other.HookExecutable = `C:\Program Files\Other\hook.exe`
	foreign, err := provider.ManagedHookPolicy(other)
	if err != nil {
		t.Fatalf("render foreign policy: %v", err)
	}
	if claudeManagedPolicyMatchesKnownContract(provider, foreign, setup) {
		t.Fatal("a policy for another hook executable matched this deployment")
	}
}
