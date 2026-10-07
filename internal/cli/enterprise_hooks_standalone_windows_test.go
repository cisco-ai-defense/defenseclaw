//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"testing"
)

// enterprise acp enroll, verify and revoke --user resolve an Entra ID account
// through the LSA and ProfileList when os/user cannot (GAP-0479).
func TestEnterpriseHookTargetResolvesAnEntraIDAccount(t *testing.T) {
	const sid = "S-1-12-1-1111111111-2222222222-3333333333-4444444444"
	previousAccount, previousHome, previousCfg := enterprisePolicyAccount, enterprisePolicyProfileHome, cfg
	t.Cleanup(func() { enterprisePolicyAccount, enterprisePolicyProfileHome, cfg = previousAccount, previousHome, previousCfg })
	cfg = nil
	enterprisePolicyAccount = func(name string) (string, string, error) {
		if name != `AzureAD\EntraAlice` {
			return "", "", errors.New("No mapping between account names and security IDs was done")
		}
		return sid, "EntraAlice", nil
	}
	enterprisePolicyProfileHome = func(id string) string {
		if id == sid {
			return `C:\Users\EntraAlice`
		}
		return ""
	}
	target, err := resolveEnterpriseHookTargetValues(`AzureAD\EntraAlice`, "", -1, -1, "", "")
	if err != nil || target.sid != sid || target.home != `C:\Users\EntraAlice` {
		t.Fatalf("target = %+v, %v; want the Entra account's SID and profile", target, err)
	}
}
