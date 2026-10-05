// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1137: enterprise policy show/verify built their options without the
// enrolled accounts, so the Copilot VS Code note said "no enrolled users are
// recorded yet" while enterprise hooks status listed both users.
func TestEnterprisePolicyOptionsCarryTheEnrolledHomes(t *testing.T) {
	previousCfg, previousLoad := cfg, enterpriseHookLoadEligibleAccounts
	t.Cleanup(func() { cfg, enterpriseHookLoadEligibleAccounts = previousCfg, previousLoad })
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile: managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{
				"copilot": {},
			}},
		},
	}
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		t.Skip(err)
	}
	var loadedFrom string
	enterpriseHookLoadEligibleAccounts = func(path string) ([]enterprisehooks.UnixEligibleAccount, error) {
		loadedFrom = path
		return []enterprisehooks.UnixEligibleAccount{
			{User: "dcm-std1", UID: 501, GID: 20, Home: "/Users/dcm-std1"},
			{User: "dcm-std2", UID: 502, GID: 20, Home: "/Users/dcm-std2"},
		}, nil
	}
	ctx, err := standaloneEnterprisePolicyOptions()
	if err != nil {
		t.Fatal(err)
	}
	if want := enterprisehooks.UnixEligibleAccountsPath(layout.ManifestPath); loadedFrom != want {
		t.Fatalf("read the accounts from %q, want %q", loadedFrom, want)
	}
	if want := []string{"/Users/dcm-std1", "/Users/dcm-std2"}; !slices.Equal(ctx.opts.CopilotUserHomes, want) {
		t.Fatalf("CopilotUserHomes = %v, want %v", ctx.opts.CopilotUserHomes, want)
	}
}
