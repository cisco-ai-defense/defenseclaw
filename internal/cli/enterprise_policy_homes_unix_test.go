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
	"os/exec"
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

// Sidecar F09: policy verify --live from root started the agent with every
// group of the account; every macOS account has more than 16, so
// setgroups(2) failed with EINVAL ("fork/exec ...: invalid argument") and
// there was no live hook proof on macOS. The credential must be the hook
// worker's: target uid and gid, primary group first, at most the platform's
// setgroups limit.
func TestEnterprisePolicyLiveCredentialRespectsTheGroupLimit(t *testing.T) {
	previousEuid := enterprisePolicyLiveGeteuid
	t.Cleanup(func() {
		enterprisePolicyLiveGeteuid = previousEuid
		enterprisehooks.SetStandaloneResolver(nil)
	})
	enterprisePolicyLiveGeteuid = func() int { return 0 }
	groups := make([]int, 0, enterpriseHookWorkerMaxGroups+50)
	for gid := 701; len(groups) < cap(groups); gid++ {
		groups = append(groups, gid)
	}
	enterprisehooks.SetStandaloneResolver(supplementaryGroupResolver{groups: groups})
	target := enterprisehooks.TargetCredentials{UserHome: "/Users/dcm-std1", UID: 502, GID: 20, Username: "dcm-std1"}
	cmd := exec.Command("/usr/bin/true")
	if err := enterprisePolicyLiveCredential(target)(cmd); err != nil {
		t.Fatal(err)
	}
	cred := cmd.SysProcAttr.Credential
	if cred == nil || cred.Uid != 502 || cred.Gid != 20 {
		t.Fatalf("credential = %+v", cred)
	}
	if len(cred.Groups) == 0 || len(cred.Groups) > enterpriseHookWorkerMaxGroups || cred.Groups[0] != 20 || cred.Groups[1] != 701 {
		t.Fatalf("groups must start with the primary group and stay within %d: %d groups %v", enterpriseHookWorkerMaxGroups, len(cred.Groups), cred.Groups[:min(len(cred.Groups), 4)])
	}

	enterprisePolicyLiveGeteuid = func() int { return 502 }
	cmd = exec.Command("/usr/bin/true")
	if err := enterprisePolicyLiveCredential(target)(cmd); err != nil || cmd.SysProcAttr != nil {
		t.Fatalf("the target user runs the agent as itself: err=%v attr=%+v", err, cmd.SysProcAttr)
	}
	enterprisePolicyLiveGeteuid = func() int { return 503 }
	if err := enterprisePolicyLiveCredential(target)(exec.Command("/usr/bin/true")); err == nil {
		t.Fatal("another standard user must be refused")
	}
}
