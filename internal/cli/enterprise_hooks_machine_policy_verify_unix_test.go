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
	"context"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0101: in enrollment.mode manifest an administrator's targets.yaml may
// list a target of a connector the lifecycle publishes through vendor machine
// policy (Copilot on macOS). The guardian proves that target by the machine
// policy and writes no per-user hook, but verify and readiness looked for the
// per-user hook file, so every lifecycle verify failed ("live registration
// check did not prove the current managed Hermes target") while status and
// the guardian were healthy. They now prove it the way the guardian does.
func TestStandaloneVerifyProvesAMachinePolicyTargetByItsPolicy(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "copilot"},
	)
	previousSet, previousCovered := enterpriseHookStandaloneMachinePolicySet, enterpriseHookStandaloneMachinePolicyCovered
	t.Cleanup(func() {
		enterpriseHookStandaloneMachinePolicySet, enterpriseHookStandaloneMachinePolicyCovered = previousSet, previousCovered
	})
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} { return map[string]struct{}{"copilot": {}} }
	covered := true
	enterpriseHookStandaloneMachinePolicyCovered = func(name string) (bool, error) { return name == "copilot" && covered, nil }
	_, sha, err := enterprisehooks.LoadManifestWithSHA256(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	standalone := cfg
	cfg = &config.Config{DataDir: f.dataDir}
	err = writeEnterpriseHookGuardianState(f.dataDir, f.manifest, sha, []enterpriseHookReconcileRow{
		protectedRow("alice", alice, "hermes"),
		{User: "alice", UserHome: alice, Connector: "copilot", OK: true},
	}, 0, true)
	cfg = standalone
	if err != nil {
		t.Fatal(err)
	}
	f.requests = nil
	registration, err := runEnterpriseHookRegistrationAttempt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if registration.AuthorizationErr != nil || registration.Failures != 0 || len(registration.Rows) != 2 {
		t.Fatalf("a machine-policy target failed readiness: auth=%v failures=%d rows=%+v", registration.AuthorizationErr, registration.Failures, registration.Rows)
	}
	for _, row := range registration.Rows {
		if !row.OK {
			t.Fatalf("row not proven: %+v", row)
		}
	}
	for _, request := range f.requests {
		for _, target := range request.Targets {
			if target.Options.ConnectorName == "copilot" {
				t.Fatalf("a machine-policy target reached the per-user worker: %+v", target)
			}
		}
	}
	// A machine policy that is not in place still fails that target.
	covered = false
	registration, err = runEnterpriseHookRegistrationAttempt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	for _, row := range registration.Rows {
		if row.Connector == "copilot" {
			failed = !row.OK && strings.Contains(row.Error, "copilot machine policy is not in place")
		}
	}
	if !failed || registration.Failures == 0 {
		t.Fatalf("a missing machine policy passed: %+v", registration.Rows)
	}
}
