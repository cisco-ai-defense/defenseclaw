// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0528: the identity posture records every group the profile assignments
// select by, which macOS checks by uid when it lists an account's groups; none
// under the Secure Client integration.
func TestIdentityPostureRecordsTheAssignmentGroups(t *testing.T) {
	prevGroups, prevFacts, prevBlocking := profileAssignmentGroups(), identityFactsEnabled.Load(), identityLookupBlocking.Load()
	t.Cleanup(func() {
		setProfileAssignmentGroups(prevGroups)
		setIdentityFactsEnabled(prevFacts)
		setIdentityLookupBlocking(prevBlocking)
		SetUserPrincipalCollectionEnabled(false)
	})
	cfg := &config.Config{}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "contractors", Match: config.ProfileMatch{Users: []string{"dcad-r102-ctr1"}}},
		{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{`DCLAB\dc-r102-devs`}}},
		{Profile: "admins", Match: config.ProfileMatch{Groups: []string{"dc-r102-admins", "dc-r102-nested"}, Connectors: []string{"codex"}}},
	}
	applyIdentityPosture(cfg)
	if got, want := profileAssignmentGroups(), []string{`DCLAB\dc-r102-devs`, "dc-r102-admins", "dc-r102-nested"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("assignment groups = %q, want %q", got, want)
	}
	if !identityLookupBlocking.Load() {
		t.Fatal("a users or groups assignment did not make lookups blocking")
	}
	secureClient := *cfg
	secureClient.DeploymentMode = "managed_enterprise"
	applyIdentityPosture(&secureClient)
	if got := profileAssignmentGroups(); len(got) != 0 {
		t.Fatalf("assignment groups under the Secure Client integration = %q, want none", got)
	}
}
