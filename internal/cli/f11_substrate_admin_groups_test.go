// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0191: administrator groups come from substrate.identity.admin_groups
// as well as --admin-groups (the chart's gateway.adminGroups).
func TestGAP0191AdminGroupsFromConfig(t *testing.T) {
	id := config.SubstrateIdentityConfig{AdminGroups: []string{"dc-admins", " platform "}}
	if got := substrateAdminGroups(id, nil); !slices.Equal(got, []string{"dc-admins", "platform"}) {
		t.Fatalf("config only = %v", got)
	}
	if got := substrateAdminGroups(id, []string{"platform", "sre"}); !slices.Equal(got, []string{"dc-admins", "platform", "sre"}) {
		t.Fatalf("config plus flag = %v", got)
	}
	if got := substrateAdminGroups(config.SubstrateIdentityConfig{}, []string{"sre"}); !slices.Equal(got, []string{"sre"}) {
		t.Fatalf("flag only = %v", got)
	}
	if got := substrateAdminGroups(config.SubstrateIdentityConfig{}, nil); len(got) != 0 {
		t.Fatalf("none = %v", got)
	}
}
