// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The macOS enumerator's record names no groups, so a managed Mac's
// guardrail.profile_assignments match.groups never matched a local group the
// user belongs to (GAP-0075). The gateway adds the groups it resolves itself
// and keeps what only root could read.
func TestSpoolFactsWithGroupsAddsTheGatewaysGroupsToTheRootRecord(t *testing.T) {
	now := time.Now().UTC()
	spool := useridentity.DirectoryFacts{
		Directory: useridentity.DirectoryEntraID, Source: useridentity.SourceMacOSPlatformSSO,
		Principal: "alice@example.test", ResolvedAt: now.Add(-time.Hour),
	}
	facts := spoolFactsWithGroups(spool, []string{"staff", "p0contractors"}, now)
	if !slices.Equal(facts.Groups, []string{"staff", "p0contractors"}) {
		t.Fatalf("groups = %v, want the gateway's", facts.Groups)
	}
	if facts.Directory != useridentity.DirectoryEntraID || facts.Source != useridentity.SourceMacOSPlatformSSO ||
		facts.Principal != "alice@example.test" || facts.Assurance != useridentity.AssuranceVerified || !facts.ResolvedAt.Equal(now) {
		t.Fatalf("the root record's facts were lost: %+v", facts)
	}
}
