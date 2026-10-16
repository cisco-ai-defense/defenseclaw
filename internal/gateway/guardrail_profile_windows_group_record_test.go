// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestProfileGroupRecordBindsToAccountSID(t *testing.T) {
	const (
		localSID     = "S-1-5-21-1-2-3-2100"
		directorySID = "S-1-5-21-4-5-6-8001"
		localGroup   = "S-1-5-21-1-2-3-3000"
		policyGroup  = "S-1-5-21-4-5-6-5000"
	)
	local := enterprisehooks.IdentitySpoolRecord{Key: localSID, User: `HOST\alex`, Facts: useridentity.DirectoryFacts{
		Groups: []string{localGroup, `HOST\team`},
	}}
	directory := enterprisehooks.IdentitySpoolRecord{Key: directorySID, User: `CORP\alex`, Facts: useridentity.DirectoryFacts{
		Groups: []string{policyGroup, `CORP\team`},
	}}
	if got, err := profileGroupSIDsForAccount(localSID, local); err != nil || !reflect.DeepEqual(got, []string{localGroup}) {
		t.Fatalf("local SID groups = %v, %v", got, err)
	}
	if got, err := profileGroupSIDsForAccount(directorySID, directory); err != nil || !reflect.DeepEqual(got, []string{policyGroup}) {
		t.Fatalf("directory SID groups = %v, %v", got, err)
	}
	if groups, err := profileGroupSIDsForAccount(localSID, directory); err == nil || len(groups) != 0 {
		t.Fatalf("another SID's record supplied groups %v, %v", groups, err)
	}
	local.Facts.GroupsPartial = true
	if groups, err := profileGroupSIDsForAccount(localSID, local); err == nil || len(groups) != 0 {
		t.Fatalf("partial token record supplied groups %v, %v", groups, err)
	}
}
