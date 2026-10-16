//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestWindowsFallbackGroupsBelongToAccountSID(t *testing.T) {
	const (
		localSID     = "S-1-5-21-1-2-3-2100"
		directorySID = "S-1-5-21-4-5-6-8001"
		localGroup   = "S-1-5-21-1-2-3-3000"
		policyGroup  = "S-1-5-21-4-5-6-5000"
	)
	previousDir, previousTrust := currentIdentitySpoolDir(), validateManagedGuardianAuthorization
	t.Cleanup(func() {
		setIdentitySpoolDir(previousDir)
		validateManagedGuardianAuthorization = previousTrust
	})
	dir := t.TempDir()
	setIdentitySpoolDir(dir)
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	for _, tc := range []struct {
		sid, name, group string
	}{
		{localSID, `HOST\alex`, localGroup},
		{directorySID, `CORP\alex`, policyGroup},
	} {
		record := enterprisehooks.IdentitySpoolRecord{
			Version: enterprisehooks.IdentitySpoolRecordVersion,
			Key:     tc.sid, User: tc.name, UpdatedAt: time.Now(),
			Facts: useridentity.DirectoryFacts{Groups: []string{tc.group, tc.name + `\team`}},
		}
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, tc.sid+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		ids, err := accountGroupIDs(&user.User{Uid: tc.sid, Username: tc.name})
		if err != nil || !reflect.DeepEqual(ids, []string{tc.group}) {
			t.Fatalf("groups of SID %s = %v, %v; want its own token group", tc.sid, ids, err)
		}
	}
}
