// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// newUPNRowFixture is an AD SID whose UPN comes from the guardian's record
// (TranslateNameW, dated kept by MarkWindowsKeptUPN when kept).
func newUPNRowFixture(t *testing.T) upnRowFixture {
	t.Helper()
	const sid = "S-1-5-21-1870-400-596-1107"
	dir := t.TempDir()
	previousDir, previousValidate := currentIdentitySpoolDir(), validateManagedGuardianAuthorization
	setIdentitySpoolDir(dir)
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() {
		setIdentitySpoolDir(previousDir)
		validateManagedGuardianAuthorization = previousValidate
	})
	return upnRowFixture{
		ctx: context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, strings.ToLower(sid)),
		publish: func(upn string, kept bool) {
			time.Sleep(time.Millisecond)
			now := time.Now().UTC()
			record := enterprisehooks.IdentitySpoolRecord{Key: sid, UpdatedAt: now,
				UPNSource: enterprisehooks.UPNSourceTranslateName, Facts: useridentity.DirectoryFacts{
					Directory: useridentity.DirectoryActiveDirectory, UPN: upn, Principal: upn}}
			if kept {
				record.UPNKeptSince = now
			}
			data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
}
