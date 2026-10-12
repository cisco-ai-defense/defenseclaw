// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0382: the account name a managed Windows gateway spells a UPN sign-in
// with is the one the SYSTEM enumerator recorded for the SID, read from its
// current, trusted record only.
func TestIdentitySpoolAccountNameReadsTheEnumeratorRecord(t *testing.T) {
	const carol = "S-1-5-21-602989718-809138714-1982218064-4078"
	dir := t.TempDir()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: carol, User: `DCLAB\ent-carol`, UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, carol+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	oldValidate, previousDir := validateManagedGuardianAuthorization, currentIdentitySpoolDir()
	trusted := true
	validateManagedGuardianAuthorization = func(string, string) error {
		if !trusted {
			return os.ErrPermission
		}
		return nil
	}
	setIdentitySpoolDir(dir)
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate; setIdentitySpoolDir(previousDir) })

	if got := identitySpoolAccountName(" " + carol + " "); got != `DCLAB\ent-carol` {
		t.Fatalf("recorded name = %q, want DCLAB\\ent-carol", got)
	}
	if got := identitySpoolAccountName("S-1-5-21-602989718-809138714-1982218064-4077"); got != "" {
		t.Fatalf("name of an account without a record = %q", got)
	}
	trusted = false
	if got := identitySpoolAccountName(carol); got != "" {
		t.Fatalf("name from an untrusted record = %q", got)
	}
}
