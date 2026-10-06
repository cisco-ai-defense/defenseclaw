// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A Windows identity record names its account, like the Linux and macOS
// records (GAP-0025).
func TestWindowsIdentitySpoolRecordNamesTheAccount(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := strings.ToUpper(user.User.Sid.String())
	dir := t.TempDir()
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[sid] = nil
	if err := WriteWindowsIdentitySpool(dir, cache, nil, nil); err != nil {
		t.Fatal(err)
	}
	record, err := ReadIdentitySpoolRecord(dir, sid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.User, `\`) {
		t.Fatalf("record user = %q, want DOMAIN\\account", record.User)
	}
}
