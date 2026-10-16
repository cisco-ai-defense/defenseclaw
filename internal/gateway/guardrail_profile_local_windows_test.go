//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os/user"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestWindowsLocalProfileSubjectKeepsUserEntryScope(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !enterprisehooks.WindowsLocalAccountSID(account.Uid) {
		t.Skip("the current account is not in the local account database")
	}
	subject := localProfileSubject(account)
	if !subject.localAccount || userEntryMatches(&subject, subject.UserName) {
		t.Fatalf("local account selected by a bare directory user entry: %+v", subject)
	}
	if !userEntryMatches(&subject, account.Uid) || !userEntryMatches(&subject, `.\`+subject.UserName) {
		t.Fatalf("local account identity entries did not select it: %+v", subject)
	}
}
