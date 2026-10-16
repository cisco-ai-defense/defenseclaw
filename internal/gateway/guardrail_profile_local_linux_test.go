//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os/user"
	"testing"
)

func TestLocalProfileSubjectKeepsLocalUserEntryScope(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	subject := localProfileSubject(account)
	if subject.LookupFailed {
		t.Fatalf("local account lookup failed: %s", subject.LookupError)
	}
	if !subject.localAccount || userEntryMatches(&subject, account.Username) {
		t.Fatalf("local account selected by a bare directory user entry: %+v", subject)
	}
	if !userEntryMatches(&subject, account.Uid) || !userEntryMatches(&subject, `.\`+account.Username) {
		t.Fatalf("local account identity entries did not select it: %+v", subject)
	}
}

func TestFallbackProfileSubjectDoesNotAssumePrincipal(t *testing.T) {
	subject := localProfileSubject(&user.User{Username: "alex@corp.example.com", Uid: "2100", Gid: "2100"})
	if userEntryMatches(&subject, "alex@corp.example.com") {
		t.Fatalf("account spelling was treated as a verified principal: %+v", subject)
	}
}
