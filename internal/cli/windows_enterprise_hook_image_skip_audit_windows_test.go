//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// rel-1-0-10 GAP-0906, natively: the audit actor of the account that runs
// retire is one the audit record keeps, and names this process's SID.
func TestHookImageRetireAuditActorIsTheCallersSIDNatively(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	actor := windowsHookImageRetireAuditActor()
	if !windowsHookImageAuditActorPattern.MatchString(actor) || !strings.HasPrefix(actor, "os:sid:"+user.User.Sid.String()+":") {
		t.Fatalf("audit actor = %q, want os:sid:%s:<name> in the audit actor form", actor, user.User.Sid.String())
	}
	if name := windowsHookImageSIDAccount(user.User.Sid.String()); name == "" || !strings.Contains(name, `\`) {
		t.Fatalf("account of this process SID = %q, want DOMAIN\\name", name)
	}
}
