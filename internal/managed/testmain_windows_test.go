// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// testStartDefaultOwner is the default owner the test process's token had
// before TestMain made it the token user.
var testStartDefaultOwner *windows.SID

// TestMain makes the test account the default owner of every fixture, before
// the first one exists. As the elevated built-in Administrator (an SSH or
// S4U session, an elevated prompt) the token's default owner is
// BUILTIN\Administrators, so a self-managed runtime folder a test made was
// Administrators-owned, and safefile.ProtectDirectory, which requires the
// token user as the owner, refused it
// (TestWriteServiceRuntimeFileSelfManagedKeepsPrivateContract, GAP-0684). A
// per-user process makes the same change at start
// (UseCurrentUserAsWindowsDefaultOwner), and the managed gateway adopts its
// service SID (AdoptWindowsGatewayServiceFileOwner). A standard user's and
// LocalSystem's tokens already default to their own account.
func TestMain(m *testing.M) {
	previous, err := testenv.OwnNewObjectsAsTokenUser()
	if err != nil {
		fmt.Fprintln(os.Stderr, "managed tests: make the test account the owner of new files:", err)
		os.Exit(2)
	}
	testStartDefaultOwner = previous
	os.Exit(m.Run())
}
