// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package budgetstore

import (
	"fmt"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestMain makes the token user the owner of every file and folder these tests
// create. An elevated administrator token (an SSH Administrator, a CI runner)
// names BUILTIN\Administrators as the default owner, and safefile rightly
// refuses the test folders as foreign-owned (GAP-2192, the GAP-2124 and
// GAP-2107 class). The per-user binaries make the same change at start
// (managed.UseCurrentUserAsWindowsDefaultOwner), so the product check is
// unchanged; a standard user token already names the user.
func TestMain(m *testing.M) {
	if _, err := testenv.OwnNewObjectsAsTokenUser(); err != nil {
		fmt.Fprintln(os.Stderr, "budgetstore tests: make the token user the owner of new files:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
