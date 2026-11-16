// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"fmt"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestMain makes the token user the owner of every file and folder the tests
// create. An elevated run (an SSH Administrator, a CI runner) otherwise
// creates them owned by BUILTIN\Administrators, which the private AI discovery
// state store refuses as foreign-owned, so every test that persists the
// inventory read back an empty store (GAP-0823). A per-user gateway runs as a
// standard user, whose objects it owns.
func TestMain(m *testing.M) {
	if _, err := testenv.OwnNewObjectsAsTokenUser(); err != nil {
		fmt.Fprintln(os.Stderr, "inventory tests: set the default owner:", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}
