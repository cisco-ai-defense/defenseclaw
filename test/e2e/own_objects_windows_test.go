// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package e2e

import (
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// ownNewObjectsAsTokenUser makes the token user the owner of every file and
// folder the suite creates. An elevated administrator token names
// BUILTIN\Administrators the default owner, and safefile refuses the
// connector fixtures as foreign-owned (the claudecode and codex rows of the
// lifecycle matrix, GAP-2192; the GAP-2124 class).
func ownNewObjectsAsTokenUser() {
	if _, err := testenv.OwnNewObjectsAsTokenUser(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e tests: make the token user the owner of new files:", err)
		os.Exit(1)
	}
}
