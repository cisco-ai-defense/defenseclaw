//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// secureClientHost reports a Secure Client DefenseClaw install: its state
// root under ProgramData exists, the same check the gateway CLI makes. A
// seam for tests.
var secureClientHost = func() bool {
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileSecureClient, os.Getenv("ProgramFiles"), os.Getenv("ProgramData"))
	if err != nil {
		return false
	}
	_, err = os.Stat(roots.StateRoot)
	return err == nil
}
