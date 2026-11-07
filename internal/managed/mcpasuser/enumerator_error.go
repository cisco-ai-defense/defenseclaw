// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package mcpasuser

import (
	"errors"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// errEnumeratorNotServing says that the as-user pipe does not exist. It is the
// Secure Client text, as it always was; enumeratorNotServing is the one to
// return.
var errEnumeratorNotServing = errors.New("the DefenseClaw hook enumerator service is not serving MCP as-user scans; " +
	"it starts them once it runs (Setup /repair restarts it)")

// errStandaloneEnumeratorNotServing is the same answer on the standalone
// profile, whose computers have no Setup installed: the installed CLI's
// repair restarts the enumerator (cowork-1-0-8 GAP-0095).
var errStandaloneEnumeratorNotServing = errors.New("the DefenseClaw hook enumerator service is not serving MCP as-user scans; " +
	"it starts them once it runs (run " + managed.WindowsAdminCommand("enterprise", "windows", "repair", "--profile", managed.ProfileStandalone) +
	" from an elevated PowerShell prompt to restart it)")

// enumeratorNotServing is errEnumeratorNotServing for the profile this
// process serves: the standalone gateway carries the profile pin, a Secure
// Client one never does.
func enumeratorNotServing() error {
	if managed.IsStandaloneProfile(managed.NormalizeEnterpriseProfile(os.Getenv(managed.EnterpriseProfileEnv))) {
		return errStandaloneEnumeratorNotServing
	}
	return errEnumeratorNotServing
}
