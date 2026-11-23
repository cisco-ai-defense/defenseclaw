//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"golang.org/x/sys/windows"
)

// rel-1-0-10 GAP-1894: the shared token facts answer both queries on a real
// token (Limited and elevated alike) and agree with windows.Token.IsElevated
// when its query succeeds.
func TestGAP1894CurrentTokenAdminFactsAnswerBothQueries(t *testing.T) {
	facts := CurrentWindowsTokenAdminFacts()
	if facts.ElevationErr != nil || facts.UserErr != nil {
		t.Fatalf("token queries failed: elevation %v, user %v", facts.ElevationErr, facts.UserErr)
	}
	if want := windows.GetCurrentProcessToken().IsElevated(); facts.Elevated != want {
		t.Fatalf("Elevated = %v, IsElevated = %v", facts.Elevated, want)
	}
	privileged, err := facts.ElevatedOrSystem()
	if err != nil {
		t.Fatalf("ElevatedOrSystem: %v", err)
	}
	if want := facts.Elevated || facts.LocalSystem; privileged != want {
		t.Fatalf("ElevatedOrSystem = %v, want %v (%+v)", privileged, want, facts)
	}
	if err := requireWindowsEnterpriseAdministrator(); (err == nil) != privileged {
		t.Fatalf("requireWindowsEnterpriseAdministrator = %v with privileged %v", err, privileged)
	}
	if err := requireWindowsClaudeTeardownAdministrator(); (err == nil) != privileged {
		t.Fatalf("requireWindowsClaudeTeardownAdministrator = %v with privileged %v", err, privileged)
	}
}
