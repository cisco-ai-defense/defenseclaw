//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestRunAsTargetAcceptsCurrentInteractiveWindowsProfile(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Skipf("current Windows token identity unavailable: %v", err)
	}
	if windowsEnterpriseSystemIdentity(user.User.Sid) {
		t.Skip("test requires an interactive Windows identity")
	}
	home, err := windowsEnterpriseTokenProfileDirectory(token)
	if err != nil {
		t.Skipf("current Windows profile unavailable: %v", err)
	}
	called := false
	if err := RunAsTarget(TargetCredentials{UserHome: home, SID: user.User.Sid.String()}, func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("RunAsTarget rejected current interactive profile: %v", err)
	}
	if !called {
		t.Fatal("target callback was not invoked")
	}
}
