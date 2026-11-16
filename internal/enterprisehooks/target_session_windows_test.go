//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func stubWindowsDeferredTargetHeal(
	t *testing.T,
	identity error,
	repair func() error,
	exact func() error,
	writer error,
) *int {
	t.Helper()
	originalIdentity := windowsEnterpriseMutationIdentityCheck
	originalRepair := windowsEnterpriseGuardianDACLRepair
	originalExact := windowsDeferredTargetDataDirExactCheck
	originalWriter := windowsDeferredTargetDataDirWriterCheck
	t.Cleanup(func() {
		windowsEnterpriseMutationIdentityCheck = originalIdentity
		windowsEnterpriseGuardianDACLRepair = originalRepair
		windowsDeferredTargetDataDirExactCheck = originalExact
		windowsDeferredTargetDataDirWriterCheck = originalWriter
		windowsDeferredTargetAccepted.Clear()
	})
	repairs := 0
	windowsEnterpriseMutationIdentityCheck = func() error { return identity }
	windowsEnterpriseGuardianDACLRepair = func(_, _ string, _ *windows.SID, directory bool) error {
		repairs++
		if !directory {
			t.Fatal("deferred data directory repaired with the file contract")
		}
		return repair()
	}
	windowsDeferredTargetDataDirExactCheck = func(string, *windows.SID) error { return exact() }
	windowsDeferredTargetDataDirWriterCheck = func(string, *windows.SID) error { return writer }
	return &repairs
}

func deferredTargetTestSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid("S-1-5-21-1000-2000-3000-500")
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// A signed-out target's data directory reset to inherit is repaired by the
// LocalSystem guardian and then passes the exact check.
func TestHealWindowsDeferredTargetDataDirRepairsDrift(t *testing.T) {
	repairs := stubWindowsDeferredTargetHeal(t, nil,
		func() error { return nil },
		func() error { return nil },
		errors.New("writer check must not run after a clean repair"))
	drift := errors.New("managed Windows DACL is not protected")
	if err := healWindowsEnterpriseDeferredTargetDataDir(`C:\Users\u`, `C:\Users\u\.defenseclaw`, deferredTargetTestSID(t), drift); err != nil {
		t.Fatalf("heal error = %v, want repaired", err)
	}
	if *repairs != 1 {
		t.Fatalf("repairs = %d, want 1", *repairs)
	}
}

// When the repair cannot run (not LocalSystem) or does not leave the exact
// form, drift that lets no untrusted principal write is accepted.
func TestHealWindowsDeferredTargetDataDirAcceptsTrustedDrift(t *testing.T) {
	for name, identity := range map[string]error{
		"not LocalSystem":  errors.New("not LocalSystem"),
		"repair not exact": nil,
	} {
		t.Run(name, func(t *testing.T) {
			stubWindowsDeferredTargetHeal(t, identity,
				func() error { return nil },
				func() error { return errors.New("still inherits") },
				nil)
			drift := errors.New("managed Windows DACL is not protected")
			if err := healWindowsEnterpriseDeferredTargetDataDir(`C:\Users\u`, `C:\Users\u\.defenseclaw`, deferredTargetTestSID(t), drift); err != nil {
				t.Fatalf("heal error = %v, want accepted", err)
			}
		})
	}
}

// An untrusted writer that survives keeps the target failed.
func TestHealWindowsDeferredTargetDataDirKeepsUntrustedWriterFatal(t *testing.T) {
	stubWindowsDeferredTargetHeal(t, nil,
		func() error { return errors.New("owner SID is not trusted") },
		func() error { return errors.New("still drifted") },
		errors.New("untrusted principal has write access"))
	drift := errors.New("managed Windows DACL is not protected")
	err := healWindowsEnterpriseDeferredTargetDataDir(`C:\Users\u`, `C:\Users\u\.defenseclaw`, deferredTargetTestSID(t), drift)
	if err == nil || !errors.Is(err, drift) {
		t.Fatalf("heal error = %v, want the original drift kept", err)
	}
}
