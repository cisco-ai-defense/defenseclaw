// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sqliteperms

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

const testGatewayAccount = `NT SERVICE\DefenseClawGateway`

// managedStoreDir builds <Cisco>\DefenseClaw\runtime\<name> with the runtime
// ACL Setup writes (SYSTEM and Administrators full, the gateway service
// Modify), owner set by owner (an SDDL owner token or a SID string), and
// pins the managed gateway service environment.
func managedStoreDir(t *testing.T, owner, extraACE string) (string, string) {
	t.Helper()
	_, root := testenv.CiscoRuntimeTree(t, "DefenseClaw")
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.WindowsServiceAccountEnv, testGatewayAccount)
	service, err := managed.WindowsServiceAccountSID(testGatewayAccount)
	if err != nil {
		t.Fatal(err)
	}
	dacl := fmt.Sprintf("(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;%s)", service)
	runtime := filepath.Join(root, "runtime")
	dir := filepath.Join(runtime, "model_usage")
	for _, p := range []string{runtime, dir} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		testenv.SetSecurity(t, p, "O:BAD:P"+dacl)
	}
	testenv.SetSecurity(t, dir, "O:BAD:P"+dacl+extraACE)
	if owner != "BA" {
		sid, err := windows.StringToSid(owner)
		if err != nil {
			t.Fatal(err)
		}
		if err := managed.RunWithWindowsRepairPrivileges(func() error {
			return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil)
		}); err != nil {
			t.Fatalf("set owner %s: %v", owner, err)
		}
	}
	return dir, service.String()
}

// GAP-1125: the managed gateway logs on as LocalSystem with a restricted
// service SID, so the store folder is owned by the service SID (the gateway
// made it) or by Administrators (Setup or an earlier build made it), never by
// the token user. Both must open, and the service write entry must survive.
func TestPrepareManagedStoreAcceptsServiceTreeOwners(t *testing.T) {
	service, err := managed.WindowsServiceAccountSID(testGatewayAccount)
	if err != nil {
		t.Fatal(err)
	}
	for name, owner := range map[string]string{
		"administrators":  "BA",
		"gateway service": service.String(),
	} {
		t.Run(name, func(t *testing.T) {
			dir, serviceSID := managedStoreDir(t, owner, "")
			db := filepath.Join(dir, "model_usage.db")
			testenv.AsAdministratorsOwner(t, func() {
				if err := Prepare(db); err != nil {
					t.Fatalf("Prepare in a %s-owned managed store folder: %v", name, err)
				}
			})
			sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(sd.String(), serviceSID) {
				t.Fatalf("the gateway service write entry was removed: %s", sd.String())
			}
		})
	}
}

// The managed branch keeps refusing a store folder a standard user can write.
func TestPrepareManagedStoreRefusesUserWritableFolder(t *testing.T) {
	dir, _ := managedStoreDir(t, "BA", "(A;OICI;0x1301bf;;;BU)")
	testenv.AsAdministratorsOwner(t, func() {
		if err := Prepare(filepath.Join(dir, "model_usage.db")); err == nil {
			t.Fatal("Prepare accepted a store folder that Users can modify")
		}
	})
}
