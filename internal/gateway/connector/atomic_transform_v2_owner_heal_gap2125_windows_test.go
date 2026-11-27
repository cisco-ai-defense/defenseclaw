// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// gap2125CertGateway is a run-scoped certification gateway service, the
// shape the installer registers under DefenseClaw-Cert\<run id>.
const gap2125CertGateway = "DefenseClawCertGateway_0123456789"

// gap2125PinGateway pins this process to service's deployment, as the managed
// services' registry Environment does.
func gap2125PinGateway(t *testing.T, service string) {
	t.Helper()
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\`+service)
}

// TestGAP2125CertificationGatewayReadGrantIsHealed: on a certification
// install the hook enumerator grants its own run-scoped gateway
// (DefenseClawCertGateway_<run id>) read on every agent folder, so the config
// a privileged writer left there inherits that grant. The heal must recognise
// this deployment's gateway, not only the production one. Fails on
// r111/rf-ent-win2 877b81e4de: the heal took only NT SERVICE\DefenseClawGateway,
// so it stayed a no-op and the route-only edit failed with Access is denied.
func TestGAP2125CertificationGatewayReadGrantIsHealed(t *testing.T) {
	gap2125PinGateway(t, gap2125CertGateway)
	path, stateDir, user := gap1651Fixture(t, nil)
	gap1827SetFolderDACL(t, filepath.Dir(path), gap1827LiveFolderSDDL(managed.WindowsServiceSIDString(gap2125CertGateway)))
	gap1827InheritFromFolder(t, path)
	if _, err := os.ReadFile(path); err == nil {
		t.Fatalf("fixture: the account can read its LocalSystem-owned config; the repro needs Access is denied")
	}

	err := atomicTransformFileWithStateDir(path, stateDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
		if !exists {
			t.Fatalf("config not seen as existing")
		}
		return atomicTransformResult{Data: append(append([]byte(nil), data...), []byte("[model_providers.dc]\n")...)}, nil
	})
	if err != nil {
		t.Fatalf("GAP-2125: route-only style edit of a LocalSystem-owned config in a folder carrying the certification gateway read grant failed: %v", err)
	}
	if owner := gap1651OwnerOf(t, path); owner == nil || !owner.Equals(user) {
		t.Fatalf("GAP-2125: config owner after edit = %v; want the account %s", owner, user)
	}
}

// TestGAP2125OnlyThisDeploymentsGatewayGrantIsHealed: the grant accepted is
// exactly this deployment's gateway. Another certification scope, the
// production gateway under a certification pin, and the certification
// gateway without a pin (a production deployment) leave the file alone.
func TestGAP2125OnlyThisDeploymentsGatewayGrantIsHealed(t *testing.T) {
	cases := []struct {
		name, pin, grant string
	}{
		{"another certification scope", gap2125CertGateway, "DefenseClawCertGateway_ffffffffff"},
		{"production grant under a certification pin", gap2125CertGateway, managed.StandaloneWindowsGatewaySvc},
		{"certification grant in a production deployment", managed.StandaloneWindowsGatewaySvc, gap2125CertGateway},
		{"certification grant under a malformed pin", "DefenseClawCertGateway_0123456789x", gap2125CertGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gap2125PinGateway(t, tc.pin)
			path, _, _ := gap1651Fixture(t, nil)
			gap1827SetFolderDACL(t, filepath.Dir(path), gap1827LiveFolderSDDL(managed.WindowsServiceSIDString(tc.grant)))
			gap1827InheritFromFolder(t, path)

			_ = healAtomicTransformV2ConfigLeftToAdmin(path)

			if owner := gap1651OwnerOf(t, path); owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
				t.Fatalf("GAP-2125: owner after the heal (pin %s, grant %s) = %v; want LocalSystem kept", tc.pin, tc.grant, owner)
			}
		})
	}
}
