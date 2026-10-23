// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"strings"
	"testing"
)

// A 1.0.3 package could leave install: setup unpinned while sandboxes were
// off. Its unchanged config must not prevent the 1.0.4 package from landing.
func TestPackageUpgradeKeepsUnpinnedDisabledOpenShellConfig(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newOSHost(t, goos)
			if goos == "linux" {
				stagePackage(t, h.testHost, "1.0.3")
			} else {
				h.payloadDir = h.payload("1.0.3")
				writeMacOSPackageFiles(t, h)
			}
			pinned := sandboxConfig(t, goos, false, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5"})
			requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package", ConfigFile: writeTempConfig(t, pinned)}))
			legacy := sandboxConfig(t, goos, false, map[string]any{"install": "setup", "driver": "docker"})
			if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), legacy, 0o640); err != nil {
				t.Fatal(err)
			}
			record, err := h.env.loadDeployment()
			if err != nil {
				t.Fatal(err)
			}
			record.ConfigSHA256 = sha256Bytes(legacy)
			if err := h.env.saveDeployment(record); err != nil {
				t.Fatal(err)
			}
			if goos == "linux" {
				stagePackage(t, h.testHost, "1.0.4")
			} else {
				replaceMacOSPackageBinaries(t, h, "1.0.4")
			}
			r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
			gateway, guardian := unitGateway, unitGuardian
			if goos == "darwin" {
				gateway, guardian = labelGateway, labelGuardian
			}
			if !r.OK || !r.Readiness.Gateway || !h.services.isActive(gateway) || !h.services.isActive(guardian) {
				t.Fatalf("1.0.4 package upgrade refused or stopped services: errors %+v, readiness %+v, gateway active %t, guardian active %t", r.Errors, r.Readiness, h.services.isActive(gateway), h.services.isActive(guardian))
			}
			upgraded, err := h.env.loadDeployment()
			if err != nil || upgraded.ProductVersion != "1.0.4" || h.read(h.env.Layout.ConfigPath) != string(legacy) {
				t.Fatalf("upgrade changed prior state: record %+v, error %v", upgraded, err)
			}
			if got := messagesOf(r.Warnings, codeOpenShellPrerequisite); !strings.Contains(got, "enterprise.openshell.version") {
				t.Fatalf("unpin fix not named: warnings %+v", r.Warnings)
			}
		})
	}
}
