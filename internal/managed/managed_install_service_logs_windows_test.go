//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// g582 round 11 review S3: the guardian and broker logs are listed with the
// administrator kind, and the running services keep them open for write. The
// layout repair gives them the plain repair (inPlaceOutOfClass: they are never
// read as policy), not the held-file transaction of a recorded content file,
// so a log a service keeps open is still repaired; config.yaml held open for
// write is still refused by name with its access list unchanged. Secure Client
// repairs both, as before.
func TestManagedInstallRepairOfAServiceLogHeldOpenForWrite(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	for _, standalone := range []bool{true, false} {
		name := "standalone"
		if !standalone {
			name = "secure client"
		}
		t.Run(name, func(t *testing.T) {
			state, files := standaloneInstallStateForTest(t, extraReaderDACL)
			broker := filepath.Join(state, "logs", "cmid-broker", "cmid-broker.log")
			if err := os.MkdirAll(filepath.Dir(broker), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(broker, []byte("broker"), 0o600); err != nil {
				t.Fatal(err)
			}
			setTestFileDACL(t, broker, testDACL(t, extraReaderDACL), true)
			pinTrustProfileForTest(t, standalone)
			configBefore := privilegedDescriptorForTest(t, files["config"])
			// As a service holds its log: write access, sharing read and
			// write (what os.OpenFile asks for on Windows).
			for _, path := range []string{files["log"], broker, files["config"]} {
				holdFileForTest(t, path, windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_READ_ATTRIBUTES,
					windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
			}

			results := RepairWindowsManagedInstall(ManagedInstallLayout{StateRoot: state}, CanonicalOptions{Quiet: true})
			for _, path := range []string{files["log"], broker} {
				result, ok := installResultFor(results, path)
				if !ok || result.Outcome != CanonicalRepaired || strings.Contains(result.RepairError, heldFileRefusal) {
					t.Fatalf("%s held open for write by its service: %+v; want it repaired", path, result)
				}
				if after := privilegedDescriptorForTest(t, path); strings.Contains(after, ";;;BU)") {
					t.Fatalf("%s descriptor after the repair = %s, want the canonical one", path, after)
				}
			}
			config, ok := installResultFor(results, files["config"])
			if !ok {
				t.Fatalf("config.yaml: no result in %+v", results)
			}
			if !standalone {
				if config.Outcome != CanonicalRepaired {
					t.Fatalf("Secure Client config.yaml held open: %+v; want the base repair", config)
				}
				return
			}
			if config.Outcome == CanonicalRepaired || !strings.Contains(config.RepairError, heldFileRefusal) || !strings.Contains(config.RepairError, files["config"]) {
				t.Fatalf("config.yaml held open for write: %+v; want the held-file refusal naming it", config)
			}
			if after := privilegedDescriptorForTest(t, files["config"]); after != configBefore {
				t.Fatalf("the refused config.yaml was changed: %s -> %s", configBefore, after)
			}
		})
	}
}
