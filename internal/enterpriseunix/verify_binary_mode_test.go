// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1235 (verify row, Linux) and GAP-1285 (macOS): verify checked the
// execute bits of the hook binary only, so a sensor helper that lost them
// left verify, and detect.sh --require-healthy which follows it, green until
// its service restarted and could not start it.
func TestVerifyReportsAManagedBinaryThatLostItsExecuteBits(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			requireOK(t, h.run(Options{Action: ActionVerify}))
			helper := filepath.Join(h.env.Layout.BinDir, binSensorHelper)
			if err := os.Chmod(h.env.P(helper), 0o644); err != nil {
				t.Fatal(err)
			}
			verify := h.run(Options{Action: ActionVerify})
			requireError(t, verify, codeVerify)
			if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, helper+" is not executable (0644)") || !strings.Contains(got, "chmod 0755 "+helper) {
				t.Fatalf("verify does not report the sensor helper without execute bits: %s", got)
			}
		})
	}
}

// GAP-0482: the lifecycle repair docs promise to reapply files, owners and
// modes. A byte-identical managed binary that only lost its execute bits (the
// sensor helper, which no sealed copy backs) is made executable again by
// repair instead of being refused as an invalid payload.
func TestRepairRestoresTheExecuteBitsOfAManagedBinaryWithIdenticalBytes(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			for _, name := range []string{binSensorHelper, binGateway} {
				path := h.env.P(filepath.Join(h.env.Layout.BinDir, name))
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				requireOK(t, h.run(Options{Action: ActionRepair}))
				if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o755 {
					t.Fatalf("repair left %s at %v (%v), want 0755", name, info, err)
				}
				requireOK(t, h.run(Options{Action: ActionVerify}))
			}
		})
	}
}
