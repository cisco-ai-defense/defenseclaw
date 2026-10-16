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

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1443: the guardian authorization ledger fell under the 0640 mask of
// the guardian folder, which only removes bits, so a ledger at 0600 that the
// gateway cannot read through its group passed verify and repair. verify
// now reports it and repair gives it 0640 back.
func TestVerifyAndRepairTheGroupReadOfTheAuthorizationLedger(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			requireOK(t, h.run(Options{Action: ActionVerify}))
			ledger := filepath.Join(h.env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile)
			if err := os.Chmod(h.env.P(ledger), 0o600); err != nil {
				t.Fatal(err)
			}
			verify := h.run(Options{Action: ActionVerify})
			requireError(t, verify, codeVerify)
			if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, managed.HookGuardianAuthorizationFile+" is 0600") {
				t.Fatalf("verify does not name the unreadable ledger: %s", got)
			}
			requireOK(t, h.run(Options{Action: ActionRepair}))
			if mode := h.mode(ledger); mode != 0o640 {
				t.Fatalf("repair left the ledger at %04o", mode)
			}
		})
	}
}
