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
	"context"
	"strings"
	"testing"
)

// GAP-1802: with the gateway's launchd label disabled, verify reported a
// healthy host (rc 0) although launchd would not start the gateway after a
// reboot, and repair re-enabled the label but said "nothing to repair".
func TestVerifyFlagsADisabledLaunchdLabelAndRepairReportsReEnabling(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	requireOK(t, h.run(Options{Action: ActionVerify}))

	h.services.disabled = map[string]bool{labelGateway: true}
	verify := h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, labelGateway+" is disabled and will not start after a reboot") || !strings.Contains(got, " repair`") {
		t.Fatalf("verify does not report the disabled label: %s", got)
	}

	repair := h.run(Options{Action: ActionRepair})
	requireOK(t, repair)
	if got := strings.Join(repair.Changes, "\n"); !strings.Contains(got, "re-enabled "+labelGateway) {
		t.Fatalf("repair does not say it re-enabled the label: %q", repair.Changes)
	}
	requireOK(t, h.run(Options{Action: ActionVerify}))
}

func TestLaunchdDisabledReadsTheOverride(t *testing.T) {
	gateway := Unit{Name: labelGateway, Kind: "gateway"}
	for output, want := range map[string]bool{
		"disabled services = {\n\t\"" + labelGateway + "\" => disabled\n}\n": true,
		"disabled services = {\n\t\"" + labelGateway + "\" => enabled\n}\n":  false,
		"disabled services = {\n}\n":                                         false,
	} {
		var calls []string
		manager := &launchdManager{env: &Env{GOOS: "darwin", Runner: printDisabledRunner{output: output, calls: &calls}}}
		if got := manager.Disabled(context.Background(), gateway); got != want {
			t.Fatalf("Disabled = %v, want %v for %q", got, want, output)
		}
	}
}
