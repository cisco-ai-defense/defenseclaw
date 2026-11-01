// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package refusalpipe

import "testing"

// GAP-2639: a CLI command report carries the refused command's fixed words
// and a command reason only; no argument, connector or hook label passes.
func TestCommandReportCarriesOnlyFixedWordsAndAReason(t *testing.T) {
	report := Report{Command: " guardrail  disable ", Reason: ReasonManagedDevice}
	message, err := Encode(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(message)
	if err != nil || decoded != (Report{Command: "guardrail disable", Reason: ReasonManagedDevice}) {
		t.Fatalf("decoded %+v, %v", decoded, err)
	}
	for _, bad := range []Report{
		{Command: "config set guardrail.mode=observe", Reason: ReasonManagedDevice},
		{Command: `scan skill C:\Users\x`, Reason: ReasonManagedDevice},
		{Command: "Setup", Reason: ReasonManagedDevice},
		{Command: "a b c d e", Reason: ReasonManagedDevice},
		{Command: "uninstall", Reason: ReasonSIDUnregistered},
		{Command: "uninstall", Reason: ReasonElevationRequired, Connector: "codex"},
		{Command: "uninstall", Reason: ReasonElevationRequired, Tool: "Bash"},
		{Connector: "codex", Reason: ReasonManagedDevice},
	} {
		if _, err := Encode(bad); err == nil {
			t.Fatalf("encoded %+v", bad)
		}
	}
}
