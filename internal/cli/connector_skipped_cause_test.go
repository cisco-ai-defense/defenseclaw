// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

const (
	skippedFolder = "/home/lane/.config/opencode"
	skippedReason = "validate plugin directory custody: " + skippedFolder + " is group/other writable"
	skippedFix    = "chmod go-w " + skippedFolder
)

// skippedDetails is the guardrail detail a gateway publishes for a connector
// it refused, in process and as a status client decodes it.
func skippedDetails(t *testing.T, decoded bool) map[string]interface{} {
	t.Helper()
	details := map[string]interface{}{
		"connectors_not_started":           []string{"opencode"},
		gateway.GuardrailNotStartedReasons: map[string]string{"opencode": skippedReason},
		gateway.GuardrailNotStartedRepairs: map[string]gateway.NotStartedRepair{"opencode": {Fix: skippedFix}},
	}
	if !decoded {
		return details
	}
	raw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSkippedConnectorCauseCarriesTheRecordedReasonAndFix(t *testing.T) {
	for _, decoded := range []bool{false, true} {
		got := guardrailNotStartedCause(skippedDetails(t, decoded), "OpenCode ")
		if want := skippedReason + "; fix: " + skippedFix; got != want {
			t.Fatalf("decoded=%v cause = %q, want %q", decoded, got, want)
		}
	}
	details := skippedDetails(t, true)
	details[gateway.GuardrailNotStartedRepairs] = map[string]interface{}{
		"opencode": map[string]interface{}{"by_hand": "replace the link", "omitted_bytes": float64(9000)},
	}
	got := guardrailNotStartedCause(details, "opencode")
	for _, want := range []string{"; by hand: replace the link", "; repair omitted: it is 9000 bytes"} {
		if !strings.Contains(got, want) {
			t.Fatalf("cause %q is missing %q", got, want)
		}
	}
	// Benign twin: no recorded reason, or another connector's, adds nothing.
	if got := guardrailNotStartedCause(map[string]interface{}{"connectors_not_started": []string{"opencode"}}, "opencode"); got != "" {
		t.Fatalf("no recorded reason: cause = %q, want empty", got)
	}
	if got := guardrailNotStartedCause(skippedDetails(t, false), "hermes"); got != "" {
		t.Fatalf("other connector: cause = %q, want empty", got)
	}
}

func TestStatusAndStartNameTheRefusalAndItsFixForASkippedConnector(t *testing.T) {
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Guardrail.Details = skippedDetails(t, true)

	roster := captureStdout(t, func() { printConnectors(&snap) })
	started := captureStdout(t, func() { printConnectorsNotStarted(snap) })
	err := everyConnectorGuardedError(everyConnectorTestConfig(t), snap)
	if err == nil {
		t.Fatal("everyConnectorGuardedError = nil, want a refusal")
	}
	for name, text := range map[string]string{"status": roster, "start": started, "require-every-connector": err.Error()} {
		for _, want := range []string{skippedFolder, skippedFix, "defenseclaw setup opencode"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s output %q is missing %q", name, text, want)
			}
		}
		if strings.Contains(text, "see gateway.log") {
			t.Fatalf("%s output %q still sends the reader to gateway.log", name, text)
		}
	}
}

func TestStatusKeepsTheGatewayLogPointerWhenNoReasonWasRecorded(t *testing.T) {
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Guardrail.Details = map[string]interface{}{"connectors_not_started": []string{"hermes"}}
	roster := captureStdout(t, func() { printConnectors(&snap) })
	started := captureStdout(t, func() { printConnectorsNotStarted(snap) })
	if !strings.Contains(roster, "see gateway.log, then run: defenseclaw setup hermes") {
		t.Fatalf("status = %q", roster)
	}
	if !strings.Contains(started, "See gateway.log for the reason, then run: defenseclaw setup hermes") {
		t.Fatalf("start = %q", started)
	}
}
