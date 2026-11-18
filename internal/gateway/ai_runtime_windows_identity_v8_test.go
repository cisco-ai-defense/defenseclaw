// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

// TestRuntimeWindowsFindingRecordBuilds pins GAP-1141. A Windows runtime
// finding names its owner DOMAIN\name with a SID and no uid. The adapter put
// that name into defenseclaw.user.name, whose syntax refuses the backslash,
// so the finding and activity records failed to build on every poll and the
// gateway logged record_build_failed every 30 s. The records carry the bare
// account and the SID as user.id (windows_sid), as the inventory does.
func TestRuntimeWindowsFindingRecordBuilds(t *testing.T) {
	t.Parallel()
	const sid = "S-1-5-21-1000000001-1000000002-1000000003-1356"
	capture := &endpointInventoryCapture{}
	snapshot := sensor.Snapshot{
		Planes: []sensor.PlaneHealth{{
			Plane: platform.PlaneC, Selected: true, Available: true, Running: true,
			Mechanism: "Windows Security event log (wevtapi)",
		}},
		Findings: []sensor.Finding{{
			FindingID: "run-0612d423097eb7f6", PID: 4124, Process: "claude.exe",
			Cmdline: `C:\Users\dcw-l50a\.local\bin\claude.exe`,
			User:    `DCFC-WINM\dcw-l50a`, UserSID: sid, Attribution: "process_owner",
			AgentName: "claude.exe", Score: 30, Severity: scoring.SeverityMedium,
			Signals: []scoring.Signal{{ID: "agent_credential_access", Weight: 30}},
			Correlation: correlate.Result{
				Verdict: correlate.VerdictAccounted, Reason: "discovery independently observed the same subject",
			},
		}},
	}
	if err := newAIRuntimeV8Adapter(capture).EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("EmitSnapshot() error = %v, want the Windows finding to build", err)
	}
	want := map[observability.EventName]bool{
		observability.EventName(observability.TelemetryEventAIRuntimeFinding):  false,
		observability.EventName(observability.TelemetryEventAIRuntimeActivity): false,
	}
	for _, record := range capture.snapshot() {
		if _, ok := want[record.EventName()]; !ok {
			continue
		}
		want[record.EventName()] = true
		body := canonicalBody(t, record)
		if body["defenseclaw.user.name"] != "dcw-l50a" || body["user.id"] != sid ||
			body["defenseclaw.user.id_kind"] != "windows_sid" {
			t.Errorf("%s user = %v/%v/%v, want dcw-l50a/%s/windows_sid", record.EventName(),
				body["defenseclaw.user.name"], body["user.id"], body["defenseclaw.user.id_kind"], sid)
		}
	}
	for event, seen := range want {
		if !seen {
			t.Errorf("no %s record emitted", event)
		}
	}
}
