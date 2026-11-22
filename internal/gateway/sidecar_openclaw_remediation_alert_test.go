// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// rel-1-0-10 GAP-0187: with operator_admin false the operator who reads
// `defenseclaw alerts` must learn there that OpenClaw was not told to disable
// the blocked asset. The INFO audit row is not an alert row, so a HIGH alert
// carries the openclaw_remediation_unavailable text.
func TestWatcherBlockWithoutOperatorAdminRaisesAnAlertRow(t *testing.T) {
	received := make(chan receivedRequest, 5)
	srv := startMockGW(t, rpcRecordingLoop(received))
	client := connectToMockGW(t, srv)
	client.SetOperatorAdmin(false)
	store, logger := testStoreAndLogger(t)
	s := &Sidecar{
		cfg: &config.Config{
			Guardrail: config.GuardrailConfig{Connector: "openclaw"},
			Gateway: config.GatewayConfig{
				Watcher: config.GatewayWatcherConfig{
					Skill: config.GatewayWatcherSkillConfig{TakeAction: true},
				},
			},
		},
		client: client,
		logger: logger,
		notify: NewNotificationQueue(),
		router: NewEventRouter(client, nil, logger, false),
	}

	s.handleAdmissionResult(watcher.AdmissionResult{
		Event:   watcher.InstallEvent{Type: watcher.InstallSkill, Name: "blocked-skill"},
		Verdict: watcher.VerdictBlocked,
		Reason:  "on block list",
	})
	s.alertWg.Wait()

	alerts, err := store.ListAlerts(50)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if strings.Contains(a.Details, "blocked-skill") && strings.Contains(a.Details, openClawRemediationUnavailableAction) &&
			strings.Contains(a.Details, "operator.admin") {
			if a.Severity != "HIGH" {
				t.Fatalf("alert severity = %q, want HIGH", a.Severity)
			}
			return
		}
	}
	t.Fatalf("no alert row names blocked-skill and %s; alerts: %+v", openClawRemediationUnavailableAction, alerts)
}
