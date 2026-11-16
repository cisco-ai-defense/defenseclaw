// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// quarantineFailureRecords reports the severity and diagnostic of the runtime
// alert (the subsystem.degraded record) and the severity and details of the
// watcher-block audit row that a failed quarantine raises.
func quarantineFailureRecords(t *testing.T, secureClient bool, err error) (alertSeverity, alertSummary, auditSeverity, auditDetails string) {
	t.Helper()
	cfg, store, logger, skillDir := setupTestEnv(t)
	if secureClient {
		cfg.DeploymentMode = "managed_enterprise"
		cfg.Enterprise.Profile = "secure_client"
	}
	capture := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(capture)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Name: "provider", Path: filepath.Join(skillDir, "provider"), Connector: "openclaw"}
	w.emitQuarantineFailure(context.Background(), evt, err)
	logs, _ := capture.snapshot()
	for _, record := range logs {
		name := string(record.EventName())
		if name != "subsystem.degraded" && name != "legacy.audit.watcher.block" {
			continue
		}
		body, present := record.Body()
		if !present {
			t.Fatalf("%s has no body", name)
		}
		fields, bodyErr := body.Object()
		if bodyErr != nil {
			t.Fatal(bodyErr)
		}
		level, _ := record.Severity()
		if name == "subsystem.degraded" {
			alertSeverity, alertSummary = string(level), fmt.Sprint(fields["defenseclaw.health.error_summary"])
		} else {
			auditSeverity, auditDetails = string(level), fmt.Sprint(fields)
		}
	}
	return alertSeverity, alertSummary, auditSeverity, auditDetails
}

// A rejected plugin with a link inside stays in place. The watcher cannot see
// whether the gateway disabled it, so the alert names the reason and does not
// claim a disable or lower the severity (GAP-0826).
func TestLinkedContentRefusalNamesTheLinkAndDoesNotClaimADisable(t *testing.T) {
	refusal := fmt.Errorf("enforce: refusing %w /plugins/provider/node_modules/dep", enforce.ErrLinkedAssetContent)
	alertSeverity, alertSummary, auditSeverity, auditDetails := quarantineFailureRecords(t, false, refusal)
	if !strings.EqualFold(alertSeverity, "HIGH") || !strings.EqualFold(auditSeverity, "HIGH") {
		t.Fatalf("severities alert=%q audit=%q, want HIGH while the disable is unconfirmed", alertSeverity, auditSeverity)
	}
	for _, text := range []string{alertSummary, auditDetails} {
		for _, want := range []string{"not quarantined", "link", "confirm the asset is disabled"} {
			if !strings.Contains(text, want) {
				t.Fatalf("record %q lacks %q", text, want)
			}
		}
		if strings.Contains(text, "blocked and disabled") || strings.Contains(text, "Quarantine failed") {
			t.Fatalf("record %q claims a disable or reports a failed move", text)
		}
	}
}

// Secure Client keeps the failed-quarantine alert and audit row unchanged, and
// so does any other failure.
func TestOtherQuarantineFailuresKeepTheFailedQuarantineRecords(t *testing.T) {
	linked := fmt.Errorf("enforce: refusing %w /plugins/provider/node_modules/dep", enforce.ErrLinkedAssetContent)
	for _, tc := range []struct {
		name         string
		secureClient bool
		err          error
	}{
		{"other failure", false, errors.New("enforce: copy asset: disk full")},
		{"Secure Client with a linked asset", true, linked},
		{"Secure Client other failure", true, errors.New("enforce: copy asset: disk full")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alertSeverity, alertSummary, auditSeverity, auditDetails := quarantineFailureRecords(t, tc.secureClient, tc.err)
			if tc.secureClient {
				// Secure Client raises no runtime alert; its audit row is the base one.
				if alertSummary != "" {
					t.Fatalf("Secure Client raised the alert %q", alertSummary)
				}
			} else if !strings.EqualFold(alertSeverity, "HIGH") || !strings.Contains(alertSummary, "Quarantine failed") {
				t.Fatalf("alert %q %q, want HIGH Quarantine failed", alertSeverity, alertSummary)
			}
			if !strings.EqualFold(auditSeverity, "HIGH") || !strings.Contains(auditDetails, "quarantine failed; inspect the source and quarantine copy") {
				t.Fatalf("audit row %q %q, want HIGH quarantine failed", auditSeverity, auditDetails)
			}
		})
	}
}
