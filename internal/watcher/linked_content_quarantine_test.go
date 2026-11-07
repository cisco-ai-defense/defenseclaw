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

// quarantineAlertFor reports the severity and diagnostic of the runtime alert
// (the subsystem.degraded record defenseclaw alerts lists) that a failed
// quarantine raises.
func quarantineAlertFor(t *testing.T, err error) (severity, summary string) {
	t.Helper()
	cfg, store, logger, skillDir := setupTestEnv(t)
	capture := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(capture)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Name: "provider", Path: filepath.Join(skillDir, "provider"), Connector: "openclaw"}
	w.emitQuarantineFailure(context.Background(), evt, err)
	logs, _ := capture.snapshot()
	for _, record := range logs {
		if string(record.EventName()) != "subsystem.degraded" {
			continue
		}
		body, present := record.Body()
		if !present {
			t.Fatal("alert has no diagnostic")
		}
		fields, bodyErr := body.Object()
		if bodyErr != nil {
			t.Fatal(bodyErr)
		}
		level, _ := record.Severity()
		return string(level), fmt.Sprint(fields["defenseclaw.health.error_summary"])
	}
	t.Fatal("quarantine failure emitted no runtime alert")
	return "", ""
}

// A rejected plugin with a link inside stays in place, disabled; the alert says
// so and is not the HIGH failed-move alert (GAP-0826).
func TestLinkedContentRefusalIsReportedAsDisabledNotQuarantined(t *testing.T) {
	refusal := fmt.Errorf("enforce: refusing %w /plugins/provider/node_modules/dep", enforce.ErrLinkedAssetContent)
	severity, summary := quarantineAlertFor(t, refusal)
	if !strings.EqualFold(severity, "MEDIUM") {
		t.Fatalf("severity = %q, want MEDIUM", severity)
	}
	for _, want := range []string{"blocked and disabled but not quarantined", "link"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("alert %q lacks %q", summary, want)
		}
	}
	if strings.Contains(summary, "Quarantine failed") {
		t.Fatalf("alert %q still reports a failed quarantine", summary)
	}
}

// The twin: any other quarantine failure keeps the HIGH failed-move alert.
func TestOtherQuarantineFailureKeepsHighAlert(t *testing.T) {
	severity, summary := quarantineAlertFor(t, errors.New("enforce: copy asset: disk full"))
	if !strings.EqualFold(severity, "HIGH") || !strings.Contains(summary, "Quarantine failed") {
		t.Fatalf("severity %q alert %q, want HIGH Quarantine failed", severity, summary)
	}
}
