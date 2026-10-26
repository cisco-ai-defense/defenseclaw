// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestActivityMetricActorIsACategoryAndAuditKeepsTheIdentity(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	actor := "account_name"
	if err := logger.LogActivity(ActivityInput{Actor: actor, Action: ActionConfigUpdate, TargetType: "config", TargetID: "config.yaml"}); err != nil {
		t.Fatal(err)
	}
	_, records := runtime.snapshot()
	if len(records) != 1 {
		t.Fatalf("records=%d", len(records))
	}
	encoded, err := records[0].Bytes()
	if err != nil || !strings.Contains(string(encoded), actor) {
		t.Fatalf("audit lost actor: %s, %v", encoded, err)
	}
	count := 0
	for _, metric := range runtime.metricSnapshot() {
		data, err := metric.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), actor) {
			t.Fatalf("metric contains account identity: %s", data)
		}
		if strings.Contains(string(data), `"defenseclaw.metric.actor":"other"`) {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("activity category metric count=%d, want 2", count)
	}
}
