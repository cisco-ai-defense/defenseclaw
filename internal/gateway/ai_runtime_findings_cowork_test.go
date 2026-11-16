// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

func TestAIRuntimeFindingsOnlyOnNewOrChangedState(t *testing.T) {
	first := sensor.Finding{FindingID: "finding-one", Process: "claude", Score: 20,
		FirstSeen: time.Unix(10, 0), LastSeen: time.Unix(20, 0)}
	changed, cursor := newAIRuntimeFindings([]sensor.Finding{first}, nil, false)
	if len(changed) != 1 || len(cursor) != 1 {
		t.Fatalf("first poll: findings=%d cursor=%d", len(changed), len(cursor))
	}
	first.LastSeen = time.Unix(30, 0)
	changed, cursor = newAIRuntimeFindings([]sensor.Finding{first}, cursor, false)
	if len(changed) != 0 || len(cursor) != 1 {
		t.Fatalf("unchanged poll: findings=%d cursor=%d", len(changed), len(cursor))
	}
	first.Signals = []scoring.Signal{{ID: "one", Weight: 10}, {ID: "two", Weight: 10}}
	first.Providers = []sensor.ProviderReach{
		{Hostname: "first.example", Category: "model", Confidence: 0.9},
		{Hostname: "second.example", Category: "model", Confidence: 0.9},
	}
	changed, cursor = newAIRuntimeFindings([]sensor.Finding{first}, cursor, false)
	if len(changed) != 1 {
		t.Fatalf("new evidence not emitted: %+v", changed)
	}
	first.Signals[0], first.Signals[1] = first.Signals[1], first.Signals[0]
	first.Providers[0], first.Providers[1] = first.Providers[1], first.Providers[0]
	changed, cursor = newAIRuntimeFindings([]sensor.Finding{first}, cursor, false)
	if len(changed) != 0 {
		t.Fatalf("reordered evidence emitted: %+v", changed)
	}
	first.Score = 30
	changed, cursor = newAIRuntimeFindings([]sensor.Finding{first}, cursor, false)
	if len(changed) != 1 || changed[0].Score != 30 {
		t.Fatalf("changed poll: %+v", changed)
	}
	changed, cursor = newAIRuntimeFindings(nil, cursor, false)
	if len(changed) != 0 || len(cursor) != 0 {
		t.Fatalf("quiet poll: findings=%d cursor=%d", len(changed), len(cursor))
	}
	changed, _ = newAIRuntimeFindings([]sensor.Finding{first}, cursor, false)
	if len(changed) != 1 {
		t.Fatalf("returning finding: %+v", changed)
	}
}

func TestSecureClientAIRuntimeFindingsKeepPollEmission(t *testing.T) {
	finding := sensor.Finding{FindingID: "finding-one", Score: 20}
	_, cursor := newAIRuntimeFindings([]sensor.Finding{finding}, nil, false)
	changed, _ := newAIRuntimeFindings([]sensor.Finding{finding}, cursor, true)
	if len(changed) != 1 {
		t.Fatalf("Secure Client poll findings: %+v", changed)
	}
}
