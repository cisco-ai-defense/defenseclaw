// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGuardrailFallbackActionPreservesProfile(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		profile  string
		severity string
		want     string
	}{
		{profile: "strict", severity: "MEDIUM", want: "block"},
		{profile: "strict", severity: "LOW", want: "alert"},
		{profile: "default", severity: "MEDIUM", want: "alert"},
		{profile: "permissive", severity: "MEDIUM", want: "allow"},
		{profile: "permissive", severity: "HIGH", want: "alert"},
	} {
		if got := guardrailFallbackActionForProfile(test.severity, test.profile); got != test.want {
			t.Errorf("profile=%s severity=%s action=%s, want %s",
				test.profile, test.severity, got, test.want)
		}
	}
}

// TestGuardrailInspectorFallbackUsesResolvedThresholds pins the one
// threshold model on the proxy path: without OPA the inspector applies the
// live generation's guardrail.block_at, not a posture of its own.
func TestGuardrailInspectorFallbackUsesResolvedThresholds(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.BlockAt = "MEDIUM"
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: cfg, Thresholds: buildThresholdTable(cfg, nil)})
	t.Cleanup(func() { liveGeneration.Store(previous) })

	inspector := NewGuardrailInspector("local", nil, nil)
	got := inspector.finalize(context.Background(), "prompt", "", "action", "", &ScanVerdict{
		Action: "alert", Severity: "MEDIUM", Scanner: "local-pattern",
	}, nil)
	if got.Action != "block" || got.Severity != "MEDIUM" {
		t.Fatalf("fallback with guardrail.block_at=MEDIUM = %+v, want MEDIUM block", got)
	}
}
