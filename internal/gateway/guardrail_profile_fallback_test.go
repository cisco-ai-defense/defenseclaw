// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
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

func TestGuardrailInspectorStrictFallbackWithoutPolicy(t *testing.T) {
	t.Parallel()

	inspector := NewGuardrailInspector("local", nil, nil, "")
	inspector.SetFallbackProfile("strict")
	got := inspector.finalize(context.Background(), "prompt", "", "action", "", &ScanVerdict{
		Action: "alert", Severity: "MEDIUM", Scanner: "local-pattern",
	}, nil)
	if got.Action != "block" || got.Severity != "MEDIUM" {
		t.Fatalf("strict no-policy fallback=%+v, want MEDIUM block", got)
	}
}

func TestGuardrailInspectorStrictFallbackWhenPolicyEngineUnavailable(t *testing.T) {
	t.Parallel()

	inspector := NewGuardrailInspector("local", nil, nil, "configured-policy")
	inspector.SetFallbackProfile("strict")
	inspector.engineInitOnce.Do(func() {
		inspector.engineLoadErr = errors.New("synthetic policy load failure")
	})
	got := inspector.finalize(context.Background(), "prompt", "", "action", "", &ScanVerdict{
		Action: "alert", Severity: "MEDIUM", Scanner: "local-pattern",
	}, nil)
	if got.Action != "block" || got.Severity != "MEDIUM" {
		t.Fatalf("strict engine-error fallback=%+v, want MEDIUM block", got)
	}
}
