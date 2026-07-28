// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestDeriveSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want gatewaylog.Severity
	}{
		{"CRITICAL", gatewaylog.SeverityCritical},
		{"critical", gatewaylog.SeverityCritical},
		{" HIGH ", gatewaylog.SeverityHigh},
		{"medium", gatewaylog.SeverityMedium},
		{"LOW", gatewaylog.SeverityLow},
		{"", gatewaylog.SeverityInfo},
		{"weird", gatewaylog.SeverityInfo},
		{"NONE", gatewaylog.SeverityInfo},
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			if got := deriveSeverity(test.in); got != test.want {
				t.Fatalf("deriveSeverity(%q) = %q; want %q", test.in, got, test.want)
			}
		})
	}
}

func TestCategoriesOf(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"dedup", []string{"pii:email", "pii:email", "injection:ignore"}, []string{"pii:email", "injection:ignore"}},
		{"skips empty", []string{"", "pii:email", ""}, []string{"pii:email"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := categoriesOf(test.in)
			if len(got) != len(test.want) {
				t.Fatalf("len=%d want %d (%v)", len(got), len(test.want), got)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("got[%d]=%q want %q", index, got[index], test.want[index])
				}
			}
		})
	}
}

func TestStampEventCorrelationUsesSourceEnvelopeAndPreservesExplicitValues(t *testing.T) {
	ctx := ContextWithRequestID(t.Context(), "request-context")
	ctx = ContextWithSessionID(ctx, "session-context")
	ctx = ContextWithAgentIdentity(ctx, AgentIdentity{
		AgentID: "agent-context", AgentName: "name-context",
		AgentInstanceID: "instance-context", SidecarInstanceID: "sidecar-context",
	})
	ctx = audit.ContextWithEnvelope(ctx, audit.CorrelationEnvelope{
		RunID: "run-context", TraceID: "trace-context", TurnID: "turn-context",
		PolicyID: "policy-context", ToolID: "tool-context",
	})
	event := gatewaylog.Event{RequestID: "request-explicit"}
	stampEventCorrelation(&event, ctx)
	if event.RequestID != "request-explicit" || event.SessionID != "session-context" ||
		event.RunID != "run-context" || event.TraceID != "trace-context" ||
		event.TurnID != "turn-context" || event.AgentID != "agent-context" ||
		event.AgentInstanceID != "instance-context" || event.SidecarInstanceID != "sidecar-context" ||
		event.PolicyID != "policy-context" || event.ToolID != "tool-context" {
		t.Fatalf("stamped event correlation = %#v", event)
	}
}
