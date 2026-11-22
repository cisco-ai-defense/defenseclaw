// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managedaid

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func verdictBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"defenseclaw.guardrail.stage":            "final",
		"defenseclaw.guardrail.effective_action": "block",
	}
	for key, value := range extra {
		body[key] = value
	}
	return body
}

func projectionAttributes(projection managedCompatibilityProjection) map[string]string {
	out := map[string]string{}
	for _, attribute := range projection.attributes {
		out[attribute.Key] = attribute.Value.GetStringValue()
	}
	return out
}

func TestProjectManagedVerdictCarriesUser(t *testing.T) {
	var event gatewaylog.Event
	var projection managedCompatibilityProjection
	body := verdictBody(map[string]any{
		"user.id":                              "S-1-5-21-1-2-3-1105",
		"defenseclaw.user.id_kind":             "windows_sid",
		"defenseclaw.user.name":                `CORP\alice`,
		"defenseclaw.user.principal":           "alice@corp.example.com",
		"defenseclaw.user.principal.assurance": "verified",
		"defenseclaw.user.email":               "alice@example.com",
	})
	if !projectManagedVerdict(&event, body, &projection) {
		t.Fatal("projection rejected the record")
	}
	if event.UserID != "S-1-5-21-1-2-3-1105" || event.UserName != `CORP\alice` {
		t.Fatalf("event user = %q / %q", event.UserID, event.UserName)
	}
	attrs := projectionAttributes(projection)
	for key, value := range body {
		if !strings.Contains(key, "user") {
			continue
		}
		if attrs[key] != value {
			t.Errorf("attribute %s = %q, want %q", key, attrs[key], value)
		}
	}
}

func TestProjectManagedVerdictWithoutUserIsUnchanged(t *testing.T) {
	var event gatewaylog.Event
	var projection managedCompatibilityProjection
	if !projectManagedVerdict(&event, verdictBody(nil), &projection) {
		t.Fatal("projection rejected the record")
	}
	if event.UserID != "" || event.UserName != "" {
		t.Fatalf("event user = %q / %q, want none", event.UserID, event.UserName)
	}
	for key := range projectionAttributes(projection) {
		if strings.Contains(key, "user") {
			t.Fatalf("unexpected attribute %s", key)
		}
	}
}

func TestProjectManagedVerdictSkipsInvalidUserValues(t *testing.T) {
	var event gatewaylog.Event
	var projection managedCompatibilityProjection
	body := verdictBody(map[string]any{
		"user.id":                strings.Repeat("1", 300),
		"defenseclaw.user.name":  "bad\x01name",
		"defenseclaw.user.email": 42,
	})
	if !projectManagedVerdict(&event, body, &projection) {
		t.Fatal("an invalid user value rejected the record")
	}
	if event.UserID != "" || event.UserName != "" || len(projectionAttributes(projection)) != 4 {
		t.Fatalf("event = %q/%q attrs = %v, want the invalid values skipped", event.UserID, event.UserName, projectionAttributes(projection))
	}
}
