// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestProjectFieldsRedactsARefusedRecordCopyLikeProject(t *testing.T) {
	engine, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	sensitive, ok := BuiltInProfile(ProfileSensitive)
	if !ok {
		t.Fatal("no sensitive profile")
	}
	const token = "ghp_1234567890abcdefghijklmnopqrstuv"
	body := map[string]any{
		"defenseclaw.hook.result":      "success",
		"defenseclaw.guardrail.reason": "denied: token=" + token,
		"defenseclaw.api.key":          "plain-credential-value",
		"defenseclaw.rule_ids":         []any{"rule-1"},
	}
	classes := map[string]observability.FieldClass{
		"/defenseclaw.hook.result":      observability.FieldClassMetadata,
		"/defenseclaw.guardrail.reason": observability.FieldClassReason,
		"/defenseclaw.api.key":          observability.FieldClassCredential,
		"/defenseclaw.rule_ids/0":       observability.FieldClassMetadata,
	}
	projected, err := engine.ProjectFields(body, classes, sensitive)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, token) || strings.Contains(text, "plain-credential-value") {
		t.Fatalf("a secret survived the projection: %s", text)
	}
	if projected["defenseclaw.hook.result"] != "success" {
		t.Fatalf("metadata changed: %s", text)
	}
	if _, kept := projected["defenseclaw.api.key"]; kept {
		t.Fatalf("credential class kept under sensitive: %s", text)
	}
	if body["defenseclaw.guardrail.reason"] != "denied: token="+token {
		t.Fatal("ProjectFields changed its input")
	}

	none, _ := BuiltInProfile(ProfileNone)
	if _, err := engine.ProjectFields(body, map[string]observability.FieldClass{}, none); err == nil {
		t.Fatal("an unclassified leaf was projected")
	}
	var nilEngine *Engine
	if _, err := nilEngine.ProjectFields(body, classes, sensitive); err == nil {
		t.Fatal("a nil engine projected")
	}
}
