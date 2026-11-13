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

func TestStricterProfileNeverKeepsMoreThanEither(t *testing.T) {
	sensitive, _ := BuiltInProfile(ProfileSensitive)
	strict, _ := BuiltInProfile(ProfileStrict)
	none, _ := BuiltInProfile(ProfileNone)
	content, _ := BuiltInProfile(ProfileContent)
	for _, tc := range []struct {
		a, b Profile
		want ProfileName
	}{
		{sensitive, strict, ProfileStrict}, {strict, sensitive, ProfileStrict},
		{sensitive, none, ProfileSensitive}, {sensitive, content, ProfileContent},
	} {
		got, err := StricterProfile("rejected_records_test", tc.a, tc.b)
		if err != nil || got.Name() != tc.want {
			t.Fatalf("StricterProfile(%s, %s) = %s, %v; want %s", tc.a.Name(), tc.b.Name(), got.Name(), err, tc.want)
		}
	}
	// A custom profile that hashes content but keeps evidence by detection:
	// the result takes the stricter cell of each class.
	custom, err := NewCustomProfile("hash_content", ProfileSensitive, nil, map[observability.FieldClass]TransformationMode{
		observability.FieldClassContent: ModeHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := StricterProfile("rejected_records_test", custom, content)
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range observability.FieldClasses() {
		modeA, _ := custom.Mode(class)
		modeB, _ := content.Mode(class)
		got, _ := mixed.Mode(class)
		if modeStrictness(got) < modeStrictness(modeA) || modeStrictness(got) < modeStrictness(modeB) {
			t.Fatalf("class %s: %s is weaker than %s or %s", class, got, modeA, modeB)
		}
	}
	if !validProfile(mixed) {
		t.Fatal("combined profile does not validate")
	}
}
