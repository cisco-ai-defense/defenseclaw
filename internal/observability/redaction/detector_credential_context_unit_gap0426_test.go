// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// Controls: text that only looks like a credential context keeps every byte
// the v1 detectors kept (no new over-redaction): counts, code, references,
// prose and a git SHA without a credential key.
func TestCredentialContextKeepsBenignTextGAP0426(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"see commit 0123456789abcdef0123456789abcdef01234567 in rel",
		"sha=0123456789abcdef0123456789abcdef01234567",
		`{"usage": {"input_tokens": 120, "max_tokens": 4096, "token_count": 12}}`,
		"last_token: 4096",
		`token := os.Getenv("SERVICE_API_TOKEN")`,
		`SERVICE_API_TOKEN = os.Getenv("SERVICE_API_TOKEN")`,
		"api_token = cfg.Token",
		`curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com`,
		"export SERVICE_API_TOKEN=${SERVICE_API_TOKEN}",
		"Bearer authentication sends a token in the header",
		"Token: the unit of text a model reads",
		"if token == expected {",
		`"token_type": "bearer"`,
		"SERVICE_API_TOKEN=<redacted type=secrets.assignment v=1>",
		"password_min_length: 12",
		"token: Optional[str] = None",
		`{"token": "Hello", "logprob": -0.1}`,
		`{\"token\": \"world\"}`,
		`{"token":" world","logprob":-0.2}`,
		`{"token":"Hello!"}`,
		"{\"token\":\"\u0120the\"}",
		"this.apiToken = apiToken;",
		"api_token = None",
		"prompt_token: 12345678",
	} {
		for _, found := range [][]candidate{recognizeInlineCredentials(input), recognizeCredentialKeys(input)} {
			for _, item := range found {
				if item.accepted {
					t.Errorf("%q: new credential-context match %q", input, input[item.start:item.end])
				}
			}
		}
	}
}

// The engine's secret classifier (the guardrail rules in the gateway) is one
// more accepted source for every detecting profile; the none profile never
// runs it, and a span past the field's bound fails the field closed.
func TestEngineSecretSpansAreRedactedGAP0426(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	input := "opaque value qq-plain-secret-shape here"
	at := strings.Index(input, "qq-plain")
	classify := func(text string) [][2]int {
		if i := strings.Index(text, "qq-plain-secret-shape"); i >= 0 {
			return [][2]int{{i, i + len("qq-plain-secret-shape")}}
		}
		return nil
	}
	result, err := detectAndRedact(input, observability.FieldClassContent, gap0426Sensitive(t), key, nil, classify)
	if err != nil || strings.Contains(result.Value, "qq-plain") || !strings.HasPrefix(result.Value, input[:at]+"<redacted type=secrets.assignment") {
		t.Fatalf("classifier span kept: %q err=%v", result.Value, err)
	}
	plain, err := DetectAndRedact(input, observability.FieldClassContent, gap0426Sensitive(t), key, nil)
	if err != nil || plain.Value != input {
		t.Fatalf("without a classifier the text changed: %q err=%v", plain.Value, err)
	}
	if _, ok := BuiltInProfile(ProfileNone); !ok {
		t.Fatal("no none profile")
	}
	long := strings.Repeat("a", 9000)
	failed, err := detectAndRedact(long, observability.FieldClassContent, gap0426Sensitive(t), key, nil,
		func(string) [][2]int { return [][2]int{{0, len(long)}} })
	if err == nil || strings.Contains(failed.Value, long[:64]) {
		t.Fatalf("an over-long flagged span was not failed closed: err=%v", err)
	}
	engine, err := NewEngine(key)
	if err != nil {
		t.Fatal(err)
	}
	with := engine.WithSecretSpans(classify)
	if with == engine || with.secretSpans == nil || engine.secretSpans != nil || with.origin == engine.origin {
		t.Fatal("WithSecretSpans must return a new engine with its own origin")
	}
}
