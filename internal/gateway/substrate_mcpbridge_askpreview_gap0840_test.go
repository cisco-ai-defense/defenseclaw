// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMCPAskPreviewHidesSecretKeysAnyCaseGAP0840: the ask preview shows no
// value under a secret-named key, whatever the key's case or separators
// (camelCase, kebab, snake, mixed) and whatever the value's type (string,
// number, bool, object, array). Other keys keep their value.
func TestMCPAskPreviewHidesSecretKeysAnyCaseGAP0840(t *testing.T) {
	const opaque = "opaquevalue12345"
	secretKeys := []string{
		"accessToken", "refreshToken", "clientSecret", "privateKey", "authToken",
		"AccessToken", "Client-Secret", "API-Key", "apiKey", "userPassword",
		"db_passwd", "passPhrase", "awsAccessKey", "credentials", "Credential",
	}
	values := map[string]string{
		"string": `"` + opaque + `"`,
		"number": `482913`,
		"bool":   `true`,
		"object": `{"v":"` + opaque + `"}`,
		"array":  `["` + opaque + `"]`,
	}
	for _, key := range secretKeys {
		for kind, val := range values {
			raw := json.RawMessage(`{"` + key + `":` + val + `,"title":"shown"}`)
			got := substrateMCPArgsPreview(raw)
			if strings.Contains(got, opaque) || strings.Contains(got, "482913") || strings.Contains(got, "true") {
				t.Errorf("key %s (%s value) leaked into the preview: %q", key, kind, got)
			}
			if !strings.Contains(got, `title="shown"`) {
				t.Errorf("key %s (%s value): the other key was lost: %q", key, kind, got)
			}
			if !strings.Contains(got, "<hidden") {
				t.Errorf("key %s (%s value): no hidden marker: %q", key, kind, got)
			}
		}
	}
	for _, key := range []string{"title", "path", "count", "branch"} {
		got := substrateMCPArgsPreview(json.RawMessage(`{"` + key + `":7}`))
		if got != key+"=7" {
			t.Errorf("plain key %s should show its value, got %q", key, got)
		}
	}
}
