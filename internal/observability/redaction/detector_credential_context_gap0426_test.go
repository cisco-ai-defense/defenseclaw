// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func gap0426Sensitive(t *testing.T) []DetectorGroup {
	t.Helper()
	profile, ok := BuiltInProfile(ProfileSensitive)
	if !ok {
		t.Fatal("no sensitive profile")
	}
	return profile.DetectorGroups()
}

// GAP-0426: a value in a credential context is redacted whatever its shape:
// an inline Authorization header, a bare Bearer credential, and a key that
// ends in a credential word (prefixed env keys included). These are the
// shapes the IB5 E1 replay found in clear in the gateway audit store.
func TestCredentialContextIsRedactedGAP0426(t *testing.T) {
	t.Parallel()
	groups := gap0426Sensitive(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	hex := "5c1e8a4f7b2d9e0361a7c4b8d2f05e9a3c6b1d47"
	opaque := "t6-aud-bearer-probe-4e8b1d"
	for _, c := range []struct{ input, secret string }{
		{"Create a file .env4 containing SERVICE_API_TOKEN=" + hex, hex},
		{"created\nSERVICE_API_TOKEN=" + hex + "\n{\"interrupted\":false}", hex},
		{"Create a file .env3 containing CANARY_BEARER=" + opaque, opaque},
		{"CANARY_BEARER=" + opaque + "\n", opaque},
		{`Run exactly this command: curl -sS -m 8 -H "Authorization: Bearer ` + opaque + `" https://example.com/ -o /dev/null`, opaque},
		{`curl -H 'Proxy-Authorization: Basic ` + opaque + `' x`, opaque},
		{"the call used Bearer " + opaque + " for auth", opaque},
		{`{"db_password": "` + opaque + `"}`, opaque},
		{"export GITLAB_PAT_TOKEN=" + opaque, opaque},
		{"dbPassword: " + opaque, opaque},
		{"X-Auth-Token: plainletters", "plainletters"},
		{"AWS_SECRET_ACCESS_KEY=" + opaque, opaque},
		{"token=" + opaque + "&x=1", opaque},
		{"https://api.example.test/v1?auth_token=" + opaque + "&x=1", opaque},
		{"https://api.example.test/v1?token=" + opaque, opaque},
		// Escaped JSON inside a string (a tool result holding stringified
		// JSON, double-encoded arguments).
		{`{\"CANARY_BEARER\":\"t6audbearerprobe4e8b1d\"}`, "t6audbearerprobe4e8b1d"},
		{`{"command":"echo '{\"SERVICE_API_TOKEN\":\"opaque-v4lue\"}' > c.json"}`, "opaque-v4lue"},
		{`{\"password\": \"` + opaque + `\"}`, opaque},
		{"DB_PASSWORD='p@ss w0rd here'", "w0rd here"},
		{`{"token": "ab12cd34"}`, "ab12cd34"},
		{`{\"headers\": {\"Authorization\": \"Bearer ` + opaque + `\"}}`, opaque},
	} {
		for _, class := range []observability.FieldClass{observability.FieldClassContent, observability.FieldClassEvidence} {
			result, err := DetectAndRedact(c.input, class, groups, key, nil)
			if err != nil {
				t.Fatalf("%q: %v", c.input, err)
			}
			if strings.Contains(result.Value, c.secret) {
				t.Errorf("%s: sensitive keeps the value in %q", class, result.Value)
			}
			if !strings.Contains(result.Value, "<redacted type=") {
				t.Errorf("%s: no replacement marker in %q", class, result.Value)
			}
		}
	}
}
