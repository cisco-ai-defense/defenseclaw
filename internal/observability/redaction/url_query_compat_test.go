// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
)

func TestRedactURLQueryCredentialsForCompatibility(t *testing.T) {
	const signature = "fixture-signature-value"
	input := "first https://example.test/a?sig=" + signature + "&safe=visible " +
		"second https://example.test/b?X-Amz-Signature=" + signature + "#fragment"
	got := RedactURLQueryCredentialsForCompatibility(input)
	want := strings.ReplaceAll(input, signature, `<redacted len=23 prefix="f" sha=b27f9371>`)
	if got != want {
		t.Fatalf("compatibility projection = %q, want %q", got, want)
	}
	if strings.Contains(got, signature) {
		t.Fatalf("signed URL credential remained in compatibility projection: %q", got)
	}
}

func TestRedactURLQueryCredentialsForCompatibilityJSONEscapedSeparators(t *testing.T) {
	const signature = "fixture-signature-value"
	input := `{"detail":"https://example.test/a?safe=visible\u0026sig=` + signature +
		`\u003Bkeep=yes#fragment"}`
	got := RedactURLQueryCredentialsForCompatibility(input)
	want := strings.Replace(input, signature, `<redacted len=23 prefix="f" sha=b27f9371>`, 1)
	if got != want {
		t.Fatalf("JSON compatibility projection = %q, want %q", got, want)
	}
	if strings.Contains(got, signature) {
		t.Fatalf("JSON-escaped signed URL credential remained in compatibility projection: %q", got)
	}
}
func TestRedactURLQueryCredentialsForCompatibilityJSONEscapedSlashes(t *testing.T) {
	const signature = "fixture-signature-value"
	input := `{"detail":"https:\/\/example.test\/a?sig=` + signature + `"}`
	got := RedactURLQueryCredentialsForCompatibility(input)
	want := `{"detail":"https:\/\/example.test\/a?sig=<redacted len=23 prefix="f" sha=b27f9371>"}`
	if got != want {
		t.Fatalf("JSON compatibility projection = %q, want %q", got, want)
	}
	if strings.Contains(got, signature) {
		t.Fatalf("JSON-escaped signed URL credential remained in compatibility projection: %q", got)
	}
}

func TestRedactURLQueryCredentialsForCompatibilityJSONEscapedBackslashPair(t *testing.T) {
	input := `{"detail":"https://example.test/a?password=prefix\\u0026safe=private-password-suffix"}`
	got := RedactURLQueryCredentialsForCompatibility(input)
	want := `{"detail":"https://example.test/a?password=<redacted len=41 prefix="p" sha=712b842a>"}`
	if got != want {
		t.Fatalf("JSON compatibility projection = %q, want %q", got, want)
	}
	if strings.Contains(got, "private-password-suffix") {
		t.Fatalf("escaped backslash pair left a credential suffix in compatibility projection: %q", got)
	}
}
