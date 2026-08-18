// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestCorrelationTokenExactGrammarAndDomains(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef0123456789abcdef")
	value := "reserved fixture value"
	tests := []struct {
		name, domain, tokenType string
		call                    func() (string, error)
	}{
		{"detect", detectDomain, "pii.email", func() (string, error) { return DetectedToken("pii.email", value, key) }},
		{"whole", wholeDomain, "field.content", func() (string, error) { return WholeToken(observability.FieldClassContent, value, key) }},
		{"oversize", oversizeDomain, "oversize.content", func() (string, error) { return OversizeToken(observability.FieldClassContent, value, key) }},
	}
	seen := map[string]struct{}{}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write([]byte(test.domain))
			_, _ = mac.Write([]byte{0})
			_, _ = mac.Write([]byte(test.tokenType))
			_, _ = mac.Write([]byte{0})
			_, _ = mac.Write([]byte(value))
			want := fmt.Sprintf("<redacted type=%s v=1 key=%s len=%d hmac=%s>", test.tokenType, hashV1KeyID(key), len(value), hex.EncodeToString(mac.Sum(nil)[:8]))
			got, err := test.call()
			if err != nil || got != want {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
			if strings.Contains(got, value) {
				t.Fatal("token disclosed input")
			}
			seen[got] = struct{}{}
		})
	}
	if len(seen) != 3 {
		t.Fatal("domain-separated operations produced equal tokens")
	}
}

func TestTokenErrorsAndFailureTokensAreValueSafe(t *testing.T) {
	t.Parallel()
	secret := "reserved-sensitive-value"
	if _, err := DetectedToken("unknown.detector", secret, make([]byte, 32)); !IsDetectorError(err, FailureValidator) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unexpected detector error: %v", err)
	}
	if _, err := WholeToken(observability.FieldClassContent, secret, []byte("short")); !IsDetectorError(err, FailureKeyUnavailable) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unexpected key error: %v", err)
	}
	for code := range registeredFailureCodes {
		token, err := FailedClosedToken(code)
		if err != nil || token != "<redacted type=failed_closed v=1 code="+string(code)+">" {
			t.Fatalf("failure %q: %q, %v", code, token, err)
		}
	}
}
