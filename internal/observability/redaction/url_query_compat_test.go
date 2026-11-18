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
	if strings.Contains(got, signature) {
		t.Fatalf("signed URL credential remained in compatibility projection: %q", got)
	}
	if !strings.Contains(got, "safe=visible") || !strings.Contains(got, "#fragment") {
		t.Fatalf("non-credential URL content changed: %q", got)
	}
}
