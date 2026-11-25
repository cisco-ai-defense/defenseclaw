// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
)

// GAP-0512: a provider token after a URL-encoded '=' ("%3D" or "%3d", as in a
// logged query string or form body) is detected like a token after '='.
func TestProviderTokenAfterAnEncodedAssignmentGAP0512(t *testing.T) {
	t.Parallel()
	aws := "AKIA" + "Z3Q7XK9M2P4W8R5T"
	gh := "ghp_" + strings.Repeat("aZ0", 12)
	for _, c := range []struct{ input, token string }{
		{"x%3D" + aws, aws},
		{"token%3d" + gh, gh},
		{"https://example.test/cb?state=1&key%3D" + aws + "&next=2", aws},
		{"a%3D" + gh + " b", gh},
	} {
		assertDetectorExact(t, "credentials.api_token", c.input, c.token)
	}
	// A token joined to other alphanumerics on its left is still part of a
	// longer token: only the exact "%3D"/"%3d" sequence stands in for '='.
	assertDetectorAbsent(t, "credentials.api_token", "x3D"+aws)
	assertDetectorAbsent(t, "credentials.api_token", "x%4D"+aws)
	assertDetectorAbsent(t, "credentials.api_token", "x%3E"+gh)
}
