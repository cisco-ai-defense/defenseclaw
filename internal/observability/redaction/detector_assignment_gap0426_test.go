// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
)

// GAP-0426: a provider token after an assignment (a .env line, a shell
// export, a tool result printing one) is detected like a token on its own.
func TestProviderTokenAfterAnAssignmentGAP0426(t *testing.T) {
	t.Parallel()
	aws := "AKIA" + "Z3Q7XK9M2P4W8R5T"
	gh := "ghp_" + strings.Repeat("aZ0", 12)
	for _, c := range []struct{ input, token string }{
		{"AWS_ACCESS_KEY_ID=" + aws, aws},
		{"export GITHUB_TOKEN=" + gh + "\n", gh},
		{"x=" + aws + " y", aws},
	} {
		assertDetectorExact(t, "credentials.api_token", c.input, c.token)
	}
	// Still part of a longer token on its left otherwise.
	assertDetectorAbsent(t, "credentials.api_token", "X"+aws)
	assertDetectorAbsent(t, "credentials.api_token", "a."+gh)
}
