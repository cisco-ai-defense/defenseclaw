// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package codesig

import (
	"context"
	"strings"
	"testing"
)

// The real /usr/bin/codesign: /bin/ls is signed by Apple, so the Apple
// anchor holds and codesign exits 0, while the Anthropic Developer ID
// requirement fails with exit 3, which VerifyDarwin names as another signer.
func TestVerifyDarwinRunsTheRealCodesign(t *testing.T) {
	if got := verifyDarwinRequirement(context.Background(), "/bin/ls", "anchor apple", "unmet", DarwinOptions{Pin: []string{"/bin/ls"}}); !got.Verified {
		t.Fatalf("/bin/ls against anchor apple = %+v, want verified", got)
	}
	got := VerifyDarwin(context.Background(), "/bin/ls", Darwin{TeamID: AnthropicTeamID, Identifier: "com.apple.ls"}, DarwinOptions{})
	if got.Verified || !strings.Contains(got.Reason, "is not signed by Apple Developer ID team "+AnthropicTeamID) {
		t.Fatalf("/bin/ls against the Anthropic requirement = %+v, want the exit-3 refusal", got)
	}
	if got := VerifyDarwin(context.Background(), "/etc/hosts", ClaudeCodeDarwin, DarwinOptions{}); got.Verified || !strings.Contains(got.Reason, "does not verify") {
		t.Fatalf("an unsigned file = %+v, want refused", got)
	}
}
