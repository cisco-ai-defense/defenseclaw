// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1279: a tool call whose arguments are shorter than the
// content judges' 20-byte minimum is still judged, on its name and its
// arguments, and kept in the session history the next call is judged with.
// A call with no tool name stays out.
func TestGAP1279ShortToolCallsReachTheToolJudge(t *testing.T) {
	j, provider := newNonceTestJudge()
	ctx := ContextWithSessionID(context.Background(), "gap1279")
	j.ObserveSessionPrompt(ctx, "tidy my inbox")
	asked := func() int {
		provider.mu.Lock()
		defer provider.mu.Unlock()
		return len(provider.captured)
	}
	_ = j.RunToolJudge(ctx, "delete_file", `{"file_id":"13"}`)
	if got := asked(); got != 1 {
		t.Fatalf("delete_file with 16 bytes of arguments must reach the tool judge: %d requests", got)
	}
	_ = j.RunToolJudge(ctx, "GmailSendEmail", `{}`)
	if got := asked(); got != 2 {
		t.Fatalf("GmailSendEmail with empty arguments must reach the tool judge: %d requests", got)
	}
	provider.mu.Lock()
	last := provider.captured[len(provider.captured)-1]
	provider.mu.Unlock()
	if user := last.Messages[len(last.Messages)-1].Content; !strings.Contains(user, "delete_file") {
		t.Fatalf("the earlier short call must be in the history of the next one: %q", user)
	}
	_ = j.RunToolJudge(ctx, "  ", `{}`)
	if got := asked(); got != 2 {
		t.Fatalf("a call with no tool name has nothing to judge: %d requests", got)
	}
}
