// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestHookLLMEventMetaCarriesHookRequestID(t *testing.T) {
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{RequestID: "hook-request-1"})

	meta := hookLLMEventMeta(ctx, "codex", "session-1", "turn-1", "gpt", "codex", "", "", "", nil)

	if meta.RequestID != "hook-request-1" {
		t.Fatalf("RequestID = %q, want hook-request-1", meta.RequestID)
	}
}
