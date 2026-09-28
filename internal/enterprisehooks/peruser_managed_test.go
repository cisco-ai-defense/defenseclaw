// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestWindowsStandalonePerUserBuiltinRejectsImpostors(t *testing.T) {
	// A built-in of a different name must not satisfy the check.
	if isWindowsStandalonePerUserBuiltin("copilot", connector.NewDevinConnector()) {
		t.Fatal("devin implementation accepted as copilot")
	}
	if isWindowsStandalonePerUserBuiltin("amp", connector.NewOpenCodeConnector()) {
		t.Fatal("opencode implementation accepted as amp")
	}
	if isWindowsStandalonePerUserBuiltin("codex", connector.NewCodexConnector()) {
		t.Fatal("codex is not a per-user connector")
	}
	if !isWindowsStandalonePerUserBuiltin("amp", connector.NewAMPConnector()) {
		t.Fatal("built-in amp rejected")
	}
}
