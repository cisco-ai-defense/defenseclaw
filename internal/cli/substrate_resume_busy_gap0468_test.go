// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0468: a busy node is told apart from a broken cluster.
func TestResumeBusySaysTheClusterIsBusyGAP0468(t *testing.T) {
	busy := substrateAPIMessage(&api.Error{Status: 503, Reason: "resume_busy"})
	if !strings.Contains(busy, "busy starting other agents") || !strings.Contains(busy, "--parallel") {
		t.Errorf("resume_busy: %q", busy)
	}
	if broken := substrateAPIMessage(&api.Error{Status: 502, Reason: "resume_failed"}); strings.Contains(broken, "busy") {
		t.Errorf("resume_failed reads as busy: %q", broken)
	}
}
