// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0730: a plugin folder other accounts can write is fixed by the command
// in the error; the gateway start error no longer tells the user to close the
// agent and run an upgrade, which changes nothing about a folder mode.
func TestGAP0730RefreshRefusalForAWritableFolderNamesNoUpgrade(t *testing.T) {
	custody := fmt.Errorf("opencode validate plugin destination: %w", connector.ErrAgentFolderCustody)
	step := refreshRefusalNextStep(custody)
	if strings.Contains(step, "upgrade") || strings.Contains(step, "close the agent") {
		t.Fatalf("custody refusal next step %q", step)
	}
	if !strings.Contains(step, "defenseclaw-gateway restart") {
		t.Fatalf("custody refusal next step %q names no restart", step)
	}
	// Benign twin: any other refusal keeps its existing next step.
	if step := refreshRefusalNextStep(fmt.Errorf("something else")); !strings.Contains(step, "defenseclaw upgrade") {
		t.Fatalf("default next step changed: %q", step)
	}
}
