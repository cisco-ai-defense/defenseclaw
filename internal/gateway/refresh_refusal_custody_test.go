// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0730: a plugin folder another account can write was answered with
// "close the agent holding its settings, then run: defenseclaw upgrade",
// which changes neither the mode, the group nor the ACL. The refusal names
// the fix; the next step is the restart that retries it.
func TestGAP0730CustodyRefusalNextStepIsARestartNotAnUpgrade(t *testing.T) {
	err := fmt.Errorf("connector opencode setup failed: %w", fmt.Errorf("opencode validate plugin destination: %w", connector.ErrPluginFolderCustody))
	got := refreshRefusalNextStep(err)
	if !strings.Contains(got, "defenseclaw-gateway restart") || strings.Contains(got, "upgrade") || strings.Contains(got, "close the agent") {
		t.Fatalf("next step = %q", got)
	}
	// Benign twin: an unrelated refusal keeps the generic advice.
	if got := refreshRefusalNextStep(errors.New("settings busy")); !strings.Contains(got, "close the agent holding its settings") {
		t.Fatalf("generic next step changed: %q", got)
	}
}
