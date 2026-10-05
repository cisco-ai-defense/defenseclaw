// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1412: a setup command that restarts the gateway first records a newer
// Codex selection; the old gateway must not raise a HIGH guardrail-degraded
// alert for that handoff, but still reports it if it persists.
func TestHookGuardSupersededSelectionIsGracedNotDegraded(t *testing.T) {
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	conn := connector.NewCodexConnector()
	err := fmt.Errorf("check: %w", connector.ErrSetupSelectionSuperseded)

	guard.reportPolicyFailure(conn, err)
	guard.mu.Lock()
	reported := guard.lastPolicyFailure
	guard.supersededSince = time.Now().Add(-2 * hookGuardSupersededGrace)
	guard.mu.Unlock()
	if reported != "" {
		t.Fatalf("superseded selection reported inside the grace window: %q", reported)
	}

	guard.reportPolicyFailure(conn, err)
	guard.mu.Lock()
	reported = guard.lastPolicyFailure
	guard.mu.Unlock()
	if reported == "" {
		t.Fatal("superseded selection that outlived the grace window was not reported")
	}
}
