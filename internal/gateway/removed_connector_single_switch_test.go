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
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-2617, single-connector start: one configured connector and a stale
// roster name with no hook contract lock and nothing installed. The stale
// name leaves the roster without a teardown, so the switch to the configured
// connector must not be refused for missing rollback authority. A stale name
// whose hooks are still installed keeps the strict refusal.
func TestSingleConnectorSwitchDropsAStaleNoLockNameGap2617(t *testing.T) {
	cases := []struct {
		name       string
		verifyErr  error
		wantRefuse bool
	}{
		{name: "nothing installed"},
		{name: "hooks still installed", verifyErr: errors.New("hook still registered"), wantRefuse: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := multiBootSidecar(t)
			s.cfg.DataDir = testenv.PrivateTempDir(t)
			s.cfg.Guardrail.Enabled = true
			s.cfg.Guardrail.Mode = "observe"
			s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
				"claudecode": {Mode: "observe"},
			}
			s.health = NewSidecarHealth()
			stale := &failedSetupCleanupConnector{
				bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "cursor"}},
				verifyErr:         tc.verifyErr,
			}
			requested := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
			registry := connector.NewRegistry()
			registry.RegisterBuiltin(stale)
			registry.RegisterBuiltin(requested)
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"cursor", "claudecode"}); err != nil {
				t.Fatal(err)
			}
			if _, err := connector.EnsureHookAPIToken(s.cfg.DataDir, "cursor"); err != nil {
				t.Fatal(err)
			}
			lock, err := connector.CaptureHookContractLockSnapshot(s.cfg.DataDir)
			if err != nil {
				t.Fatal(err)
			}
			transaction := multiConnectorSetupTransaction{hookLockState: lock}
			err = s.teardownPreviousConnectorTransaction(
				context.Background(), registry, requested,
				"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
				&transaction,
			)
			if tc.wantRefuse {
				if err == nil || !strings.Contains(err.Error(), "without complete prior-registration rollback authority") {
					t.Fatalf("err=%v, want the rollback-authority refusal for a name with hooks still installed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("single-connector switch refused for a stale no-lock name with nothing installed: %v", err)
			}
			if len(transaction.removed) != 0 || len(transaction.keptRegistrations) != 0 {
				t.Fatalf("removed=%v kept=%v, want neither (the stale name is dropped, not torn down or kept)", transaction.removed, transaction.keptRegistrations)
			}
			if stale.teardownCalls != 0 {
				t.Fatalf("teardown ran %d time(s) for a connector with nothing installed", stale.teardownCalls)
			}
		})
	}
}
