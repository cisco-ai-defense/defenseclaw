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
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-2617: a connector that left config.yaml and has no hook contract lock
// and nothing installed is dropped from the active roster (its leftover hook
// credential removed) instead of being retained for a teardown retry that can
// never succeed. A registration still in the agent keeps the retain path.
func TestRemovedConnectorWithNothingInstalledLeavesTheRosterGap2617(t *testing.T) {
	cases := []struct {
		name       string
		verifyErr  error
		withToken  bool
		wantRetain []string
	}{
		{name: "nothing installed", wantRetain: nil},
		{name: "hooks still installed", verifyErr: errors.New("hook still registered"), wantRetain: []string{"cursor"}},
		{name: "leftover hook credential", withToken: true, wantRetain: nil},
		{name: "hooks and credential still installed", verifyErr: errors.New("hook still registered"), withToken: true, wantRetain: []string{"cursor"}},
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
			removed := &failedSetupCleanupConnector{
				bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "cursor"}},
				verifyErr:         tc.verifyErr,
			}
			survivor := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
			registry := connector.NewRegistry()
			registry.RegisterBuiltin(removed)
			registry.RegisterBuiltin(survivor)
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"claudecode", "cursor"}); err != nil {
				t.Fatal(err)
			}
			if tc.withToken {
				if _, err := connector.EnsureHookAPIToken(s.cfg.DataDir, "cursor"); err != nil {
					t.Fatal(err)
				}
			}
			lock, err := connector.CaptureHookContractLockSnapshot(s.cfg.DataDir)
			if err != nil {
				t.Fatal(err)
			}
			candidates, retained, _ := s.removedConnectorRollbackCandidates(
				registry, connector.LoadActiveConnectors(s.cfg.DataDir), []string{"claudecode"},
				"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
				lock,
			)
			if len(candidates) != 0 {
				t.Fatalf("candidates=%v, want none (no rollback authority to tear down)", candidates)
			}
			if !reflect.DeepEqual(retained, tc.wantRetain) {
				t.Fatalf("retained=%v, want %v", retained, tc.wantRetain)
			}
			tokenPath, err := connector.HookAPITokenFilePath(s.cfg.DataDir, "cursor")
			if err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Lstat(tokenPath)
			if dropped := tc.wantRetain == nil; dropped && !os.IsNotExist(statErr) {
				t.Fatalf("dropped connector kept its hook credential: %v", statErr)
			} else if !dropped && tc.withToken && statErr != nil {
				t.Fatalf("retained connector lost its hook credential: %v", statErr)
			}
			if removed.teardownCalls != 0 {
				t.Fatalf("teardown ran %d time(s) without rollback authority", removed.teardownCalls)
			}
		})
	}
}
