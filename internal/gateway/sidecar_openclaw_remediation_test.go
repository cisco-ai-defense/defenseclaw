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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// rel-1-0-10 GAP-0111: with operator_admin false a watcher block sends
// nothing to OpenClaw, and the audit row and the alert say why.
func TestWatcherBlockWithoutOperatorAdminSendsNothingAndSaysWhy(t *testing.T) {
	received := make(chan receivedRequest, 5)
	srv := startMockGW(t, rpcRecordingLoop(received))
	client := connectToMockGW(t, srv)
	client.SetOperatorAdmin(false)
	store, logger := testStoreAndLogger(t)
	notify := NewNotificationQueue()
	s := &Sidecar{
		cfg: &config.Config{
			Guardrail: config.GuardrailConfig{Connector: "openclaw"},
			Gateway: config.GatewayConfig{
				Watcher: config.GatewayWatcherConfig{
					Skill: config.GatewayWatcherSkillConfig{TakeAction: true},
				},
			},
		},
		client: client,
		logger: logger,
		notify: notify,
		router: NewEventRouter(client, nil, logger, false),
	}

	s.handleAdmissionResult(watcher.AdmissionResult{
		Event:   watcher.InstallEvent{Type: watcher.InstallSkill, Name: "blocked-skill"},
		Verdict: watcher.VerdictBlocked,
		Reason:  "on block list",
	})
	s.alertWg.Wait()

	select {
	case rpc := <-received:
		if rpc.Method == "skills.update" {
			t.Fatalf("skills.update sent to OpenClaw without operator.admin")
		}
	case <-time.After(200 * time.Millisecond):
	}

	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Target == "blocked-skill" && strings.Contains(e.Details, openClawRemediationUnavailableAction) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit row for blocked-skill names %s", openClawRemediationUnavailableAction)
	}
	pending := notify.ActiveNotifications()
	if len(pending) == 0 || !slices.Contains(pending[0].Actions, openClawRemediationUnavailableAction) ||
		slices.Contains(pending[0].Actions, "disabled") {
		t.Fatalf("alert actions = %+v, want %s and not disabled", pending, openClawRemediationUnavailableAction)
	}
}
