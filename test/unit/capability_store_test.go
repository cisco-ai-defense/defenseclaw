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

package unit

import (
	"testing"
	"time"
)

func TestLogCapabilityDecision(t *testing.T) {
	store := newTestStore(t)

	err := store.LogCapabilityDecision("support-bot", "jira.get_issue", `{"project":"ENG-123"}`, true, "capability matched", "read_jira_ticket")
	if err != nil {
		t.Fatalf("LogCapabilityDecision: %v", err)
	}

	err = store.LogCapabilityDecision("support-bot", "slack.post_message", `{"channel":"#general"}`, false, "constraint mismatch", "")
	if err != nil {
		t.Fatalf("LogCapabilityDecision: %v", err)
	}

	decisions, err := store.ListCapabilityDecisions(10)
	if err != nil {
		t.Fatalf("ListCapabilityDecisions: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decisions))
	}

	// Most recent first
	if decisions[0].Resource != "slack.post_message" {
		t.Errorf("expected most recent first, got %s", decisions[0].Resource)
	}
	if decisions[0].Allowed {
		t.Error("expected denied decision")
	}
	if decisions[1].Allowed != true {
		t.Error("expected allowed decision")
	}
}

func TestRecordCapabilityCall(t *testing.T) {
	store := newTestStore(t)

	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		err := store.RecordCapabilityCall("support-bot", "jira.get_issue", now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("RecordCapabilityCall: %v", err)
		}
	}

	count, err := store.CountCapabilityCalls("support-bot", now.Add(-1*time.Second), now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("CountCapabilityCalls: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 calls, got %d", count)
	}

	// Different agent should have 0
	count, err = store.CountCapabilityCalls("other-agent", now.Add(-1*time.Second), now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("CountCapabilityCalls: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 calls for other agent, got %d", count)
	}
}
