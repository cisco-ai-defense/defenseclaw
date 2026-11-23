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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0557: a queued unattended ask is an approval request a person must
// answer; a webhook with min_severity HIGH (the documented default) never
// got it, because the ask carries no finding severity. Approval requests
// are not filtered by min_severity; an events list still decides.
func TestGAP0557ApprovalRequestReachesAHighWebhook(t *testing.T) {
	high := newCollector()
	defer high.Close()
	listed := newCollector()
	defer listed.Close()
	blockOnly := newCollector()
	defer blockOnly.Close()
	d := newTestDispatcher([]config.WebhookConfig{
		{URL: high.URL(), Type: "generic", MinSeverity: "HIGH", Enabled: true},
		{URL: listed.URL(), Type: "generic", MinSeverity: "CRITICAL", Events: []string{"approval-request"}, Enabled: true},
		{URL: blockOnly.URL(), Type: "generic", MinSeverity: "INFO", Events: []string{"block"}, Enabled: true},
	})
	if d == nil {
		t.Fatal("no dispatcher")
	}
	defer d.Close()
	d.Dispatch(audit.Event{Timestamp: time.Now().UTC(), Action: string(audit.ActionApprovalRequest), Target: "pypi.org",
		Actor: "defenseclaw-substrate", Details: "ask=ask-1 actor=eng-web/bob-1 unattended=true", Severity: "MEDIUM"})
	// A MEDIUM finding is still filtered by min_severity HIGH.
	d.Dispatch(audit.Event{Timestamp: time.Now().UTC(), Action: "guardrail-alert", Target: "x", Severity: "MEDIUM"})
	deadline := time.Now().Add(5 * time.Second)
	for (high.count() < 1 || listed.count() < 1) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if high.count() != 1 {
		t.Fatalf("HIGH endpoint got %d posts, want the approval request only", high.count())
	}
	if listed.count() != 1 {
		t.Fatalf("an endpoint listing approval-request got %d posts", listed.count())
	}
	if blockOnly.count() != 0 {
		t.Fatalf("an endpoint whose events list leaves approval requests out got %d posts", blockOnly.count())
	}
}
