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

package extproc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0387: the callout can hold a request only for its message budget
// (under the egress filter's 2 s message timeout), so a pending ask an
// unattended run queued must tell the agent to wait and send the request
// again until the ask's expiry. Before, the refusal said "Tell the user ...
// Retry once they approve it": nobody watches an unattended run, so the
// agent ended its task 8 s later, before anyone could answer.
func TestGAP0387UnattendedPendingAskTellsTheAgentToWaitAndRetry(t *testing.T) {
	exp := time.Date(2026, 11, 17, 16, 5, 0, 0, time.UTC)
	var unattended atomic.Bool
	unattended.Store(true)
	// The gateway's callout ask route: the ask stays pending.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "ask-9", "state": "pending", "unattended": unattended.Load(), "expires": exp})
	}))
	defer srv.Close()
	h := newHarness(t, nil)
	h.eng.asks = &AskClient{url: srv.URL, http: srv.Client(), poll: 5 * time.Millisecond}
	h.eng.cfg.Ask.Hold = 60 * time.Millisecond
	r := req("eng-web", "PUT", "files.example.io", "/")
	decide := func() (string, string) {
		t.Helper()
		v := h.eng.DecideHeaders(context.Background(), r)
		if v.Allow || v.Category != CategoryAskPending || v.AskID != "ask-9" {
			t.Fatalf("pending ask: %+v", v)
		}
		var body struct {
			Reason       string `json:"reason"`
			HowToUnblock string `json:"how_to_unblock"`
		}
		if err := json.Unmarshal(h.eng.refusalBody(r, v), &body); err != nil {
			t.Fatal(err)
		}
		return body.Reason, body.HowToUnblock
	}
	reason, hint := decide()
	for _, want := range []string{"ask-9", "Do not end the task", "send the same request again", "2026-11-17T16:05:00Z"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("unattended how_to_unblock %q lacks %q", hint, want)
		}
	}
	if strings.Contains(hint, "Tell the user") || !strings.Contains(reason, "a person has been asked") {
		t.Fatalf("unattended refusal reads like an attended one: reason %q, hint %q", reason, hint)
	}
	// An attended (interactive) pending ask keeps its text.
	unattended.Store(false)
	if _, hint := decide(); !strings.Contains(hint, "Tell the user") || strings.Contains(hint, "Do not end the task") {
		t.Fatalf("attended pending ask hint: %q", hint)
	}
}
