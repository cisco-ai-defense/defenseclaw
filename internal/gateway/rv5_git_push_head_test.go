//go:build !windows

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
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
)

// RV4-7: an approved push answers again only for the commit the person
// approved; another head of the same branch is a new ask.
func TestRV5GitPushApprovalIsForOneHead(t *testing.T) {
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Asks = asks.NewMemory()
		c.GitPush = func(string) string { return config.SubstrateGitPushAsk }
	})
	push := func(head, askID string) map[string]any {
		b, _ := json.Marshal(map[string]any{"host": "git.example.test", "repo": "team/app", "branch": "agent/x", "head": head,
			"commits": 1, "files": 1, "ask_id": askID})
		rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/push", "p-alice", string(b))
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return v
	}
	h1, h2 := strings.Repeat("a", 40), strings.Repeat("b", 40)
	v := push(h1, "")
	id, _ := v["ask_id"].(string)
	if v["decision"] != "ask" || id == "" {
		t.Fatalf("ask: %v", v)
	}
	summary, _ := v["summary"].(string)
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/asks/"+id, "p-alice", `{"decision":"approve"}`); rec.Code/100 != 2 {
		t.Fatalf("approve %d %s", rec.Code, rec.Body)
	}
	if v := push(h1, id); v["decision"] != "allow" {
		t.Fatalf("approved head: %v", v)
	}
	if v := push(h1, ""); v["decision"] != "allow" {
		t.Fatalf("approved head, next run: %v", v)
	}
	for _, askID := range []string{"", id} {
		if v := push(h2, askID); v["decision"] != "ask" || v["ask_id"] == id {
			t.Fatalf("another head (ask_id %q) reused the approval: %v", askID, v)
		}
	}
	if !strings.Contains(summary, h1[:12]) {
		t.Fatalf("the ask does not name the commit: %q", summary)
	}
}
