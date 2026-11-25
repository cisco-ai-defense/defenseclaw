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

// GAP-0768: the push ask names the exact address the launcher pushes to,
// and an address that is not https://HOST/REPO(.git) is refused.
func TestRV4GitPushAskNamesTheURL(t *testing.T) {
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Asks = asks.NewMemory()
		c.GitPush = func(string) string { return config.SubstrateGitPushAsk }
	})
	push := func(u string) (int, map[string]any) {
		b, _ := json.Marshal(map[string]any{"host": "git.example.test", "repo": "team/app", "url": u, "branch": "agent/x",
			"head": strings.Repeat("a", 40), "commits": 1, "files": 1})
		rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/push", "p-alice", string(b))
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return rec.Code, v
	}
	code, v := push("https://git.example.test/team/app.git")
	if code != http.StatusOK || v["summary"] != "Push agent/x at aaaaaaaaaaaa (1 commits, 1 files) to https://git.example.test/team/app.git?" {
		t.Fatalf("ask: %d %v", code, v)
	}
	for _, bad := range []string{"https://other.example/team/app.git", "http://git.example.test/team/app", "https://git.example.test/team/app2"} {
		if code, _ := push(bad); code != http.StatusBadRequest {
			t.Errorf("url %q: %d, want 400", bad, code)
		}
	}
}
