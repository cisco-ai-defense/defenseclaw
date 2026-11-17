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

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// GAP-0388: the actor view of an unattended actor says what its asks do,
// so status on a queue profile does not say asks are denied.
func TestGAP0388ActorViewNamesTheUnattendedAskRule(t *testing.T) {
	for _, tc := range []struct {
		name          string
		rule          func(string) SubstrateUnattendedAsk
		asks, timeout string
	}{
		{"no rule", nil, "deny", ""},
		{"deny", func(string) SubstrateUnattendedAsk { return SubstrateUnattendedAsk{} }, "deny", ""},
		{"queue", func(p string) SubstrateUnattendedAsk {
			return SubstrateUnattendedAsk{Queue: p == "eng", Timeout: 5 * time.Minute}
		}, "queue", "5m0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.UnattendedAsk = tc.rule })
			rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-bob", "")
			var got struct {
				Actors []map[string]any `json:"actors"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || len(got.Actors) != 1 {
				t.Fatalf("list: %d %s", rec.Code, rec.Body)
			}
			a := got.Actors[0]
			if a["unattended_asks"] != tc.asks || (tc.timeout != "" && a["ask_timeout"] != tc.timeout) || (tc.timeout == "" && a["ask_timeout"] != nil) {
				t.Fatalf("unattended actor view: %v, want asks %s timeout %q", a, tc.asks, tc.timeout)
			}
			rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Actors) != 1 || got.Actors[0]["unattended_asks"] != nil {
				t.Fatalf("an attended actor names an unattended ask rule: %s", rec.Body)
			}
		})
	}
}
