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

// GAP-0388: an unattended actor's view says what its asks do, from its
// profile's unattended_asks, so status does not say "denied" for a run
// whose asks are queued.
func TestSubstrateActorViewSaysWhatUnattendedAsksDo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rule    func(string) SubstrateUnattendedAsk
		asks    string
		timeout float64
	}{
		{"no rule denies", nil, "deny", 0},
		{"deny", func(string) SubstrateUnattendedAsk { return SubstrateUnattendedAsk{} }, "deny", 0},
		{"queue", func(p string) SubstrateUnattendedAsk {
			return SubstrateUnattendedAsk{Queue: p == "eng", Timeout: 30 * time.Minute}
		}, "queue", 1800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.UnattendedAsk = tc.rule })
			rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/bob-1", "p-admin", "")
			var one map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("get: %d %s", rec.Code, rec.Body)
			}
			if one["unattended_asks"] != tc.asks {
				t.Errorf("get unattended_asks = %v, want %s", one["unattended_asks"], tc.asks)
			}
			if got, _ := one["ask_timeout_seconds"].(float64); got != tc.timeout {
				t.Errorf("get ask_timeout_seconds = %v, want %v", one["ask_timeout_seconds"], tc.timeout)
			}
			rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors?all=1", "p-admin", "")
			var list struct {
				Actors []map[string]any `json:"actors"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("list: %d %s", rec.Code, rec.Body)
			}
			for _, a := range list.Actors {
				want := any(nil) // an attended actor does not ask on its own
				if a["unattended"] == true {
					want = tc.asks
				}
				if a["unattended_asks"] != want {
					t.Errorf("list %v: unattended_asks = %v, want %v", a["name"], a["unattended_asks"], want)
				}
			}
		})
	}
}
