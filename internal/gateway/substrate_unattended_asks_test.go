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

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
)

// D12 queue (lane F3): an unattended actor whose profile says
// unattended_asks: queue gets a pending ask that expires after the
// profile's ask_timeout; with deny (or no rule) it is denied at once.
func TestSubstrateUnattendedAskQueue(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  func(string) SubstrateUnattendedAsk
		state string
	}{
		{"no rule", nil, asks.StateDenied},
		{"deny", func(string) SubstrateUnattendedAsk { return SubstrateUnattendedAsk{} }, asks.StateDenied},
		{"queue", func(p string) SubstrateUnattendedAsk {
			return SubstrateUnattendedAsk{Queue: p == "eng", Timeout: 7 * time.Minute}
		}, asks.StatePending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := asks.NewMemory()
			fake := ateapifake.New()
			fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "bob-1"}})
			f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Asks = asksDirect{store}; c.Policies = fake; c.UnattendedAsk = tc.rule })
			rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout,
				`{"actor":{"atespace":"eng-web","name":"bob-1"},"host":"x.example.org"}`, "X-DefenseClaw-Client", "substrate-extproc")
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || got["state"] != tc.state {
				t.Fatalf("unattended ask: %d %s, want state %s", rec.Code, rec.Body, tc.state)
			}
			if tc.state != asks.StatePending {
				return
			}
			if got["unattended"] != true {
				t.Fatalf("a queued ask is not marked unattended: %v", got)
			}
			created, _ := time.Parse(time.RFC3339Nano, got["created"].(string))
			expires, _ := time.Parse(time.RFC3339Nano, got["expires"].(string))
			if d := expires.Sub(created); d != 7*time.Minute {
				t.Fatalf("queued ask expires after %s, want the profile's 7m", d)
			}
		})
	}
}

func TestAskTimeoutReplacesTheStoreExpiry(t *testing.T) {
	store := asks.NewMemory()
	got, err := store.OpenAsk(t.Context(), asks.Ask{Atespace: "a", UID: "u", Host: "h", TimeoutSeconds: 120})
	if err != nil || got.Expires.Sub(got.Created) != 2*time.Minute {
		t.Fatalf("timeout ask: %+v %v", got, err)
	}
	got, _ = store.OpenAsk(t.Context(), asks.Ask{Atespace: "a", UID: "u2", Host: "h", TimeoutSeconds: int64((48 * time.Hour) / time.Second)})
	if got.Expires.Sub(got.Created) != asks.MaxAskTimeout {
		t.Fatalf("timeout not capped: %s", got.Expires.Sub(got.Created))
	}
	got, _ = store.OpenAsk(t.Context(), asks.Ask{Atespace: "a", UID: "u3", Host: "h"})
	if got.Expires.Sub(got.Created) != asks.DefaultAskExpiry {
		t.Fatalf("default expiry changed: %s", got.Expires.Sub(got.Created))
	}
}
