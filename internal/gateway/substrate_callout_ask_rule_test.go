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
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
)

// TestSubstrateCalloutAskApprovalIsPerRuleGAP0177: approving one url rule
// ask on a host does not approve another url rule's ask there, nor a host
// ask; a host ask approval covers later host asks only. The rule travels on
// the wire and is kept on the ask.
func TestSubstrateCalloutAskApprovalIsPerRuleGAP0177(t *testing.T) {
	store := asks.NewMemory()
	fake := ateapifake.New()
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "bob-1"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Asks, c.Policies = asksDirect{store}, fake
		c.UnattendedAsk = func(string) SubstrateUnattendedAsk { return SubstrateUnattendedAsk{Queue: true, Timeout: time.Minute} }
	})
	post := func(rule string) map[string]any {
		t.Helper()
		body := `{"actor":{"atespace":"eng-web","name":"bob-1"},"host":"api.github.com","rule":"` + rule + `","summary":"POST api.github.com/x"}`
		rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout, body, "X-DefenseClaw-Client", "substrate-extproc")
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: %s", rule, rec.Body)
		}
		return got
	}
	release := post("url_rules:release-ask")
	if release["state"] != asks.StatePending || release["rule"] != "url_rules:release-ask" {
		t.Fatalf("first ask: %v", release)
	}
	if _, err := store.Resolve(context.Background(), asks.ResolveRequest{ID: release["id"].(string), Decision: "approve", CallerID: ownerOf(bob).ID()}); err != nil {
		t.Fatal(err)
	}
	if got := post("url_rules:release-ask"); got["state"] != asks.StateApproved {
		t.Fatalf("the same rule after its approval: %v", got)
	}
	// Another rule on the same host, and a host ask, are asked again.
	if got := post("url_rules:delete-ask"); got["state"] != asks.StatePending || got["id"] == release["id"] {
		t.Fatalf("another rule on the approved host: %v", got)
	}
	hostAsk := post("ask_hosts:api.github.com")
	if hostAsk["state"] != asks.StatePending {
		t.Fatalf("a host ask after an url rule approval: %v", hostAsk)
	}
	// A host approval covers host asks, never an url rule's.
	if _, err := store.Resolve(context.Background(), asks.ResolveRequest{ID: hostAsk["id"].(string), Decision: "approve", CallerID: ownerOf(bob).ID()}); err != nil {
		t.Fatal(err)
	}
	if got := post("ask_hosts:api.github.com"); got["state"] != asks.StateApproved {
		t.Fatalf("the host ask after its approval: %v", got)
	}
	if got := post("url_rules:other-ask"); got["state"] != asks.StatePending {
		t.Fatalf("an url rule after a host approval: %v", got)
	}
}
