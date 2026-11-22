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
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0563: the generic webhook post of a tool call refused in an Agent
// Substrate actor named only the guardrail profile and the gateway pod as
// host. It names the actor, its atespace, person and profile, and whether
// the run is unattended, as the actor's audit row does; a host request
// gets none of these keys.
func TestGAP0563WebhookNamesTheSubstrateActor(t *testing.T) {
	const uid = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	key, err := sandboxreg.SubstrateKey("eng-web", uid)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.Registration{Key: key, Atespace: "eng-web", Name: "bob-1", UID: uid, Connector: "claudecode",
		Profile: "eng", Unattended: true, Person: registry.Person{Subject: "bob-subject"}}
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor("eng-web", "bob-1", uid, "actor/eng-web/bob-1", key))
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)

	post := func(ctx context.Context) map[string]any {
		t.Helper()
		evt := audit.Event{Timestamp: time.Now().UTC(), Action: string(audit.ActionBlock), Target: "Bash",
			Actor: "defenseclaw-hook", Severity: "HIGH", Connector: "claudecode",
			Structured: map[string]any{webhookAttributionKey: webhookAttributionFor(ctx)}}
		payload, err := formatGenericPayload(evt)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatal(err)
		}
		return m["event"].(map[string]any)
	}
	got := post(ctx)
	for k, want := range map[string]any{"substrate_actor": "bob-1", "substrate_atespace": "eng-web",
		"substrate_person": sanitizeLLMEventUser("bob-subject"), "substrate_profile": "eng", "substrate_unattended": true} {
		if got[k] != want {
			t.Errorf("actor post %s = %v, want %v", k, got[k], want)
		}
	}
	host := post(context.Background())
	for _, k := range []string{"substrate_actor", "substrate_atespace", "substrate_person", "substrate_profile", "substrate_unattended"} {
		if _, ok := host[k]; ok {
			t.Errorf("a host request's post carries %s", k)
		}
	}
}
