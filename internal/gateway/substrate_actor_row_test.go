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
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-1019: list encodes typed rows; they must be byte for byte the JSON the
// map of actorView (plus state and activity) gave, for every shape of actor.
func TestSubstrateActorRowMatchesView(t *testing.T) {
	created := time.Date(2026, 11, 23, 9, 12, 3, 456789000, time.UTC)
	person := registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example.org", Subject: "alice", Principal: "alice@example.org"}
	workload := registry.Person{Kind: identity.PersonWorkload, Issuer: "https://ci.example.org", Subject: "repo:ci"}
	base := registry.Registration{Key: "k1", Atespace: "eng-web", Name: "a1", UID: subUID1, Person: person, Profile: "eng", Connector: "claudecode", Template: "t1", CreatedAt: created}
	with := func(f func(*registry.Registration)) registry.Registration { r := base; f(&r); return r }
	regs := map[string]registry.Registration{
		"plain":       base,
		"no template": with(func(r *registry.Registration) { r.Template, r.BatchID = "", "b-7" }),
		"unattended":  with(func(r *registry.Registration) { r.Unattended = true }),
		"queue eng":   with(func(r *registry.Registration) { r.Unattended, r.Profile = true, "queue" }),
		"queue zero":  with(func(r *registry.Registration) { r.Unattended, r.Profile = true, "queue0" }),
		"conflict": with(func(r *registry.Registration) {
			r.PolicyConflict = &registry.PolicyConflict{Since: created, Reverts: 3}
		}),
		"deleted":      with(func(r *registry.Registration) { r.Deleted = true }),
		"attributed":   with(func(r *registry.Registration) { r.Attributed, r.Person = true, registry.Person{} }),
		"workload":     with(func(r *registry.Registration) { r.Person = workload }),
		"html in name": with(func(r *registry.Registration) { r.Name, r.Template = "a<b>&c", " x\"y" }),
		"zero created": with(func(r *registry.Registration) { r.CreatedAt = time.Time{} }),
	}
	st := &substrateState{cfg: SubstrateConfig{UnattendedAsk: func(profile string) SubstrateUnattendedAsk {
		switch profile {
		case "queue":
			return SubstrateUnattendedAsk{Queue: true, Timeout: 10 * time.Minute}
		case "queue0":
			return SubstrateUnattendedAsk{Queue: true}
		}
		return SubstrateUnattendedAsk{}
	}}}
	act := &substrateActivityOut{State: SubstrateStateIdle, Last: created, LastKind: "hook", LastTool: created, PendingAsks: 0, Notify: true}
	enc := func(v any) []byte {
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(v); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	for name, reg := range regs {
		for _, state := range []string{"", "running"} {
			for _, a := range []*substrateActivityOut{nil, act} {
				row := st.actorRow(reg)
				row.State, row.Activity = state, a
				v := st.actorView(reg)
				if state != "" {
					v["state"] = state
				}
				if a != nil {
					v["activity"] = a
				}
				if got, want := enc(row), enc(v); !bytes.Equal(got, want) {
					t.Errorf("%s (state %q, activity %v):\n row %s\n map %s", name, state, a != nil, got, want)
				}
			}
		}
	}
}
