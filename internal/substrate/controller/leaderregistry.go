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

package controller

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// ConnectorUnknown is the connector of an attributed registration the
// controller writes before the template's attestation names one.
const ConnectorUnknown = "unknown"

// LeaderRegistry is Registry over the gateway leader's registration store
// (registry.Remote over the leader RPC, mTLS with the controller's pod
// identity): the single source of truth the launcher writes to (GAP-0125).
// A leader error is returned as is, so the controller holds and changes no
// policy; a miss means the leader has no registration.
type LeaderRegistry struct {
	Store registry.Store
	Now   func() time.Time
}

var _ Registry = (*LeaderRegistry)(nil)

// Get implements Registry. A tombstone is no registration.
func (l *LeaderRegistry) Get(ctx context.Context, atespace, uid string) (Registration, bool, error) {
	r, ok, err := l.Store.Get(ctx, atespace, uid)
	if err != nil || !ok || r.Deleted {
		return Registration{}, false, err
	}
	return fromLeader(r), true, nil
}

// Put implements Registry: the controller writes attributed actors and
// adopted forks.
func (l *LeaderRegistry) Put(ctx context.Context, c Registration) error {
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	return l.Store.Put(ctx, toLeader(c, now()))
}

func fromLeader(r registry.Registration) Registration {
	out := Registration{Atespace: r.Atespace, Name: r.Name, UID: r.UID, Template: r.Template, Profile: r.Profile,
		Task: r.Unattended, BatchID: r.BatchID, ParentUID: r.ParentUID, owner: r.Person, connector: r.Connector}
	switch {
	case r.Attributed && r.ParentUID != "":
		out.Source, out.ForkedBy = SourceFork, ForkedByUnknown
	case r.Attributed:
		out.Source = SourceAtespace
	case r.ParentUID != "":
		out.Source, out.ForkedBy = SourceFork, ForkedByDefenseClaw
	default:
		out.Source = SourceLauncher
	}
	if !r.Attributed {
		if r.Person.Kind == "workload" {
			out.Workload = r.Person.Subject
		} else {
			out.Person = r.Person.Subject
		}
	}
	return out
}

func toLeader(c Registration, now time.Time) registry.Registration {
	r := registry.Registration{Atespace: c.Atespace, Name: c.Name, UID: c.UID, Template: c.Template, Profile: c.Profile,
		Unattended: c.Task, BatchID: c.BatchID, ParentUID: c.ParentUID, Connector: c.connector, CreatedAt: now.UTC()}
	if r.Connector == "" {
		r.Connector = ConnectorUnknown
	}
	if c.Person == "" && c.Workload == "" {
		r.Attributed = true // D3: attributed to its atespace, never a person
		return r
	}
	r.Person = c.owner
	if r.Person.Subject == "" {
		// A registration made in this process without the leader's record
		// (tests, the in-memory registry): keep the subject.
		r.Person = registry.Person{Kind: "person", Subject: c.Person}
		if c.Workload != "" {
			r.Person = registry.Person{Kind: "workload", Subject: c.Workload}
		}
	}
	return r
}
