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
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// LeaderRegistry is Registry over the gateway leader's registrations
// (registry.Remote over the leader RPC, mTLS with the controller's pod
// identity), so the controller and the gateway share one record per actor
// UID: the launcher's registration is what attributes a launcher actor
// (GAP-0125), and the controller's attributed and fork records reach the
// gateway. A store error is returned as is, so the controller holds and
// changes no policy; a miss or a tombstone is no registration.
type LeaderRegistry struct {
	Store registry.Store
	Now   func() time.Time
}

var _ Registry = (*LeaderRegistry)(nil)

// Get implements Registry.
func (l *LeaderRegistry) Get(ctx context.Context, atespace, uid string) (Registration, bool, error) {
	r, ok, err := l.Store.Get(ctx, atespace, uid)
	if err != nil || !ok || r.Deleted {
		return Registration{}, false, err
	}
	return fromLeader(r), true, nil
}

func fromLeader(r registry.Registration) Registration {
	out := Registration{Atespace: r.Atespace, Name: r.Name, UID: r.UID, Template: r.Template, Profile: r.Profile,
		Task: r.Unattended, BatchID: r.BatchID, ParentUID: r.ParentUID, ForkedBy: r.ForkedBy,
		Approved: slices.Clone(r.Approved), Source: SourceLauncher}
	switch {
	case r.ParentUID != "":
		out.Source = SourceFork
	case r.Attributed:
		out.Source = SourceAtespace
	}
	if !r.Attributed {
		if r.Person.Kind == identity.PersonWorkload {
			out.Workload = r.Person.Subject
		} else {
			out.Person = r.Person.Subject
		}
	}
	return out
}

// Put implements Registry: an attributed actor, an adopted fork, or a
// change (approvals, forked_by) to a record that exists. An existing
// record keeps every field the launcher wrote.
func (l *LeaderRegistry) Put(ctx context.Context, in Registration) error {
	cur, ok, err := l.Store.Get(ctx, in.Atespace, in.UID)
	if err != nil {
		return err
	}
	if ok {
		cur.Approved, cur.ForkedBy = slices.Clone(in.Approved), in.ForkedBy
		if cur.Template == "" {
			cur.Template = in.Template
		}
		return l.Store.Put(ctx, cur)
	}
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	reg := registry.Registration{Atespace: in.Atespace, Name: in.Name, UID: in.UID, Template: in.Template, Profile: in.Profile,
		Unattended: in.Task, BatchID: in.BatchID, ParentUID: in.ParentUID, ForkedBy: in.ForkedBy,
		Approved: slices.Clone(in.Approved), Attributed: true, CreatedAt: now().UTC()}
	// Only a fork DefenseClaw made keeps the parent's person (and with it
	// per-person secrets); a fork made outside DefenseClaw is attributed
	// to its atespace (GAP-0082).
	if in.Source == SourceFork && in.ParentUID != "" && in.ForkedBy == ForkedByDefenseClaw {
		parent, pok, perr := l.Store.Get(ctx, in.Atespace, in.ParentUID)
		if perr != nil {
			return perr
		}
		if pok && !parent.Attributed && !parent.Deleted {
			reg.Attributed = false
			reg.Person, reg.Connector, reg.KitVersion, reg.HookContract = parent.Person, parent.Connector, parent.KitVersion, parent.HookContract
			reg.HarnessVersion, reg.TemplateDigest, reg.Secrets = parent.HarnessVersion, parent.TemplateDigest, slices.Clone(parent.Secrets)
		}
	}
	return l.Store.Put(ctx, reg)
}
