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

var (
	_ Registry       = (*LeaderRegistry)(nil)
	_ FreshRegistry  = (*LeaderRegistry)(nil)
	_ Tombstoner     = (*LeaderRegistry)(nil)
	_ ConflictMarker = (*LeaderRegistry)(nil)
)

// Get implements Registry.
func (l *LeaderRegistry) Get(ctx context.Context, atespace, uid string) (Registration, bool, error) {
	r, ok, err := l.Store.Get(ctx, atespace, uid)
	if err != nil || !ok || r.Deleted {
		return Registration{}, false, err
	}
	return fromLeader(r), true, nil
}

// freshStore is a store that can read past its miss cache (registry.Remote).
type freshStore interface {
	GetFresh(ctx context.Context, atespace, uid string) (registry.Registration, bool, error)
}

// GetFresh implements FreshRegistry: past the store's miss cache when it has
// one, else the same as Get.
func (l *LeaderRegistry) GetFresh(ctx context.Context, atespace, uid string) (Registration, bool, error) {
	fs, ok := l.Store.(freshStore)
	if !ok {
		return l.Get(ctx, atespace, uid)
	}
	r, found, err := fs.GetFresh(ctx, atespace, uid)
	if err != nil || !found || r.Deleted {
		return Registration{}, false, err
	}
	return fromLeader(r), true, nil
}

func fromLeader(r registry.Registration) Registration {
	out := Registration{Atespace: r.Atespace, Name: r.Name, UID: r.UID, Template: r.Template, Profile: r.Profile,
		Task: r.Unattended, BatchID: r.BatchID, ParentUID: r.ParentUID, ForkedBy: r.ForkedBy,
		Approved: slices.Clone(r.Approved), Source: SourceLauncher,
		Connector: r.Connector, AgentVersion: r.HarnessVersion, HookContract: r.HookContract,
		KitVersion: r.KitVersion, TemplateDigest: r.TemplateDigest, RelayStreams: r.RelayStreams, PolicyConflict: r.PolicyConflict != nil}
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
// record keeps every field the launcher wrote. An attributed record that
// names no kit takes the attested kit once (GAP-0351).
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
		if registry.KitFillable(cur) && in.Source == SourceAtespace && in.Connector != "" {
			cur.Connector, cur.HarnessVersion, cur.HookContract = in.Connector, in.AgentVersion, in.HookContract
			cur.KitVersion, cur.TemplateDigest, cur.RelayStreams = in.KitVersion, in.TemplateDigest, in.RelayStreams
		}
		return l.Store.Put(ctx, cur)
	}
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	reg := registry.Registration{Atespace: in.Atespace, Name: in.Name, UID: in.UID, Template: in.Template, Profile: in.Profile,
		Unattended: in.Task, BatchID: in.BatchID, ParentUID: in.ParentUID, ForkedBy: in.ForkedBy,
		Connector: in.Connector, HarnessVersion: in.AgentVersion, HookContract: in.HookContract,
		KitVersion: in.KitVersion, TemplateDigest: in.TemplateDigest, RelayStreams: in.RelayStreams,
		Approved: slices.Clone(in.Approved), Attributed: true, CreatedAt: now().UTC()}
	// A fork is attributed: DefenseClaw makes none, so it never keeps the
	// parent's person or per-person secrets (GAP-0082, GAP-0425).
	return l.Store.Put(ctx, reg)
}

// MarkDeleted implements Tombstoner: the actor is gone from Substrate, so its
// registration becomes a tombstone (kept for audit; Get no longer finds it).
// No registration, or one already deleted, needs nothing.
func (l *LeaderRegistry) MarkDeleted(ctx context.Context, atespace, uid string) error {
	cur, ok, err := l.Store.Get(ctx, atespace, uid)
	if err != nil || !ok || cur.Deleted {
		return err
	}
	cur.Deleted = true
	return l.Store.Put(ctx, cur)
}

// latestStore is a store that can read past its whole cache
// (registry.Remote).
type latestStore interface {
	GetLatest(ctx context.Context, atespace, uid string) (registry.Registration, bool, error)
}

// MarkConflict implements ConflictMarker: it sets (c non-nil) or clears the
// actor's policy_conflict mark on its registration, which is what the
// gateway shows in list, status, policy explain and doctor (GAP-0398). The
// record is read past the cache so the write keeps every newer field. No
// registration, or a tombstone, needs nothing.
func (l *LeaderRegistry) MarkConflict(ctx context.Context, atespace, uid string, c *registry.PolicyConflict) error {
	get := l.Store.Get
	if ls, ok := l.Store.(latestStore); ok {
		get = ls.GetLatest
	}
	cur, ok, err := get(ctx, atespace, uid)
	if err != nil || !ok || cur.Deleted || (cur.PolicyConflict == nil) == (c == nil) {
		return err
	}
	cur.PolicyConflict = c
	return l.Store.Put(ctx, cur)
}
