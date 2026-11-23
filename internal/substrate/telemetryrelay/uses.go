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

package telemetryrelay

import (
	"context"
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// MethodHostUses is a gateway replica's read of when some actors last
// reached each host (secrets list: LAST USED). Only gateways may call it.
const MethodHostUses = "TelemetryHostUses"

// Bounds of the host-use map.
const (
	// DefaultMaxHostUses bounds the map in (actor, host) entries; past it
	// the oldest eighth goes.
	DefaultMaxHostUses = 20000
	// DefaultMaxHostUsesPerActor bounds one actor's hosts; past it the
	// actor's own oldest entry goes, so one agent that calls many hosts
	// cannot push out another person's last use (RV7-2).
	DefaultMaxHostUsesPerActor = 256
	// maxHostUseActors bounds the actors of one read (the reader sends
	// more in batches); maxHostUseAnswer bounds its uses: the most a full
	// map holds.
	maxHostUseActors = 256
	maxHostUseAnswer = DefaultMaxHostUses
)

// ActorRef names one registered actor.
type ActorRef struct {
	Atespace string `json:"atespace"`
	UID      string `json:"uid"`
}

// HostUsesRequest asks for the host uses of at most 256 actors.
type HostUsesRequest struct {
	Actors []ActorRef `json:"actors"`
}

// HostUse is the newest allowed request of one actor to one host.
type HostUse struct {
	Atespace string    `json:"atespace"`
	UID      string    `json:"uid"`
	Host     string    `json:"host"`
	At       time.Time `json:"at"`
}

// HostUsesResponse is the newest uses first, at most maxHostUseAnswer.
type HostUsesResponse struct {
	Uses []HostUse `json:"uses,omitempty"`
}

// noteUsesLocked records the newest allowed request of each registered
// actor to each host, from the callout's egress records (the leader has
// named the actor from its registration). Substrate's egress adds a bound
// secret to every allowed request to the secret's hosts, so this is what
// secrets list reads a binding's last use from: no write on the request
// path, and it covers your own bindings, which the callout does not know
// (S6b). The map is in memory: a new leader starts empty.
func (s *Store) noteUsesLocked(recs []Record, now time.Time) {
	for _, r := range recs {
		if r.Kind != KindEgress || r.Decision != "allow" || r.Unregistered || r.UID == "" || r.Atespace == "" || r.Host == "" {
			continue
		}
		at := r.At
		if at.IsZero() || at.After(now) {
			at = now
		}
		a := ActorRef{Atespace: r.Atespace, UID: r.UID}
		hosts := s.uses[a]
		if hosts == nil {
			if s.uses == nil {
				s.uses = map[ActorRef]map[string]time.Time{}
			}
			hosts = map[string]time.Time{}
			s.uses[a] = hosts
		}
		if old, ok := hosts[r.Host]; !ok {
			if len(hosts) >= DefaultMaxHostUsesPerActor {
				oh, ot := oldestUse(hosts)
				if !at.After(ot) {
					continue
				}
				delete(hosts, oh)
				s.useCount--
			}
			s.useCount++
		} else if !at.After(old) {
			continue
		}
		hosts[r.Host] = at
	}
	maxN := s.MaxHostUses
	if maxN <= 0 {
		maxN = DefaultMaxHostUses
	}
	if s.useCount > maxN {
		s.trimUsesLocked(maxN - maxN/8)
	}
}

// oldestUse is the host of an actor's oldest entry, and its time.
func oldestUse(hosts map[string]time.Time) (host string, at time.Time) {
	for h, t := range hosts {
		if host == "" || t.Before(at) || (t.Equal(at) && h < host) {
			host, at = h, t
		}
	}
	return host, at
}

// trimUsesLocked keeps the keep newest entries.
func (s *Store) trimUsesLocked(keep int) {
	all := s.allUsesLocked(func(ActorRef) bool { return true })
	for _, u := range all[min(keep, len(all)):] {
		a := ActorRef{Atespace: u.Atespace, UID: u.UID}
		delete(s.uses[a], u.Host)
		if len(s.uses[a]) == 0 {
			delete(s.uses, a)
		}
		s.useCount--
	}
}

// allUsesLocked lists the entries of the actors want keeps, newest first.
func (s *Store) allUsesLocked(want func(ActorRef) bool) []HostUse {
	var out []HostUse
	for a, hosts := range s.uses {
		if !want(a) {
			continue
		}
		for h, at := range hosts {
			out = append(out, HostUse{Atespace: a.Atespace, UID: a.UID, Host: h, At: at})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		if out[i].UID != out[j].UID {
			return out[i].UID < out[j].UID
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// HostUses implements MethodHostUses: the host uses of the named actors
// (the first 256), newest first, at most maxHostUseAnswer.
func (s *Store) HostUses(_ context.Context, in HostUsesRequest) (HostUsesResponse, error) {
	actors := in.Actors
	if len(actors) > maxHostUseActors {
		actors = actors[:maxHostUseActors]
	}
	want := make(map[ActorRef]bool, len(actors))
	for _, a := range actors {
		want[a] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.allUsesLocked(func(a ActorRef) bool { return want[a] })
	if len(out) > maxHostUseAnswer {
		out = out[:maxHostUseAnswer]
	}
	return HostUsesResponse{Uses: out}, nil
}

// UseReader is a gateway replica's client of MethodHostUses.
type UseReader struct {
	Leader *leader.Client
}

// HostUses reads the host uses of actors from the leader, maxHostUseActors
// actors per call, so a person with more agents sees all of them (RV7-3).
func (u *UseReader) HostUses(ctx context.Context, actors []ActorRef) ([]HostUse, error) {
	if u == nil || u.Leader == nil || len(actors) == 0 {
		return nil, nil
	}
	var all []HostUse
	for len(actors) > 0 {
		batch := actors[:min(maxHostUseActors, len(actors))]
		actors = actors[len(batch):]
		var out HostUsesResponse
		if err := u.Leader.Call(ctx, MethodHostUses, leader.NewRequestID(), HostUsesRequest{Actors: batch}, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Uses...)
	}
	return all, nil
}
