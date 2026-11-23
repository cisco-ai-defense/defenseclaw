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
	"encoding/json"
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
	// an eighth goes, from the people with the most entries first.
	DefaultMaxHostUses = 20000
	// DefaultMaxHostUsesPerActor bounds one actor's hosts; past it the
	// actor's own oldest entry goes, so one agent that calls many hosts
	// cannot push out another person's last use (RV7-2).
	DefaultMaxHostUsesPerActor = 256
	// maxHostUseActors bounds the actors of one read (the reader sends
	// more in batches); maxHostUseAnswer and maxHostUseAnswerBytes bound
	// its uses: the most a full map holds, and room under the leader's
	// 4 MiB body limit (RV8-6: 20000 long host names came to about 7 MB,
	// and the whole read failed).
	maxHostUseActors      = 256
	maxHostUseAnswer      = DefaultMaxHostUses
	maxHostUseAnswerBytes = 3 << 20
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

// HostUsesResponse is the newest uses first, at most maxHostUseAnswer
// (and maxHostUseAnswerBytes). Truncated says older uses were left out.
type HostUsesResponse struct {
	Uses      []HostUse `json:"uses,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
}

// noteUsesLocked records the newest allowed request of each registered
// actor to each host, from the callout's egress records (the leader has
// named the actor from its registration). Substrate's egress adds a bound
// secret to every allowed request to the secret's hosts, so this is what
// secrets list reads a binding's last use from: no write on the request
// path, and it covers your own bindings, which the callout does not know
// (S6b). The map is in memory: a new leader starts empty. owners[i] is
// the person the registration of recs[i] belongs to ("" when unknown).
func (s *Store) noteUsesLocked(recs []Record, owners []string, now time.Time) {
	for i, r := range recs {
		if r.Kind != KindEgress || r.Decision != "allow" || r.Unregistered || r.UID == "" || r.Atespace == "" || r.Host == "" {
			continue
		}
		at := r.At
		if at.IsZero() || at.After(now) {
			at = now
		}
		a := ActorRef{Atespace: r.Atespace, UID: r.UID}
		if i < len(owners) && owners[i] != "" {
			if s.useOwner == nil {
				s.useOwner = map[ActorRef]string{}
			}
			s.useOwner[a] = owners[i]
		}
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

// trimUsesLocked cuts the map to keep entries, fairly: the people with the
// most entries lose theirs first, and within one person the actors with
// the most; each loses its oldest. So one person's many agents cannot push
// out another person's last use (RV8-2: 80 agents of one person, 256 hosts
// each, erased everyone else's when the trim kept the newest overall). An
// actor with no person (a fork, an actor made outside DefenseClaw, or any
// actor when the leader has no registry) is grouped by its atespace: the
// registry attributes such an actor to its atespace, never to a person
// (D3), and the atespace is the one thing the leader proves about it (the
// registration must match the record's atespace). So many of them count
// as one group and cannot outnumber the people (RV9-1: 100 attributed
// actors, each a group of its own, pushed out another person's oldest
// use). A fork is not grouped under its parent's person: DefenseClaw makes
// no forks, the parent comes from the fork's source tag, and a fork is not
// that person's actor (GAP-0425), so grouping it there would let forks
// crowd out the parent person's own actors.
func (s *Store) trimUsesLocked(keep int) {
	type actorUses struct {
		a    ActorRef
		uses []HostUse
	}
	groups := map[string][]*actorUses{}
	for a, hosts := range s.uses {
		au := &actorUses{a: a}
		for h, at := range hosts {
			au.uses = append(au.uses, HostUse{Atespace: a.Atespace, UID: a.UID, Host: h, At: at})
		}
		sortUses(au.uses)
		key := s.useOwner[a]
		if key == "" {
			key = "\x00" + a.Atespace
		}
		groups[key] = append(groups[key], au)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sizes, newest := make([]int, len(keys)), make([]time.Time, len(keys))
	for i, k := range keys {
		as := groups[k]
		sort.Slice(as, func(x, y int) bool { return as[x].a.Atespace+"/"+as[x].a.UID < as[y].a.Atespace+"/"+as[y].a.UID })
		for _, au := range as {
			sizes[i] += len(au.uses)
			if au.uses[0].At.After(newest[i]) {
				newest[i] = au.uses[0].At
			}
		}
	}
	keepG := fairShares(sizes, newest, keep)
	for i, k := range keys {
		if keepG[i] >= sizes[i] {
			continue
		}
		as := groups[k]
		ss, nn := make([]int, len(as)), make([]time.Time, len(as))
		for j, au := range as {
			ss[j], nn[j] = len(au.uses), au.uses[0].At
		}
		keepA := fairShares(ss, nn, keepG[i])
		for j, au := range as {
			for _, u := range au.uses[keepA[j]:] {
				delete(s.uses[au.a], u.Host)
				s.useCount--
			}
			if len(s.uses[au.a]) == 0 {
				delete(s.uses, au.a)
				delete(s.useOwner, au.a)
			}
		}
	}
}

// fairShares splits keep entries between groups of the given sizes: each
// keeps up to the largest level L with sum(min(size, L)) <= keep, and the
// groups above L with the newest entries keep one more while room is left.
// A group at or under the level keeps all it has.
func fairShares(sizes []int, newest []time.Time, keep int) []int {
	out := make([]int, len(sizes))
	total, most := 0, 0
	for _, n := range sizes {
		total += n
		most = max(most, n)
	}
	if total <= keep {
		copy(out, sizes)
		return out
	}
	upTo := func(l int) int {
		t := 0
		for _, n := range sizes {
			t += min(n, l)
		}
		return t
	}
	lo, hi := 0, most // upTo(lo) <= keep < upTo(hi)
	for hi-lo > 1 {
		if m := (lo + hi) / 2; upTo(m) <= keep {
			lo = m
		} else {
			hi = m
		}
	}
	var above []int
	for i, n := range sizes {
		out[i] = min(n, lo)
		if n > lo {
			above = append(above, i)
		}
	}
	sort.SliceStable(above, func(x, y int) bool { return newest[above[x]].After(newest[above[y]]) })
	for _, i := range above[:min(max(keep-upTo(lo), 0), len(above))] {
		out[i]++
	}
	return out
}

// sortUses orders uses newest first (then by UID and host).
func sortUses(out []HostUse) {
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		if out[i].UID != out[j].UID {
			return out[i].UID < out[j].UID
		}
		return out[i].Host < out[j].Host
	})
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
	sortUses(out)
	return out
}

// HostUses implements MethodHostUses: the host uses of the named actors
// (the first 256), newest first, at most maxHostUseAnswer uses and
// maxHostUseAnswerBytes of JSON.
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
	out := s.allUsesLocked(func(a ActorRef) bool { return want[a] })
	s.mu.Unlock()
	n, size := 0, 0
	for ; n < len(out) && n < maxHostUseAnswer; n++ {
		b, err := json.Marshal(out[n])
		if err != nil {
			return HostUsesResponse{}, err
		}
		if size += len(b) + 1; size > maxHostUseAnswerBytes {
			break
		}
	}
	return HostUsesResponse{Uses: out[:n], Truncated: n < len(out)}, nil
}

// UseReader is a gateway replica's client of MethodHostUses.
type UseReader struct {
	Leader *leader.Client
}

// HostUses reads the host uses of actors from the leader, maxHostUseActors
// actors per call, so a person with more agents sees all of them (RV7-3),
// newest first across every call (RV8-3: each call's answer was newest
// first, the merge was not, and last used named an older agent and time).
// When an answer was cut short, uses at or before its oldest one are left
// out: another call's older use could stand in for a newer one the cut
// answer lost.
func (u *UseReader) HostUses(ctx context.Context, actors []ActorRef) ([]HostUse, error) {
	if u == nil || u.Leader == nil || len(actors) == 0 {
		return nil, nil
	}
	var all []HostUse
	var cut time.Time
	for len(actors) > 0 {
		batch := actors[:min(maxHostUseActors, len(actors))]
		actors = actors[len(batch):]
		var out HostUsesResponse
		if err := u.Leader.Call(ctx, MethodHostUses, leader.NewRequestID(), HostUsesRequest{Actors: batch}, &out); err != nil {
			return nil, err
		}
		if out.Truncated {
			if len(out.Uses) == 0 {
				return nil, nil
			}
			if at := out.Uses[len(out.Uses)-1].At; at.After(cut) {
				cut = at
			}
		}
		all = append(all, out.Uses...)
	}
	sortUses(all)
	if !cut.IsZero() {
		n := 0
		for n < len(all) && all[n].At.After(cut) {
			n++
		}
		all = all[:n]
	}
	return all, nil
}
