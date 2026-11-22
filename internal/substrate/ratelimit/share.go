// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// The budgets are an actor's and an atespace's across the gateway replicas,
// not one replica's (substrate-1 GAP-0566: with two replicas a flooding
// actor got 2 x per_actor_rps). Once a second, while it has traffic, a
// replica tells the leader how many requests each actor and atespace sent
// it, and the leader answers with the count of every replica. The replica's
// buckets then hold the actor and the atespace to their share of the
// budget, in proportion to the requests the replica gets: an actor that
// reaches only this replica keeps the whole budget, one spread evenly over
// two replicas gets half on each. Before the first answer (the first second
// of a flood) and while a replica has not heard from the leader for
// shareStale, each replica applies the whole budget, as before.
//
// The concurrent-request cap (DefaultPerActorInFlight) stays per replica:
// it bounds work in one process.

// MethodShare is the leader method of the exchange.
const MethodShare = "RateShare"

const (
	// ShareInterval is how often a replica with traffic reports.
	ShareInterval = time.Second
	// shareStale is how long a share holds without a new answer.
	shareStale = 3 * ShareInterval
	// maxShareReplicas bounds the replicas the leader keeps reports of.
	maxShareReplicas = 64
	// maxReplicaID bounds a replica id.
	maxReplicaID = 64
)

// ShareReport is one replica's requests per second over its last interval,
// by actor UID and by atespace.
type ShareReport struct {
	Replica   string             `json:"replica"`
	Actors    map[string]float64 `json:"actors,omitempty"`
	Atespaces map[string]float64 `json:"atespaces,omitempty"`
}

// ShareAnswer is every replica's requests per second for the keys of a
// report, that report's included.
type ShareAnswer struct {
	Actors    map[string]float64 `json:"actors,omitempty"`
	Atespaces map[string]float64 `json:"atespaces,omitempty"`
}

// ShareFunc sends a report to the leader.
type ShareFunc func(ctx context.Context, in ShareReport) (ShareAnswer, error)

// ShareThrough makes the limiter exchange its counts through send. A nil
// send keeps the budgets per replica.
func (l *Limiter) ShareThrough(send ShareFunc) {
	var id [8]byte
	_, _ = rand.Read(id[:])
	l.mu.Lock()
	defer l.mu.Unlock()
	l.send, l.replica = send, hex.EncodeToString(id[:])
	l.lastReport = l.cfg.Now()
}

// shareLocked starts an exchange when one is due, and drops shares that
// have not been confirmed for shareStale.
func (l *Limiter) shareLocked(now time.Time) {
	if !l.shareAt.IsZero() && now.Sub(l.shareAt) > shareStale {
		l.shareAt = time.Time{}
		l.applyLocked(now, ShareReport{}, ShareAnswer{})
	}
	if l.send == nil || l.sharing || now.Sub(l.lastReport) < ShareInterval {
		return
	}
	// Counts over a long quiet spell are per second of that spell; clamp,
	// so one late report can't make this replica's share look tiny.
	secs := min(max(now.Sub(l.lastReport).Seconds(), ShareInterval.Seconds()/2), 2*ShareInterval.Seconds())
	l.lastReport = now
	rep := ShareReport{Replica: l.replica, Actors: map[string]float64{}, Atespaces: map[string]float64{}}
	for uid, a := range l.actors {
		if a.attempts > 0 {
			rep.Actors[uid] = float64(a.attempts) / secs
			a.attempts = 0
		}
	}
	for name, s := range l.atespaces {
		if s.attempts > 0 {
			rep.Atespaces[name] = float64(s.attempts) / secs
			s.attempts = 0
		}
	}
	l.sharing = true
	go l.exchange(rep)
}

func (l *Limiter) exchange(rep ShareReport) {
	ctx, cancel := context.WithTimeout(context.Background(), ShareInterval)
	defer cancel()
	ans, err := l.send(ctx, rep)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sharing = false
	if err == nil {
		now := l.cfg.Now()
		l.shareAt = now
		l.applyLocked(now, rep, ans)
	}
}

// applyLocked sets every bucket to its share of the budget; a key the
// report does not name gets the whole budget.
func (l *Limiter) applyLocked(now time.Time, rep ShareReport, ans ShareAnswer) {
	floor := min(1, l.cfg.PerActorRPS)
	for uid, a := range l.actors {
		r := max(l.cfg.PerActorRPS*shareOf(rep.Actors[uid], ans.Actors[uid]), floor)
		if a.lim.Limit() != rate.Limit(r) {
			a.lim.SetLimitAt(now, rate.Limit(r))
			a.lim.SetBurstAt(now, max(1, int(math.Ceil(2*r))))
		}
	}
	for name, s := range l.atespaces {
		r := max(l.cfg.PerAtespaceRPS*shareOf(rep.Atespaces[name], ans.Atespaces[name]), floor)
		if s.lim.Limit() != rate.Limit(r) {
			s.lim.SetLimitAt(now, rate.Limit(r))
			s.lim.SetBurstAt(now, max(1, int(math.Ceil(r))))
		}
	}
}

// shareOf is this replica's part of the cluster's requests (1 when it has
// all of them, or none were counted).
func shareOf(local, total float64) float64 {
	if local <= 0 || total <= local || math.IsNaN(total) || math.IsInf(total, 0) {
		return 1
	}
	return local / total
}

// Shares is the leader's side of the exchange: the newest report of each
// replica, for shareStale.
type Shares struct {
	Now func() time.Time

	mu       sync.Mutex
	replicas map[string]shareEntry
}

type shareEntry struct {
	at  time.Time
	rep ShareReport
}

// ErrBadShare is a report the leader refuses.
var ErrBadShare = errors.New("ratelimit: invalid share report")

// ErrShareFull is a report from one replica too many.
var ErrShareFull = errors.New("ratelimit: too many gateway replicas report")

// Share keeps rep and answers the cluster's counts for its keys.
func (s *Shares) Share(_ context.Context, rep ShareReport) (ShareAnswer, error) {
	if rep.Replica == "" || len(rep.Replica) > maxReplicaID || len(rep.Actors) > maxTracked || len(rep.Atespaces) > maxTracked {
		return ShareAnswer{}, ErrBadShare
	}
	for _, m := range []map[string]float64{rep.Actors, rep.Atespaces} {
		for _, v := range m {
			if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
				return ShareAnswer{}, ErrBadShare
			}
		}
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.replicas {
		if now.Sub(e.at) > shareStale {
			delete(s.replicas, id)
		}
	}
	if s.replicas == nil {
		s.replicas = map[string]shareEntry{}
	}
	if _, ok := s.replicas[rep.Replica]; !ok && len(s.replicas) >= maxShareReplicas {
		return ShareAnswer{}, ErrShareFull
	}
	s.replicas[rep.Replica] = shareEntry{at: now, rep: rep}
	ans := ShareAnswer{Actors: make(map[string]float64, len(rep.Actors)), Atespaces: make(map[string]float64, len(rep.Atespaces))}
	for _, e := range s.replicas {
		for k := range rep.Actors {
			ans.Actors[k] += e.rep.Actors[k]
		}
		for k := range rep.Atespaces {
			ans.Atespaces[k] += e.rep.Atespaces[k]
		}
	}
	return ans, nil
}
