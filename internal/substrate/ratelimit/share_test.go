// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// shareCluster is n limiters that exchange through one leader Shares on a
// fake clock; every exchange finishes before the next step.
type shareCluster struct {
	mu       sync.Mutex
	now      time.Time
	shares   *Shares
	limiters []*Limiter
	down     bool
}

func newShareCluster(n int, cfg Config) *shareCluster {
	c := &shareCluster{now: time.Date(2026, 11, 17, 23, 0, 0, 0, time.UTC)}
	c.shares = &Shares{Now: c.clock}
	cfg.Now = c.clock
	for range n {
		l := New(cfg)
		l.ShareThrough(func(ctx context.Context, in ShareReport) (ShareAnswer, error) {
			if c.isDown() {
				return ShareAnswer{}, errors.New("leader down")
			}
			return c.shares.Share(ctx, in)
		})
		c.limiters = append(c.limiters, l)
	}
	return c
}

func (c *shareCluster) clock() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *shareCluster) isDown() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.down
}

// acquire is one request on limiter i; it waits for an exchange it started
// until the limiter has applied the answer. send returns before exchange
// takes l.mu again to clear sharing and apply it, so the wait is on
// sharing, not on send: a step that saw the old budget admitted too much
// on a loaded runner, and a stale sharing made the next step's guess wrong.
func (c *shareCluster) acquire(i int, atespace, uid string) bool {
	l := c.limiters[i]
	release, err := l.Acquire(atespace, uid)
	for {
		l.mu.Lock()
		busy := l.sharing
		l.mu.Unlock()
		if !busy {
			break
		}
		runtime.Gosched()
	}
	if err != nil {
		return false
	}
	release()
	return true
}

// run sends perReplicaRPS requests a second of uid to each limiter in
// spread, for secs seconds, and returns the admitted requests per second
// of the cluster over the last measure seconds.
func (c *shareCluster) run(spread []int, uid string, perReplicaRPS, secs, measure int) float64 {
	step := time.Second / time.Duration(perReplicaRPS)
	steps := secs * perReplicaRPS
	admitted := 0
	for k := range steps {
		for _, i := range spread {
			if c.acquire(i, "eng-web", uid) && k >= (secs-measure)*perReplicaRPS {
				admitted++
			}
		}
		c.mu.Lock()
		c.now = c.now.Add(step)
		c.mu.Unlock()
	}
	return float64(admitted) / float64(measure)
}

// substrate-1 GAP-0566: an actor spread over two replicas is held to the
// budget in total; one that reaches one replica keeps all of it.
func TestSubstrateGAP0566ShareHoldsTheActorToItsBudget(t *testing.T) {
	cfg := Config{PerActorRPS: 20, PerAtespaceRPS: 500, PerActorInFlight: 1000}
	c := newShareCluster(2, cfg)
	if got := c.run([]int{0, 1}, "flooder", 200, 8, 5); math.Abs(got-20) > 2 {
		t.Fatalf("spread over two replicas: %.1f/s admitted, want about 20", got)
	}
	c = newShareCluster(2, cfg)
	if got := c.run([]int{0}, "sticky", 200, 8, 5); math.Abs(got-20) > 2 {
		t.Fatalf("on one replica: %.1f/s admitted, want about 20", got)
	}
	// Without the exchange each replica holds it to the whole budget.
	solo := []*Limiter{New(Config{PerActorRPS: 20, PerAtespaceRPS: 500, PerActorInFlight: 1000, Now: c.clock}),
		New(Config{PerActorRPS: 20, PerAtespaceRPS: 500, PerActorInFlight: 1000, Now: c.clock})}
	c.limiters = solo
	if got := c.run([]int{0, 1}, "per-replica", 200, 8, 5); math.Abs(got-40) > 3 {
		t.Fatalf("per-replica limiters: %.1f/s admitted, want about 40 (2 x 20)", got)
	}
}

// A replica that can't reach the leader goes back to the whole budget
// after shareStale, and shares again when the leader answers.
func TestSubstrateGAP0566ShareWithoutTheLeaderIsPerReplica(t *testing.T) {
	c := newShareCluster(2, Config{PerActorRPS: 20, PerAtespaceRPS: 500, PerActorInFlight: 1000})
	if got := c.run([]int{0, 1}, "a", 200, 5, 3); math.Abs(got-20) > 2 {
		t.Fatalf("shared: %.1f/s", got)
	}
	c.mu.Lock()
	c.down = true
	c.mu.Unlock()
	if got := c.run([]int{0, 1}, "a", 200, 8, 3); math.Abs(got-40) > 3 {
		t.Fatalf("leader down: %.1f/s admitted, want about 40 (per replica)", got)
	}
	c.mu.Lock()
	c.down = false
	c.mu.Unlock()
	if got := c.run([]int{0, 1}, "a", 200, 5, 3); math.Abs(got-20) > 2 {
		t.Fatalf("leader back: %.1f/s", got)
	}
}

// The leader refuses reports it can't use and keeps at most
// maxShareReplicas replicas; a stale replica's counts drop out.
func TestSubstrateGAP0566SharesBounds(t *testing.T) {
	now := time.Date(2026, 11, 17, 23, 0, 0, 0, time.UTC)
	s := &Shares{Now: func() time.Time { return now }}
	ctx := context.Background()
	for _, bad := range []ShareReport{
		{},
		{Replica: strings.Repeat("r", maxReplicaID+1)},
		{Replica: "r", Actors: map[string]float64{"a": -1}},
		{Replica: "r", Atespaces: map[string]float64{"e": math.NaN()}},
		{Replica: "r", Actors: map[string]float64{"a": math.Inf(1)}},
	} {
		if _, err := s.Share(ctx, bad); !errors.Is(err, ErrBadShare) {
			t.Fatalf("%+v: err=%v, want ErrBadShare", bad, err)
		}
	}
	if ans, err := s.Share(ctx, ShareReport{Replica: "r1", Actors: map[string]float64{"a": 30}}); err != nil || ans.Actors["a"] != 30 {
		t.Fatalf("r1: %+v %v", ans, err)
	}
	ans, err := s.Share(ctx, ShareReport{Replica: "r2", Actors: map[string]float64{"a": 10, "b": 5}})
	if err != nil || ans.Actors["a"] != 40 || ans.Actors["b"] != 5 {
		t.Fatalf("r2: %+v %v", ans, err)
	}
	for i := 3; i <= maxShareReplicas; i++ {
		if _, err := s.Share(ctx, ShareReport{Replica: fmt.Sprintf("r%02d", i)}); err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
	if _, err := s.Share(ctx, ShareReport{Replica: "one-too-many"}); !errors.Is(err, ErrShareFull) {
		t.Fatalf("replica %d: err=%v, want ErrShareFull", maxShareReplicas+1, err)
	}
	now = now.Add(shareStale + time.Second)
	if ans, err := s.Share(ctx, ShareReport{Replica: "r2", Actors: map[string]float64{"a": 10}}); err != nil || ans.Actors["a"] != 10 {
		t.Fatalf("after r1 went stale: %+v %v", ans, err)
	}
}
