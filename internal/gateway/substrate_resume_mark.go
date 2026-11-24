// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

// The first hook call of an actor after a resume (GAP-0486) is decided by
// the leader, across the replicas (telemetryrelay.Resumes). A replica
// claims only for an actor in its copy of the leader's suspended set, at
// most once per suspend; the claim runs while the hook call is served and
// the audit row and the metric wait for it at most resumeClaimWait. A claim
// that is late or fails marks nothing: a missed mark, never a wrong one.
const (
	resumeClaimWait    = 500 * time.Millisecond
	resumeClaimTimeout = 2 * time.Second
	// substrateRelayJoinWait bounds the replica's first resume sync, before
	// its listeners serve.
	substrateRelayJoinWait = 2 * time.Second
)

type substrateResumeClaim struct {
	done chan struct{}
	ok   bool // written before done closes

	once  sync.Once
	first bool
}

func startSubstrateResumeClaim(t *telemetryrelay.Taker, uid string, start time.Time) *substrateResumeClaim {
	c := &substrateResumeClaim{done: make(chan struct{})}
	go func() {
		defer close(c.done)
		ctx, cancel := context.WithTimeout(context.Background(), resumeClaimTimeout)
		defer cancel()
		c.ok = t.Resumes().Claim(ctx, t.Leader, uid, start)
	}()
	return c
}

// isFirst waits for the claim's answer, at most resumeClaimWait, once: every
// row of the call sees the same answer.
func (c *substrateResumeClaim) isFirst() bool {
	if c == nil {
		return false
	}
	c.once.Do(func() {
		t := time.NewTimer(resumeClaimWait)
		defer t.Stop()
		select {
		case <-c.done:
			c.first = c.ok
		case <-t.C:
		}
	})
	return c.first
}

type substrateFirstHookAfterResumeKey struct{}

func withFirstHookAfterResume(ctx context.Context, c *substrateResumeClaim) context.Context {
	return context.WithValue(ctx, substrateFirstHookAfterResumeKey{}, c)
}

func firstHookAfterResume(ctx context.Context) bool {
	c, _ := ctx.Value(substrateFirstHookAfterResumeKey{}).(*substrateResumeClaim)
	return c.isFirst()
}
