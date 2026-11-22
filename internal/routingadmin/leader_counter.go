// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"errors"
	"time"
)

// SpendRPC is the leader's side of the spend counter as a gateway replica
// calls it (internal/substrate/spendleader.Client). It is an interface here
// so this package does not import the leader transport.
type SpendRPC interface {
	SpendPush(ctx context.Context, epoch string, rows []SeedRow) error
	SpendTotals(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error)
}

// LeaderCounterTimeout bounds one leader call, so a lost leader never holds
// the sync loop (the transport retries a leader change for 45 s on its own).
const LeaderCounterTimeout = 4 * time.Second

// LeaderCounter is the SpendCounter of a cluster gateway replica: the spend
// of every replica lives in the one file of the leader, which survives a pod
// restart (the pod-local file did not). Push and Totals run only on the sync
// loop, never on a model call; the call path reads the in-memory Ledger.
type LeaderCounter struct {
	rpc     SpendRPC
	timeout time.Duration
}

var _ SpendCounter = (*LeaderCounter)(nil)

// NewLeaderCounter returns the counter over rpc.
func NewLeaderCounter(rpc SpendRPC) *LeaderCounter {
	return &LeaderCounter{rpc: rpc, timeout: LeaderCounterTimeout}
}

func (c *LeaderCounter) ctx(parent context.Context) (context.Context, context.CancelFunc) {
	d := LeaderCounterTimeout
	if c != nil && c.timeout > 0 {
		d = c.timeout
	}
	return context.WithTimeout(parent, d)
}

// Push sends this replica's absolute totals.
func (c *LeaderCounter) Push(ctx context.Context, epoch string, rows []SeedRow) error {
	if c == nil || c.rpc == nil {
		return errors.New("budget spend: no leader")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return c.rpc.SpendPush(ctx, epoch, rows)
}

// Totals reads every other replica's spend (and the spend of this replica's
// earlier processes).
func (c *LeaderCounter) Totals(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error) {
	if c == nil || c.rpc == nil {
		return nil, errors.New("budget spend: no leader")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return c.rpc.SpendTotals(ctx, epoch, since, keys)
}
