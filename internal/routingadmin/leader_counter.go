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

// SpendViewRPC is a SpendRPC that also answers the admin view's reads
// (spendleader.Client; GAP-0894): per-budget sums and a read of listed keys
// only.
type SpendViewRPC interface {
	SpendSums(ctx context.Context, epoch string, q []SumQuery) ([]PrefixSum, error)
	SpendKeys(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error)
}

// SpendOverRPC is a SpendRPC whose by-key read also names the keys at or
// over a budget's limit (spendleader.Client; GAP-0892).
type SpendOverRPC interface {
	SpendTotalsOver(ctx context.Context, epoch string, since time.Time, keys []string, over []OverQuery) ([]SeedRow, []string, error)
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

var (
	_ SpendCounter = (*LeaderCounter)(nil)
	_ OverReader   = (*LeaderCounter)(nil)
	_ SumReader    = (*LeaderCounter)(nil)
	_ KeyReader    = (*LeaderCounter)(nil)
)

var errNoViewRPC = errors.New("budget spend: the leader has no admin view reads")

// PrefixSums reads the per-budget sums of every epoch (an older
// leader: an error, and the view stays this replica's).
func (c *LeaderCounter) PrefixSums(ctx context.Context, epoch string, q []SumQuery) ([]PrefixSum, error) {
	v, ok := c.viewRPC()
	if !ok {
		return nil, errNoViewRPC
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return v.SpendSums(ctx, epoch, q)
}

// TotalsKeys reads every other epoch's spend of keys only.
func (c *LeaderCounter) TotalsKeys(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error) {
	v, ok := c.viewRPC()
	if !ok {
		return nil, errNoViewRPC
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return v.SpendKeys(ctx, epoch, since, keys)
}

func (c *LeaderCounter) viewRPC() (SpendViewRPC, bool) {
	if c == nil || c.rpc == nil {
		return nil, false
	}
	v, ok := c.rpc.(SpendViewRPC)
	return v, ok
}

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

// TotalsOver is Totals that also reads the keys at or over the limits of
// over and the budgets with more of them than OverQuery.Max. An rpc without
// it reads as Totals does.
func (c *LeaderCounter) TotalsOver(ctx context.Context, epoch string, since time.Time, keys []string, over []OverQuery) ([]SeedRow, []string, error) {
	if c == nil || c.rpc == nil {
		return nil, nil, errors.New("budget spend: no leader")
	}
	o, ok := c.rpc.(SpendOverRPC)
	if !ok {
		rows, err := c.Totals(ctx, epoch, since, keys)
		return rows, nil, err
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return o.SpendTotalsOver(ctx, epoch, since, keys, over)
}
