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
// so this package does not import the leader transport. The by-key read
// also names the keys at or over a budget's limit (SpendTotalsOver,
// GAP-0892); SpendSums and SpendKeys answer the admin view (GAP-0894).
// Every leader answers all of them: no release has a spend leader without
// them (GAP-0940).
type SpendRPC interface {
	SpendPush(ctx context.Context, epoch string, rows []SeedRow) error
	SpendTotals(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error)
	SpendTotalsOver(ctx context.Context, epoch string, since time.Time, keys []string, over []OverQuery) ([]SeedRow, []string, error)
	SpendSums(ctx context.Context, epoch string, q []SumQuery) ([]PrefixSum, error)
	SpendKeys(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error)
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

var errNoLeader = errors.New("budget spend: no leader")

// UnknownRPC is the leader's side of the shared unknown-cost marks
// (spendleader.Client): it takes this replica's marks and answers every
// replica's live ones (substrate-1:GAP-1118).
type UnknownRPC interface {
	SpendUnknown(ctx context.Context, epoch string, marks []UnknownMark) ([]UnknownMark, error)
}

// UnknownSharer is a counter that shares the unknown-cost marks of the
// replicas (LeaderCounter).
type UnknownSharer interface {
	ShareUnknown(ctx context.Context, epoch string, marks []UnknownMark) ([]UnknownMark, error)
}

var _ UnknownSharer = (*LeaderCounter)(nil)

// ShareUnknown sends this replica's unknown-cost marks and returns every
// replica's. A leader transport without the method fails it, and the marks
// stay this replica's own.
func (c *LeaderCounter) ShareUnknown(ctx context.Context, epoch string, marks []UnknownMark) ([]UnknownMark, error) {
	if c == nil || c.rpc == nil {
		return nil, errNoLeader
	}
	u, ok := c.rpc.(UnknownRPC)
	if !ok {
		return nil, errNoLeader
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return u.SpendUnknown(ctx, epoch, marks)
}

// PrefixSums reads the per-budget sums of every epoch (a failed read keeps
// the view this replica's).
func (c *LeaderCounter) PrefixSums(ctx context.Context, epoch string, q []SumQuery) ([]PrefixSum, error) {
	if c == nil || c.rpc == nil {
		return nil, errNoLeader
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return c.rpc.SpendSums(ctx, epoch, q)
}

// TotalsKeys reads every other epoch's spend of keys only.
func (c *LeaderCounter) TotalsKeys(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error) {
	if c == nil || c.rpc == nil {
		return nil, errNoLeader
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return c.rpc.SpendKeys(ctx, epoch, since, keys)
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
		return errNoLeader
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return c.rpc.SpendPush(ctx, epoch, rows)
}

// Totals reads every other replica's spend (and the spend of this replica's
// earlier processes).
func (c *LeaderCounter) Totals(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error) {
	if c == nil || c.rpc == nil {
		return nil, errNoLeader
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return c.rpc.SpendTotals(ctx, epoch, since, keys)
}

// TotalsOver is Totals that also reads the keys at or over the limits of
// over and the budgets with more of them than OverQuery.Max.
func (c *LeaderCounter) TotalsOver(ctx context.Context, epoch string, since time.Time, keys []string, over []OverQuery) ([]SeedRow, []string, error) {
	if c == nil || c.rpc == nil {
		return nil, nil, errNoLeader
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	return c.rpc.SpendTotalsOver(ctx, epoch, since, keys, over)
}
