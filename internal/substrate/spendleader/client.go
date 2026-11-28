// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package spendleader

import (
	"context"
	"errors"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Client is a gateway replica's side. It satisfies routingadmin.SpendRPC.
// Every call runs on a timer, never on a model call.
type Client struct {
	Leader *leader.Client
}

var _ routingadmin.SpendRPC = (*Client)(nil)

func (c *Client) call(ctx context.Context, method string, in, out any) error {
	if c == nil || c.Leader == nil {
		return errors.New("spendleader: no leader client")
	}
	return c.Leader.Call(ctx, method, leader.NewRequestID(), in, out)
}

// SpendPush sends this replica's absolute spend, in chunks of at most
// maxSpendRows rows and about maxPageBytes (each row is stored on its own,
// so a chunk that fails is sent again whole with the next push).
func (c *Client) SpendPush(ctx context.Context, epoch string, rows []routingadmin.SeedRow) error {
	for first := true; first || len(rows) > 0; first = false {
		n, size := 0, 0
		for ; n < len(rows) && n < maxSpendRows; n++ {
			if size += rowBytes(rows[n]); n > 0 && size > maxPageBytes {
				break
			}
		}
		in := SpendPushRequest{Epoch: epoch, Rows: wireRows(rows[:n])}
		if err := c.call(ctx, MethodSpendPush, in, nil); err != nil {
			return err
		}
		rows = rows[n:]
	}
	return nil
}

// SpendTotals reads every other epoch's spend since the UTC day of since,
// page by page. With keys (non-nil), only those of the capped keys
// (actor:, batch:) are read, in requests of at most maxKeys keys, so
// launcher-minted keys never push a read past maxTotalsPages (which fails
// it: the budgets then read as not loaded, never as partial).
func (c *Client) SpendTotals(ctx context.Context, epoch string, since time.Time, keys []string) ([]routingadmin.SeedRow, error) {
	rows, _, err := c.SpendTotalsOver(ctx, epoch, since, keys, nil)
	return rows, err
}

var _ routingadmin.SpendRPC = (*Client)(nil)

// SpendKeys reads every other epoch's spend of keys only (the admin view's
// actor list, GAP-0894), in requests of at most maxKeys keys.
func (c *Client) SpendKeys(ctx context.Context, epoch string, since time.Time, keys []string) ([]routingadmin.SeedRow, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	rows, _, err := c.totals(ctx, epoch, since, keys, nil, true)
	return rows, err
}

var _ routingadmin.UnknownRPC = (*Client)(nil)

// SpendUnknown sends this replica's unknown-cost marks and reads every
// replica's (substrate-1:GAP-1118). A leader of a release without the method
// answers unknown_method, and the caller keeps its own marks.
func (c *Client) SpendUnknown(ctx context.Context, epoch string, marks []routingadmin.UnknownMark) ([]routingadmin.UnknownMark, error) {
	if len(marks) > maxUnknownMarks {
		marks = marks[:maxUnknownMarks]
	}
	in := SpendUnknownRequest{Epoch: epoch}
	for _, m := range marks {
		if markKey(m.Key) {
			in.Marks = append(in.Marks, SpendMark{Key: m.Key, At: m.At.Unix()})
		}
	}
	var out SpendUnknownAnswer
	if err := c.call(ctx, MethodSpendUnknown, in, &out); err != nil {
		return nil, err
	}
	got := make([]routingadmin.UnknownMark, 0, len(out.Marks))
	for _, m := range out.Marks {
		got = append(got, routingadmin.UnknownMark{Key: m.Key, At: time.Unix(m.At, 0)})
	}
	return got, nil
}

// SpendSums reads the per-budget sums of every epoch (GAP-0894).
func (c *Client) SpendSums(ctx context.Context, epoch string, q []routingadmin.SumQuery) ([]routingadmin.PrefixSum, error) {
	in := SpendSumsRequest{Epoch: epoch}
	for _, s := range q {
		in.Sums = append(in.Sums, SpendOver{Prefix: s.Prefix, Since: s.Since.UTC().Format(time.DateOnly), Limit: s.Limit})
	}
	var out SpendSumsAnswer
	if err := c.call(ctx, MethodSpendSums, in, &out); err != nil {
		return nil, err
	}
	sums := make([]routingadmin.PrefixSum, 0, len(out.Sums))
	for _, s := range out.Sums {
		sums = append(sums, routingadmin.PrefixSum{Prefix: s.Prefix, Total: s.Total, Peak: s.Peak, Subjects: s.Subjects, Exceeded: s.Exceeded})
	}
	return sums, nil
}

// SpendTotalsOver is SpendTotals whose by-key read also asks for the keys
// at or over each budget's limit in over (with the first key chunk), and
// returns the budget ids with more of them than OverQuery.Max (GAP-0892).
func (c *Client) SpendTotalsOver(ctx context.Context, epoch string, since time.Time, keys []string, over []routingadmin.OverQuery) ([]routingadmin.SeedRow, []string, error) {
	return c.totals(ctx, epoch, since, keys, over, false)
}

// totals is the paged read; keysOnly keeps only keys from the first chunk.
func (c *Client) totals(ctx context.Context, epoch string, since time.Time, keys []string, over []routingadmin.OverQuery, keysOnly bool) ([]routingadmin.SeedRow, []string, error) {
	base := SpendTotalsRequest{Epoch: epoch, Since: since.UTC().Format(time.DateOnly), ByKey: keys != nil}
	var wireOver []SpendOver
	if keys != nil {
		for _, o := range over {
			wireOver = append(wireOver, SpendOver{Prefix: o.Prefix, Since: o.Since.UTC().Format(time.DateOnly), Limit: o.Limit, Max: o.Max})
		}
	}
	var rows []routingadmin.SeedRow
	var full []string
	pages := 0
	for start := 0; ; start += maxKeys {
		in := base
		if keys != nil {
			in.Keys, in.KeysOnly = keys[start:min(start+maxKeys, len(keys))], keysOnly || start > 0
			if start == 0 && !keysOnly {
				in.Over = wireOver
			}
		}
		for {
			if pages == maxTotalsPages {
				return nil, nil, errors.New("spendleader: spend answer too large")
			}
			pages++
			var out SpendTotalsAnswer
			if err := c.call(ctx, MethodSpendTotals, in, &out); err != nil {
				return nil, nil, err
			}
			for _, r := range out.Rows {
				rows = append(rows, routingadmin.SeedRow{Day: r.Day, Key: r.Key, USD: r.USD})
			}
			if in.Over != nil && in.AfterDay == "" {
				full = out.OverFull
			}
			if !out.More || len(out.Rows) == 0 {
				break
			}
			last := out.Rows[len(out.Rows)-1]
			in.AfterDay, in.AfterKey = last.Day, last.Key
		}
		if keys == nil || start+maxKeys >= len(keys) {
			return rows, full, nil
		}
	}
}

// UsagePush sends this replica's absolute hourly usage buckets.
func (c *Client) UsagePush(ctx context.Context, epoch string, rows []modelusage.RemoteRow) error {
	return c.call(ctx, MethodUsagePush, UsagePushRequest{Epoch: epoch, Rows: rows}, nil)
}

// UsageQuery reads a rollup. q.Owner and q.AllOwners must come from the
// verified caller of the usage API.
func (c *Client) UsageQuery(ctx context.Context, q modelusage.Query) ([]modelusage.Row, error) {
	in := UsageQueryRequest{By: q.By, Owner: q.Owner, AllOwners: q.AllOwners, Batch: q.Batch, Limit: q.Limit}
	if !q.From.IsZero() {
		in.From = q.From.Unix()
	}
	if !q.To.IsZero() {
		in.To = q.To.Unix()
	}
	var out UsageQueryAnswer
	if err := c.call(ctx, MethodUsageQuery, in, &out); err != nil {
		return nil, err
	}
	return out.Rows, nil
}
