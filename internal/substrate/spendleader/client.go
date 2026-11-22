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

// SpendPush sends this replica's absolute spend.
func (c *Client) SpendPush(ctx context.Context, epoch string, rows []routingadmin.SeedRow) error {
	in := SpendPushRequest{Epoch: epoch, Rows: make([]SpendRow, 0, len(rows))}
	for _, r := range rows {
		in.Rows = append(in.Rows, SpendRow{Day: r.Day, Key: r.Key, USD: r.USD})
	}
	return c.call(ctx, MethodSpendPush, in, nil)
}

// SpendTotals reads every other epoch's spend since the UTC day of since.
func (c *Client) SpendTotals(ctx context.Context, epoch string, since time.Time, keys []string) ([]routingadmin.SeedRow, error) {
	var out SpendTotalsAnswer
	if err := c.call(ctx, MethodSpendTotals, SpendTotalsRequest{Epoch: epoch, Since: since.UTC().Format(time.DateOnly), Keys: keys}, &out); err != nil {
		return nil, err
	}
	rows := make([]routingadmin.SeedRow, 0, len(out.Rows))
	for _, r := range out.Rows {
		rows = append(rows, routingadmin.SeedRow{Day: r.Day, Key: r.Key, USD: r.USD})
	}
	return rows, nil
}

// UsagePush sends this replica's absolute hourly usage buckets.
func (c *Client) UsagePush(ctx context.Context, epoch string, rows []modelusage.RemoteRow) error {
	return c.call(ctx, MethodUsagePush, UsagePushRequest{Epoch: epoch, Rows: rows}, nil)
}

// UsageQuery reads a rollup. q.Owner and q.AllOwners must come from the
// verified caller of the usage API.
func (c *Client) UsageQuery(ctx context.Context, q modelusage.Query) ([]modelusage.Row, error) {
	in := UsageQueryRequest{By: q.By, Owner: q.Owner, AllOwners: q.AllOwners, Limit: q.Limit}
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
