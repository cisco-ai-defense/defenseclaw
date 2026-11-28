// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/spendleader"
)

// spendUsageRetentionDays is how long the leader keeps usage buckets: a
// month of budget window plus a margin.
const spendUsageRetentionDays = 31

// serveSpendUsage registers the cluster spend and usage methods on the
// leader and returns the function that closes their stores. With
// substrate.usage.enabled: false it registers nothing, opens no file and
// returns a no-op: a gateway's call gets unknown_method, and replicas run
// no push loop (admin-off switch).
func serveSpendUsage(srv *leader.Server, cfg *config.Config, storeDir string) (func(), error) {
	if cfg != nil && !cfg.Substrate.Usage.UsageEnabled() {
		return func() {}, nil
	}
	us := modelusage.NewStore(filepath.Join(storeDir, "usage", "usage.db"))
	if err := us.Configure(true, spendUsageRetentionDays); err != nil {
		return nil, fmt.Errorf("leader usage store: %w", err)
	}
	counter := routingadmin.NewLocalCounter(storeDir)
	spendleader.Serve(srv, &spendleader.Service{Counter: counter, Usage: us})
	fmt.Fprintf(os.Stderr, "[substrate] leader: cluster spend and usage on %s\n", storeDir)
	return func() {
		_ = counter.Close()
		_ = us.Configure(false, spendUsageRetentionDays)
	}, nil
}
