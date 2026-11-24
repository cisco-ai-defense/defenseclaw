// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/spendleader"
)

// TestLeaderSpendRejectsNonGatewayPeer: only the gateway peer calls the spend
// and usage methods; the callout and the controller are refused, so neither
// can post fake spend or read another person's usage.
func TestLeaderSpendRejectsNonGatewayPeer(t *testing.T) {
	p := substrateLeaderPermissions([]string{"spiffe://c/gw"}, []string{"spiffe://c/co"}, []string{"spiffe://c/ctl"})
	for _, m := range spendleader.Methods {
		if !p.Allows("spiffe://c/gw", m) {
			t.Errorf("gateway must call %s", m)
		}
		for _, peer := range []string{"spiffe://c/co", "spiffe://c/ctl", "spiffe://c/other", ""} {
			if p.Allows(peer, m) {
				t.Errorf("peer %q must not call %s", peer, m)
			}
		}
	}
}

// TestServeSpendUsageOffRegistersNothing: substrate.usage.enabled false opens
// no store and registers no method (M-PERF-1: off costs nothing).
func TestServeSpendUsageOffRegistersNothing(t *testing.T) {
	off := false
	cfg := &config.Config{}
	cfg.Substrate.Usage.Enabled = &off
	dir := t.TempDir()
	srv := &leader.Server{IsLeader: func() bool { return true }}
	closeFn, err := serveSpendUsage(srv, cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	closeFn()
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("off must create no file: %v", ents)
	}
}

func TestServeSpendUsageOnOpensStores(t *testing.T) {
	dir := t.TempDir()
	srv := &leader.Server{IsLeader: func() bool { return true }}
	closeFn, err := serveSpendUsage(srv, &config.Config{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	if ents, _ := os.ReadDir(dir); len(ents) == 0 {
		t.Fatal("on must create the usage store")
	}
}
