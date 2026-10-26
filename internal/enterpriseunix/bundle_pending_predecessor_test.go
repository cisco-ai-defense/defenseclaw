// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// A higher version may go ahead over a bundle that another run committed and
// the gateway has not confirmed (kept applied through an outage). When its
// transaction fails and puts that unconfirmed predecessor back, the receipt
// records no rollback (rolled_back means the last good bundle enforces
// again), the predecessor stays applied and installed and is reported as
// such, and the next plain ensure confirms it from the live gateway without
// a redelivery (GAP-1186).
func TestAFailedHigherDeliveryOverAPendingBundleIsNotARollback(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, restart := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			b.env.bundleFault = func(phase string) error {
				if phase == enterprisebundle.StateApplied {
					b.healthy = false
				}
				return nil
			}
			pathB := b.dir(3, v2)
			requireError(t, b.apply(pathB), codeBundleNotConfirmed)
			pendingConfig := b.read(b.env.Layout.ConfigPath)
			if got := b.receipt(bundleID(3)); got.State != enterprisebundle.StateApplied {
				t.Fatalf("setup: receipt = %+v", got)
			}
			b.env.bundleFault = func(phase string) error {
				if phase == "transaction" {
					return errors.New("injected fault in the transaction")
				}
				return nil
			}
			r := b.apply(b.dir(4, restart))
			if r.OK {
				t.Fatal("the apply with a fault succeeded")
			}
			got := b.receipt(bundleID(4))
			if got.State != enterprisebundle.StateFailed || got.RolledBack {
				t.Fatalf("the failed delivery claims a rollback while the unconfirmed predecessor is installed: %+v", got)
			}
			if kept := b.receipt(bundleID(3)); kept.State != enterprisebundle.StateApplied || kept.RolledBack {
				t.Fatalf("pending predecessor = %+v", kept)
			}
			if b.read(b.env.Layout.ConfigPath) != pendingConfig || b.state().Current.BundleID != bundleID(1) {
				t.Fatalf("the predecessor's config was replaced: state=%+v", b.state())
			}
			if !messagesContain(r.Warnings, bundleID(3)) {
				t.Fatalf("the restored predecessor was not reported: %+v", r.Warnings)
			}
			// The rollback records the restored bytes under a new
			// generation (the counter never goes back) and the pending
			// receipt follows it, so it still proves its commit (GAP-1186).
			b.env.bundleFault = nil
			b.healthy = true
			requireOK(t, b.run(Options{Action: ActionEnsure}))
			if got := b.receipt(bundleID(3)); got.State != enterprisebundle.StateConfirmed || b.state().Current.BundleID != bundleID(3) ||
				b.read(b.env.Layout.ConfigPath) != pendingConfig {
				t.Fatalf("the pending bundle was not confirmed by the next ensure: receipt=%+v state=%+v", got, b.state())
			}
		})
	}
}

// GAP-1803 (review RB1-4), the killed variant of GAP-1186: a higher
// delivery killed after its config write over a committed, unconfirmed
// bundle is rolled back by the next run's recovery to that bundle's bytes,
// and that same plain ensure confirms the bundle without a redelivery. This
// already holds without a rebind: the recovery puts the snapshot's
// generation record back with the bytes, so the pending receipt's
// generation still names them.
func TestAKilledHigherDeliveryOverAPendingBundleKeepsItProvable(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, restart := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			b.env.bundleFault = func(phase string) error {
				if phase == enterprisebundle.StateApplied {
					b.healthy = false
				}
				return nil
			}
			requireError(t, b.apply(b.dir(3, v2)), codeBundleNotConfirmed)
			pendingConfig := b.read(b.env.Layout.ConfigPath)
			if got := b.receipt(bundleID(3)); got.State != enterprisebundle.StateApplied {
				t.Fatalf("setup: receipt = %+v", got)
			}
			b.healthy = true
			b.env.bundleFault = func(phase string) error {
				if phase == "transaction" {
					panic("killed after the config write")
				}
				return nil
			}
			func() {
				defer func() { _ = recover() }()
				b.apply(b.dir(4, restart))
			}()
			b.env.bundleFault = nil
			r := b.run(Options{Action: ActionEnsure})
			requireOK(t, r)
			if b.read(b.env.Layout.ConfigPath) != pendingConfig {
				t.Fatal("the recovery did not put the pending bundle's config back")
			}
			if got := b.receipt(bundleID(3)); got.State != enterprisebundle.StateConfirmed || b.state().Current.BundleID != bundleID(3) {
				t.Fatalf("the pending bundle was not confirmed after the recovery: receipt=%+v state=%+v warnings=%+v", got, b.state(), r.Warnings)
			}
			if got := b.receipt(bundleID(4)); got.State != enterprisebundle.StateFailed || got.RolledBack {
				t.Fatalf("killed delivery = %+v, want failed without a rollback claim", got)
			}
		})
	}
}
