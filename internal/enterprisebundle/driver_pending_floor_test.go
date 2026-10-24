// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// Bundle versions only move up over a pending bundle as over the confirmed
// one (the shared driver, which Windows uses): while a newer bundle's config
// is committed and its receipt is applied, or staged with the commit, and
// the gateway cannot prove it, an older version, a repeat of the confirmed
// bundle and other content under the pending version are version_not_newer
// before anything is promoted. The pending receipt stays open, and a retry
// of the pending bundle itself goes ahead.
func TestDriverAnOlderDeliveryDoesNotReplaceAPendingBundle(t *testing.T) {
	for _, pendingState := range []string{enterprisebundle.StateApplied, enterprisebundle.StateStaged} {
		for _, older := range []string{"lower version", "repeat of the confirmed bundle", "other content at the pending version"} {
			t.Run(pendingState+"/"+older, func(t *testing.T) {
				f := newFixture(t, bundleConfig(t), nil)
				d := driverFor(t, f)
				compose := func(version uint64, summary string) *enterprisebundle.Bundle {
					in := f.in
					in.Version, in.ChangeSummary = version, summary
					_, raw, err := enterprisebundle.Compose(t.Context(), in)
					if err != nil {
						t.Fatal(err)
					}
					return f.signed(t, raw)
				}
				confirmed, err := d.Prepare(t.Context(), f.bundle, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := d.Finish(confirmed, confirmed.ConfigSHA256, nil, installPreparedBundle(t, d, confirmed), false, nil); err != nil {
					t.Fatal(err)
				}
				newer := compose(f.in.Version+2, "pending")
				d.EnforcedConfig = confirmed.Config
				pending, err := d.Prepare(t.Context(), newer, nil)
				if err != nil {
					t.Fatal(err)
				}
				installPreparedBundle(t, d, pending)
				if pendingState == enterprisebundle.StateApplied {
					if _, err := d.Finish(pending, pending.ConfigSHA256, nil, enterprisebundle.GatewayPolicy{}, false, nil); enterprisebundle.CodeOf(err) != enterprisebundle.CodeNotConfirmed {
						t.Fatalf("setup: outage did not leave the receipt applied: %v", err)
					}
				}
				report, rollback, err := d.SettleRun(pending.Config, nil)
				if err != nil || len(report.Pending) != 1 || len(rollback) != 0 {
					t.Fatalf("setup: report=%+v rollback=%+v error=%v", report, rollback, err)
				}
				var delivery *enterprisebundle.Bundle
				switch older {
				case "lower version":
					delivery = compose(f.in.Version+1, "older")
				case "repeat of the confirmed bundle":
					delivery = f.bundle
				default:
					delivery = compose(f.in.Version+2, "other content")
				}
				d.EnforcedConfig = pending.Config
				got, err := d.Prepare(t.Context(), delivery, nil)
				if enterprisebundle.CodeOf(err) != enterprisebundle.CodeVersionNotNewer || !strings.Contains(err.Error(), pending.Receipt.BundleID) {
					t.Fatalf("an older delivery went ahead over the pending bundle: prepared=%+v error=%v", got, err)
				}
				if got == nil || got.AlreadyApplied || got.Config != nil || got.Receipt == nil || got.Receipt.State != enterprisebundle.StateFailed {
					t.Fatalf("refused delivery = %+v", got)
				}
				unsettled, err := d.Store.Unsettled()
				if err != nil || len(unsettled) != 1 || unsettled[0].ReceiptID != pending.Receipt.ReceiptID || unsettled[0].State != pendingState {
					t.Fatalf("the pending receipt did not stay open: %+v, %v", unsettled, err)
				}
				state, err := d.Store.LoadState()
				if err != nil || state.Current == nil || state.Current.Version != f.in.Version {
					t.Fatalf("current moved: %+v, %v", state, err)
				}
				retry, err := d.Prepare(t.Context(), newer, nil)
				if err != nil || retry.AlreadyApplied || retry.Receipt == nil {
					t.Fatalf("a retry of the pending bundle was refused: %+v, %v", retry, err)
				}
			})
		}
	}
}
