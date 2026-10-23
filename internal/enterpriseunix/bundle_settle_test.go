// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// On Linux a bundle the gateway did not confirm is settled by a deferred
// start of the apply service: the transaction stopped the path unit while it
// wrote config.yaml, so that write never starts it. macOS needs none (its
// apply LaunchDaemon watches config.yaml).
func TestBundleNotConfirmedSchedulesTheSettleOnLinux(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, _ := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			b.env.bundleFault = func(phase string) error {
				if phase == enterprisebundle.StateApplied {
					b.healthy = false
				}
				return nil
			}
			before := len(b.runner.calls)
			r := b.apply(b.dir(2, v2))
			b.env.bundleFault = nil
			requireError(t, r, codeBundleNotConfirmed)
			var scheduled []string
			for _, call := range b.runner.calls[before:] {
				if strings.HasPrefix(call, "systemd-run ") && strings.HasSuffix(call, " systemctl start --no-block "+unitApplyService) {
					scheduled = append(scheduled, call)
				}
			}
			if goos == "darwin" {
				if len(scheduled) != 0 || settleWarning(r) {
					t.Fatalf("darwin scheduled a settle: %v %+v", scheduled, r.Warnings)
				}
				return
			}
			if len(scheduled) != 1 || !settleWarning(r) {
				t.Fatalf("linux: want one deferred apply start and its warning, got %v %+v", scheduled, r.Warnings)
			}
		})
	}
}

func settleWarning(r *enterprisestatus.Result) bool {
	for _, w := range r.Warnings {
		if w.Code == codeInputChanged && strings.Contains(w.Message, "applied but the gateway has not confirmed it") {
			return true
		}
	}
	return false
}

// A carried applied receipt stays pending through an outage, then confirms
// from the upgraded gateway's digest of its verified stored bundle. The
// receipt keeps the digest recorded by the old build.
func TestBundleSettleAfterProductUpgradeKeepsAnEnforcedReceipt(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, sourceVersion := range []string{"1.0.2", "1.0.3"} {
			t.Run(goos+"/"+sourceVersion, func(t *testing.T) {
				b := newBundleHost(t, goos)
				b.env.ProductVersion = sourceVersion
				requireOK(t, b.run(Options{Action: ActionUpgrade, PayloadDir: b.payload(sourceVersion)}))
				v1, v2, _ := bundleConfigs(b.testHost)
				requireOK(t, b.apply(b.dir(1, v1)))
				b.env.bundleFault = func(phase string) error {
					if phase == enterprisebundle.StateApplied {
						b.healthy = false
					}
					return nil
				}
				requireError(t, b.apply(b.dir(2, v2)), codeBundleNotConfirmed)
				b.env.bundleFault = nil
				before := b.receipt(bundleID(2))
				installed := b.read(b.env.Layout.ConfigPath)
				if before.State != enterprisebundle.StateApplied || before.EffectivePolicyDigest == "" || b.state().Current.BundleID != bundleID(1) {
					t.Fatalf("outage did not leave B applied and A current: receipt=%+v state=%+v", before, b.state())
				}
				upgradeBundleHostDigest(b)
				requireError(t, b.run(Options{Action: ActionEnsure}), codeBundleNotConfirmed)
				if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateApplied ||
					b.read(b.env.Layout.ConfigPath) != installed || b.state().Current.BundleID != bundleID(1) {
					t.Fatalf("an outage after upgrade undid the applied bundle: receipt=%+v state=%+v", got, b.state())
				}
				b.healthy = true
				b.frozen = before.EffectivePolicyDigest
				requireError(t, b.run(Options{Action: ActionEnsure}), codeBundleNotConfirmed)
				if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateApplied ||
					b.read(b.env.Layout.ConfigPath) != installed {
					t.Fatalf("the older gateway still enforces the pending bundle: receipt=%+v", got)
				}
				b.frozen = ""
				requireOK(t, b.run(Options{Action: ActionEnsure}))
				if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateConfirmed ||
					got.EffectivePolicyDigest != before.EffectivePolicyDigest || b.state().Current.BundleID != bundleID(2) ||
					b.read(b.env.Layout.ConfigPath) != installed {
					t.Fatalf("the upgraded gateway did not confirm the historical receipt: receipt=%+v state=%+v", got, b.state())
				}
			})
		}
	}
}
