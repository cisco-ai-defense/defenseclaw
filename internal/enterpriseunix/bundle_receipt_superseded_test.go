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
)

// GAP-1166: pending bundle B is replaced by a higher bundle C that applies
// and is confirmed. When B settles, the deployment holds C's config: B is
// failed(superseded), never rolled_back, because nothing put back the last
// good bundle.
func TestPendingBundleReplacedByAHigherBundleIsSuperseded(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := pendingBundleHost(t, goos, "1.0.3")
			v1, _, _ := bundleConfigs(b.testHost)
			// B stays pending through the settle that starts C's run: the
			// gateway does not answer until C is received.
			b.healthy = false
			b.env.bundleFault = func(phase string) error {
				if phase == enterprisebundle.StateReceived {
					b.healthy = true
				}
				return nil
			}
			b.mapPromotedBundleOwners(3)
			requireOK(t, b.apply(b.dir(3, v1+"# bundle 3\n")))
			b.env.bundleFault = nil
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(3) {
				t.Fatalf("bundle 3 is not current: %+v", st)
			}
			if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateApplied {
				requireSuperseded(t, got)
				return
			}
			requireOK(t, b.run(Options{Action: ActionEnsure}))
			requireSuperseded(t, b.receipt(bundleID(2)))
		})
	}
}

// GAP-1574: a first bundle whose run was killed after it was applied, before
// the deployment committed, is rolled back by the next run's recovery to the
// config the host had before it. Nothing replaced it: it is interrupted,
// never superseded.
func TestKilledFirstBundleIsInterruptedNotSuperseded(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, _, _ := bundleConfigs(b.testHost)
			before := b.read(b.env.Layout.ConfigPath)
			b.env.bundleFault = func(phase string) error {
				if phase == enterprisebundle.StateApplied {
					panic("crash at applied")
				}
				return nil
			}
			func() {
				defer func() { _ = recover() }()
				b.apply(b.dir(1, v1))
			}()
			b.env.bundleFault = nil
			if got := b.receipt(bundleID(1)); got.State != enterprisebundle.StateApplied {
				t.Fatalf("setup: receipt = %+v", got)
			}
			r := b.run(Options{Action: ActionEnsure})
			got := b.receipt(bundleID(1))
			if got.State != enterprisebundle.StateFailed || got.ErrorCode != enterprisebundle.CodeInterrupted ||
				strings.Contains(got.ErrorMessage, "later config replaced") {
				t.Fatalf("killed first bundle = %+v, want failed interrupted", got)
			}
			if messagesContain(r.Warnings, "replaced by a later config") {
				t.Fatalf("the settle says a later config replaced the bundle: %+v", r.Warnings)
			}
			if b.read(b.env.Layout.ConfigPath) != before {
				t.Fatal("the recovery did not put the config from before the bundle back")
			}
		})
	}
}

func requireSuperseded(t *testing.T, got *enterprisebundle.Receipt) {
	t.Helper()
	if got.State != enterprisebundle.StateFailed || got.RolledBack || got.ErrorCode != enterprisebundle.CodeSuperseded {
		t.Fatalf("replaced pending receipt = %+v, want failed superseded, not rolled back", got)
	}
}
