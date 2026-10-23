// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// A repeated delivery of the current bundle over an installed config that
// drifted in a restart-required setting is refused restart_deferred with
// RefuseRestart, before the caller's transaction; with no drift it stays
// already_applied.
func TestDriverRepeatedBundleDefersARestartForDrift(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	p, err := d.Prepare(ctx, f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Finish(p, p.ConfigSHA256, nil, installPreparedBundle(t, d, p), false, nil); err != nil {
		t.Fatal(err)
	}
	d.RefuseRestart = func(enforced, rendered []byte) string {
		if bytes.Equal(enforced, rendered) {
			return ""
		}
		return enterprisebundle.RestartDeferralReason([]string{"gateway.port"}, false)
	}

	d.EnforcedConfig = append(append([]byte(nil), p.Config...), "gateway:\n  port: 1\n"...)
	again, err := d.Prepare(ctx, f.bundle, nil)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeRestartDeferred || again == nil || again.AlreadyApplied ||
		again.Receipt == nil || again.Receipt.State != enterprisebundle.StateFailed || again.Receipt.ErrorCode != enterprisebundle.CodeRestartDeferred {
		t.Fatalf("repeat over a drifted config = %+v, %v", again, err)
	}
	if st, err := d.Store.LoadState(); err != nil || st.Current == nil || st.Current.BundleID != p.Receipt.BundleID {
		t.Fatalf("state = %+v, %v", st, err)
	}

	d.EnforcedConfig = p.Config
	same, err := d.Prepare(ctx, f.bundle, nil)
	if err != nil || same == nil || !same.AlreadyApplied || same.Receipt != nil {
		t.Fatalf("repeat over the bundle config = %+v, %v", same, err)
	}
}
