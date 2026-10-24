// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// apply --defer-restart applies a bundle the running gateway takes hot and
// refuses one that restarts it, before anything changes, with
// restart_deferred and the retry exit code; without the flag the same
// bundle applies.
func TestBundleApplyDeferRestart(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, restart := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			b.env.DeferRestart = true
			requireOK(t, b.apply(b.dir(2, v2)))
			installed := b.read(b.env.Layout.ConfigPath)
			from := len(b.services.calls)
			r := b.apply(b.dir(3, restart))
			requireError(t, r, string(enterprisebundle.CodeRestartDeferred))
			if r.ExitCode != enterprisestatus.BusyExitCode(goos) {
				t.Fatalf("exit %d, want the retry exit %d", r.ExitCode, enterprisestatus.BusyExitCode(goos))
			}
			if rc := b.receipt(bundleID(3)); rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeRestartDeferred || rc.Dir != "" {
				t.Fatalf("receipt = %+v", rc)
			}
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(2) {
				t.Fatalf("current = %+v", st.Current)
			}
			if b.read(b.env.Layout.ConfigPath) != installed || gatewayTouched(b.testHost, from) {
				t.Fatal("a deferred bundle changed the config or touched the gateway")
			}
			b.env.DeferRestart = false
			requireOK(t, b.apply(b.dir(4, restart)))
			if rc := b.receipt(bundleID(4)); rc.State != enterprisebundle.StateConfirmed || !rc.Restart {
				t.Fatalf("receipt without --defer-restart = %+v", rc)
			}
		})
	}
}
