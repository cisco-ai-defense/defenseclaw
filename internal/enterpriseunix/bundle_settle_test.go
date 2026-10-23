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
