// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// With RefuseRestart (apply --defer-restart) a bundle that restarts the
// gateway is refused restart_deferred before it is promoted; one that does
// not is prepared as before.
func TestDriverDeferRestartRefusesBeforePromotion(t *testing.T) {
	for _, restarts := range []bool{true, false} {
		f := newFixture(t, bundleConfig(t), nil)
		d := driverFor(t, f)
		var seen []byte
		d.RefuseRestart = func(_, rendered []byte) string {
			seen = rendered
			if restarts {
				return enterprisebundle.RestartDeferralReason([]string{"gateway.port"}, false)
			}
			return ""
		}
		p, err := d.Prepare(context.Background(), f.bundle, nil)
		if len(seen) == 0 {
			t.Fatal("RefuseRestart did not see the rendered config")
		}
		if !restarts {
			if err != nil || p == nil || p.Receipt == nil || p.Receipt.State != enterprisebundle.StateStaged {
				t.Fatalf("no-restart prepare = %+v, %v", p, err)
			}
			continue
		}
		if enterprisebundle.CodeOf(err) != enterprisebundle.CodeRestartDeferred || p == nil || p.Receipt == nil ||
			p.Receipt.State != enterprisebundle.StateFailed || p.Receipt.ErrorCode != enterprisebundle.CodeRestartDeferred ||
			!strings.Contains(err.Error(), "gateway.port") {
			t.Fatalf("restart prepare = %+v, %v", p, err)
		}
		version := d.Store.VersionDir(enterprisebundle.VersionDirNameForReceipt(p.Receipt.Version, p.Receipt.BundleID, p.Receipt.ReceiptID))
		if _, statErr := os.Stat(version); !os.IsNotExist(statErr) {
			t.Fatalf("a deferred bundle was promoted: %v", statErr)
		}
	}
}

func TestRestartDeferralReason(t *testing.T) {
	if got := enterprisebundle.RestartDeferralReason(nil, false); got != "" {
		t.Fatalf("no restart: %q", got)
	}
	if got := enterprisebundle.RestartDeferralReason(nil, true); !strings.Contains(got, "cannot tell") {
		t.Fatalf("unknown: %q", got)
	}
	if got := enterprisebundle.RestartDeferralReason([]string{"a.b", "c"}, false); !strings.Contains(got, "(a.b, c)") {
		t.Fatalf("restart: %q", got)
	}
}
