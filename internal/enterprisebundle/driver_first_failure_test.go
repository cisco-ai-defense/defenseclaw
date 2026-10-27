// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-0751: a delivery whose transaction failed while the gateway was held
// down installed nothing: the config the run started with (or none) stays,
// the receipt stays pending (never failed, never rolled back) and the run
// reports not_confirmed; the next run that does not retry it settles it as
// interrupted.
func TestDriverGatewayOutageLeavesTheDeliveryPending(t *testing.T) {
	for _, first := range []bool{true, false} {
		name := "first bundle"
		if !first {
			name = "over the last good bundle"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), nil)
			d := driverFor(t, f)
			installed, base := "", []byte("config_version: 9\n")
			if !first {
				d.EnforcedConfig = base
				if err := os.MkdirAll(filepath.Dir(d.ConfigPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(d.ConfigPath, base, 0o600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(base)
				installed = hex.EncodeToString(sum[:])
			}
			p, err := d.Prepare(t.Context(), f.bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			rolledBack := false
			_, err = d.Finish(p, installed, []string{"bundle_policy_not_adopted"}, enterprisebundle.GatewayPolicy{}, false,
				func() (string, bool) { rolledBack = true; return "", true })
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeNotConfirmed || rolledBack {
				t.Fatalf("finish = %v (rollback %v), want not_confirmed with nothing rolled back", err, rolledBack)
			}
			if enterprisebundle.Finished(p.Receipt.State) || p.Receipt.RolledBack {
				t.Fatalf("receipt = %+v, want pending", p.Receipt)
			}
			var cfg []byte
			if !first {
				cfg = base
			}
			report, _, err := d.SettleRun(cfg, nil)
			if err != nil || len(report.Interrupted) != 1 {
				t.Fatalf("next run: report=%+v err=%v, want the pending delivery interrupted", report, err)
			}
		})
	}
}

// GAP-1206: a first bundle whose transaction failed is rolled back to "no
// config" only when the config file is absent and the gateway answers and
// does not report the candidate. An unreadable installed config also hashes
// to "", and proves nothing; nor does a gateway that does not answer
// (GAP-1617).
func TestDriverFirstBundleFailureClaimsRollbackOnlyFromAnAbsentConfig(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	for _, tc := range []struct {
		name                  string
		unreadable, candidate bool
		gatewayDown           bool
		want                  bool
	}{
		{name: "absent config, gateway reports no policy", want: true},
		{name: "unreadable config", unreadable: true},
		{name: "absent config, gateway still reports the candidate", candidate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := driverFor(t, f)
			p, err := d.Prepare(t.Context(), f.bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			if p.Receipt.BaseConfigSHA256 != enterprisebundle.NoBaseConfig {
				t.Fatalf("base config = %q, want none", p.Receipt.BaseConfigSHA256)
			}
			if tc.unreadable {
				// A config path that exists but cannot be read as a file.
				if err := os.MkdirAll(d.ConfigPath, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			// A gateway that answers but runs no policy for the candidate.
			policy := enterprisebundle.GatewayPolicy{ReloadError: "no config"}
			if tc.gatewayDown {
				policy = enterprisebundle.GatewayPolicy{}
			}
			if tc.candidate {
				policy = enforcing(p.Receipt.ExpectedDigest)
				policy.BundleID, policy.BundleVersion = p.Receipt.BundleID, p.Receipt.Version
			}
			_, err = d.Finish(p, "", []string{"lifecycle_failed"}, policy, false, nil)
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeApplyFailed {
				t.Fatalf("finish = %v, want apply_failed", err)
			}
			if p.Receipt.State != enterprisebundle.StateFailed || p.Receipt.RolledBack != tc.want {
				t.Fatalf("receipt = %+v, want failed with rolled_back %v", p.Receipt, tc.want)
			}
		})
	}
}
