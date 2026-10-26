// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

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
		{name: "absent config, gateway down", gatewayDown: true},
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
