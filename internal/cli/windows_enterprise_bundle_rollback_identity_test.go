// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-0445 (fix/r104-windows): a rollback to the confirmed bundle is adopted
// only once the gateway names that bundle and version. An incomplete
// reference, or a config record that would name another bundle, refuses
// before anything is written; it never becomes a digest-only adoption.
func TestWindowsBundleRollbackIdentityNeedsTheConfirmedBundle(t *testing.T) {
	const id = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8"
	confirmed := &enterprisebundle.Ref{BundleID: id, Version: 5}
	for _, tc := range []struct {
		name    string
		ref     *enterprisebundle.Ref
		written configwrite.BundleRef
		ok      bool
	}{
		{name: "confirmed bundle", ref: confirmed, written: configwrite.BundleRef{ID: id, Version: 5}, ok: true},
		{name: "no reference", ref: nil, written: configwrite.BundleRef{ID: id, Version: 5}},
		{name: "invalid bundle id", ref: &enterprisebundle.Ref{BundleID: "not-a-bundle", Version: 5}, written: configwrite.BundleRef{ID: "not-a-bundle", Version: 5}},
		{name: "zero version", ref: &enterprisebundle.Ref{BundleID: id}, written: configwrite.BundleRef{ID: id}},
		{name: "record names another bundle", ref: confirmed, written: configwrite.BundleRef{ID: "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T9", Version: 5}},
		{name: "record names another version", ref: confirmed, written: configwrite.BundleRef{ID: id, Version: 4}},
		{name: "record names no bundle", ref: confirmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := windowsBundleRollbackIdentity(tc.ref, tc.written)
			if tc.ok {
				if err != nil || got.ID != id || got.Version != 5 {
					t.Fatalf("identity = %+v, %v", got, err)
				}
				return
			}
			if err == nil || got.ID != "" {
				t.Fatalf("an unproven rollback identity was accepted: %+v", got)
			}
		})
	}
	// The adoption check then needs the gateway to name exactly that bundle.
	report := policyDigestReport{GatewayReportedDigest: "sha256:aa", GatewayReportedConfigGeneration: 7,
		GatewayReportedBundleID: id, GatewayReportedBundleVersion: 4}
	report.Digest, report.ConfigGeneration, report.ConfigGenerationRecorded = "sha256:aa", 7, true
	if windowsHotConfigReportAdopted(report, configwrite.BundleRef{ID: id, Version: 5}) {
		t.Fatal("a gateway naming another version adopted the rollback")
	}
	report.GatewayReportedBundleVersion = 5
	if !windowsHotConfigReportAdopted(report, configwrite.BundleRef{ID: id, Version: 5}) {
		t.Fatal("the confirmed bundle was not adopted")
	}
}
