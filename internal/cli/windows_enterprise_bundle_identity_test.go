// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

const (
	hotIdentityBundle = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8"
	hotIdentityOther  = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T9"
)

// A hot-applied bundle config is adopted only once the gateway names the
// bundle: a repeated delivery of the confirmed bundle has no receipt, so it
// names the confirmed current bundle (review loop round 2). Every way of not
// knowing that bundle fails before the write.
func TestWindowsHotBundleIdentityNamesTheConfirmedBundleOfARepeat(t *testing.T) {
	confirmed := []byte("config_version: 9\nguardrail:\n  hook_self_heal_debounce_ms: 600\n")
	ref := &enterprisebundle.Ref{BundleID: hotIdentityBundle, Version: 4}
	repeat := &enterprisebundle.Prepared{AlreadyApplied: true, Config: confirmed}
	written := configwrite.BundleRef{ID: hotIdentityBundle, Version: 4, SignerKeyID: "k1"}
	for _, tc := range []struct {
		name    string
		p       *enterprisebundle.Prepared
		written configwrite.BundleRef
		current []byte
		ref     *enterprisebundle.Ref
		want    configwrite.BundleRef
		err     string
	}{
		{name: "no bundle", p: nil},
		{name: "prepared without a change", p: &enterprisebundle.Prepared{}},
		{name: "repeat of the confirmed bundle", p: repeat, written: written, current: confirmed, ref: ref,
			want: configwrite.BundleRef{ID: hotIdentityBundle, Version: 4}},
		{name: "repeat with no current bundle", p: repeat, written: written, current: nil, ref: nil, err: "no confirmed current bundle"},
		{name: "repeat with an invalid current reference", p: repeat, written: written, current: confirmed,
			ref: &enterprisebundle.Ref{BundleID: "not-a-bundle", Version: 4}, err: "no confirmed current bundle"},
		{name: "repeat with a zero current version", p: repeat, written: written, current: confirmed,
			ref: &enterprisebundle.Ref{BundleID: hotIdentityBundle}, err: "no confirmed current bundle"},
		{name: "repeat after the current bundle moved", p: repeat, written: written,
			current: []byte("config_version: 9\n"), ref: ref, err: "no longer renders"},
		{name: "repeat with no rendered config", p: &enterprisebundle.Prepared{AlreadyApplied: true}, written: written,
			current: nil, ref: ref, err: "no longer renders"},
		{name: "repeat recorded as another bundle", p: repeat, written: configwrite.BundleRef{ID: hotIdentityOther, Version: 4},
			current: confirmed, ref: ref, err: "would name bundle"},
		{name: "repeat recorded as another version", p: repeat, written: configwrite.BundleRef{ID: hotIdentityBundle, Version: 3},
			current: confirmed, ref: ref, err: "would name bundle"},
		{name: "repeat recorded as no bundle", p: repeat, current: confirmed, ref: ref, err: "would name bundle"},
		{name: "new delivery", p: &enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{BundleID: hotIdentityOther, Version: 5}},
			written: configwrite.BundleRef{ID: hotIdentityOther, Version: 5}, want: configwrite.BundleRef{ID: hotIdentityOther, Version: 5}},
		{name: "new delivery without an identity", p: &enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{}}, err: "no bundle ID and version"},
		{name: "new delivery recorded as another bundle", p: &enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{BundleID: hotIdentityOther, Version: 5}},
			written: written, err: "would name bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := windowsHotBundleIdentity(tc.p, tc.written, tc.current, tc.ref)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) || got != (configwrite.BundleRef{}) {
					t.Fatalf("identity = %+v, %v; want an error naming %q", got, err, tc.err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("identity = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

// The gateway's report proves a bundle config only with that bundle's ID and
// version; a matching digest and generation are not enough.
func TestWindowsHotConfigReportAdoptedRequiresTheBundleIdentity(t *testing.T) {
	enforcing := func(id string, version uint64) policyDigestReport {
		return policyDigestReport{
			EffectivePolicy:                 gateway.EffectivePolicy{Digest: "sha256:abc", ConfigGeneration: 7, ConfigGenerationRecorded: true},
			GatewayReportedDigest:           "sha256:abc",
			GatewayReportedConfigGeneration: 7,
			GatewayReportedBundleID:         id,
			GatewayReportedBundleVersion:    version,
		}
	}
	bundle := configwrite.BundleRef{ID: hotIdentityBundle, Version: 4}
	for _, tc := range []struct {
		name   string
		report policyDigestReport
		bundle configwrite.BundleRef
		want   bool
	}{
		{"bundle named", enforcing(hotIdentityBundle, 4), bundle, true},
		{"another bundle", enforcing(hotIdentityOther, 4), bundle, false},
		{"another version", enforcing(hotIdentityBundle, 3), bundle, false},
		{"no bundle reported", enforcing("", 0), bundle, false},
		{"no bundle expected", enforcing("", 0), configwrite.BundleRef{}, true},
		{"digest differs", func() policyDigestReport {
			r := enforcing(hotIdentityBundle, 4)
			r.GatewayReportedDigest = "sha256:def"
			return r
		}(), bundle, false},
		{"reload rejected", func() policyDigestReport {
			r := enforcing(hotIdentityBundle, 4)
			r.GatewayLastReloadError = "rule pack"
			return r
		}(), bundle, false},
		{"generation not recorded", func() policyDigestReport {
			r := enforcing(hotIdentityBundle, 4)
			r.ConfigGenerationRecorded = false
			return r
		}(), bundle, false},
		{"older generation", func() policyDigestReport {
			r := enforcing(hotIdentityBundle, 4)
			r.GatewayReportedConfigGeneration = 6
			return r
		}(), bundle, false},
	} {
		if got := windowsHotConfigReportAdopted(tc.report, tc.bundle); got != tc.want {
			t.Errorf("%s: adopted = %t, want %t", tc.name, got, tc.want)
		}
	}
}
