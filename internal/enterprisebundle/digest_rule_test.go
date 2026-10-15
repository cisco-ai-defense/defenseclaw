// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"strings"
	"testing"
)

// TestCompareSignedDigestRule is the GAP-0113 decision table, run for every
// signer and device platform pair: a digest the device disproves refuses
// with digest_mismatch whatever platform signed it, and only another signer
// product version is unverifiable.
func TestCompareSignedDigestRule(t *testing.T) {
	const (
		version = "9.9.9"
		signed  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		local   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		sub1    = "sha256:111111111111"
		sub2    = "sha256:222222222222"
	)
	signerComponents := []DigestComponent{{Name: "builtin", Digest: sub1}, {Name: "config", Digest: sub1}, {Name: "rule_pack:custom", Digest: sub1}}
	for _, tc := range []struct {
		name         string
		signerOS     string // "" is the device platform: a same-host signer
		version      string
		local        string
		components   map[string]string
		noSigned     bool // the signer reported no components
		nonstandard  bool
		want         digestOutcome
		wantRefusal  bool
		wantDetail   []string
		forbidDetail []string
	}{
		{name: "same host, equal", local: signed, components: map[string]string{"builtin": sub1, "config": sub1, "rule_pack:custom": sub1}, want: digestVerified},
		{name: "cross host, consistent", signerOS: "other", local: signed, components: map[string]string{"builtin": sub1, "config": sub1, "rule_pack:custom": sub1}, want: digestVerified},
		{name: "same host, config differs", local: local, components: map[string]string{"builtin": sub1, "config": sub2, "rule_pack:custom": sub1},
			wantRefusal: true, wantDetail: []string{"component config differs"}, forbidDetail: []string{"sign with the build"}},
		{name: "cross host, wrong config", signerOS: "other", local: local, components: map[string]string{"builtin": sub1, "config": sub2, "rule_pack:custom": sub1},
			wantRefusal: true, wantDetail: []string{"component config differs", "the signer computed the digest on "}},
		{name: "cross host, config and pack differ", signerOS: "other", local: local, components: map[string]string{"builtin": sub1, "config": sub2, "rule_pack:custom": sub2},
			wantRefusal: true, wantDetail: []string{"component config, rule_pack:custom differs"}},
		{name: "cross host, component only on the device", signerOS: "other", local: local, components: map[string]string{"builtin": sub1, "config": sub1, "rule_pack:custom": sub1, "rego": sub1},
			wantRefusal: true, wantDetail: []string{"component rego differs"}},
		{name: "cross host, builtin only", signerOS: "other", local: local, components: map[string]string{"builtin": sub2, "config": sub1, "rule_pack:custom": sub1},
			wantRefusal: true, wantDetail: []string{"component builtin differs", "sign with the build the devices run"}},
		{name: "same host, builtin only", local: local, components: map[string]string{"builtin": sub2, "config": sub1, "rule_pack:custom": sub1},
			wantRefusal: true, wantDetail: []string{"component builtin differs"}},
		{name: "cross host, tampered overall digest", signerOS: "other", local: local, components: map[string]string{"builtin": sub1, "config": sub1, "rule_pack:custom": sub1},
			wantRefusal: true, wantDetail: []string{"this host computes " + local}, forbidDetail: []string{"component"}},
		{name: "cross host, no signed components", signerOS: "other", local: local, noSigned: true, components: map[string]string{"config": sub2},
			wantRefusal: true, forbidDetail: []string{"component"}},
		{name: "cross host, no device components", signerOS: "other", local: local,
			wantRefusal: true, forbidDetail: []string{"component"}},
		{name: "other product version, differs", signerOS: "other", version: "9.9.8", local: local, components: map[string]string{"builtin": sub2}, want: digestOtherProduct},
		{name: "other product version, equal", version: "9.9.8", local: signed, want: digestOtherProduct},
		{name: "other product version, non-standard layout", version: "9.9.8", local: local, nonstandard: true, want: digestOtherProduct},
		{name: "non-standard layout, differs", signerOS: "other", local: local, nonstandard: true, want: digestLayoutDependent},
		{name: "non-standard layout, equal", local: signed, nonstandard: true, want: digestVerified},
	} {
		for _, device := range Platforms {
			for _, signer := range Platforms {
				if (tc.signerOS == "") != (signer == device) {
					continue
				}
				t.Run(tc.name+"/"+signer+"-signs-"+device, func(t *testing.T) {
					ep := EffectivePolicy{ProductVersion: version, ComputedOn: signer, Digests: map[string]string{device: signed}}
					if tc.version != "" {
						ep.ProductVersion = tc.version
					}
					if !tc.noSigned {
						ep.Components = map[string][]DigestComponent{device: signerComponents}
					}
					got, err := compareSignedDigest(ep, device, version, tc.local, tc.components, !tc.nonstandard)
					if tc.wantRefusal {
						if CodeOf(err) != CodeDigestMismatch || got != 0 {
							t.Fatalf("want digest_mismatch, got outcome %d, %v", got, err)
						}
						detail := err.Error()
						for _, want := range append(tc.wantDetail, "effective_policy.digests."+device, "on "+signer+" with the same product version "+version) {
							if !strings.Contains(detail, want) {
								t.Fatalf("refusal %q lacks %q", detail, want)
							}
						}
						for _, forbid := range tc.forbidDetail {
							if strings.Contains(detail, forbid) {
								t.Fatalf("refusal %q has %q", detail, forbid)
							}
						}
						return
					}
					if err != nil || got != tc.want {
						t.Fatalf("outcome = %d, %v; want %d", got, err, tc.want)
					}
				})
			}
		}
	}
}

// A refusal names at most maxNamedComponents components.
func TestCompareSignedDigestBoundsNamedComponents(t *testing.T) {
	signed := make([]DigestComponent, 0, 12)
	local := map[string]string{}
	for i := range 12 {
		name := "rule_pack:" + string(rune('a'+i))
		signed = append(signed, DigestComponent{Name: name, Digest: "sha256:111111111111"})
		local[name] = "sha256:222222222222"
	}
	ep := EffectivePolicy{ProductVersion: "9.9.9", ComputedOn: PlatformLinux,
		Digests:    map[string]string{PlatformWindows: "sha256:" + strings.Repeat("a", 64)},
		Components: map[string][]DigestComponent{PlatformWindows: signed}}
	_, err := compareSignedDigest(ep, PlatformWindows, "9.9.9", "sha256:"+strings.Repeat("b", 64), local, true)
	if CodeOf(err) != CodeDigestMismatch || !strings.Contains(err.Error(), "rule_pack:h, ...") || strings.Contains(err.Error(), "rule_pack:i") {
		t.Fatalf("bounded refusal = %v", err)
	}
}
