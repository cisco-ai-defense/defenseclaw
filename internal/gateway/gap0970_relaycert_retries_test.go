//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0970 (RV-S1H3 ping-pong probe): renewals that prove the previous
// serial inside the grace were unbounded and wrote INFO rows only, so two
// holders of the previous key could take the live serial from each other
// quietly. One retry is a lost reply and stays INFO; the second and later
// are HIGH, and are still issued.
func TestGAP0970RepeatedRetriesAreHigh(t *testing.T) {
	for _, tc := range []struct {
		name    string
		managed bool
		mode    string
	}{
		{"managed", true, ""},
		{"flag", false, config.SubstrateRelayCertReissueFlag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, store := tixRelayCA(t), gap0928Store(t)
			g := gap0861New(ca, store, tc.managed, tc.mode)
			_, _, r1, k1 := gap0928Cert(t, g)
			var rows []string
			for i := 0; i < 4; i++ {
				code, row, _, _ := gap0958Renew(t, g, r1, k1)
				if code != 200 {
					t.Fatalf("renewal %d proving the same certificate: %d %s", i, code, row)
				}
				rows = append(rows, row)
			}
			want := []string{"INFO substrate.relay.cert", "INFO substrate.relay.cert",
				"HIGH substrate.relay.cert_retry_repeated", "HIGH substrate.relay.cert_retry_repeated"}
			if !slices.Equal(rows, want) {
				t.Fatalf("rows %v, want %v", rows, want)
			}
		})
	}
}

// GAP-0970: the count is per grace. A renewal of the live one, and the
// relay presenting the live one at attach, each start it over.
func TestGAP0970RetryCountIsPerGrace(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	g := gap0861New(ca, store, true, "")
	_, _, r1, k1 := gap0928Cert(t, g)
	for i := 0; i < 3; i++ { // R1 -> R2, then two retries: the last is HIGH
		gap0958Renew(t, g, r1, k1)
	}
	code, _, r4, k4 := gap0958Renew(t, g, r1, k1)
	if code != 200 {
		t.Fatalf("retry: %d", code)
	}
	// The relay presents the live one: the grace is done and the count too.
	if err := g.attach(t, r4); err != nil {
		t.Fatalf("attach: %v", err)
	}
	code, row, r5, k5 := gap0958Renew(t, g, r4, k4)
	if code != 200 || row != "INFO substrate.relay.cert" {
		t.Fatalf("renewal of the live one: %d %s", code, row)
	}
	// A lost reply for that renewal is one retry again: INFO.
	if code, row, _, _ := gap0958Renew(t, g, r4, k4); code != 200 || row != "INFO substrate.relay.cert" {
		t.Fatalf("first retry of the next grace: %d %s", code, row)
	}
	_ = r5
	_ = k5
}
