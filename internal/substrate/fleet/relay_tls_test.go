// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"slices"
	"strings"
	"testing"
)

func TestCheckRelayTLSReady(t *testing.T) {
	present := &RelayCA{Secret: "defenseclaw-relay-ca", Present: true}
	missing := &RelayCA{Secret: "defenseclaw-relay-ca"}
	for _, tc := range []struct {
		name, mode string
		ca         *RelayCA
		want, has  string
	}{
		{"off needs no CA and does not warn", "off", nil, Pass, "without an audit row"},
		{"off with a missing CA still passes", "off", missing, Pass, "off"},
		{"not read", "auto", nil, Skip, "not read"},
		{"unreadable", "auto", &RelayCA{Secret: "s", Note: "forbidden"}, Skip, "forbidden"},
		{"auto with the CA", "", present, Pass, "substrate.relay.plain"},
		{"auto without the CA", "auto", missing, Warn, "relay_ca_missing"},
		{"required with the CA", "required", present, Pass, "relay_tls_required"},
		{"required without the CA", "required", missing, Fail, "Run setup again"},
	} {
		got := CheckRelayTLSReady(Observed{RelayTLS: tc.mode, RelayCA: tc.ca})
		if got.ID != CheckRelayTLS || got.Status != tc.want || !strings.Contains(got.Message, tc.has) {
			t.Errorf("%s: %+v, want %s with %q", tc.name, got, tc.want, tc.has)
		}
	}
	if !slices.Contains(CheckIDs, CheckRelayTLS) {
		t.Fatalf("doctor does not print %s: %v", CheckRelayTLS, CheckIDs)
	}
}
