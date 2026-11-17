// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// GAP-0505 (lead ruling on the RBAC exception): only the controller reads
// the egress callout slot, so it publishes each read to the leader, and the
// gateways read it there. The controller may publish and not read the
// gateways' view; the callout may do neither; the gateways may read.
func TestSubstrateLeaderCalloutPermissionsGAP0505(t *testing.T) {
	const (
		gw   = "spiffe://cluster.local/ns/dc/sa/defenseclaw-gateway"
		co   = "spiffe://cluster.local/ns/dc/sa/defenseclaw-callout"
		ctlr = "spiffe://cluster.local/ns/dc/sa/defenseclaw-controller"
	)
	p := substrateLeaderPermissions([]string{gw}, []string{co}, []string{ctlr})
	for _, tc := range []struct {
		peer, method string
		want         bool
	}{
		{ctlr, leader.MethodCalloutPublish, true},
		{ctlr, leader.MethodCalloutStatus, false},
		{co, leader.MethodCalloutPublish, false},
		{co, leader.MethodCalloutStatus, false},
		{gw, leader.MethodCalloutStatus, true},
		{"spiffe://cluster.local/ns/other/sa/default", leader.MethodCalloutPublish, false},
	} {
		if got := p.Allows(tc.peer, tc.method); got != tc.want {
			t.Errorf("%s %s: %v, want %v", tc.peer, tc.method, got, tc.want)
		}
	}
}
