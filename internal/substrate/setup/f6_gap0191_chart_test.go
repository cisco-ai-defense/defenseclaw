// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"slices"
	"testing"
)

// GAP-0191: flags, a private OIDC CA and administrator groups are added to
// the gateway's serve flags, never in place of them.
func TestGAP0191GatewayFlagsAreAppended(t *testing.T) {
	helm := helmBinary(t)
	var gw map[string]any
	for _, o := range decodeMaps(t, renderChart(t, helm, "oidc-private")) {
		if o["kind"] == "Deployment" && dig(o, "metadata", "name") == "defenseclaw-gateway" {
			gw = o
		}
	}
	if gw == nil {
		t.Fatal("no gateway Deployment")
	}
	pod := dig(gw, "spec", "template", "spec")
	c := asList(dig(pod, "containers"))[0]
	args := asList(dig(c, "args"))
	for _, want := range []any{"serve", "--substrate", "--admin-groups=dc-admins", "--admin-groups=platform-admins",
		"--oidc-ca-file=/etc/defenseclaw/oidc-ca/ca.crt", "--chain-retention=48h"} {
		if !slices.Contains(args, want) {
			t.Errorf("args lack %v: %v", want, args)
		}
	}
	if args[0] != "serve" {
		t.Errorf("the serve flags are not first: %v", args)
	}
	mounted := false
	for _, m := range asList(dig(c, "volumeMounts")) {
		if dig(m, "name") == "oidc-ca" && dig(m, "mountPath") == "/etc/defenseclaw/oidc-ca" && dig(m, "readOnly") == true {
			mounted = true
		}
	}
	vol := false
	for _, v := range asList(dig(pod, "volumes")) {
		if dig(v, "name") == "oidc-ca" && dig(v, "configMap", "name") == "lab-oidc-ca" {
			vol = true
		}
	}
	if !mounted || !vol {
		t.Errorf("CA mount %v, volume %v", mounted, vol)
	}
	env := false
	for _, e := range asList(dig(c, "env")) {
		if dig(e, "name") == "GODEBUG" {
			env = true
		}
	}
	if !env {
		t.Error("extraEnv not rendered")
	}
}
