// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

// GAP-0477: the gateway pod's skill scanner sidecar has no Secret, no token
// and no port, shares only the scan folder with the gateway, and is not
// rendered when gateway.skillScanner.enabled is false.
func TestChartSkillScannerSidecar(t *testing.T) {
	helm := helmBinary(t)
	for _, tc := range []struct {
		values string
		extra  []string
		want   bool
	}{
		{"default", nil, true},
		{"managed", nil, true},
		{"default", []string{"--set", "gateway.skillScanner.enabled=false"}, false},
	} {
		objs := decodeObjects(t, renderChart(t, helm, tc.values, tc.extra...))
		var gw k8sObject
		for _, o := range objs {
			if o.Kind == "Deployment" && o.Metadata["name"] == "defenseclaw-gateway" {
				gw = o
			}
		}
		pod := dig(gw.Spec, "template", "spec")
		var side, main any
		for _, c := range dig(pod, "containers").([]any) {
			switch dig(c, "name") {
			case "skill-scanner":
				side = c
			case "gateway":
				main = c
			}
		}
		if (side != nil) != tc.want {
			t.Fatalf("%s %v: sidecar rendered=%v", tc.values, tc.extra, side != nil)
		}
		gwScan := false
		for _, m := range dig(main, "volumeMounts").([]any) {
			gwScan = gwScan || dig(m, "name") == "skill-scan"
		}
		if gwScan != tc.want {
			t.Fatalf("%s %v: gateway scan mount=%v", tc.values, tc.extra, gwScan)
		}
		if side == nil {
			continue
		}
		if dig(side, "ports") != nil || dig(side, "env") != nil || dig(side, "envFrom") != nil {
			t.Fatalf("%s: the sidecar has ports or env: %v", tc.values, side)
		}
		mounts := map[string]bool{}
		for _, m := range dig(side, "volumeMounts").([]any) {
			mounts[dig(m, "name").(string)] = true
		}
		if len(mounts) != 2 || !mounts["skill-scan"] || !mounts["skill-scan-tmp"] {
			t.Fatalf("%s: the sidecar mounts %v, want only skill-scan and skill-scan-tmp", tc.values, mounts)
		}
		if dig(side, "securityContext", "readOnlyRootFilesystem") != true {
			t.Fatalf("%s: the sidecar root file system is writable", tc.values)
		}
	}
}
