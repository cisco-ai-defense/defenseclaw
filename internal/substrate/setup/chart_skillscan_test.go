// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

// GAP-0477: the gateway pod's skill scanner sidecar has no Secret, no token
// and no port, shares only the scan folder with the gateway, and is not
// rendered unless gateway.skillScanner.enabled is true (off by default,
// GAP-1103: a default install pulls only published images).
func TestChartSkillScannerSidecar(t *testing.T) {
	helm := helmBinary(t)
	for _, tc := range []struct {
		values string
		extra  []string
		want   bool
	}{
		{"default", nil, false},
		{"managed", nil, false},
		{"default", []string{"--set", "gateway.skillScanner.enabled=true"}, true},
		{"managed", []string{"--set", "gateway.skillScanner.enabled=true"}, true},
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
		// GAP-0828: the container is the scanner's boundary in the
		// pod-contained mode the chart selects explicitly.
		podMode := false
		for _, a := range dig(side, "args").([]any) {
			podMode = podMode || a == "--pod-contained"
		}
		if !podMode {
			t.Fatalf("%s: the sidecar does not pass --pod-contained: %v", tc.values, dig(side, "args"))
		}
		if v := dig(pod, "shareProcessNamespace"); v != false {
			t.Fatalf("%s: shareProcessNamespace=%v, the scan worker must be PID 1 of its own PID namespace", tc.values, v)
		}
		if v := dig(pod, "automountServiceAccountToken"); v != false {
			t.Fatalf("%s: automountServiceAccountToken=%v", tc.values, v)
		}
		sc := dig(side, "securityContext")
		for _, want := range []struct {
			path []string
			v    any
		}{
			{[]string{"runAsNonRoot"}, true},
			{[]string{"runAsUser"}, 65532},
			{[]string{"runAsGroup"}, 65532},
			{[]string{"allowPrivilegeEscalation"}, false},
			{[]string{"readOnlyRootFilesystem"}, true},
			{[]string{"seccompProfile", "type"}, "RuntimeDefault"},
		} {
			if got := dig(sc, want.path...); got != want.v {
				t.Fatalf("%s: sidecar securityContext %v=%v (%T), want %v", tc.values, want.path, got, got, want.v)
			}
		}
		if drop, _ := dig(sc, "capabilities", "drop").([]any); len(drop) != 1 || drop[0] != "ALL" {
			t.Fatalf("%s: sidecar capabilities drop=%v, want [ALL]", tc.values, drop)
		}
		if dig(sc, "capabilities", "add") != nil || dig(sc, "privileged") != nil {
			t.Fatalf("%s: sidecar securityContext adds privilege: %v", tc.values, sc)
		}
	}
}
