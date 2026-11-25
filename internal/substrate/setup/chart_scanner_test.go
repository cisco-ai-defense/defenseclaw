// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// The sidecar is off by default (GAP-1103); with enabled=true it runs as the
// pod's non-root identity and the chart refuses a root or unset one.
func TestChartScannerUsesPodIdentity(t *testing.T) {
	helm := helmBinary(t)
	objs := decodeObjects(t, renderChart(t, helm, "default", "--set", "gateway.skillScanner.enabled=true,podSecurityContext.runAsUser=12001,podSecurityContext.runAsGroup=12002"))
	found := false
	for _, o := range objs {
		if o.Kind != "Deployment" || o.Metadata["name"] != "defenseclaw-gateway" {
			continue
		}
		pod := dig(o.Spec, "template", "spec")
		for _, c := range dig(pod, "containers").([]any) {
			if dig(c, "name") != "skill-scanner" {
				continue
			}
			found = true
			sc := dig(c, "securityContext")
			if got := fmt.Sprint(dig(sc, "runAsUser")); got != "12001" {
				t.Errorf("sidecar uid = %s", got)
			}
			if got := fmt.Sprint(dig(sc, "runAsGroup")); got != "12002" {
				t.Errorf("sidecar gid = %s", got)
			}
		}
	}
	if !found {
		t.Fatal("no scanner sidecar")
	}
	for _, set := range []string{
		"podSecurityContext.runAsUser=0",
		"podSecurityContext.runAsGroup=0",
		"podSecurityContext.runAsUser=null",
		"podSecurityContext.runAsGroup=null",
	} {
		cmd := exec.Command(helm, "template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", "gateway.skillScanner.enabled=true", "--set", set)
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "podSecurityContext") {
			t.Errorf("%s: rendered instead of refusing an unusable scanner identity: %v %s", set, err, out)
		}
	}
}
