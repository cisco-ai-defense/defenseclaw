// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"testing"
)

// TestChartKubeSignInFalseKeepsTheBinding: --no-kube-sign-in=false is the
// sign-in on (a Go bool flag), so the auth-delegator binding stays (R3a P3).
func TestChartKubeSignInFalseKeepsTheBinding(t *testing.T) {
	helm := helmBinary(t)
	objs := decodeObjects(t, renderChart(t, helm, "kube-signin", "--set-json", `gateway.args=["serve","--substrate","--no-kube-sign-in=false"]`))
	if len(clusterScoped(objs)) != 1 || hookPlanFrom(t, objs).AuthDelegatorBinding == "" {
		t.Fatalf("--no-kube-sign-in=false: binding missing (%d cluster-scoped)", len(clusterScoped(objs)))
	}
}

// TestChartGatewaySecretVolumesHaveAMode: every Secret the gateway mounts
// is 0440 (owner and the pod's fsGroup), the relay session key included
// (R3a P3: it had the 0644 default).
func TestChartGatewaySecretVolumesHaveAMode(t *testing.T) {
	helm := helmBinary(t)
	objs := decodeObjects(t, renderChart(t, helm, "kube-signin"))
	seen := 0
	for _, o := range objs {
		if o.Kind != "Deployment" || fmt.Sprint(o.Metadata["name"]) != "defenseclaw-gateway" {
			continue
		}
		tmpl, _ := o.Spec["template"].(map[string]any)
		spec, _ := tmpl["spec"].(map[string]any)
		vols, _ := spec["volumes"].([]any)
		for _, v := range vols {
			vm, _ := v.(map[string]any)
			sec, ok := vm["secret"].(map[string]any)
			if !ok {
				continue
			}
			seen++
			if mode := fmt.Sprint(sec["defaultMode"]); mode != "288" {
				t.Errorf("gateway Secret volume %v: defaultMode %s, want 0440 (288)", vm["name"], mode)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no gateway Secret volumes rendered")
	}
}
