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
	"os/exec"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
)

func calloutConfigFrom(t *testing.T, out []byte) *extproc.Config {
	t.Helper()
	for _, o := range decodeObjects(t, out) {
		if o.Kind == "ConfigMap" && o.Metadata["name"] == "defenseclaw-callout" {
			cc, err := extproc.ParseConfig([]byte(o.Data["callout.yaml"].(string)))
			if err != nil {
				t.Fatalf("callout.yaml: %v", err)
			}
			return cc
		}
	}
	t.Fatal("no callout ConfigMap")
	return nil
}

// TestChartCalloutManaged is GAP-0090 per D8: a managed enterprise install
// renders managed true for the callout (chain.failure_mode auto means
// closed) and refuses chain.failure_mode open; an OSS install renders
// neither.
// managedImages names the template registries a managed install must list (the chart refuses it without them),
// so the renders below fail or pass for the chain mode only.
const managedImages = "config.substrate.templates.allowed_images={registry.example.test/*}"

func TestChartCalloutManaged(t *testing.T) {
	helm := helmBinary(t)
	cc := calloutConfigFrom(t, renderChart(t, helm, "default", "--set", "config.deployment_mode=managed_enterprise", "--set", managedImages))
	if !cc.Managed || cc.Chain.FailureMode != extproc.ChainAuto {
		t.Errorf("managed/auto: managed=%v chain.failure_mode=%q", cc.Managed, cc.Chain.FailureMode)
	}
	// GAP-0015: the tool verdict route is on by default.
	if cc.Judge.URL == "" || cc.Judge.TokenFile == "" {
		t.Errorf("managed: no tool verdict route by default: %+v", cc.Judge)
	}
	args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion,
		"--set", "config.deployment_mode=managed_enterprise", "--set", managedImages,
		"--set", "config.substrate.extproc.chain.failure_mode=open"}
	if err := exec.Command(helm, args...).Run(); err == nil {
		t.Error("managed/open: accepted")
	}
	cc = calloutConfigFrom(t, renderChart(t, helm, "default"))
	if cc.Managed || cc.Chain.FailureMode != extproc.ChainAuto {
		t.Errorf("oss/auto: managed=%v chain.failure_mode=%q", cc.Managed, cc.Chain.FailureMode)
	}
}
