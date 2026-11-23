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

package cli

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// B5.4: the substrate.skill_scan row fails on a managed install and warns on
// the others when the scanner is not running, and says when the gateway
// config turns scanning off even though the sidecar runs.
func TestB54DoctorSkillScanManagedFailsOSSWarns(t *testing.T) {
	pod := func(ready string) string {
		return `{"spec":{"containers":[{"name":"gateway","image":"g:1"},{"name":"skill-scanner","image":"r/defenseclaw-scanner:1.0.11"}]},"status":{"containerStatuses":[{"name":"skill-scanner","ready":` + ready + `}]}}`
	}
	noSidecar := `{"spec":{"containers":[{"name":"gateway","image":"g:1"}]}}`
	const oss = "substrate:\n  supported_versions: \">=1.0.10\"\n"
	const mgd = "deployment_mode: managed_enterprise\nsubstrate:\n  supported_versions: \">=1.0.10\"\n"
	const off = "substrate:\n  skills:\n    scan:\n      enabled: false\n"
	for _, tc := range []struct{ name, cfg, pods, status, want string }{
		{"oss-down", oss, pod("false"), doctorWarn, "New skills are allowed with an alert there."},
		{"managed-down", mgd, pod("false"), doctorFail, "New skills are refused there."},
		{"oss-no-sidecar", oss, noSidecar, doctorWarn, "not running on 1 of 1"},
		{"managed-no-sidecar", mgd, noSidecar, doctorFail, "New skills are refused there."},
		{"config-off", off, pod("true"), doctorSkip, "substrate.skills.scan.enabled: false"},
		{"managed-ready", mgd, pod("true"), doctorOK, "Skill scanner ready"},
		// GAP-0936: the OSS strict tier refuses new skills like managed.
		{"oss-strict-down", "guardrail:\n  rule_pack: strict\nsubstrate:\n  supported_versions: \">=1.0.10\"\n", pod("false"), doctorFail, "New skills are refused there."},
		{"oss-strict-no-sidecar", "guardrail:\n  rule_pack: strict\nsubstrate:\n  skills: {}\n", noSidecar, doctorFail, "New skills are refused there."},
		{"oss-balanced-down", "guardrail:\n  rule_pack: balanced\nsubstrate:\n  skills: {}\n", pod("false"), doctorWarn, "New skills are allowed with an alert there."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := substrateKubectl
			t.Cleanup(func() { substrateKubectl = old })
			substrateKubectl = func(_ context.Context, _ *substrateClusterFlags, args ...string) ([]byte, error) {
				if slices.Contains(args, "configmaps") {
					data, _ := json.Marshal(map[string]string{"config.yaml": tc.cfg})
					return []byte(`{"items":[{"metadata":{"name":"defenseclaw-config"},"data":` + string(data) + `}]}`), nil
				}
				return []byte(`{"items":[` + tc.pods + `]}`), nil
			}
			c := doctorSkillScan(context.Background(), &substrateClusterFlags{namespace: "defenseclaw-system"})
			if c.ID != "substrate.skill_scan" || c.Status != tc.status || !strings.Contains(c.Summary, tc.want) {
				t.Fatalf("row %+v, want %s %q", c, tc.status, tc.want)
			}
		})
	}
}
