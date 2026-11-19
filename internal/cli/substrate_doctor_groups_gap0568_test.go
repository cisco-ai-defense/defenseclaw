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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gap0568Rows runs the cluster doctor checks on a config.yaml whose ops
// profile is assigned to groups, and returns the group_forms rows.
func gap0568Rows(t *testing.T, groups string, run func(kf *substrateClusterFlags) []substrateCheck) []substrateCheck {
	t.Helper()
	fakeKubectl(t, nil)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	body := "substrate:\n  launcher_atespaces:\n    eng: [eng-web]\n" +
		"guardrail:\n  default_profile: eng\n  profile_assignments:\n" +
		"    - profile: ops\n      match:\n        groups: [" + groups + "]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	kf := &substrateClusterFlags{installFile: writeInstall(t, fleetInstallOK), namespace: "defenseclaw-system", substrateNS: "ate-system", configFile: cfg}
	var rows []substrateCheck
	for _, c := range run(kf) {
		if c.ID == "cluster.group_forms" {
			rows = append(rows, c)
		}
	}
	return rows
}

// GAP-0568 (E4 J15 one-sided shape): the ops assignment named a group by
// its Keycloak id next to a group name. Tokens carry one form, so the id
// matched nobody and the contractor got the default profile, while doctor
// said ready for agents. Doctor now warns, naming the profile; this config
// alone shows it (verify prints the same line).
func TestGAP0568AssignmentMixingGroupIDsAndNamesIsFlagged(t *testing.T) {
	rows := gap0568Rows(t, "dc-r102-admins, 3f2a6c1e-9b4d-4c2a-8e7f-1a2b3c4d5e6f", func(kf *substrateClusterFlags) []substrateCheck {
		return doctorKubeChecks(t.Context(), kf)
	})
	if len(rows) != 1 || rows[0].Status != doctorWarn || !strings.Contains(rows[0].Summary, "profile ops") ||
		!strings.Contains(rows[0].Summary, "group ids: 3f2a6c1e-9b4d-4c2a-8e7f-1a2b3c4d5e6f") || rows[0].Fix == "" {
		t.Fatalf("group_forms rows = %+v, want one warning for profile ops", rows)
	}
	// One form throughout, with no token to compare: nothing to say.
	if rows := gap0568Rows(t, "dc-r102-admins, dc-r102-contractors", func(kf *substrateClusterFlags) []substrateCheck {
		return doctorKubeChecks(t.Context(), kf)
	}); len(rows) != 0 {
		t.Errorf("names only, no token: %+v", rows)
	}
}

// GAP-0568: with a signed-in token the form the sign-in server sends is
// known. An assignment written only in ids while tokens carry names (or the
// reverse) is flagged with the claim's real form and an example.
func TestGAP0568AssignmentInAnotherFormThanTheTokenIsFlagged(t *testing.T) {
	rows := gap0568Rows(t, "3f2a6c1e-9b4d-4c2a-8e7f-1a2b3c4d5e6f", func(kf *substrateClusterFlags) []substrateCheck {
		return doctorKubeChecks(t.Context(), kf, "dc-r102-admins", "dc-r102-contractors")
	})
	if len(rows) != 1 || !strings.Contains(rows[0].Summary, "profile ops matches group ids") ||
		!strings.Contains(rows[0].Summary, "sends group names (such as dc-r102-admins)") {
		t.Fatalf("ids vs names: %+v", rows)
	}
	rows = gap0568Rows(t, "dc-r102-contractors", func(kf *substrateClusterFlags) []substrateCheck {
		return doctorKubeChecks(t.Context(), kf, "/dc/dc-r102-admins")
	})
	if len(rows) != 1 || !strings.Contains(rows[0].Summary, "sends group paths") {
		t.Fatalf("names vs paths: %+v", rows)
	}
	if rows := gap0568Rows(t, "dc-r102-contractors", func(kf *substrateClusterFlags) []substrateCheck {
		return doctorKubeChecks(t.Context(), kf, "dc-r102-admins")
	}); len(rows) != 0 {
		t.Errorf("same form: %+v", rows)
	}
}
