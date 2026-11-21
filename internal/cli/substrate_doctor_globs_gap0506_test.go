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

// GAP-0506 (J35 shape): a match.substrate glob meets an atespace that holds
// actors and that DefenseClaw neither created nor lists, so the profile does
// not apply there (E3). Only the controller said so, once per actor; doctor
// now has a warning row for it, naming the atespace, the glob and the fix.
// A launcher atespace the glob meets, and an atespace listed by name, are
// not reported.
func TestGAP0506DoctorWarnsWhenAGlobMeetsAForeignAtespace(t *testing.T) {
	fakeKubectl(t, nil)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	body := "substrate:\n  launcher_atespaces:\n    eng: [eng-web]\n" +
		"guardrail:\n  profile_assignments:\n" +
		"    - profile: eng\n      match:\n        substrate:\n          atespaces: [\"eng-*\", \"*-team\", data-team]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	kf := &substrateClusterFlags{installFile: writeInstall(t, fleetInstallOK), namespace: "defenseclaw-system", substrateNS: "ate-system", configFile: cfg}
	var rows []substrateCheck
	for _, c := range doctorKubeChecks(t.Context(), kf) {
		if c.ID == "cluster.atespace_globs" {
			rows = append(rows, c)
		}
	}
	if len(rows) != 1 || rows[0].Status != doctorWarn || !strings.Contains(rows[0].Summary, "atespace other-team matches the glob *-team") || rows[0].Fix == "" {
		t.Fatalf("glob rows = %+v, want one warning for other-team", rows)
	}
	for _, not := range []string{"eng-web", "data-team"} {
		if strings.Contains(rows[0].Summary, "atespace "+not+" ") {
			t.Errorf("%s was reported: %+v", not, rows[0])
		}
	}
}
