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

package openshell_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// NVIDIA's pinned install.sh makes gawk print three "escape sequence"
// warnings on an RPM-based computer (NVIDIA/OpenShell#4768). The script is
// digest-pinned and cannot be edited, so the plan tells an RPM-based
// operator, before consent, that the lines are harmless, and says nothing
// to anyone else.
func TestInstallPlanNamesTheGawkWarningsOnRPMHostsOnly(t *testing.T) {
	cases := []struct {
		name, osRelease, goos string
		want                  bool
	}{
		{"rhel", "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\n", "linux", true},
		{"rocky by ID_LIKE", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", "linux", true},
		{"amazon linux", "ID=\"amzn\"\nID_LIKE=\"fedora\"\n", "linux", true},
		{"ubuntu", "ID=ubuntu\nID_LIKE=debian\n", "linux", false},
		{"no os-release", "", "linux", false},
		{"mac", "ID=\"rhel\"\n", "darwin", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
			f.inst.GOOS = tc.goos
			f.inst.OSRelease = filepath.Join(t.TempDir(), "os-release")
			if tc.osRelease != "" {
				if err := os.WriteFile(f.inst.OSRelease, []byte(tc.osRelease), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.inst.Install(context.Background()); err != nil {
				t.Fatalf("install on %s: %v", tc.goos, err)
			}
			plan := f.out.String()
			if got := strings.Contains(plan, "awk: warning: escape sequence"); got != tc.want {
				t.Fatalf("plan names the gawk warnings = %v, want %v:\n%s", got, tc.want, plan)
			}
		})
	}
}
