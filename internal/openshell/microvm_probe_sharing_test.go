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
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestDoctorChecksTheHookFireProbeDirOnMicroVMs: the hook-fire probe of an
// image build mounts its MicroVM name-resolution files from a private
// directory under the user cache directory (GAP-0037), so the MicroVM
// file sharing check judges that directory, not $TMPDIR (GAP-0402): a
// Docker Desktop that shares the home but not the temp folders passes, one
// that shares the temp folders but not the home fails, and on a Mac an
// engine other than Docker Desktop (Colima, OrbStack), which also runs
// containers in a VM, is judged by the home directory instead of skipped.
func TestDoctorChecksTheHookFireProbeDirOnMicroVMs(t *testing.T) {
	const pass, warn, fail = openshell.StatusPass, openshell.StatusWarn, openshell.StatusFail
	const why = " (the hook-fire probe of an image build mounts a MicroVM\x27s /etc/hosts from there; sandboxes mount nothing)"
	for _, tc := range []struct {
		name, engine string
		// shared is what Docker Desktop shares, given the home directory and
		// the temp folder ($TMPDIR, a directory that holds neither the home
		// nor the probe directory).
		shared   func(home, tmp string) []string
		override string
		status   openshell.CheckStatus
		detail   string // after the probe directory
		fix      string
	}{
		{name: "Docker Desktop sharing the home only", engine: "Docker Desktop",
			shared: func(home, _ string) []string { return []string{home} },
			status: pass, detail: " is shared with Docker Desktop" + why},
		{name: "Docker Desktop sharing the temp folders only", engine: "Docker Desktop",
			shared: func(_, tmp string) []string { return []string{tmp} },
			status: fail, detail: " is not shared with Docker Desktop, so the hook-fire probe cannot run an image",
			fix: " (or your home directory) in Docker Desktop → Settings → Resources → File sharing (/Users is shared by default)"},
		{name: "Colima", engine: "Ubuntu 24.04.3 LTS",
			status: pass, detail: " is under your home directory, which Colima and OrbStack share with the VM they run containers in by default" + why},
		{name: "Colima, a probe directory outside the home", engine: "Ubuntu 24.04.3 LTS", override: "/var/folders/1r/T",
			status: warn, detail: " is outside your home directory, and the VM this Docker engine runs containers in may not see it",
			fix: " with the VM of your Docker engine (Colima: add it under mounts in ~/.colima/default/colima.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.onMicroVMs()
			t.Setenv("HOME", f.home)
			t.Setenv("XDG_CACHE_HOME", "")
			// The temp folder is a directory of its own: a fixed /tmp holds the
			// fake home on a host whose test temp root is under /tmp (the CI
			// runners), so "shares the temp folders" would share the home too.
			tmp := t.TempDir()
			if rel, err := filepath.Rel(tmp, f.home); err == nil && !strings.HasPrefix(rel, "..") {
				t.Fatalf("the temp folder %s holds the fake home %s", tmp, f.home)
			}
			t.Setenv("TMPDIR", tmp)
			probe := openshell.HookFireProbeDir()
			if !strings.HasPrefix(probe, f.home+string(filepath.Separator)) || !strings.HasSuffix(probe, filepath.Join("defenseclaw", "hookfire")) {
				t.Fatalf("HookFireProbeDir = %q, want one under %s", probe, f.home)
			}
			// The default, as sandbox doctor runs it.
			f.doctor.TempDir = nil
			if tc.override != "" {
				f.doctor.TempDir, probe = func() string { return tc.override }, tc.override
			}
			var shared []string
			if tc.shared != nil {
				shared = tc.shared(f.home, tmp)
			}
			f.runner.On("docker info", dockerInfoJSON("29.1.5", tc.engine, nil), nil)
			f.doctor.DockerDesktop = func() (*openshell.DockerDesktop, error) { return &openshell.DockerDesktop{FileSharing: shared}, nil }
			c := expectCheck(t, f.run(), openshell.CheckIDDockerFileSharing, tc.status, probe+tc.detail)
			if !strings.HasPrefix(c.Detail, probe) {
				t.Fatalf("detail %q does not start with the probe directory %s", c.Detail, probe)
			}
			if (tc.fix == "") != (c.Fix == nil) || (tc.fix != "" && !strings.Contains(c.Fix.Summary, probe+tc.fix)) {
				t.Fatalf("fix = %+v, want one containing %q", c.Fix, probe+tc.fix)
			}
		})
	}
}
