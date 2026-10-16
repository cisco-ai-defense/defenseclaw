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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// On a Mac every Docker engine runs containers in a Linux VM. An engine other
// than Docker Desktop (Colima, OrbStack) was skipped with "bind mounts come
// straight from the host filesystem"; its VM sees the home directory by
// default, and the check says so (FG-06 hand-off to the lead). Docker Engine
// on Linux keeps the skip.
func TestDoctorFileSharingOfAMacDockerEngineOtherThanDockerDesktop(t *testing.T) {
	f := newDoctorFixture(t)
	f.onBrew()
	c := expectCheck(t, f.run(), openshell.CheckIDDockerFileSharing, openshell.StatusPass, "runs containers in a VM")
	if strings.Contains(c.Detail, "host filesystem") || !strings.Contains(c.Detail, f.home) || !strings.Contains(c.Detail, "colima.yaml") {
		t.Fatalf("detail = %q, want the VM, the home directory and the Colima mount fix", c.Detail)
	}

	linux := newDoctorFixture(t)
	expectCheck(t, linux.run(), openshell.CheckIDDockerFileSharing, openshell.StatusSkip, "host filesystem")
}
