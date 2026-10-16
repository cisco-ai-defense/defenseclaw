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

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// GAP-0481: verify's missing-driver warning carries the shared
// administrator install, checked against the digest this build pins, that
// the managed user's sandbox doctor names too.
func TestSandboxPrerequisiteDriverFixIsThePinnedInstall(t *testing.T) {
	h := newOSHost(t, "linux")
	h.writeExecutables(t, "/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/sbin/mke2fs")
	r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"}))
	requireOK(t, r)
	if state, _ := rowState(r, "sandbox microvm driver"); state != "missing: openshell-driver-vm is not installed" {
		t.Fatalf("microvm driver row = %q", state)
	}
	fix := openshell.AdminVMDriverFix("linux", sandboxHostArch)
	var got string
	for _, w := range r.Warnings {
		if w.Code == codeOpenShellPrerequisite && strings.Contains(w.Message, "(microvm driver)") {
			got = w.Message
		}
	}
	for _, want := range []string{fix.Summary, fix.Command, "enterprise.openshell.install: setup"} {
		if want == "" || !strings.Contains(got, want) {
			t.Errorf("driver warning lacks %q:\n%s", want, got)
		}
	}
}
