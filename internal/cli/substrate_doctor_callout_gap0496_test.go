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

// GAP-0496 (J32 shape): another callout holds Substrate's egress slot.
// Without substrate.extproc.enabled: false the callout check fails and its
// fix line says to remove the other callout or keep it with the callout off
// (setup refuses while it is in the file, so "run setup" alone is wrong).
// With the callout off on purpose, doctor no longer fails on it: a warning
// that names the protections that are off.
func TestGAP0496CalloutOffOnPurposeIsAWarningWithTheRightFix(t *testing.T) {
	fakeKubectl(t, nil)
	other := strings.Replace(fleetInstallOK, "defenseclaw-system/defenseclaw-callout:9443", "default/other-callout:9443", 1)
	kf := &substrateClusterFlags{installFile: writeInstall(t, other), namespace: "defenseclaw-system", substrateNS: "ate-system"}
	row := func() substrateCheck {
		t.Helper()
		for _, c := range doctorKubeChecks(t.Context(), kf) {
			if c.ID == "cluster.callout_registered" {
				return c
			}
		}
		t.Fatal("no callout_registered row")
		return substrateCheck{}
	}

	on := row()
	if on.Status != doctorFail || !strings.Contains(on.Fix, "remove the other callout") || !strings.Contains(on.Fix, "substrate.extproc.enabled: false") {
		t.Errorf("callout on, other callout in the slot: %+v", on)
	}

	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("substrate:\n  enabled: true\n  extproc:\n    enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kf.configFile = cfg
	off := row()
	if off.Status != doctorWarn || !strings.Contains(off.Summary, "substrate.extproc.enabled: false") ||
		!strings.Contains(off.Summary, "ask hosts") || !strings.Contains(off.Summary, "other-callout") {
		t.Errorf("callout off on purpose: %+v", off)
	}
	if strings.Contains(off.Fix, "setup --install-file FILE, then") && !strings.Contains(off.Fix, "off on purpose") {
		t.Errorf("callout off: the fix line still says to run setup: %q", off.Fix)
	}
}
