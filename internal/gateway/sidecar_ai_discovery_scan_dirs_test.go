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

package gateway

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1962: `sandbox setup` turns openshell.enabled on through a hot
// reload. The discovery service reads the sandboxes' scan records only
// from the folder it was built with, empty while sandboxes were off, so
// `agent usage --sandbox NAME` stayed empty until the gateway restarted.
// A reload that changes a scan record folder rebuilds the service.
func TestAIDiscoveryRebuildsWhenSandboxesTurnOn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no sandboxes on Windows")
	}
	oldCfg := config.DefaultConfig()
	oldCfg.DataDir = t.TempDir()
	oldCfg.OpenShell.Enabled = false
	newCfg := *oldCfg
	newCfg.OpenShell.Enabled = true
	if !aiDiscoveryNeedsRestart(oldCfg, &newCfg) {
		t.Fatal("turning sandboxes on keeps a discovery service that never reads the sandboxes' scan records")
	}
	if !aiDiscoveryNeedsRestart(&newCfg, oldCfg) {
		t.Fatal("turning sandboxes off keeps a discovery service that still reads the sandboxes' scan records")
	}
	same := newCfg
	same.OpenShell.EgressPort = newCfg.OpenShell.EgressPort + 1
	if aiDiscoveryNeedsRestart(&newCfg, &same) {
		t.Fatal("an openshell edit that leaves the scan folders alone rebuilt the discovery service")
	}
}
