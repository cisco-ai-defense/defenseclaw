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

package watcher

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1120: a standalone managed Windows gateway never runs a scanner to
// fingerprint it before the scan's runtime admission; other hosts probe as
// before.
func TestScannerVersionProbeIsRefusedOnAManagedWindowsGateway(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "managed_enterprise")
	t.Setenv(managed.EnterpriseProfileEnv, "standalone")
	if !refuseScannerVersionProbe("windows") {
		t.Fatal("a standalone managed Windows gateway probes the scanner")
	}
	if refuseScannerVersionProbe("linux") {
		t.Fatal("a managed Linux gateway lost its scanner version probe")
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	if refuseScannerVersionProbe("windows") {
		t.Fatal("a per-user Windows gateway lost its scanner version probe")
	}
}
