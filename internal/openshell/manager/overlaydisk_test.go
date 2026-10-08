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

package manager

import (
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestAFullMicroVMDiskIsNamed (GAP-0297): a MicroVM stopped with its own
// disk full did not start again; start printed OpenShell's guest console
// and status said only "error". The start names the full disk and the way
// on, and the status says why the sandbox is in the error phase.
func TestAFullMicroVMDiskIsNamed(t *testing.T) {
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "fullbox", Copy: true})
	e.stopBox("fullbox")
	e.fake.FailStart(openshell.DefaultWorkspace, "fullbox", types.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProcessExited",
		Message: "VM process exited with status 0; guest console tail: [0.001s] setting up writable overlay root [0.156s] using prepared image rootfs lowerdir " +
			"touch: cannot touch '/newroot/etc/passwd': Read-only file system"})
	_, err := e.m.Start(t.Context(), "fullbox", sandboxapi.StartRequest{})
	apiErr := wantCode(t, err, sandboxapi.CodeConflict)
	if apiErr.Message != "fullbox cannot start: "+overlayDiskFullText || strings.Contains(apiErr.Message+apiErr.Detail, "newroot") ||
		!strings.Contains(apiErr.Detail, "overlay_disk_mib") || !strings.Contains(apiErr.Detail, "defenseclaw sandbox delete fullbox") {
		t.Fatalf("start refusal = %+v", apiErr)
	}
	if sb := e.get("fullbox"); sb.Phase != "error" || sb.PhaseReason != overlayDiskFullText {
		t.Fatalf("status phase = %q (%q), want error with the full disk", sb.Phase, sb.PhaseReason)
	}
}
