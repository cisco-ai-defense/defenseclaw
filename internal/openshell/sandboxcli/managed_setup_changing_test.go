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

package sandboxcli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func TestManagedOperationalRefusalsHaveOnlyTheRemedy(t *testing.T) {
	m := &sandboxapi.ManagedStatus{Profile: "contractors", RequestAccess: sandboxapi.RequestAccessFallback}
	for _, code := range []string{sandboxapi.CodeAdminViolation, sandboxapi.CodeUnavailable} {
		for _, reason := range []string{sandboxrelay.ReasonDaemonOutdated, sandboxrelay.DetailSetupChanging} {
			message := "Stop your sandboxes with `defenseclaw sandbox stop NAME`, then retry."
			text, ok := managedErrorText(&sandboxapi.Error{Code: code, Message: message, Detail: reason}, m)
			if !ok || text != message {
				t.Fatalf("%s/%s: %q, %t", code, reason, text, ok)
			}
		}
	}
}

// #1203: while the organization's switch of the sandbox driver is under
// way, `run` and `doctor` say so and send nobody to IT for an exception;
// a setup that is really missing keeps the contact.
func TestManagedSetupSwitchIsANoticeWithoutTheContact(t *testing.T) {
	m := &sandboxapi.ManagedStatus{Profile: "contractors", RequestAccess: "it-help@example.com"}
	text, ok := managedErrorText(&sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: sandboxrelay.UnavailableSetupChanging,
		Detail: sandboxrelay.DetailSetupChanging}, m)
	if !ok || text != sandboxrelay.UnavailableSetupChanging || strings.Contains(text, "it-help") || strings.Contains(text, "exception") {
		t.Fatalf("switch refusal = %q, %t", text, ok)
	}
	text, ok = managedErrorText(&sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: sandboxapi.AdminMessage,
		Detail: "OpenShell is not set up on this computer"}, m)
	if !ok || !strings.Contains(text, "it-help@example.com") {
		t.Fatalf("missing setup = %q, %t", text, ok)
	}
	row := managedRuntimeCheck(&sandboxapi.ManagedStatus{Unavailable: sandboxrelay.UnavailableSetupChanging, RequestAccess: "it-help@example.com"})
	if row.Status != openshell.StatusWarn || row.Fix == nil || strings.Contains(row.Fix.Summary, "it-help") {
		t.Fatalf("doctor row = %+v", row)
	}
	row = managedRuntimeCheck(&sandboxapi.ManagedStatus{Unavailable: "OpenShell is not set up on this computer", RequestAccess: "it-help@example.com"})
	if row.Status != openshell.StatusFail || row.Fix == nil || !strings.Contains(row.Fix.Summary, "it-help") {
		t.Fatalf("missing setup row = %+v", row)
	}
}
