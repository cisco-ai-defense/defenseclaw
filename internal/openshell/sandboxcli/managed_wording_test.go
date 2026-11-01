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

package sandboxcli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// #1202 (GAP-2437): what a person on a managed computer reads when the sandbox
// service does not answer, when a stop or delete loses the OpenShell gateway,
// and when another account holds the sandboxes. None of it shows the daemon's
// internal URL, gRPC text or the service manager's text, and each names the
// next step.
func TestManagedSandboxMessagesShowNoInternalText(t *testing.T) {
	withManagedHost(t)
	internal := []string{"http://", "sandbox-daemon", "deadline exceeded", "grpc", "rpc error", "systemctl", "Job for"}

	// (d) The daemon does not answer: each cause sandboxapi words.
	for _, cause := range []string{
		"it did not answer in time",
		"nothing accepted the connection on its port",
		"the connection failed before it answered",
	} {
		err := apiError(&sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the DefenseClaw daemon is not reachable", Detail: cause})
		want := "your sandbox service does not answer (" + cause + "); " + managedServiceFix
		if err.Error() != want {
			t.Fatalf("daemon down: %q, want %q", err.Error(), want)
		}
	}

	// (b) and (c) A delete or a keep-on-exit stop after a gateway loss.
	raw := "Cancelled: grpc: the client connection is closing"
	texts := map[string]string{
		"delete": (&sessionDeleteError{name: "r5r", err: errors.New("OpenShell: wait for sandbox r5r deletion failed: " + raw)}).Error(),
	}
	text, ok := managedErrorText(&sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "OpenShell: stop failed", Detail: raw}, nil)
	if !ok {
		t.Fatal("a gateway transport failure is not worded")
	}
	texts["managed stop"] = text
	for name, got := range texts {
		if !strings.Contains(got, "the connection to the OpenShell gateway closed") {
			t.Errorf("%s: %q does not say the gateway connection closed", name, got)
		}
		if !strings.Contains(got, "retry") {
			t.Errorf("%s: %q gives no retry step", name, got)
		}
	}

	// (a) Another account holds the sandboxes.
	texts["account busy"] = managedAccountBusyText
	for name, got := range texts {
		for _, bad := range internal {
			if strings.Contains(got, bad) {
				t.Errorf("%s: %q shows %q", name, got, bad)
			}
		}
	}
	if !strings.Contains(managedAccountBusyText, "another account is using sandboxes") {
		t.Errorf("account busy: %q", managedAccountBusyText)
	}
}
