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

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0505: during a directory outage that leaves the computer unable to
// look the account up (SSSD stopped), `sandbox policy explain` shows the
// provisional default policy while a new managed run stops, because ssh, over
// which OpenShell reaches the sandbox, refuses the account. The refusal says
// what stops and what keeps working, that it is not the organization's
// policy, and whom to tell if it lasts; it asks for no policy exception.
func TestManagedRunAccountOutageIsNotAPolicyRefusal(t *testing.T) {
	outage := &openshell.AccountLookupError{Err: errors.New("ssh -G: No user exists for uid 94404116")}
	for _, tc := range []struct {
		contact, want string
	}{
		{contact: "it@example.invalid", want: "If it lasts, tell IT: it@example.invalid."},
		{contact: "", want: "If it lasts, contact your IT help desk."},
		{contact: "Contact your IT help desk for sandbox access.", want: "If it lasts, tell IT: Contact your IT help desk for sandbox access."},
	} {
		ta := newTestApp(t, "")
		ta.daemon.explain.Managed = &sandboxapi.ManagedExplain{Profile: "offline-floor", Provisional: true, Allowed: true, AllowHostPorts: true, RequestAccess: tc.contact}
		ta.AccountCheck = func() error { return outage }
		err := ta.Run(bg, RunOptions{Harness: "claude", Copy: true})
		wantErr(t, err, sandboxapi.AccountUnknownText,
			"a new sandbox can't start and `sandbox connect` and `sandbox exec` can't reach a running one",
			"agents already running keep working", "This isn't your organization's sandbox policy.", tc.want)
		if strings.Contains(err.Error(), "Need an exception") || strings.Contains(err.Error(), "ssh") || ta.creates() != 0 {
			t.Fatalf("err = %v, creates %d", err, ta.creates())
		}
	}
}
