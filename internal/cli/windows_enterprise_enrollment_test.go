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
	"bytes"
	"testing"
)

// Status lists each enrolled account and each connector's state (GAP-1073).
func TestWindowsEnterpriseEnrollmentAccounts(t *testing.T) {
	accounts := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{
		{User: "dcw-std2", SID: "S-1-5-21-1-2-3-1002", Connector: "copilot", Pending: true},
		{User: "dcw-std1", SID: "S-1-5-21-1-2-3-1001", Connector: "codex", OK: true},
		{User: "dcw-std1", SID: "S-1-5-21-1-2-3-1001", Connector: "claudecode", OK: true},
		{SID: "S-1-5-21-1-2-3-1003", Connector: "codex", Error: "profile gone"},
	})
	var out bytes.Buffer
	writeWindowsEnterpriseEnrollmentAccounts(&out, accounts)
	want := "  Account dcw-std1 (S-1-5-21-1-2-3-1001): claudecode enrolled, codex enrolled\n" +
		"  Account dcw-std2 (S-1-5-21-1-2-3-1002): copilot pending\n" +
		"  Account S-1-5-21-1-2-3-1003: codex failed\n"
	if out.String() != want {
		t.Fatalf("accounts:\n%s\nwant:\n%s", out.String(), want)
	}
	if len(accounts) != 3 || accounts[0].Connectors["codex"] != "enrolled" {
		t.Fatalf("accounts = %+v", accounts)
	}
}
