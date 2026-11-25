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
)

// rel-1-0-10:GAP-1781: the Sandbox runtime row fails with the daemon's
// cause, a gateway database a newer OpenShell migrated, and its recovery,
// which the account can carry out itself (not only "ask IT").
func TestGAP1781RuntimeRowNamesMigratedDatabase(t *testing.T) {
	reason := openshell.GatewayDBNewerText("0.1.9", "0.1.6")
	row := managedRuntimeCheck(&sandboxapi.ManagedStatus{InstallMode: "setup", OpenShellVersion: "0.1.6",
		Unavailable: reason, Recovery: openshell.GatewayDBRecovery("0.1.9"), RequestAccess: "it-help@example.com"}, sandboxapi.ManagedOffUnavailable)
	if row.Status != openshell.StatusFail || row.Detail != reason {
		t.Fatalf("row = %+v", row)
	}
	if row.Fix == nil || !strings.Contains(row.Fix.Summary, "ask IT to pin OpenShell 0.1.9 or newer") ||
		!strings.Contains(row.Fix.Summary, "move ~/.local/state/openshell/gateway/openshell.db") {
		t.Fatalf("fix = %+v", row.Fix)
	}
}
