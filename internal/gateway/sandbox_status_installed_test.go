// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"strings"
	"testing"
)

// GAP-1993: the status carries the installed OpenShell next to the required.
func TestManagedStatusCarriesTheInstalledOpenShell(t *testing.T) {
	prev := sandboxInstalledOpenShellVersion
	sandboxInstalledOpenShellVersion = func() string { return "0.1.3" }
	t.Cleanup(func() { sandboxInstalledOpenShellVersion = prev })
	f := newSandboxDaemonFixture(t)
	f.run(t)
	if got := managedStatusJSON(t, f); !strings.Contains(got, `"installed_openshell_version":"0.1.3"`) {
		t.Fatalf("the installed OpenShell is not in the status: %s", got)
	}
}
