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

package enterprisehooks

import (
	"strings"
	"testing"
)

func TestWindowsClaudeManagedHooksOnlyConflictReportsOnlyExplicitFalse(t *testing.T) {
	const path = `C:\Program Files\ClaudeCode\managed-settings.d\99-other.json`
	err := windowsClaudeManagedHooksOnlyConflict(path, map[string]interface{}{"allowManagedHooksOnly": false})
	if err == nil || !strings.Contains(err.Error(), path) ||
		!strings.Contains(err.Error(), "claude_code.allow_unmanaged_hooks") {
		t.Fatalf("explicit false conflict = %v, want the file and the opt-out key", err)
	}
	for name, settings := range map[string]map[string]interface{}{
		"absent":   {"model": "x"},
		"true":     {"allowManagedHooksOnly": true},
		"non-bool": {"allowManagedHooksOnly": "false"},
	} {
		if err := windowsClaudeManagedHooksOnlyConflict(path, settings); err != nil {
			t.Fatalf("%s: unexpected conflict %v", name, err)
		}
	}
}

func TestClaudeManagedHooksOnlyStateNames(t *testing.T) {
	if got := ClaudeManagedHooksOnlyState(false); got != ClaudeManagedHooksOnlyEnforced {
		t.Fatalf("default state = %q", got)
	}
	if got := ClaudeManagedHooksOnlyState(true); got != ClaudeManagedHooksOnlyDisabledByAdmin {
		t.Fatalf("opt-out state = %q", got)
	}
}
