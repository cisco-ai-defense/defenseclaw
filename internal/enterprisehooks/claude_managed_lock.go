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

import "fmt"

// windowsClaudeManagedHooksOnlyConflict reports another administrator
// managed-settings file that contradicts the DefenseClaw managed-hooks-only
// lock. Claude merges managed-settings.json first and managed-settings.d/*.json
// alphabetically after it, so a later-sorting drop-in with
// allowManagedHooksOnly=false turns the lock off. An earlier file with the same
// value is overridden by DefenseClaw's drop-in, but it still records an
// administrator decision that differs from DefenseClaw's; both are reported so
// the administrator resolves the conflict explicitly (remove the key, or opt
// out with claude_code.allow_unmanaged_hooks) instead of one policy silently
// winning. Claude treats a non-boolean value as true, so only an explicit false
// conflicts.
func windowsClaudeManagedHooksOnlyConflict(path string, settings map[string]interface{}) error {
	raw, exists := settings["allowManagedHooksOnly"]
	if !exists {
		return nil
	}
	if value, ok := raw.(bool); !ok || value {
		return nil
	}
	return fmt.Errorf(
		"enterprise hooks: Claude Code managed policy %s sets allowManagedHooksOnly=false, "+
			"which conflicts with the DefenseClaw managed-hooks-only lock; remove the setting "+
			"or set claude_code.allow_unmanaged_hooks: true in the DefenseClaw config",
		path,
	)
}
