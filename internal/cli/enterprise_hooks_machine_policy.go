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
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// applyEnterpriseHookMachinePolicyPreferences copies the administrator's
// machine-wide hook-policy choices from config into one install/verify
// request: the Claude Code managed-hooks-only opt-out and the Cursor
// foreign-hook allowlist. The allowlist is always non-nil here so the
// published protected state follows the configuration exactly.
func applyEnterpriseHookMachinePolicyPreferences(opts *enterprisehooks.InstallOptions) error {
	if cfg == nil {
		return fmt.Errorf("enterprise hooks: config is not loaded")
	}
	approved, err := cfg.ApprovedForeignHooksForConnector("cursor")
	if err != nil {
		return err
	}
	opts.ClaudeCodeAllowUnmanagedHooks = cfg.ClaudeCodeAllowUnmanagedHooks()
	opts.CursorApprovedForeignHooks = approved
	return nil
}

// enterpriseHookMachinePolicyWarnings reports deliberate administrator
// choices that weaken hook enforcement so status never presents them as a
// silent default.
func enterpriseHookMachinePolicyWarnings(
	currentCfg *config.Config,
	rows []enterpriseHookReconcileRow,
) []string {
	var warnings []string
	optOut := currentCfg.ClaudeCodeAllowUnmanagedHooks()
	for _, row := range rows {
		if row.Result != nil &&
			row.Result.ClaudeManagedHooksOnly == enterprisehooks.ClaudeManagedHooksOnlyDisabledByAdmin {
			optOut = true
			break
		}
	}
	if optOut {
		warnings = append(warnings,
			"Claude Code managed-hooks-only lock is disabled by claude_code.allow_unmanaged_hooks: "+
				"user, project, local and plugin hooks run beside DefenseClaw's managed hooks",
		)
	}
	return warnings
}
