// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "github.com/defenseclaw/defenseclaw/internal/config"

// ManagedHookFailMode is the fail mode the managed hook renderer writes into
// connector's hooks for cfg. It delegates to the hook renderer resolver: the
// Windows renderer wraps cfg.EffectiveHookFailModeForConnector in
// windowsEnterpriseHookFailMode for every hook it writes and lowers closed
// to open for an agent that cannot fail closed (Hermes), so status reports
// that value and never derives one from the raw config (GAP-0001).
func ManagedHookFailMode(cfg *config.Config, connector string) string {
	return renderedHookFailModeFor(connector, windowsEnterpriseHookFailMode(connector, cfg.EffectiveHookFailModeForConnector(connector)))
}

// WindowsStandaloneMachinePolicyHook reports whether connector's DefenseClaw
// hook is in vendor machine policy on a standalone Windows device through
// its runtime-only rows (Copilot always, OpenCode while its machine policy
// is in force); Codex, Claude Code and Cursor are reported by their own
// machine policy state.
func WindowsStandaloneMachinePolicyHook(connector string) bool {
	return windowsStandaloneRuntimeOnlyInstall(connector)
}
