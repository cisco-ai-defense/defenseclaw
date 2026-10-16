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

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsAgentSettingsNotRestoredCode is the Linux and macOS warning code
// for an agent config the guardian had to put back or recreate.
const windowsAgentSettingsNotRestoredCode = "agent_settings_not_restored"

// windowsEnterpriseAgentSettingsNotices reads the standalone guardian's
// agent config notices (a seam for tests).
var windowsEnterpriseAgentSettingsNotices = func() []string {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return nil
	}
	return enterpriseHookGuardianNoticeMessages(layout.DataDir)
}

// applyWindowsEnterpriseAgentSettings warns, per account and connector,
// about a Hermes config.yaml or Devin config.json that went missing and that
// the guardian put back from a copy or recreated with DefenseClaw's hooks
// only (GAP-0588, GAP-0564 on Linux and macOS). The hooks are in place, so
// it is a warning: security_complete and the exit code stay as they are.
func applyWindowsEnterpriseAgentSettings(result *enterprisestatus.Result) {
	if result == nil || !result.Installed || result.TransactionPending {
		return
	}
	switch result.Action {
	case "status", "verify", "ensure", "repair":
	default:
		return
	}
	for _, message := range windowsEnterpriseAgentSettingsNotices() {
		result.AddWarning(windowsAgentSettingsNotRestoredCode, message)
	}
}
