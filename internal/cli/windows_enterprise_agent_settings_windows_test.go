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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0588: the Windows status and verify warn about an agent config the
// guardian put back or recreated, as Linux and macOS do, and stay security
// complete; other actions and a host that is not installed say nothing.
func TestWindowsStatusWarnsAboutAgentSettingsTheGuardianCouldNotPutBack(t *testing.T) {
	previous := windowsEnterpriseAgentSettingsNotices
	t.Cleanup(func() { windowsEnterpriseAgentSettingsNotices = previous })
	windowsEnterpriseAgentSettingsNotices = func() []string {
		return []string{"hermes for user erin: the Hermes config.yaml went missing and DefenseClaw had no copy of it to put back"}
	}
	for _, action := range []string{"status", "verify"} {
		result := &enterprisestatus.Result{Action: action, Installed: true, SecurityComplete: true}
		applyWindowsEnterpriseAgentSettings(result)
		if len(result.Warnings) != 1 || result.Warnings[0].Code != windowsAgentSettingsNotRestoredCode ||
			!strings.Contains(result.Warnings[0].Message, "hermes for user erin") || !result.SecurityComplete {
			t.Fatalf("%s: warnings %+v, security complete %t", action, result.Warnings, result.SecurityComplete)
		}
	}
	for _, result := range []*enterprisestatus.Result{{Action: "uninstall", Installed: true}, {Action: "status"}} {
		applyWindowsEnterpriseAgentSettings(result)
		if len(result.Warnings) != 0 {
			t.Fatalf("%s (installed %t) warned: %+v", result.Action, result.Installed, result.Warnings)
		}
	}
}
