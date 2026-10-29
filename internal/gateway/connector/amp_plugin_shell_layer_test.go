// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"regexp"
	"testing"
)

// ampShellLayerPattern is the check the Windows Setup acceptance
// (scripts/windows-native-ci.ps1, wizard-selected Amp) and the Windows
// connector contract (scripts/live-connector-e2e/run-windows.ps1,
// setup-created Amp) run over the Amp policy plugin: the plugin talks to the
// gateway itself and must not depend on a shell hook, WSL or a POSIX shell.
var ampShellLayerPattern = regexp.MustCompile(`(?i)defenseclaw-hook(?:\.exe|\.cmd)|\bwsl\b|\bbash\b|\bchmod\b`)

// TestAmpPluginNamesNoShellLayer: every rendered Amp policy plugin, the
// per-user one included, passes that check, its comments too (GAP-2326: a
// comment naming Bash failed both Windows checks).
func TestAmpPluginNamesNoShellLayer(t *testing.T) {
	for _, v := range []struct {
		managed  bool
		failMode string
	}{{false, "closed"}, {false, "open"}, {true, "closed"}, {true, "open"}} {
		body, err := renderHookTemplate("amp-plugin.ts", templateData{
			APIAddr:         "127.0.0.1:18970",
			TokenFileJS:     javaScriptStringContent(`C:\Users\dcw\.defenseclaw\hooks\.amp.token`),
			GatewayBinaryJS: javaScriptStringContent(`C:\Users\dcw\AppData\Local\DefenseClaw\bin\defenseclaw-gateway.exe`),
			FailMode:        v.failMode,
			Managed:         v.managed,
		})
		if err != nil {
			t.Fatalf("render managed=%v fail=%s: %v", v.managed, v.failMode, err)
		}
		if m := ampShellLayerPattern.FindString(string(body)); m != "" {
			t.Errorf("managed=%v fail=%s: the Amp plugin names %q, which the Windows checks read as a shell hook or compatibility layer", v.managed, v.failMode, m)
		}
	}
}
