// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The Copilot CLI loads every hook file in ~/.copilot/hooks, so on a managed
// host it also runs the guardian's VS Code Local hook file
// (defenseclaw-vscode.json) next to its machine policy hooks, and every CLI
// event was evaluated, audited and exported twice (GAP-1075). The VS Code
// Local command answers that second delivery with a plain allow, without
// asking the gateway, when the agent engine running it is the Copilot CLI
// and DefenseClaw's Copilot machine policy hooks are in force: the machine
// policy hook evaluates the same event. VS Code's own deliveries (its
// extension host is never an executable named copilot) are unchanged.
//
// VS Code's Copilot CLI agent host ("forwarded to the @agent-host-copilotcli
// coding agent") runs the same engine as copilot-runtime.exe from VS Code's
// copilot-sdk, which loads both files too (GAP-1779, managed Windows).

// hookCopilotCLIMachinePolicyInForce is replaceable in tests.
var hookCopilotCLIMachinePolicyInForce = copilotCLIMachinePolicyInForce

func copilotCLIRunsVSCodeLocalHook(connectorName, surface string, enterpriseManaged bool) bool {
	if !enterpriseManaged || strings.ToLower(strings.TrimSpace(connectorName)) != "copilot" ||
		strings.TrimSpace(surface) != connector.CopilotHookSurfaceVSCodeLocal {
		return false
	}
	engine := strings.ToLower(filepath.Base(strings.ReplaceAll(hookAgentExecutable(), `\`, "/")))
	switch strings.TrimSuffix(engine, ".exe") {
	case "copilot", "copilot-runtime":
	default:
		return false
	}
	return hookCopilotCLIMachinePolicyInForce()
}
