// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

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
