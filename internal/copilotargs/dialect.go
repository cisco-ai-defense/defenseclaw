// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import "strings"

// SurfaceVSCodeLocal is the --hook-surface value of a Copilot hook command
// registered for the VS Code Local harness. The hook forwards it in the
// X-DefenseClaw-Hook-Dialect header.
const SurfaceVSCodeLocal = "vscode-local"

// LocalDialect returns the event a Copilot hook body is judged as and
// whether the gateway reads it in the VS Code Local dialect (tool_name,
// tool_input) rather than the CLI dialect (toolName, toolArgs). Both inputs
// are bound to the registered hook command; no body field selects a route.
//
// A command of the vscode-local surface reads its bound event in the Local
// dialect. A CLI hook file keeps its CLI route even when another harness
// invokes it. Schema mismatches fail closed at the gateway and resolver.
func LocalDialect(surface, boundEvent string) (string, bool) {
	boundEvent = strings.TrimSpace(boundEvent)
	if strings.TrimSpace(surface) == SurfaceVSCodeLocal {
		return boundEvent, true
	}
	return boundEvent, false
}
