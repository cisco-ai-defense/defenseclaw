// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// agentHookConfigFindings adds the hook configuration findings of a tool
// call. On a Windows host a shell call is judged in both readings, as the
// protected decision and the registration readers judge it: the POSIX
// grammar Git Bash uses, and a backslash inside a word read as a path
// separator (hookpaths.WindowsShellReading). A finding of either reading is
// kept, so a native path such as C:\Users\me\.claude\settings.json names the
// file whichever shell runs the call.
func agentHookConfigFindings(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	out := agentHookConfigFindingsAs(ctx, request, findings)
	reading, windows := hookpaths.WindowsShellReading(agentHookConfigRawShellCommand(request.Input))
	if !windows {
		return out
	}
	request.Input.Command = reading
	return agentHookConfigFindingsAs(ctx, request, out)
}
