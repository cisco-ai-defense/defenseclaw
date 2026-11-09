// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A Codex shell call runs in the workdir the model gave it, but the Codex
// PreToolUse hook sends only {"command": ...} as tool_input and the session
// cwd as cwd (GAP-1388): a relative `echo x >> AGENTS.md` with workdir set to
// another folder was judged, and its folder snapshotted, as if it ran in the
// session folder, so a pre-existing AGENTS.md there was writable in action
// mode. The call itself, with its workdir, is in the session rollout
// (transcript_path) under the hook tool_use_id: Codex records the model
// output item before it runs the tool. A managed gateway cannot read the
// rollout; its hook client does and sends the workdir (hookpaths.CallWorkdirKey).

// codexTranscriptCallWorkdir is the workdir argument of the Codex function
// call req.ToolUseID in the session rollout req.TranscriptPath, when the
// hook tool_input has none. It reads only on a gateway that reads the caller
// files, and never for a sandbox request. "" when there is no such call or
// argument (hookpaths.CodexRolloutCallWorkdir).
func codexTranscriptCallWorkdir(ctx context.Context, req codexHookRequest) string {
	if isSandboxHookRequest(ctx) || !instructionGatewayReadsFiles(ctx) {
		return ""
	}
	if _, present := req.ToolInput["workdir"]; present {
		return ""
	}
	return hookpaths.CodexRolloutCallWorkdir(instructionHome(ctx), req.TranscriptPath, req.ToolUseID)
}
