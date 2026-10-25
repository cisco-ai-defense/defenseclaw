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

package gateway

import (
	"context"
	"encoding/json"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// inspectHermesWriteToolPolicyCtx is inspectSandboxShellToolPolicyCtx for a
// Hermes native file-write call projected onto views
// (connector.HermesTrustedWriteViews), whose first view action already
// carries. Every other view is judged on its own as well, and so, for a
// sandbox call, is each absolute target in the guest directory that holds
// it (the form a relative target already takes). The verdict takes the
// strongest of them; the extra views only ever add to it, and a call the
// static allow list or managed mode settles is left as it is. With no views
// it is inspectSandboxShellToolPolicyCtx.
func (a *APIServer) inspectHermesWriteToolPolicyCtx(
	ctx context.Context,
	req *ToolInspectRequest,
	action trustedActionRequest,
	command json.RawMessage,
	commandTool string,
	views []connector.HermesWriteView,
) *ToolInspectVerdict {
	if len(views) == 0 {
		return a.inspectSandboxShellToolPolicyCtx(ctx, req, action, command, commandTool)
	}
	dispatched := false
	record := action.record
	action.record = func(facts actionfacts.Facts, findings []RuleFinding) {
		dispatched = true
		if record != nil {
			record(facts, findings)
		}
	}
	verdict := a.inspectSandboxShellToolPolicyCtx(ctx, req, action, command, commandTool)
	if verdict == nil || !dispatched {
		return verdict
	}
	cfg, connectorName := a.decisionConfig(ctx), firstNonEmpty(req.Connector, action.Connector)
	for _, extra := range hermesWriteViewRequests(ctx, action, views) {
		verdict = mergeSandboxShellCommandVerdict(ctx, cfg, connectorName, verdict, dispatchTrustedAction(ctx, extra))
	}
	return verdict
}

// hermesWriteViewRequests are the trusted-action requests of views beyond
// the one action judges: views[1:], and the guest-directory form of every
// absolute sandbox target.
func hermesWriteViewRequests(ctx context.Context, action trustedActionRequest, views []connector.HermesWriteView) []trustedActionRequest {
	base := action
	base.record, base.recordTelemetry = nil, nil
	var requests []trustedActionRequest
	for i, view := range views {
		if i > 0 {
			request := base
			request.Input.Tool, request.Input.Args = view.Tool, view.Args
			requests = append(requests, request)
		}
		if request, ok := hermesSandboxGuestDirRequest(ctx, base, view); ok {
			requests = append(requests, request)
		}
	}
	return requests
}

// hermesSandboxGuestDirRequest judges an absolute target of a sandbox call
// by its name in the directory that holds it, with that directory as the
// working directory (its host mount, and the guest directory itself for
// guest-side checks). That is how a relative target is judged, so a link in
// a mounted directory is read on the host the same way for both spellings.
// ok is false for host traffic, a relative or "~" target, and a directory
// with no host mount.
func hermesSandboxGuestDirRequest(ctx context.Context, base trustedActionRequest, view connector.HermesWriteView) (trustedActionRequest, bool) {
	if !isSandboxHookRequest(ctx) || !path.IsAbs(view.Path) || strings.ContainsAny(view.Path, "\\\x00") {
		return trustedActionRequest{}, false
	}
	clean := path.Clean(view.Path)
	dir, name := path.Dir(clean), path.Base(clean)
	if name == "/" || name == "." || name == ".." {
		return trustedActionRequest{}, false
	}
	hostDir := hookCWDForContext(ctx, dir)
	if hostDir == "" {
		return trustedActionRequest{}, false
	}
	args, ok := view.Retarget(name)
	if !ok {
		return trustedActionRequest{}, false
	}
	request := base
	request.Input.Tool, request.Input.Args, request.Input.CWD = view.Tool, args, hostDir
	request.SandboxGuestCWD = dir
	request.patchHostView = true
	// The client's resolved targets name the call's own spelling and
	// working directory, not this one.
	request.ResolvedWriteTargets = nil
	return request, true
}
