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
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A Copilot hook command registered for the VS Code Local harness carries
// --hook-surface vscode-local, which the hook forwards in
// connector.HookDialectHeader. The request context records it so every
// profile lookup for the request (hookProfileForRequest) gets the Local
// dialect profile, connector.CopilotVSCodeLocalProfile. The per-user default
// and permissive CLI document uses a shared body decoder under its bound
// CLI event.

type copilotVSCodeLocalKey struct{}
type copilotCLISharedEventKey struct{}

func withCopilotVSCodeLocal(ctx context.Context) context.Context {
	return context.WithValue(ctx, copilotVSCodeLocalKey{}, true)
}

func copilotVSCodeLocalFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(copilotVSCodeLocalKey{}).(bool)
	return v
}

func withCopilotCLISharedEvent(ctx context.Context, event string) context.Context {
	return context.WithValue(ctx, copilotCLISharedEventKey{}, event)
}

func copilotCLISharedEventFromContext(ctx context.Context) string {
	v, _ := ctx.Value(copilotCLISharedEventKey{}).(string)
	return v
}

func copilotCLIMixedLocalFields(payload map[string]interface{}) bool {
	for key := range payload {
		if copilotargs.CLIHookLocalForeignField(key) {
			return true
		}
	}
	return false
}

// copilotSharedLocalFileCall marks a Local-dialect body delivered through the
// per-user CLI document. The file-tool class is decided where the typed facts
// are read (actionfacts.PathTool), so every accepted file operation, whatever
// its tool name, has its resolved target judged like its lexical path.
func copilotSharedLocalFileCall(ctx context.Context, req agentHookRequest) bool {
	if req.ConnectorName != "copilot" {
		return false
	}
	_, local := copilotargs.CLIHookLocalEvent(
		copilotCLISharedEventFromContext(ctx), payloadString(req.Payload, "hook_event_name"))
	return local
}

func copilotHookDialectFromHeaders(header http.Header) string {
	return strings.TrimSpace(header.Get(connector.HookDialectHeader))
}
