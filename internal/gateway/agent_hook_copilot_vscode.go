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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A Copilot hook command registered for the VS Code Local harness carries
// --hook-surface vscode-local, which the hook forwards in
// connector.HookDialectHeader. The request context records it so every
// profile lookup for the request (hookProfileForRequest) gets the Local
// dialect profile, connector.CopilotVSCodeLocalProfile. Requests without the
// marker keep the Copilot CLI profile unchanged.

type copilotVSCodeLocalKey struct{}

func withCopilotVSCodeLocal(ctx context.Context) context.Context {
	return context.WithValue(ctx, copilotVSCodeLocalKey{}, true)
}

func copilotVSCodeLocalFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(copilotVSCodeLocalKey{}).(bool)
	return v
}

func copilotHookDialectFromHeaders(header http.Header) string {
	return strings.TrimSpace(header.Get(connector.HookDialectHeader))
}
